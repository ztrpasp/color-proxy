"""L3 下的 HTTP 内容级准入端到端测试（D20，docs/design-l3-v2.md §8.7）。

装配方式同 ``test_l3_dataplane.py``：两端数据面在进程内对接，报文是真的 CoLoR 报文，
只有链路是假的。区别是这里的假链路默认**异步**——``send`` 只入队，``pump()`` 才投递。
真实环境里准入 GET 的回复由收包线程送回，与 tun 读线程并发；同步投递会把"请求被扣住、
等 GET 回复"这一段时间压成零，看不见扣留。

可用 ``python -m pytest tests/test_l3_content.py`` 运行，
也可直接 ``python tests/test_l3_content.py`` 运行（无需 pytest、无需管理员）。
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from colorproxy import publish
from colorproxy.config import (
    Config,
    L3Config,
    L3ServiceConfig,
    PeerConfig,
    ServiceConfig,
    _load_l3,
    load_config,
)
from colorproxy.consumer.config import (
    AppService,
    ConsumerConfig,
    ConsumerL3Config,
    _load_l3 as _load_consumer_l3,
)
from colorproxy.consumer.messages import build_get
from colorproxy.consumer.state import ConsumerState
from colorproxy.l3.consumer import L3Consumer
from colorproxy.l3.provider import L3Provider
from colorproxy.messages import is_ack
from colorproxy.protocol.constants import DATA_FIRST_BYTE, GET_FIRST_BYTE
from colorproxy.protocol.packets import ColorData, ColorGet
from colorproxy.protocol.sid import (
    content_url,
    sid_hex_from_packet,
    sid_hex_from_service,
    sid_hex_from_url,
)
from colorproxy.state import ProviderState
from colorproxy.tun.device import LoopbackTun

PROVIDER_NID = 0xA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1
CONSUMER_NID = 0xB2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2
PROVIDER_IP = "172.10.0.2"     # 提供端 CoLoR 地址
CONSUMER_IP = "10.10.0.2"      # 消费端 CoLoR 地址
RM_IP = "10.10.0.5"
SERVICE_IP = "172.10.9.2"      # 虚服务地址（D18）
CONSUMER_TUN = "10.99.1.1"
HTTP_PORT = 8000
OTHER_PORT = 3306              # 发布了但不受内容级管控的端点
PUBLISHED = ("/hello.html", "/items.html", "/api/items")
ISN = 1000                     # 客户端初始序号
SRV_ISN = 50000                # 源站初始序号


# ---------------------------------------------------------------- 装配

def _http_service() -> L3ServiceConfig:
    return L3ServiceConfig(proto="tcp", ip=SERVICE_IP, port=HTTP_PORT, app="http", paths=PUBLISHED)


def _provider_state() -> ProviderState:
    services = (_http_service(), L3ServiceConfig(proto="tcp", ip=SERVICE_IP, port=OTHER_PORT))
    config = Config(
        nid=PROVIDER_NID, ipv4=PROVIDER_IP, rm_ipv4="172.10.0.5",
        services=[ServiceConfig(f"http://{PROVIDER_IP}:8000/x", PROVIDER_IP, 8000)],
        l3=L3Config(
            enabled=True, tun_ip=SERVICE_IP, peer_routes=("10.99.1.0/24",),
            peers=(PeerConfig(nid=CONSUMER_NID, tun_ip=CONSUMER_TUN),), services=services,
        ),
    )
    state = ProviderState(config)
    state.set_domain_info([(CONSUMER_NID, CONSUMER_IP)], [])
    publish._publish_l3_services(state, _Sink())   # 走真的发布代码登记两张表
    return state


def _consumer_state(**l3_kwargs) -> ConsumerState:
    config = ConsumerConfig(
        nid=CONSUMER_NID, ipv4=CONSUMER_IP, rm_ipv4=RM_IP,
        l3=ConsumerL3Config(
            enabled=True, tun_ip=CONSUMER_TUN, capture_routes=(f"{SERVICE_IP}/32",),
            app_services=(AppService("tcp", SERVICE_IP, HTTP_PORT, "http"),), **l3_kwargs,
        ),
    )
    state = ConsumerState(config)
    state.set_domain_info([(PROVIDER_NID, PROVIDER_IP)], [])
    # 模拟 RM 下发的 SID 表：两条服务级 + 每条已发布 URL 一条
    for port in (HTTP_PORT, OTHER_PORT):
        state.add_sid(sid_hex_from_service(PROVIDER_NID, "tcp", SERVICE_IP, port))
    for path in PUBLISHED:
        state.add_sid(_url_sid(path))
    return state


class _Sink:
    """吞掉一切发送的假发送器（只用于发布阶段）。"""

    def __init__(self) -> None:
        self.sent: list = []

    def send(self, dst_ip: str, packet) -> None:
        self.sent.append((dst_ip, packet))


class _Link:
    """假链路：按首字节与 B 位分派到两端数据面，入口与真实装配一致。

    ``sync=False``（默认）时只入队，``pump()`` 才投递；``deny_sids`` 模拟 RM 的 ACL。
    """

    def __init__(self, *, sync: bool = False) -> None:
        self.sync = sync
        self.provider: L3Provider | None = None
        self.consumer: L3Consumer | None = None
        self.queue: list[bytes] = []
        self.get_sids: list[str] = []
        self.deny_sids: set[str] = set()
        self.unclaimed: list[bytes] = []

    def send(self, _dst_ip: str, packet) -> None:
        payload = bytes(packet)
        if payload[0] == GET_FIRST_BYTE:
            self.get_sids.append(_sid_of_get(payload))
        if self.sync:
            self._deliver(payload)
        else:
            self.queue.append(payload)

    def pump(self) -> None:
        while self.queue:
            self._deliver(self.queue.pop(0))

    def _deliver(self, payload: bytes) -> None:
        handled = False
        if payload[0] == GET_FIRST_BYTE:
            if _sid_of_get(payload) in self.deny_sids:
                return  # RM 的 ACL：静默丢弃
            handled = self.provider.handle_get(payload)
        elif payload[0] == DATA_FIRST_BYTE:
            handled = self.provider.handle_upstream(payload) if is_ack(payload) \
                else self.consumer.handle_data(payload)
        if not handled:
            self.unclaimed.append(payload)


def _wire(*, sync: bool = False, **consumer_l3):
    link = _Link(sync=sync)
    provider = L3Provider(_provider_state(), LoopbackTun(SERVICE_IP), link)
    consumer = L3Consumer(_consumer_state(**consumer_l3), LoopbackTun(CONSUMER_TUN), link)
    link.provider, link.consumer = provider, consumer
    return link, provider, consumer


def _sid_of_get(payload: bytes) -> str:
    get = ColorGet(payload)
    return sid_hex_from_packet(bytes(get.NSID), bytes(get.LSID))


def _url_sid(path: str) -> str:
    return sid_hex_from_url(PROVIDER_NID, content_url(SERVICE_IP, HTTP_PORT, path))


def _port_sid(port: int = HTTP_PORT) -> str:
    return sid_hex_from_service(PROVIDER_NID, "tcp", SERVICE_IP, port)


# ---------------------------------------------------------------- 报文样本

def _client(off: int = 0, payload: bytes = b"", flags: str = "PA",
            sport: int = 51000, dport: int = HTTP_PORT) -> bytes:
    """客户端发出的段；``off`` 是流内偏移（第一个数据字节为 0）。"""
    packet = IP(src=CONSUMER_TUN, dst=SERVICE_IP) / TCP(
        sport=sport, dport=dport, seq=ISN + 1 + off, ack=SRV_ISN + 1, flags=flags)
    if payload:
        packet = packet / Raw(payload)
    return bytes(IP(bytes(packet)))


def _syn(sport: int = 51000, dport: int = HTTP_PORT) -> bytes:
    return bytes(IP(bytes(IP(src=CONSUMER_TUN, dst=SERVICE_IP) / TCP(
        sport=sport, dport=dport, seq=ISN, flags="S", options=[("MSS", 1200)]))))


def _synack(dport: int = 51000, sport: int = HTTP_PORT) -> bytes:
    return bytes(IP(bytes(IP(src=SERVICE_IP, dst=CONSUMER_TUN) / TCP(
        sport=sport, dport=dport, seq=SRV_ISN, ack=ISN + 1, flags="SA", options=[("MSS", 1200)]))))


def _request(path: str) -> bytes:
    return f"GET {path} HTTP/1.1\r\nHost: {SERVICE_IP}:{HTTP_PORT}\r\n\r\n".encode()


def _connect(link: _Link, provider: L3Provider, consumer: L3Consumer, sport: int = 51000,
             dport: int = HTTP_PORT) -> None:
    """跑完三次握手（经服务级隧道），清掉两端 tun 的记录。"""
    consumer.on_tun_packet(_syn(sport, dport))
    link.pump()
    provider.on_tun_packet(_synack(sport, dport))
    link.pump()
    consumer.on_tun_packet(_client(0, flags="A", sport=sport, dport=dport))
    link.pump()
    provider.tun.pop_written()
    consumer.tun.pop_written()


def _injected(provider: L3Provider) -> list[bytes]:
    """提供端注入本机协议栈的内层包的 TCP 载荷（RST 记作 b"<RST>"）。"""
    out = []
    for packet in provider.tun.pop_written():
        tcp = IP(packet)[TCP]
        out.append(b"<RST>" if tcp.flags.R else bytes(tcp.payload))
    return out


def _url_gets(link: _Link) -> list[str]:
    urls = {_url_sid(path): path for path in PUBLISHED}
    return [urls.get(sid, "?") for sid in link.get_sids if sid != _port_sid() and sid != _port_sid(OTHER_PORT)]


def _expire(consumer: L3Consumer) -> None:
    consumer.content.tick(time.monotonic() + consumer.config.tunnel_timeout_sec + 0.5)


# ---------------------------------------------------------------- 主路径

def test_published_url_is_held_until_url_get_answers() -> None:
    link, provider, consumer = _wire()
    _connect(link, provider, consumer)
    assert consumer.counters.get("admit_get") == 0 and len(link.get_sids) == 1, "握手只发了服务级 GET"

    request = _request("/hello.html?id=1")
    assert consumer.on_tun_packet(_client(0, request))
    assert _injected(provider) == [], "GET 回复之前请求不能放出去"
    assert _url_gets(link) == ["/hello.html"], "query 不参与 SID"

    link.pump()
    assert _injected(provider) == [request], "回复到了，请求原样放行"
    assert consumer.counters.get("http_admit_get") == 1
    assert consumer.counters.get("http_admit_ok") == 1
    assert provider.counters.get("content_get") == 1
    assert provider.tunnels.count() == 1, "URL SID 不记隧道：数据只走服务级 SID"
    assert link.unclaimed == [], "所有报文都有人认领"

    # 响应照旧经服务级隧道回来
    response = bytes(IP(bytes(IP(src=SERVICE_IP, dst=CONSUMER_TUN) / TCP(
        sport=HTTP_PORT, dport=51000, seq=SRV_ISN + 1, ack=ISN + 1 + len(request), flags="PA")
        / Raw(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))))
    provider.on_tun_packet(response)
    link.pump()
    assert [bytes(IP(p)[TCP].payload) for p in consumer.tun.pop_written()] == \
        [b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"]


def test_unpublished_url_resets_both_sides_without_get() -> None:
    link, provider, consumer = _wire()
    _connect(link, provider, consumer)
    request = _request("/nope.html")
    assert not consumer.on_tun_packet(_client(0, request))
    assert _url_gets(link) == [], "SID 表里没有就不必问 RM"
    assert consumer.counters.get("http_url_miss") == 1

    (to_client,) = [IP(p) for p in consumer.tun.pop_written()]
    assert to_client.src == SERVICE_IP and to_client[TCP].flags == "RA"
    assert to_client[TCP].seq == SRV_ISN + 1, "seq 必须是客户端的 RCV.NXT"
    assert to_client[TCP].ack == ISN + 1 + len(request)

    link.pump()
    (to_server,) = [IP(p) for p in provider.tun.pop_written()]
    assert to_server[TCP].flags == "R" and to_server[TCP].seq == ISN + 1, "seq 必须是源站的 RCV.NXT"

    assert not consumer.on_tun_packet(_client(len(request), flags="A")), "复位后残余上行一律丢"


def test_acl_denied_url_times_out_then_resets() -> None:
    link, provider, consumer = _wire()
    link.deny_sids.add(_url_sid("/items.html"))
    _connect(link, provider, consumer)
    consumer.on_tun_packet(_client(0, _request("/items.html")))
    link.pump()
    assert _injected(provider) == [] and consumer.tun.pop_written() == [], "超时前什么都不发"

    consumer.content.tick(time.monotonic())
    assert consumer.counters.get("http_admit_timeout") == 0, "没到超时不能动"
    _expire(consumer)
    assert consumer.counters.get("http_admit_timeout") == 1
    assert [IP(p)[TCP].flags for p in consumer.tun.pop_written()] == ["RA"]
    link.pump()
    assert _injected(provider) == [b"<RST>"]


def test_keep_alive_each_request_needs_its_own_get() -> None:
    link, provider, consumer = _wire()
    link.deny_sids.add(_url_sid("/api/items"))
    _connect(link, provider, consumer)
    first, second, third = _request("/hello.html"), _request("/items.html"), _request("/api/items")

    consumer.on_tun_packet(_client(0, first))
    link.pump()
    consumer.on_tun_packet(_client(len(first), second))
    link.pump()
    assert _injected(provider) == [first, second]
    assert _url_gets(link) == ["/hello.html", "/items.html"]

    consumer.on_tun_packet(_client(len(first) + len(second), third))
    link.pump()
    _expire(consumer)
    link.pump()
    assert _injected(provider) == [b"<RST>"], "第三个 URL 被拒：连接复位，前两个早已放行"


def test_request_line_split_across_segments() -> None:
    link, provider, consumer = _wire()
    _connect(link, provider, consumer)
    request = _request("/hello.html")
    head, tail = request[:8], request[8:]
    consumer.on_tun_packet(_client(0, head))
    assert _url_gets(link) == [], "请求行没收全，还不知道 URL"
    consumer.on_tun_packet(_client(len(head), tail))
    assert _url_gets(link) == ["/hello.html"]
    link.pump()
    assert _injected(provider) == [head, tail], "两段按序放行"


def test_retransmissions_of_held_and_admitted_segments() -> None:
    link, provider, consumer = _wire()
    _connect(link, provider, consumer)
    request = _request("/hello.html")
    consumer.on_tun_packet(_client(0, request))
    consumer.on_tun_packet(_client(0, request))   # 客户端 RTO 重传
    link.pump()
    assert _injected(provider) == [request], "扣着的段被重传，只放一份"
    assert len(_url_gets(link)) == 1
    assert consumer.on_tun_packet(_client(0, request))
    link.pump()
    assert _injected(provider) == [request], "已准入数据的重传照常转发（源站可能真需要它）"


def test_concurrent_connections_for_same_url_share_one_get() -> None:
    link, provider, consumer = _wire()
    _connect(link, provider, consumer, sport=51000)
    _connect(link, provider, consumer, sport=51001)
    request = _request("/hello.html")
    consumer.on_tun_packet(_client(0, request, sport=51000))
    consumer.on_tun_packet(_client(0, request, sport=51001))
    assert _url_gets(link) == ["/hello.html"], "同一 URL 同时只有一个 GET 在途"
    link.pump()
    assert _injected(provider) == [request, request]
    assert consumer.counters.get("http_admit_ok") == 2


def test_pure_ack_and_trailing_fin_are_not_held() -> None:
    link, provider, consumer = _wire()
    link.deny_sids.add(_url_sid("/items.html"))
    _connect(link, provider, consumer)
    first = _request("/hello.html")
    consumer.on_tun_packet(_client(0, first))
    link.pump()
    provider.tun.pop_written()

    # 请求之间的 FIN：不带请求字节，不能被"下一个请求还没收全"的界限扣住
    consumer.on_tun_packet(_client(len(first), flags="FA"))
    link.pump()
    assert [IP(p)[TCP].flags for p in provider.tun.pop_written()] == ["FA"]

    # 另一条连接：请求被扣着（ACL 不回）期间，确认下行数据的纯 ACK 照常通过
    _connect(link, provider, consumer, sport=52000)
    consumer.on_tun_packet(_client(0, _request("/items.html"), sport=52000))
    consumer.on_tun_packet(_client(0, flags="A", sport=52000))
    link.pump()
    assert [IP(p)[TCP].flags for p in provider.tun.pop_written()] == ["A"]


def test_non_http_on_watched_port_resets() -> None:
    link, provider, consumer = _wire()
    _connect(link, provider, consumer)
    assert not consumer.on_tun_packet(_client(0, b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03"))
    assert consumer.counters.get("http_parse_rst") == 1
    assert [IP(p)[TCP].flags for p in consumer.tun.pop_written()] == ["RA"]
    link.pump()
    assert _injected(provider) == [b"<RST>"]


def test_unwatched_port_is_not_parsed() -> None:
    link, provider, consumer = _wire()
    _connect(link, provider, consumer, dport=OTHER_PORT)
    assert consumer.on_tun_packet(_client(0, b"\x00\x01binary", dport=OTHER_PORT))
    link.pump()
    assert _injected(provider) == [b"\x00\x01binary"], "没配 app_services 的端点与 D20 之前完全一样"
    assert consumer.counters.get("http_req") == 0


def test_mid_stream_connection_is_parsed_from_first_segment() -> None:
    """没见过 SYN 的连接（被空闲清理过）：从第一段起解析，是 HTTP 就照常准入。"""
    link, provider, consumer = _wire()
    _connect(link, provider, consumer)
    consumer.content._conns.clear()          # 模拟空闲清理
    request = _request("/hello.html")
    consumer.on_tun_packet(_client(300, request))
    link.pump()
    assert _injected(provider) == [request]


def test_syn_with_data_is_stripped_so_request_cannot_bypass_gate() -> None:
    """TCP Fast Open：SYN 里的数据只能等客户端重发、过准入，不能随 SYN 直达源站。"""
    link, provider, consumer = _wire()
    link.deny_sids.add(_url_sid("/items.html"))
    secret = _request("/items.html")
    tfo = bytes(IP(bytes(IP(src=CONSUMER_TUN, dst=SERVICE_IP) / TCP(
        sport=51000, dport=HTTP_PORT, seq=ISN, flags="S", options=[("MSS", 1200)]) / Raw(secret))))
    consumer.on_tun_packet(tfo)
    link.pump()
    (syn,) = [IP(p) for p in provider.tun.pop_written()]
    assert syn[TCP].flags == "S" and bytes(syn[TCP].payload) == b"", "SYN 放过去，数据剥掉"
    # 源站只确认 SYN，客户端按普通数据重发：照常被准入拦下
    provider.on_tun_packet(_synack())
    link.pump()
    consumer.on_tun_packet(_client(0, secret))
    link.pump()
    assert _injected(provider) == [], "被拒的 URL 不能借 SYN 绕过去"


def test_synchronous_link_does_not_deadlock() -> None:
    """GET 的回复在同一个调用栈里就送回来（同步链路），也不能死锁或丢掉等它的请求。"""
    link, provider, consumer = _wire(sync=True)
    _connect(link, provider, consumer)
    request = _request("/hello.html")
    assert consumer.on_tun_packet(_client(0, request))
    assert _injected(provider) == [request]


def test_late_duplicate_reply_is_swallowed() -> None:
    link, provider, consumer = _wire()
    _connect(link, provider, consumer)
    consumer.on_tun_packet(_client(0, _request("/hello.html")))
    link.pump()
    # 提供端对同一个 GET 再回一次隧道 DATA：应被 L3 认领，不落到 v1
    provider.handle_get(bytes(build_get(_url_sid("/hello.html"), CONSUMER_NID, 9)))
    link.pump()
    assert link.unclaimed == []


def test_service_ticker_sweeps_content_timeouts() -> None:
    """准入超时不扫就永远不 RST（客户端干等）：装配层必须把 tick 挂上 ticker。"""
    from colorproxy.l3.service import ConsumerL3Service

    service = ConsumerL3Service(_consumer_state(), _Sink(), tun=LoopbackTun(CONSUMER_TUN))
    service._build_dataplane()
    assert service.dataplane.content is not None
    assert service.dataplane.content.tick in service._periodic_tasks()

    plain = ConsumerState(ConsumerConfig(
        nid=CONSUMER_NID, ipv4=CONSUMER_IP, rm_ipv4=RM_IP,
        l3=ConsumerL3Config(enabled=True, tun_ip=CONSUMER_TUN, capture_routes=(f"{SERVICE_IP}/32",)),
    ))
    bare = ConsumerL3Service(plain, _Sink(), tun=LoopbackTun(CONSUMER_TUN))
    bare._build_dataplane()
    assert bare.dataplane.content is None, "没配 app_services 就不构造准入门"


# ---------------------------------------------------------------- 提供端

def test_provider_publishes_url_sids_alongside_service_sid() -> None:
    state = _provider_state()
    assert state.l3_content_count() == len(PUBLISHED)
    assert state.get_l3_service(_port_sid()) is not None, "端点自己的服务级 SID 照常发布"
    service, url = state.get_l3_content(_url_sid("/api/items"))
    assert url == "http://172.10.9.2:8000/api/items" and service.port == HTTP_PORT

    sink = _Sink()
    fresh = ProviderState(state.config)
    publish._publish_l3_services(fresh, sink)
    assert len(sink.sent) == 2 + len(PUBLISHED), "两条服务级 + 每个 URL 一条 ANN"
    publish._publish_l3_services(fresh, sink)
    assert len(sink.sent) == 2 + len(PUBLISHED), "重复发布不重发 ANN（RM 拒重复 AM=1）"


def test_provider_refuses_url_get_from_unknown_consumer() -> None:
    sink = _Sink()
    provider = L3Provider(_provider_state(), LoopbackTun(SERVICE_IP), sink)
    stranger = 0xC3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3
    assert provider.handle_get(bytes(build_get(_url_sid("/hello.html"), stranger, 1)))
    assert sink.sent == [] and provider.counters.get("content_get") == 0


def test_provider_drops_upstream_data_carrying_url_sid() -> None:
    from colorproxy.consumer.messages import build_ack

    sink = _Sink()
    provider = L3Provider(_provider_state(), LoopbackTun(SERVICE_IP), sink)
    ack = bytes(build_ack(_url_sid("/hello.html"), CONSUMER_NID, [], 1, b"GET / HTTP/1.1\r\n\r\n"))
    assert provider.handle_upstream(ack), "URL SID 归 L3，不能落到 v1"
    assert provider.tun.pop_written() == []


# ---------------------------------------------------------------- 配置校验

def _l3_error(entry: dict) -> str:
    try:
        _load_l3({"enabled": False, "services": [entry]})
    except ValueError as exc:
        return str(exc)
    raise AssertionError(f"应当拒绝：{entry}")


def test_provider_config_validates_app_and_paths() -> None:
    base = {"proto": "tcp", "ip": SERVICE_IP, "port": HTTP_PORT}
    assert _l3_error({**base, "paths": ["/a"]})
    assert _l3_error({**base, "app": "http"})
    assert _l3_error({**base, "app": "ftp", "paths": ["/a"]})
    assert _l3_error({**base, "app": "http", "paths": ["a"]})
    assert _l3_error({**base, "app": "http", "paths": ["/a?x=1"]})
    assert _l3_error({**base, "app": "http", "paths": ["/a", "/a"]})
    assert _l3_error({**base, "proto": "udp", "app": "http", "paths": ["/a"]})
    assert _l3_error({**base, "port": 0, "app": "http", "paths": ["/a"]})
    ok = _load_l3({"enabled": False, "services": [{**base, "app": "HTTP", "paths": ["/a", "/b"]}]})
    assert ok.services[0].content_urls == ("http://172.10.9.2:8000/a", "http://172.10.9.2:8000/b")


def test_provider_config_rejects_url_colliding_with_v1() -> None:
    data = {
        "nid": "a1" * 16, "ipv4": PROVIDER_IP, "rm_ipv4": "172.10.0.5",
        "services": [{"url": "http://172.10.9.2:8000/hello.html"}],
        "l3": {"enabled": False, "services": [
            {"proto": "tcp", "ip": SERVICE_IP, "port": HTTP_PORT, "app": "http", "paths": ["/hello.html"]},
        ]},
    }
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "config.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        try:
            load_config(path)
        except ValueError as exc:
            assert "同一条 SID" in str(exc)
        else:
            raise AssertionError("v1 与 L3 内容级撞 SID 必须拒绝启动")
        data["services"][0]["url"] = "http://172.10.0.2:8000/hello.html"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        assert load_config(path).l3.services[0].app == "http", "地址不同就不撞"


def test_consumer_config_validates_app_services() -> None:
    def load(entries):
        return _load_consumer_l3({"enabled": False, "capture_routes": [f"{SERVICE_IP}/32"],
                                  "app_services": entries}, rm_ipv4=RM_IP)

    good = {"proto": "tcp", "ip": SERVICE_IP, "port": HTTP_PORT, "app": "http"}
    assert load([good]).app_services == (AppService("tcp", SERVICE_IP, HTTP_PORT, "http"),)
    for bad in ({**good, "ip": "172.10.9.3"}, {**good, "app": "smtp"}, {**good, "port": 0},
                {**good, "proto": "udp"}):
        try:
            load([bad])
        except ValueError:
            continue
        raise AssertionError(f"应当拒绝：{bad}")
    try:
        load([good, good])
    except ValueError:
        pass
    else:
        raise AssertionError("重复条目应当拒绝")


def _run_all() -> int:
    funcs = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in funcs:
        try:
            fn()
            print(f"  PASS {fn.__name__}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"  FAIL {fn.__name__}: {exc!r}")
    print(f"\n{len(funcs) - failed}/{len(funcs)} passed")
    return failed


if __name__ == "__main__":
    raise SystemExit(_run_all())
