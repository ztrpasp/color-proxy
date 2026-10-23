"""被动 FTP 的数据连接跟随控制连接：端到端测试（D21，docs/design-l3-v2.md §8.8）。

装配方式同 ``test_l3_acceptance.py``：两端数据面在进程内对接，报文是真的 CoLoR 报文，只有
链路是假的（同步投递）。源站的回复由测试直接写进提供端的 ``on_tun_packet``，客户端的包写进
消费端的 ``on_tun_packet``，与真机上两边内核往 tun 里写包是同一个入口。

提供端只发布 ``tcp://ip:21``（``app:"ftp"``）与 ``tcp://ip:3306``，**不发布通配**：数据连接
能通，只能是因为 227/229 登记的期望。

可用 ``python -m pytest tests/test_l3_ftp.py`` 运行，
也可直接 ``python tests/test_l3_ftp.py`` 运行（无需 pytest、无需管理员）。
"""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from colorproxy.config import Config, L3Config, L3ServiceConfig, PeerConfig, ServiceConfig, _load_l3
from colorproxy.consumer.config import (
    AppService,
    ConsumerConfig,
    ConsumerL3Config,
    _load_l3 as _load_consumer_l3,
)
from colorproxy.consumer.messages import build_get, build_l3_upstream
from colorproxy.consumer.state import ConsumerState
from colorproxy.l3.consumer import L3Consumer
from colorproxy.l3.ftp import CLOSE_LINGER_SEC, EXPECT_TTL_SEC, wildcard_conflicts
from colorproxy.l3.provider import L3Provider
from colorproxy.messages import is_ack
from colorproxy.protocol.constants import DATA_FIRST_BYTE, GET_FIRST_BYTE
from colorproxy.protocol.sid import sid_hex_from_service
from colorproxy.state import ProviderState
from colorproxy.tun import ipv4
from colorproxy.tun.device import LoopbackTun

PROVIDER_NID = 0xA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1
CONSUMER_NID = 0xB2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2
OTHER_NID = 0xC3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3   # 另一个合法消费端
PROVIDER_IP = "172.10.0.2"
CONSUMER_IP = "10.10.0.2"
OTHER_IP = "10.10.0.3"
RM_IP = "10.10.0.5"
SERVICE_IP = "172.10.9.2"
CONSUMER_TUN = "10.99.1.1"
OTHER_TUN = "10.99.1.2"
FTP_PORT = 21
MYSQL_PORT = 3306
DATA_PORT = 50123
CTRL_CPORT = 40000      # 客户端控制连接的源端口
DATA_CPORT = 41000      # 客户端数据连接的源端口
ISN = 1000
SRV_ISN = 70000


# ---------------------------------------------------------------- 装配

class _Link:
    """假链路（同步投递），按首字节与 B 位分派，入口与真实装配一致。"""

    def __init__(self) -> None:
        self.provider: L3Provider | None = None
        self.consumer: L3Consumer | None = None
        self.dropped: list[bytes] = []
        self.gets = 0

    def send(self, _dst_ip: str, packet) -> None:
        payload = bytes(packet)
        if payload[0] == GET_FIRST_BYTE:
            self.gets += 1
            if self.provider is not None and self.provider.handle_get(payload):
                return
        elif payload[0] == DATA_FIRST_BYTE:
            if is_ack(payload):
                if self.provider is not None and self.provider.handle_upstream(payload):
                    return
            elif self.consumer is not None and self.consumer.handle_data(payload):
                return
        self.dropped.append(payload)


def _wire(*, wildcard: bool = False):
    services = [
        L3ServiceConfig(proto="tcp", ip=SERVICE_IP, port=FTP_PORT, app="ftp"),
        L3ServiceConfig(proto="tcp", ip=SERVICE_IP, port=MYSQL_PORT),
    ]
    if wildcard:
        services.append(L3ServiceConfig(proto="tcp", ip=SERVICE_IP, port=0))
    provider_config = Config(
        nid=PROVIDER_NID, ipv4=PROVIDER_IP, rm_ipv4="172.10.0.5",
        services=[ServiceConfig(f"http://{PROVIDER_IP}:8000/x", PROVIDER_IP, 8000)],
        l3=L3Config(
            enabled=True, tun_ip=SERVICE_IP, peer_routes=("10.99.1.0/24",),
            peers=(PeerConfig(nid=CONSUMER_NID, tun_ip=CONSUMER_TUN),
                   PeerConfig(nid=OTHER_NID, tun_ip=OTHER_TUN)),
            services=tuple(services),
        ),
    )
    provider_state = ProviderState(provider_config)
    provider_state.set_domain_info([(CONSUMER_NID, CONSUMER_IP), (OTHER_NID, OTHER_IP)], [])
    for service in services:
        provider_state.add_l3_service(
            sid_hex_from_service(PROVIDER_NID, service.proto, service.ip, service.port), service)

    consumer_config = ConsumerConfig(
        nid=CONSUMER_NID, ipv4=CONSUMER_IP, rm_ipv4=RM_IP,
        l3=ConsumerL3Config(
            enabled=True, tun_ip=CONSUMER_TUN, capture_routes=(f"{SERVICE_IP}/32",),
            app_services=(AppService("tcp", SERVICE_IP, FTP_PORT, "ftp"),),
        ),
    )
    consumer_state = ConsumerState(consumer_config)
    consumer_state.set_domain_info([(PROVIDER_NID, PROVIDER_IP)], [])
    for service in services:
        consumer_state.add_sid(sid_hex_from_service(PROVIDER_NID, "tcp", SERVICE_IP, service.port))

    link = _Link()
    provider = L3Provider(provider_state, LoopbackTun(SERVICE_IP), link)
    consumer = L3Consumer(consumer_state, LoopbackTun(CONSUMER_TUN), link)
    link.provider, link.consumer = provider, consumer
    return link, provider, consumer


def _sid(port: int) -> str:
    return sid_hex_from_service(PROVIDER_NID, "tcp", SERVICE_IP, port)


def _seg(sport: int, dport: int, flags: str, seq: int, ack: int = 0, payload: bytes = b"",
         src: str = CONSUMER_TUN, dst: str = SERVICE_IP) -> bytes:
    packet = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
    if payload:
        packet = packet / Raw(payload)
    return bytes(IP(bytes(packet)))


def _from_server(sport: int, dport: int, flags: str, seq: int, ack: int = 0,
                 payload: bytes = b"") -> bytes:
    return _seg(sport, dport, flags, seq, ack, payload, src=SERVICE_IP, dst=CONSUMER_TUN)


def _ports(raw: bytes) -> tuple[int, int]:
    header = ipv4.parse_header(raw)
    assert header is not None
    ports = ipv4.parse_ports(raw, header)
    assert ports is not None
    return ports


class _Control:
    """一条 FTP 控制连接：替两端记住序号，按真实顺序把包写进两端的 tun 入口。"""

    def __init__(self, provider: L3Provider, consumer: L3Consumer, cport: int = CTRL_CPORT) -> None:
        self.provider, self.consumer, self.cport = provider, consumer, cport
        self.c_seq, self.s_seq = ISN, SRV_ISN

    def open(self, *, handshake: bool = True) -> "_Control":
        if handshake:
            assert self.consumer.on_tun_packet(_seg(self.cport, FTP_PORT, "S", self.c_seq))
            self.c_seq += 1
            assert self.provider.on_tun_packet(
                _from_server(FTP_PORT, self.cport, "SA", self.s_seq, self.c_seq))
            self.s_seq += 1
            assert self.consumer.on_tun_packet(
                _seg(self.cport, FTP_PORT, "A", self.c_seq, self.s_seq))
            self.reply(b"220 color-proxy test\r\n")
        return self

    def command(self, line: bytes) -> None:
        assert self.consumer.on_tun_packet(
            _seg(self.cport, FTP_PORT, "PA", self.c_seq, self.s_seq, line))
        self.c_seq += len(line)

    def reply(self, line: bytes, *, seq: int | None = None) -> None:
        start = self.s_seq if seq is None else seq
        assert self.provider.on_tun_packet(
            _from_server(FTP_PORT, self.cport, "PA", start, self.c_seq, line))
        self.s_seq = max(self.s_seq, start + len(line))

    def epsv(self, port: int = DATA_PORT) -> None:
        self.command(b"EPSV\r\n")
        self.reply(b"229 Entering Extended Passive Mode (|||%d|)\r\n" % port)


def _drain(provider: L3Provider, consumer: L3Consumer) -> None:
    provider.tun.pop_written()
    consumer.tun.pop_written()


def _data_syn(consumer: L3Consumer, cport: int = DATA_CPORT, port: int = DATA_PORT) -> None:
    consumer.on_tun_packet(_seg(cport, port, "S", 9000))


# ---------------------------------------------------------------- 正常路径

def test_epsv_data_connection_rides_control_sid_without_extra_get() -> None:
    link, provider, consumer = _wire()
    _Control(provider, consumer).open().epsv()
    assert provider.counters.get("ftp_expect") == 1
    assert link.gets == 1, "控制连接首建隧道一个 GET"
    _drain(provider, consumer)

    _data_syn(consumer)
    assert link.gets == 1, "数据连接继承控制连接的准入，不再发 GET（D21 对 D19 的例外）"
    injected = provider.tun.pop_written()
    assert [_ports(p) for p in injected] == [(DATA_CPORT, DATA_PORT)]
    assert provider.counters.get("ftp_data_admit") == 1
    assert provider.tunnels.count() == 1, "数据连接没有自己的隧道，走控制 SID 那一条"

    # 回程：源站从数据端口回 SYN-ACK 和数据，都经控制 SID 送到客户端
    assert provider.on_tun_packet(_from_server(DATA_PORT, DATA_CPORT, "SA", 1, 9001))
    assert provider.on_tun_packet(_from_server(DATA_PORT, DATA_CPORT, "PA", 2, 9001, b"x" * 1000))
    delivered = consumer.tun.pop_written()
    assert [_ports(p) for p in delivered] == [(DATA_PORT, DATA_CPORT)] * 2
    for name in ("admit_drop", "sid_miss", "no_tunnel_drop", "src_bind_drop"):
        assert provider.counters.get(name) == 0, name
    assert link.dropped == []


def test_pasv_registers_on_service_address_not_the_one_in_227() -> None:
    link, provider, consumer = _wire()
    control = _Control(provider, consumer).open()
    control.command(b"PASV\r\n")
    # 227 里写的是别的地址：不信它，照样登记在控制连接的服务地址上（不给别的主机开洞）
    control.reply(b"227 Entering Passive Mode (10,0,0,9,195,80).\r\n")
    assert provider.counters.get("ftp_expect") == 1
    _drain(provider, consumer)
    _data_syn(consumer, port=50000)
    assert [_ports(p) for p in provider.tun.pop_written()] == [(DATA_CPORT, 50000)]


# ---------------------------------------------------------------- 拒绝路径

def test_data_syn_without_announcement_is_dropped() -> None:
    link, provider, consumer = _wire()
    _Control(provider, consumer).open()
    _drain(provider, consumer)
    _data_syn(consumer)
    assert provider.tun.pop_written() == []
    assert provider.counters.get("admit_drop") == 1
    assert link.gets == 1, "没登记的端口照样走控制 SID 去提供端，由提供端拒绝；消费端不发 GET"


def test_unsolicited_or_embedded_227_registers_nothing() -> None:
    link, provider, consumer = _wire()
    control = _Control(provider, consumer).open()
    # 没有前置 PASV 的 227：不认
    control.command(b"NOOP\r\n")
    control.reply(b"227 Entering Passive Mode (172,10,9,2,195,80)\r\n")
    # PASV 的回复是多行的 213，中间夹着 227/229：都是正文
    control.command(b"PASV\r\n")
    control.reply(b"213-Status\r\n227 Entering Passive Mode (172,10,9,2,195,81)\r\n"
                  b"229 Entering Extended Passive Mode (|||50002|)\r\n213 End\r\n")
    # EPSV 却回了 227：代码与命令对不上，不认
    control.command(b"EPSV\r\n")
    control.reply(b"227 Entering Passive Mode (172,10,9,2,195,82)\r\n")
    assert provider.counters.get("ftp_expect") == 0
    assert provider.ftp is not None and provider.ftp.counts()[1] == 0


def test_dangerous_ports_are_rejected() -> None:
    """数据端口撞上另一条已发布服务（3306）、特权端口、控制端口本身：一律拒绝登记。"""
    link, provider, consumer = _wire()
    control = _Control(provider, consumer).open()
    for port in (MYSQL_PORT, 1000, FTP_PORT):
        control.epsv(port)
    assert provider.counters.get("ftp_expect_reject") == 3
    assert provider.counters.get("ftp_expect") == 0
    _drain(provider, consumer)
    _data_syn(consumer, port=1000)
    assert provider.tun.pop_written() == []


def test_expectation_is_one_shot_but_syn_retransmit_passes() -> None:
    link, provider, consumer = _wire()
    _Control(provider, consumer).open().epsv()
    _drain(provider, consumer)
    _data_syn(consumer)
    _data_syn(consumer)                       # 同一四元组的 SYN 重传
    assert len(provider.tun.pop_written()) == 2
    _data_syn(consumer, cport=DATA_CPORT + 1)  # 换个源端口再连：期望已经兑现掉了
    assert provider.tun.pop_written() == []
    assert provider.counters.get("ftp_data_admit") == 1
    assert provider.counters.get("admit_drop") == 1


def test_spoofed_source_cannot_consume_expectation() -> None:
    link, provider, consumer = _wire()
    _Control(provider, consumer).open().epsv()
    _drain(provider, consumer)
    forged = build_l3_upstream(_sid(FTP_PORT), CONSUMER_NID, [], 1,
                               _seg(DATA_CPORT, DATA_PORT, "S", 9000, src=OTHER_TUN))
    assert provider.handle_upstream(bytes(forged))
    assert provider.tun.pop_written() == []
    assert provider.counters.get("src_bind_drop") == 1
    _data_syn(consumer)                       # 期望没被伪造包用掉，正主照样能连
    assert len(provider.tun.pop_written()) == 1


def test_other_consumer_cannot_use_expectation() -> None:
    link, provider, consumer = _wire()
    _Control(provider, consumer).open().epsv()
    _drain(provider, consumer)
    # 另一个合法消费端也有控制 SID 的隧道（它自己的 GET 被放行了）
    assert provider.handle_get(bytes(build_get(_sid(FTP_PORT), OTHER_NID, 7)))
    stolen = build_l3_upstream(_sid(FTP_PORT), OTHER_NID, [], 7,
                               _seg(DATA_CPORT, DATA_PORT, "S", 9000, src=OTHER_TUN))
    assert provider.handle_upstream(bytes(stolen))
    assert provider.tun.pop_written() == []
    assert provider.counters.get("admit_drop") == 1


def test_data_on_another_services_sid_is_not_ftp_data() -> None:
    """期望绑在控制 SID 上：同一消费端拿 3306 的隧道送数据端口的包，照样被拦。"""
    link, provider, consumer = _wire()
    _Control(provider, consumer).open().epsv()
    consumer.on_tun_packet(_seg(42000, MYSQL_PORT, "S", 1))   # 建起 3306 的隧道
    _drain(provider, consumer)
    smuggled = build_l3_upstream(_sid(MYSQL_PORT), CONSUMER_NID, [], 1,
                                 _seg(DATA_CPORT, DATA_PORT, "S", 9000))
    assert provider.handle_upstream(bytes(smuggled))
    assert provider.tun.pop_written() == []
    assert provider.counters.get("admit_drop") == 1


# ---------------------------------------------------------------- 生命周期

def test_expectation_expires() -> None:
    link, provider, consumer = _wire()
    _Control(provider, consumer).open().epsv()
    _drain(provider, consumer)
    assert provider.ftp is not None
    provider.ftp.tick(time.monotonic() + EXPECT_TTL_SEC + 1)
    assert provider.counters.get("ftp_expect_expired") == 1
    _data_syn(consumer)
    assert provider.tun.pop_written() == []


def test_data_connection_outlives_expectation_and_is_cleaned_after_close() -> None:
    for closing in ("rst", "fin"):
        link, provider, consumer = _wire()
        _Control(provider, consumer).open().epsv()
        _drain(provider, consumer)
        _data_syn(consumer)
        assert provider.on_tun_packet(_from_server(DATA_PORT, DATA_CPORT, "SA", 1, 9001))
        assert provider.ftp is not None
        provider.ftp.tick(time.monotonic() + EXPECT_TTL_SEC + 1)   # 期望早过了 TTL
        consumer.on_tun_packet(_seg(DATA_CPORT, DATA_PORT, "PA", 9001, 2, b"STOR data"))
        assert len(provider.tun.pop_written()) == 2, f"{closing}：建立后的数据连接不受期望 TTL 影响"

        if closing == "rst":
            consumer.on_tun_packet(_seg(DATA_CPORT, DATA_PORT, "R", 9010))
        else:
            consumer.on_tun_packet(_seg(DATA_CPORT, DATA_PORT, "FA", 9010, 2))
            assert provider.on_tun_packet(_from_server(DATA_PORT, DATA_CPORT, "FA", 2, 9011))
        consumer.on_tun_packet(_seg(DATA_CPORT, DATA_PORT, "A", 9011, 3))   # 收尾的 ACK 还能过
        assert len(provider.tun.pop_written()) == 2, closing
        provider.ftp.tick(time.monotonic() + CLOSE_LINGER_SEC + 1)
        assert provider.ftp.counts()[2] == 0, f"{closing}：收尾后数据连接应被清掉"
        consumer.on_tun_packet(_seg(DATA_CPORT, DATA_PORT, "A", 9011, 3))
        assert provider.tun.pop_written() == [], closing


def test_retransmitted_229_does_not_double_register() -> None:
    link, provider, consumer = _wire()
    control = _Control(provider, consumer).open()
    control.command(b"EPSV\r\n")
    line = b"229 Entering Extended Passive Mode (|||%d|)\r\n" % DATA_PORT
    start = control.s_seq
    control.reply(line)
    control.reply(line, seq=start)            # 下行丢了，源站重传
    assert provider.counters.get("ftp_expect") == 1
    _drain(provider, consumer)
    _data_syn(consumer)                       # 期望仍在
    assert len(provider.tun.pop_written()) == 1


def test_mid_stream_join_waits_for_alignment() -> None:
    """没看到控制连接的 SYN（例如提供端刚重启）：对齐之前不登记。"""
    link, provider, consumer = _wire()
    control = _Control(provider, consumer)
    control.c_seq, control.s_seq = 5000, 80000
    control.epsv(50001)                       # 第一行可能是半截：两个方向都丢到行尾
    control.epsv(50002)                       # 第一条完整回复只用来对齐
    assert provider.counters.get("ftp_expect") == 0
    assert provider.counters.get("ftp_resync") >= 1
    control.epsv(50003)
    assert provider.counters.get("ftp_expect") == 1
    _drain(provider, consumer)
    _data_syn(consumer, port=50002)
    assert provider.tun.pop_written() == []
    _data_syn(consumer, port=50003)
    assert len(provider.tun.pop_written()) == 1


def test_sequence_gap_resyncs() -> None:
    link, provider, consumer = _wire()
    control = _Control(provider, consumer).open()
    control.command(b"EPSV\r\n")
    control.s_seq += 10                       # 有 10 个字节提供端没看到
    control.reply(b"229 Entering Extended Passive Mode (|||%d|)\r\n" % DATA_PORT)
    control.epsv(50002)                       # 对齐用，不登记
    assert provider.counters.get("ftp_expect") == 0
    assert provider.counters.get("ftp_resync") == 1
    control.epsv(50003)                       # 对齐之后恢复正常，命令与回复也没错位
    control.epsv(50004)
    assert provider.counters.get("ftp_expect") == 2


def test_echoed_bare_lf_cannot_forge_a_229() -> None:
    """``MKD`` 的参数带裸 LF，源站把它回显进 257：这半句不能被当成一条 229。"""
    link, provider, consumer = _wire()
    control = _Control(provider, consumer).open()
    control.command(b"MKD foo\n229 (|||3389|)\r\nEPSV\r\n")
    control.reply(b'257 "/foo\n229 (|||3389|)" created\r\n')
    control.reply(b"229 Entering Extended Passive Mode (|||%d|)\r\n" % DATA_PORT)
    # 命令方向宽松地按 LF 切出了三条，源站只当两条：配对错开，连这次正常的 EPSV 也看漏了。
    # 看漏只会让这个（自己捣乱的）客户端连不上数据端口，不会多放东西
    assert provider.counters.get("ftp_expect") == 0
    _drain(provider, consumer)
    _data_syn(consumer, port=3389)
    assert provider.tun.pop_written() == [], "3389 不能被开洞"


# ---------------------------------------------------------------- 不影响其他服务 / 配置

def test_other_published_service_keeps_its_own_sid_and_d19() -> None:
    link, provider, consumer = _wire()
    _Control(provider, consumer).open()
    consumer.on_tun_packet(_seg(42000, MYSQL_PORT, "S", 1))
    assert link.gets == 2, "3306 首建自己的隧道"
    consumer.on_tun_packet(_seg(42001, MYSQL_PORT, "S", 1))
    assert link.gets == 3, "3306 的新连接照样走 D19"
    assert provider.tunnels.count() == 2


def test_wildcard_conflict_is_detected() -> None:
    services = [L3ServiceConfig(proto="tcp", ip=SERVICE_IP, port=FTP_PORT, app="ftp"),
                L3ServiceConfig(proto="tcp", ip=SERVICE_IP, port=0)]
    assert wildcard_conflicts(services) == [SERVICE_IP]
    assert wildcard_conflicts(services[:1]) == []
    # 同时发布了通配时，消费端优先命中通配：数据连接走 :0 的 SID（D21 被架空，启动会告警）
    link, provider, consumer = _wire(wildcard=True)
    _Control(provider, consumer).open()
    _drain(provider, consumer)
    _data_syn(consumer)
    assert consumer.tunnels.get(_sid(0)) is not None


def test_provider_config_validates_ftp() -> None:
    base = {"proto": "tcp", "ip": SERVICE_IP, "port": FTP_PORT, "app": "ftp"}
    ok = _load_l3({"enabled": False, "services": [base]})
    assert ok.services[0].app == "ftp"
    for bad in ([{**base, "port": 0}], [{**base, "proto": "udp"}],
                [{**base, "paths": ["/x"]}], [base, {**base, "port": 2121}]):
        try:
            _load_l3({"enabled": False, "services": bad})
        except ValueError:
            continue
        raise AssertionError(f"应当拒绝：{bad}")


def test_consumer_config_validates_ftp() -> None:
    def load(entries):
        return _load_consumer_l3({"enabled": False, "capture_routes": [f"{SERVICE_IP}/32"],
                                  "app_services": entries}, rm_ipv4=RM_IP)

    base = {"proto": "tcp", "ip": SERVICE_IP, "port": FTP_PORT, "app": "ftp"}
    assert load([base]).app_services == (AppService("tcp", SERVICE_IP, FTP_PORT, "ftp"),)
    for bad in ([{**base, "port": 0}], [base, {**base, "port": 2121}]):
        try:
            load(bad)
        except ValueError:
            continue
        raise AssertionError(f"应当拒绝：{bad}")


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
