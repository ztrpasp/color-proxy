"""L3 数据面端到端测试（docs/design-l3-v2.md §7.1 / §7.2 / §7.3）。

把两端数据面在进程内对接：报文是**真的 CoLoR 报文**（经 packets.py 构建与解析），
只有链路是假的（按目的 IP 直接投递，代替 RM/BR 与网卡）。这比设计里 M1c 的
"用 UDP 直连代替 CoLoR"覆盖得更多，且完全不需要管理员权限或 tun 设备。

域内场景（PID 为空）已足以覆盖两个方向的全部判据；跨域的 PID 语义由共用代码
``reverse_path_for_ack`` 承担，已有 tests/test_consumer.py 的单元测试覆盖，这里不
另造一个"假 BR"去测自己的假设。

可用 ``python -m pytest tests/test_l3_dataplane.py`` 运行，
也可直接 ``python tests/test_l3_dataplane.py`` 运行（无需 pytest）。
"""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.packet import Raw

from colorproxy.config import Config, L3Config, L3ServiceConfig, PeerConfig, ServiceConfig
from colorproxy.consumer.config import ConsumerConfig, ConsumerL3Config
from colorproxy.consumer.messages import build_l3_upstream
from colorproxy.consumer.state import ConsumerState
from colorproxy.l3.consumer import L3Consumer
from colorproxy.l3.provider import L3Provider
from colorproxy.messages import is_ack
from colorproxy.protocol.constants import (
    DATA_FIRST_BYTE,
    GET_FIRST_BYTE,
    WEB_MSG_TYPE_MASK,
    WebMsgType,
)
from colorproxy.protocol.packets import ColorData
from colorproxy.protocol.sid import sid_hex_from_service
from colorproxy.state import ProviderState
from colorproxy.tun.device import LoopbackTun

PROVIDER_NID = 0xA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1
CONSUMER_NID = 0xB2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2
PROVIDER_IP = "172.10.0.2"
CONSUMER_IP = "10.10.0.2"
RM_IP = "10.10.0.1"
CONSUMER_TUN = "10.99.1.1"
PROVIDER_TUN = "10.99.1.254"
OTHER_TUN = "10.99.1.2"        # 另一个消费端的 tun 地址，用于伪造源地址的测试
SERVICE_PORT = 8000
CLAMP = 1240


# ---------------------------------------------------------------- 装配

def _provider_state(*services: tuple[str, int]) -> ProviderState:
    endpoints = services or (("tcp", SERVICE_PORT),)
    config = Config(
        nid=PROVIDER_NID, ipv4=PROVIDER_IP, rm_ipv4="172.10.0.5",
        services=[ServiceConfig(f"http://{PROVIDER_IP}:8000/x", PROVIDER_IP, 8000)],
        l3=L3Config(
            enabled=True, tun_ip=PROVIDER_TUN, peer_routes=("10.99.1.0/24",),
            mss_clamp=CLAMP,
            peers=(PeerConfig(nid=CONSUMER_NID, tun_ip=CONSUMER_TUN),),
            services=tuple(
                L3ServiceConfig(proto=proto, ip=PROVIDER_IP, port=port)
                for proto, port in endpoints
            ),
        ),
    )
    state = ProviderState(config)
    state.set_domain_info([(CONSUMER_NID, CONSUMER_IP)], [])  # 域内：消费端 NID -> IP
    for service in config.l3.services:
        state.add_l3_service(
            sid_hex_from_service(PROVIDER_NID, service.proto, service.ip, service.port), service
        )
    return state


def _consumer_state(*services: tuple[str, int], **l3_kwargs) -> ConsumerState:
    endpoints = services or (("tcp", SERVICE_PORT),)
    config = ConsumerConfig(
        nid=CONSUMER_NID, ipv4=CONSUMER_IP, rm_ipv4=RM_IP,
        l3=ConsumerL3Config(
            enabled=True, tun_ip=CONSUMER_TUN, mss_clamp=CLAMP,
            capture_routes=(f"{PROVIDER_IP}/32",), **l3_kwargs,
        ),
    )
    state = ConsumerState(config)
    state.set_domain_info([(PROVIDER_NID, PROVIDER_IP)], [])  # 域内：提供方 NID -> IP
    for proto, port in endpoints:
        state.add_sid(sid_hex_from_service(PROVIDER_NID, proto, PROVIDER_IP, port))
    return state


class _Link:
    """假链路：按目的 IP 把报文投递给对端数据面，代替 RM/BR 与物理网卡。

    分派方式与真实装配一致（provider.py / consumer.py 的 ``_on_payload``）：
    按首字节分 GET/DATA，DATA 再按 B 位分上下行，最后按 SID 落在哪张表里选模式（D13）。
    """

    def __init__(self) -> None:
        self.provider: L3Provider | None = None
        self.consumer: L3Consumer | None = None
        self.dropped: list[tuple[str, bytes]] = []   # 没人认领的报文
        self.log: list[tuple[str, int]] = []         # (目的IP, 首字节)

    def send(self, dst_ip: str, packet) -> None:
        payload = bytes(packet)
        self.log.append((dst_ip, payload[0]))
        # 消费端把 GET 发给 RM，由 RM/BR 转发到提供端；这里直接交给提供端
        if payload[0] == GET_FIRST_BYTE:
            if self.provider is not None and self.provider.handle_get(payload):
                return
        elif payload[0] == DATA_FIRST_BYTE:
            if is_ack(payload):
                if self.provider is not None and self.provider.handle_upstream(payload):
                    return
            elif self.consumer is not None:
                load = bytes(ColorData(payload).payload)
                web_type = load[0] & WEB_MSG_TYPE_MASK if load else None
                if web_type == WebMsgType.TUNNEL and self.consumer.handle_tunnel(payload):
                    return
                if web_type == WebMsgType.IP_DOWNSTREAM and self.consumer.handle_downstream(payload):
                    return
        self.dropped.append((dst_ip, payload))


def _wire(*, provider_services=(("tcp", SERVICE_PORT),), consumer_services=None, **consumer_l3):
    """建好两端数据面与假链路，返回 (link, provider, consumer)。"""
    link = _Link()
    provider = L3Provider(_provider_state(*provider_services), LoopbackTun(PROVIDER_TUN), link)
    consumer = L3Consumer(
        _consumer_state(*(consumer_services or provider_services), **consumer_l3),
        LoopbackTun(CONSUMER_TUN), link,
    )
    link.provider, link.consumer = provider, consumer
    return link, provider, consumer


# ---------------------------------------------------------------- 报文样本

def _client_syn(dport: int = SERVICE_PORT, sport: int = 51000, mss_value: int = 1460) -> bytes:
    return bytes(IP(bytes(
        IP(src=CONSUMER_TUN, dst=PROVIDER_IP)
        / TCP(sport=sport, dport=dport, flags="S", options=[("MSS", mss_value)])
    )))


def _origin_synack(sport: int = SERVICE_PORT, dport: int = 51000, mss_value: int = 1460) -> bytes:
    return bytes(IP(bytes(
        IP(src=PROVIDER_IP, dst=CONSUMER_TUN)
        / TCP(sport=sport, dport=dport, flags="SA", options=[("MSS", mss_value)])
    )))


def _sid(proto: str = "tcp", port: int = SERVICE_PORT) -> str:
    return sid_hex_from_service(PROVIDER_NID, proto, PROVIDER_IP, port)


def _forged_upstream(inner: bytes, proto: str = "tcp", port: int = SERVICE_PORT) -> bytes:
    """绕开消费端数据面，直接构造一个上行 DATA（用于测提供端的准入校验）。"""
    return bytes(build_l3_upstream(_sid(proto, port), CONSUMER_NID, [], 1, inner))


# ---------------------------------------------------------------- 端到端

def test_tcp_handshake_traverses_both_directions() -> None:
    """客户端 SYN → GET → 隧道 → 冲刷 → 注入源站；源站 SYN-ACK → 回送 → 写回消费端 tun。"""
    link, provider, consumer = _wire()

    # ① 客户端首个包：算出 SID、无隧道 → 入队 + 发 GET；GET 由假链路交给提供端，
    #    提供端回隧道 DATA，消费端收到后冲刷首包 —— 全在这一次调用里连锁完成
    assert consumer.on_tun_packet(_client_syn())
    assert consumer.tunnels.get(_sid()) is not None, "隧道应已建立"

    injected = provider.tun.pop_written()
    assert len(injected) == 1, "首包应已冲刷并注入提供端协议栈"

    # 注入的包：地址端到端不变（D2 不做 NAT），MSS 已被消费端 clamp
    from colorproxy.tun import ipv4 as _ipv4
    header = _ipv4.parse_header(injected[0])
    assert _ipv4.format_ipv4(header.src) == CONSUMER_TUN
    assert _ipv4.format_ipv4(header.dst) == PROVIDER_IP
    assert dict(IP(injected[0])[TCP].options)["MSS"] == CLAMP

    # ② 源站回 SYN-ACK：提供端由内层源三元组反推 SID、由内层目的查 peers[]
    assert provider.on_tun_packet(_origin_synack())
    delivered = consumer.tun.pop_written()
    assert len(delivered) == 1, "回程包应写回消费端 tun"
    back = IP(delivered[0])
    assert back.src == PROVIDER_IP and back.dst == CONSUMER_TUN
    assert back[TCP].flags.SA
    assert dict(back[TCP].options)["MSS"] == CLAMP, "提供端侧也必须 clamp（§6.2 只做一侧会黑洞）"

    assert link.dropped == [], f"不应有无人认领的报文：{link.dropped}"
    assert provider.counters.get("admit_drop") == 0
    assert consumer.counters.get("sid_miss") == 0


def test_udp_flows_both_directions() -> None:
    """UDP 同样走通（视频流场景），且 tcp/udp 是两个不同的服务。"""
    link, provider, consumer = _wire(provider_services=(("udp", 5004),))
    rtp = bytes(IP(bytes(IP(src=CONSUMER_TUN, dst=PROVIDER_IP) / UDP(sport=40000, dport=5004) / Raw(b"rtp"))))
    assert consumer.on_tun_packet(rtp)
    assert len(provider.tun.pop_written()) == 1

    reply = bytes(IP(bytes(IP(src=PROVIDER_IP, dst=CONSUMER_TUN) / UDP(sport=5004, dport=40000) / Raw(b"pong"))))
    assert provider.on_tun_packet(reply)
    assert len(consumer.tun.pop_written()) == 1

    # 同 ip:port 的 TCP 不在已发布服务里 → SID 未命中
    tcp_same_port = bytes(IP(bytes(IP(src=CONSUMER_TUN, dst=PROVIDER_IP) / TCP(dport=5004))))
    assert not consumer.on_tun_packet(tcp_same_port)
    assert consumer.counters.get("sid_miss") == 1


# ---------------------------------------------------------------- §7.3 准入校验

def test_admission_rejects_wrong_destination_port() -> None:
    """持有 :8000 的 SID 不得借隧道打到 :22——不逐包校验的话这条隧道就是个跳板。"""
    link, provider, consumer = _wire()
    assert consumer.on_tun_packet(_client_syn())        # 先把隧道建起来
    provider.tun.pop_written()

    forged = bytes(IP(bytes(IP(src=CONSUMER_TUN, dst=PROVIDER_IP) / TCP(dport=22, flags="S"))))
    assert provider.handle_upstream(_forged_upstream(forged))
    assert provider.tun.pop_written() == [], "越权的包绝不能注入协议栈"
    assert provider.counters.get("admit_drop") == 1


def test_admission_rejects_other_host_destination() -> None:
    """也不得打到提供端可达的其它地址（D9 弱主机模型下投递范围是本机全部网卡）。"""
    link, provider, consumer = _wire()
    assert consumer.on_tun_packet(_client_syn())
    provider.tun.pop_written()

    forged = bytes(IP(bytes(IP(src=CONSUMER_TUN, dst="172.10.0.5") / TCP(dport=8000, flags="S"))))
    assert provider.handle_upstream(_forged_upstream(forged))
    assert provider.tun.pop_written() == []
    assert provider.counters.get("admit_drop") == 1


def test_admission_rejects_forged_inner_source() -> None:
    """rev.3 的来源校验：伪造成别的消费端的 tun 地址必须被拦（D14，回程劫持）。"""
    link, provider, consumer = _wire()
    assert consumer.on_tun_packet(_client_syn())
    provider.tun.pop_written()

    forged = bytes(IP(bytes(
        IP(src=OTHER_TUN, dst=PROVIDER_IP) / TCP(dport=SERVICE_PORT, flags="S")
    )))
    assert provider.handle_upstream(_forged_upstream(forged))
    assert provider.tun.pop_written() == [], "伪造源地址的包绝不能注入"
    assert provider.counters.get("src_bind_drop") == 1
    assert provider.counters.get("admit_drop") == 0, "这一条应记在来源计数上，便于区分病因"


def test_unknown_consumer_cannot_build_tunnel() -> None:
    """peers[] 里没有的消费端连隧道都建不起来（握手期就把原因说清楚）。"""
    from colorproxy.consumer.messages import build_get

    link, provider, _consumer = _wire()
    stranger = 0xC3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3
    assert provider.handle_get(bytes(build_get(_sid(), stranger, 7)))
    assert provider.tunnels.get(_sid(), stranger) is None
    assert provider.counters.get("tunnel_up") == 0


def test_downstream_rejects_wrong_destination() -> None:
    """下行包目的必须是本机 tun 地址，防对端串流（§7.1 下行第 3 步）。"""
    link, provider, consumer = _wire()
    assert consumer.on_tun_packet(_client_syn())
    provider.tun.pop_written()
    consumer.tun.pop_written()

    # 提供端"发错人"：内层目的是另一个消费端的 tun 地址
    stray = bytes(IP(bytes(IP(src=PROVIDER_IP, dst=OTHER_TUN) / TCP(sport=SERVICE_PORT, dport=51000))))
    load = bytes([WebMsgType.IP_DOWNSTREAM | 0x01]) + stray
    from colorproxy.messages import build_data_packet

    packet = bytes(build_data_packet(PROVIDER_NID, _sid(), CONSUMER_NID, [], 1, load))
    assert consumer.handle_downstream(packet)
    assert consumer.tun.pop_written() == []
    assert consumer.counters.get("admit_drop") == 1


# ---------------------------------------------------------------- §3.3 通配回程

def test_return_path_picks_wildcard_sid_for_ephemeral_port() -> None:
    """被动 FTP：数据连接的临时端口只能靠通配项命中，且不与控制连接串台（D14）。"""
    link, provider, consumer = _wire(provider_services=(("tcp", 21), ("tcp", 0)))

    # 控制连接（:21）与数据连接（:50123）各建一条隧道——它们是两个不同的 SID
    assert consumer.on_tun_packet(_client_syn(dport=21, sport=51000))
    assert consumer.on_tun_packet(_client_syn(dport=50123, sport=51001))
    assert provider.tunnels.count() == 2
    provider.tun.pop_written()
    link.log.clear()

    # 控制连接的回程 → 精确 SID
    assert provider.on_tun_packet(_origin_synack(sport=21, dport=51000))
    # 数据连接的回程 → 通配 SID
    assert provider.on_tun_packet(_origin_synack(sport=50123, dport=51001))

    written = consumer.tun.pop_written()
    assert len(written) == 2, "两条隧道的回程都应各自写回，不能互相覆盖"
    sports = sorted(IP(packet)[TCP].sport for packet in written)
    assert sports == [21, 50123]
    assert provider.counters.get("no_tunnel_drop") == 0


def test_return_path_drops_unpublished_source_endpoint() -> None:
    """源端点不是本机发布的服务 → sid_miss，不猜、不学（取消 PeerTun 学习的后果）。"""
    link, provider, consumer = _wire()
    assert consumer.on_tun_packet(_client_syn())
    provider.tun.pop_written()
    consumer.tun.pop_written()

    stray = bytes(IP(bytes(IP(src=PROVIDER_IP, dst=CONSUMER_TUN) / TCP(sport=9999, dport=51000))))
    assert not provider.on_tun_packet(stray)
    assert consumer.tun.pop_written() == []
    assert provider.counters.get("sid_miss") == 1


def test_return_path_drops_unknown_peer() -> None:
    link, provider, consumer = _wire()
    assert consumer.on_tun_packet(_client_syn())
    provider.tun.pop_written()

    stray = bytes(IP(bytes(IP(src=PROVIDER_IP, dst="10.99.1.77") / TCP(sport=SERVICE_PORT, dport=51000))))
    assert not provider.on_tun_packet(stray)
    assert provider.counters.get("no_peer_drop") == 1


# ---------------------------------------------------------------- D11 / D15

def test_icmp_is_not_tunneled() -> None:
    """D11：应用发起的 ICMP 不进隧道。"""
    link, provider, consumer = _wire()
    ping = bytes(IP(bytes(IP(src=CONSUMER_TUN, dst=PROVIDER_IP) / ICMP())))
    assert not consumer.on_tun_packet(ping)
    assert consumer.counters.get("proto_drop") == 1
    assert link.log == [], "不该为 ICMP 发出任何 CoLoR 报文"


def test_debug_switch_lets_icmp_through() -> None:
    """联调开关放行 ICMP（端口按 0 处理），让 ping 能作最小连通性判据（§8.2）。"""
    link, provider, consumer = _wire(
        provider_services=(("tcp", 0),), debug_tunnel_icmp=True
    )
    ping = bytes(IP(bytes(IP(src=CONSUMER_TUN, dst=PROVIDER_IP) / ICMP())))
    assert consumer.on_tun_packet(ping)
    assert consumer.counters.get("proto_drop") == 0
    assert consumer.counters.get("sid_hit") == 1


def test_fragments_dropped_in_both_directions() -> None:
    """D15：分片一律丢并单独计数——症状与"大 UDP 静默丢"相同，必须能区分。"""
    link, provider, consumer = _wire(provider_services=(("udp", 5004),))
    first_piece = bytes(IP(bytes(
        IP(src=CONSUMER_TUN, dst=PROVIDER_IP, flags="MF") / UDP(sport=1, dport=5004) / Raw(b"x" * 16)
    )))
    assert not consumer.on_tun_packet(first_piece)
    assert consumer.counters.get("frag_drop") == 1
    assert consumer.counters.get("sid_miss") == 0, "不能把分片记成 SID 未命中，病因完全不同"

    later_piece = bytes(IP(bytes(
        IP(src=PROVIDER_IP, dst=CONSUMER_TUN, frag=3, proto=17) / Raw(b"y" * 16)
    )))
    assert not provider.on_tun_packet(later_piece)
    assert provider.counters.get("frag_drop") == 1


# ---------------------------------------------------------------- §5.2 首包缓冲

def test_first_packets_queue_then_flush_in_order() -> None:
    """隧道未建立时入队，建立后按序冲刷；同一 SID 只发一次 GET。"""
    link = _Link()
    provider = L3Provider(_provider_state(), LoopbackTun(PROVIDER_TUN), link)
    consumer = L3Consumer(_consumer_state(), LoopbackTun(CONSUMER_TUN), link)
    link.consumer = consumer   # 先不接提供端：隧道建不起来，包全留在队列里

    for index in range(3):
        assert consumer.on_tun_packet(_client_syn(sport=51000 + index))
    gets = [entry for entry in link.log if entry[1] == GET_FIRST_BYTE]
    assert len(gets) == 1, "同一条 SID 只应发一次 GET（客户端 SYN 重传时很容易发重）"
    assert consumer.counters.get("firstpkt_queued") == 3

    # 接上提供端，补一个包触发不了握手（已 pending），需由隧道 DATA 冲刷
    link.provider = provider
    from colorproxy.consumer.messages import build_get

    assert provider.handle_get(bytes(build_get(_sid(), CONSUMER_NID, 1)))
    injected = provider.tun.pop_written()
    assert len(injected) == 3, "三个首包都应冲刷"
    assert [IP(p)[TCP].sport for p in injected] == [51000, 51001, 51002], "必须按入队序"


def test_first_packet_queue_caps_and_drops_oldest() -> None:
    """上限 4 个包：超限丢最老的（新包更可能是客户端重传，更有用）。"""
    link = _Link()
    consumer = L3Consumer(_consumer_state(), LoopbackTun(CONSUMER_TUN), link)
    link.consumer = consumer

    for index in range(6):
        consumer.on_tun_packet(_client_syn(sport=51000 + index))
    assert consumer.counters.get("firstpkt_dropped") == 2

    provider = L3Provider(_provider_state(), LoopbackTun(PROVIDER_TUN), link)
    link.provider = provider
    from colorproxy.consumer.messages import build_get

    provider.handle_get(bytes(build_get(_sid(), CONSUMER_NID, 1)))
    kept = [IP(p)[TCP].sport for p in provider.tun.pop_written()]
    assert kept == [51002, 51003, 51004, 51005], f"应留下最后 4 个，实为 {kept}"


def test_handshake_timeout_drops_queue_and_allows_retry() -> None:
    """握手超时必须丢队列并退回未建立态，否则首包永久滞留（§5.2）。"""
    link = _Link()
    consumer = L3Consumer(
        _consumer_state(tunnel_timeout_sec=0.05), LoopbackTun(CONSUMER_TUN), link
    )
    link.consumer = consumer

    consumer.on_tun_packet(_client_syn())
    assert consumer.tunnels.is_pending(_sid())
    time.sleep(0.08)
    consumer.expire_handshakes()

    assert not consumer.tunnels.is_pending(_sid()), "超时后应退回未建立状态"
    assert consumer.counters.get("firstpkt_dropped") == 1

    # 下一个包应重新触发 GET
    link.log.clear()
    consumer.on_tun_packet(_client_syn())
    assert [entry for entry in link.log if entry[1] == GET_FIRST_BYTE], "应重新发 GET"


# ---------------------------------------------------------------- D13 分派

def test_load0_mismatch_is_counted_but_still_forwarded() -> None:
    """load[0] 只作宽松校验：不符照常转发，只计数（D13）。"""
    link, provider, consumer = _wire()
    assert consumer.on_tun_packet(_client_syn())
    provider.tun.pop_written()

    inner = bytes(IP(bytes(IP(src=CONSUMER_TUN, dst=PROVIDER_IP) / TCP(dport=SERVICE_PORT))))
    wrong = bytes(build_l3_upstream(_sid(), CONSUMER_NID, [], 1, inner))
    # 把 load[0] 的类型位改成 v1 的 HTTP_REQUEST
    body = bytearray(wrong)
    load_offset = body[6]
    body[load_offset] = WebMsgType.HTTP_REQUEST | 0x01

    assert provider.handle_upstream(bytes(body))
    assert provider.counters.get("load0_mismatch") == 1
    assert len(provider.tun.pop_written()) == 1, "宽松放行：类型位不符也照常转发"


def test_provider_hands_back_non_l3_sid() -> None:
    """SID 不在 L3 表里时返回 False，交回调用方走 v1 路径（两模式共存，§12）。"""
    link, provider, _consumer = _wire()
    web_sid = sid_hex_from_service(PROVIDER_NID, "tcp", PROVIDER_IP, 9999)  # 未发布
    inner = bytes(IP(bytes(IP(src=CONSUMER_TUN, dst=PROVIDER_IP) / TCP(dport=SERVICE_PORT))))
    packet = bytes(build_l3_upstream(web_sid, CONSUMER_NID, [], 1, inner))
    assert provider.handle_upstream(packet) is False

    from colorproxy.consumer.messages import build_get

    assert provider.handle_get(bytes(build_get(web_sid, CONSUMER_NID, 1))) is False


def test_local_multicast_noise_is_counted_separately() -> None:
    """本机往 tun 上发的组播（mDNS/SSDP）单独计数，不得混进 sid_miss。

    M1c 真机实测：新建的 tun 上这类包每秒好几个，一次 7 秒的运行里 20 个 sid_miss
    全是它们。而 §10.4 给 sid_miss 的含义是"路由把不该进的流量导进了 tun"——一个要
    改配置、一个什么都不用做，混在一起等于没有诊断。
    """
    _link, provider, consumer = _wire()

    for dst, dport in (("239.255.255.250", 3702), ("224.0.0.251", 5353)):
        packet = bytes(IP(bytes(
            IP(src=CONSUMER_TUN, dst=dst) / UDP(sport=50000, dport=dport) / Raw(b"x" * 40)
        )))
        assert consumer.on_tun_packet(packet) is False
    assert consumer.counters.get("nonunicast_drop") == 2
    assert consumer.counters.get("sid_miss") == 0, "噪声不得计进 sid_miss"

    # 提供端的回送方向同样会读到这些包（服务地址就在 tun 上，噪声源地址正是它）
    noise = bytes(IP(bytes(
        IP(src=PROVIDER_TUN, dst="224.0.0.251") / UDP(sport=5353, dport=5353) / Raw(b"x" * 40)
    )))
    assert provider.on_tun_packet(noise) is False
    assert provider.counters.get("nonunicast_drop") == 1
    assert provider.counters.get("sid_miss") == 0


def test_subnet_broadcast_noise_is_counted_separately() -> None:
    """定向广播（NetBIOS 137 就是这么发的）光判组播抓不到，要按本网段算。"""
    _link, provider, consumer = _wire()
    packet = bytes(IP(bytes(
        IP(src=CONSUMER_TUN, dst="10.99.1.255") / UDP(sport=137, dport=137) / Raw(b"x" * 40)
    )))
    assert consumer.on_tun_packet(packet) is False
    assert consumer.counters.get("nonunicast_drop") == 1
    assert consumer.counters.get("sid_miss") == 0

    limited = bytes(IP(bytes(
        IP(src=PROVIDER_TUN, dst="255.255.255.255") / UDP(sport=68, dport=67) / Raw(b"x" * 40)
    )))
    assert provider.on_tun_packet(limited) is False
    assert provider.counters.get("nonunicast_drop") == 1


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
