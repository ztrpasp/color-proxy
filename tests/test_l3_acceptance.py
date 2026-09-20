"""M4 三个验收用例的离线部分（docs/design-l3-v2.md §11 M4、§3.3、§7.1、§8.3）。

M4 的完整判据是"被动 FTP 上传下载 / 一条视频流连续 5 分钟 / MySQL 增删改查"，那需要
**两台机器**（两个内核）才能跑：同一个内核上两个内层端点都是本机地址，流量会环回
短路，根本不进隧道（理由见 tools/l3_m1c_loopback.py 的模块文档）。真客户端验收的
操作步骤见 docs/M4-acceptance.md。

本文件钉死的是另一半：**三个应用各自特有的、跑真客户端之前就该排掉的危险点**。
它们都是协议层面的判据，与客户端软件无关，在假链路上验证完全充分：

1. **被动 FTP**：控制连接走 ``tcp://ip:21``、数据连接走临时端口只能命中通配
   ``tcp://ip:0`` —— 这是**两条隧道**。rev.2 的单键 ``PeerTun[内层src]`` 在这里会
   互相覆盖，回程包从错误的隧道发出（§3.3 末段、§7.3 的"通配 SID 串台"）。D14 取消
   数据面学习就是为了这个，必须有回归把它钉住。
2. **视频流**：内层 UDP 净载荷 ≤ 1252 字节是硬约束（D15）。超过就被内核分片，而
   分片一律丢弃——症状是"小包通、大 UDP 静默丢"。同时验证一条隧道能承载持续流量、
   不随包数增长出任何 per-packet 状态。
3. **MySQL**：一条长连接上的大量小往返必须**共用同一条隧道**（§5.1：隧道以 SID 为
   单位，不以流为单位），只握手一次。

可 ``python tests/test_l3_acceptance.py`` 直接运行（无需 pytest、无需管理员）。
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from colorproxy.config import Config, L3Config, L3ServiceConfig, PeerConfig, ServiceConfig
from colorproxy.consumer.config import ConsumerConfig, ConsumerL3Config
from colorproxy.consumer.messages import build_l3_upstream
from colorproxy.consumer.state import ConsumerState
from colorproxy.l3.consumer import L3Consumer
from colorproxy.l3.provider import L3Provider
from colorproxy.messages import is_ack
from colorproxy.protocol.constants import DATA_FIRST_BYTE, GET_FIRST_BYTE
from colorproxy.protocol.sid import sid_hex_from_service
from colorproxy.state import ProviderState
from colorproxy.tun import ipv4
from colorproxy.tun.device import LoopbackTun

PROVIDER_NID = 0xA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1
CONSUMER_NID = 0xB2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2
PROVIDER_IP = "172.10.0.2"
CONSUMER_IP = "10.10.0.2"
RM_IP = "10.10.0.1"
#: §2.5 虚服务地址：服务绑在提供端 color0 自己的地址上
SERVICE_IP = "172.10.9.2"
CONSUMER_TUN = "10.99.1.1"
CLAMP = 1240
MTU = 1280
#: 内层 UDP 净载荷硬上限：1280 − 20(IP) − 8(UDP)（§7.1 第 3 步）
UDP_PAYLOAD_LIMIT = MTU - 28


# ---------------------------------------------------------------- 装配

class _Link:
    """假链路：按装配层的判据把报文投给对端数据面（与 provider.py/consumer.py 一致）。"""

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


def _wire(services: tuple[tuple[str, int], ...]):
    """按给定的服务列表建好两端数据面与假链路。"""
    provider_config = Config(
        nid=PROVIDER_NID, ipv4=PROVIDER_IP, rm_ipv4="172.10.0.5",
        services=[ServiceConfig(f"http://{PROVIDER_IP}:8000/x", PROVIDER_IP, 8000)],
        l3=L3Config(
            enabled=True, tun_ip=SERVICE_IP, tun_mtu=MTU, mss_clamp=CLAMP,
            peer_routes=("10.99.1.0/24",),
            peers=(PeerConfig(nid=CONSUMER_NID, tun_ip=CONSUMER_TUN),),
            services=tuple(L3ServiceConfig(proto=p, ip=SERVICE_IP, port=n) for p, n in services),
        ),
    )
    provider_state = ProviderState(provider_config)
    provider_state.set_domain_info([(CONSUMER_NID, CONSUMER_IP)], [])
    for service in provider_config.l3.services:
        provider_state.add_l3_service(
            sid_hex_from_service(PROVIDER_NID, service.proto, service.ip, service.port), service)

    consumer_config = ConsumerConfig(
        nid=CONSUMER_NID, ipv4=CONSUMER_IP, rm_ipv4=RM_IP,
        l3=ConsumerL3Config(enabled=True, tun_ip=CONSUMER_TUN, tun_mtu=MTU,
                            mss_clamp=CLAMP, capture_routes=(f"{SERVICE_IP}/32",)),
    )
    consumer_state = ConsumerState(consumer_config)
    consumer_state.set_domain_info([(PROVIDER_NID, PROVIDER_IP)], [])
    for proto, port in services:
        consumer_state.add_sid(sid_hex_from_service(PROVIDER_NID, proto, SERVICE_IP, port))

    link = _Link()
    provider = L3Provider(provider_state, LoopbackTun(SERVICE_IP, mtu=MTU), link)
    consumer = L3Consumer(consumer_state, LoopbackTun(CONSUMER_TUN, mtu=MTU), link)
    link.provider, link.consumer = provider, consumer
    return link, provider, consumer


def _sid(proto: str, port: int) -> str:
    return sid_hex_from_service(PROVIDER_NID, proto, SERVICE_IP, port)


# ---------------------------------------------------------------- 报文样本

def _tcp(sport: int, dport: int, flags: str = "S", payload: bytes = b"",
         src: str = CONSUMER_TUN, dst: str = SERVICE_IP) -> bytes:
    packet = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    if payload:
        packet = packet / Raw(payload)
    return bytes(IP(bytes(packet)))


def _udp(sport: int, dport: int, size: int, src: str = CONSUMER_TUN,
         dst: str = SERVICE_IP, df: bool = False) -> bytes:
    header = IP(src=src, dst=dst, flags="DF") if df else IP(src=src, dst=dst)
    return bytes(IP(bytes(header / UDP(sport=sport, dport=dport) / Raw(b"v" * size))))


def _inner(raw: bytes) -> tuple[str, str, int, int]:
    """取内层包的 (src_ip, dst_ip, sport, dport)，用于断言"回给了谁"。"""
    header = ipv4.parse_header(raw)
    assert header is not None
    sport, dport = ipv4.parse_ports(raw, header)
    return ipv4.format_ipv4(header.src), ipv4.format_ipv4(header.dst), sport, dport


# ================================================================ 用例一：被动 FTP

def test_passive_ftp_uses_two_independent_tunnels() -> None:
    """控制连接(:21) 与被动数据连接(临时端口→通配 :0) 是**两条隧道**，不得互相覆盖。

    这正是 rev.2 的单键 ``PeerTun[内层 src_ip]`` 会出事的场景：同一消费端的两条隧道
    内层源地址是同一个，学习表互相覆盖，回程包会从错误的隧道发出（§3.3、§7.3）。
    """
    link, provider, consumer = _wire((("tcp", 21), ("tcp", 0)))

    assert consumer.on_tun_packet(_tcp(50001, 21))          # 控制连接
    assert consumer.on_tun_packet(_tcp(50002, 56789))       # 被动数据连接 → 通配
    assert consumer.tunnels.get(_sid("tcp", 21)) is not None
    assert consumer.tunnels.get(_sid("tcp", 0)) is not None, "数据连接必须命中通配 SID"
    assert link.gets == 2, "两条 SID 各握手一次"

    injected = provider.tun.pop_written()
    assert len(injected) == 2
    assert {_inner(p)[3] for p in injected} == {21, 56789}

    # 回程：两条连接分别回包，各自由内层**源端口**反推 SID（§7.2 回送第 2 步）
    assert provider.on_tun_packet(_tcp(21, 50001, "SA", src=SERVICE_IP, dst=CONSUMER_TUN))
    assert provider.on_tun_packet(_tcp(56789, 50002, "SA", src=SERVICE_IP, dst=CONSUMER_TUN))
    delivered = consumer.tun.pop_written()
    assert len(delivered) == 2, "两条连接的回程都必须到达"
    assert {_inner(p)[2] for p in delivered} == {21, 56789}
    assert {_inner(p)[3] for p in delivered} == {50001, 50002}, "端口不能串台"

    assert provider.tunnels.count() == 2
    assert link.dropped == [], f"不应有无人认领的报文：{len(link.dropped)} 个"
    assert provider.counters.get("no_tunnel_drop") == 0
    assert provider.counters.get("admit_drop") == 0


def test_passive_ftp_wildcard_degrades_destination_granularity_only() -> None:
    """§8.3：通配只把**目的**粒度放宽到主机级，**来源**侧不退化。"""
    link, provider, consumer = _wire((("tcp", 21), ("tcp", 0)))
    assert consumer.on_tun_packet(_tcp(50002, 56789))
    provider.tun.pop_written()

    # 目的侧：同一 IP 上任意端口都被放行 —— 这是通配的已知代价，写进论述里的那一条
    forged = bytes(build_l3_upstream(_sid("tcp", 0), CONSUMER_NID, [], 1,
                                     _tcp(50003, 9999)))
    assert provider.handle_upstream(forged)
    assert len(provider.tun.pop_written()) == 1, "通配下同 IP 的其它端口会被放行（§8.3）"
    assert provider.counters.get("admit_drop") == 0

    # 目的侧：换一个 IP 仍然拦得住 —— 通配放宽的只是端口，不是地址
    other_ip = bytes(build_l3_upstream(_sid("tcp", 0), CONSUMER_NID, [], 1,
                                       _tcp(50004, 9999, dst="172.10.9.99")))
    assert provider.handle_upstream(other_ip)
    assert provider.tun.pop_written() == []
    assert provider.counters.get("admit_drop") == 1

    # 来源侧：伪造内层源地址照样被拦，与端口粒度无关（§7.3、§8.3 末段）
    spoofed = bytes(build_l3_upstream(_sid("tcp", 0), CONSUMER_NID, [], 1,
                                      _tcp(50005, 56789, src="10.99.1.2")))
    assert provider.handle_upstream(spoofed)
    assert provider.tun.pop_written() == []
    assert provider.counters.get("src_bind_drop") == 1


# ================================================================ 用例二：视频流

def test_video_stream_sustains_one_tunnel() -> None:
    """一条 UDP 流持续打 600 个包：只握手一次、包全到、不随包数长出 per-packet 状态。"""
    link, provider, consumer = _wire((("udp", 5004),))
    total = 600

    for index in range(total):
        assert consumer.on_tun_packet(_udp(40000, 5004, 1100 + index % 100))
    assert link.gets == 1, "同一条 SID 只握手一次（D1，隧道长期有效）"
    assert consumer.tunnels.count() == 1
    assert len(provider.tun.pop_written()) == total, "所有包都必须注入源站侧"

    # 回程同样持续
    for index in range(total):
        assert provider.on_tun_packet(
            _udp(5004, 40000, 1000, src=SERVICE_IP, dst=CONSUMER_TUN))
    assert len(consumer.tun.pop_written()) == total

    # 隧道与流缓存都以 SID 为单位，不以包/流为单位（§5.1）
    assert provider.tunnels.count() == 1
    assert len(consumer.flows) == 1
    assert consumer.counters.get("sid_hit") == total
    assert provider.counters.get("no_tunnel_drop") == 0
    assert link.dropped == []


def test_video_payload_at_the_documented_limit_passes() -> None:
    """净载荷正好 1252 字节（= 1280 − 20 − 8）必须通过：这是部署说明里写的上限。"""
    _link, provider, consumer = _wire((("udp", 5004),))
    packet = _udp(40000, 5004, UDP_PAYLOAD_LIMIT)
    assert len(packet) == MTU, "刚好一个 MTU"
    assert consumer.on_tun_packet(packet)
    assert len(provider.tun.pop_written()) == 1
    assert consumer.counters.get("frag_drop") == 0
    assert consumer.counters.get("mtu_drop") == 0


def test_video_oversized_datagram_is_counted_not_silent() -> None:
    """超限的大 UDP 必须**计入计数器**而不是无声消失（M3 的验收判据）。

    内核会按 tun MTU 把它分片，两片都被 D15 丢弃；代理直接读到超长包（DF=1）的
    情形则计 mtu_drop。两条路径都要有名字，否则症状就是"小包通、大 UDP 静默丢"。
    """
    _link, _provider, consumer = _wire((("udp", 5004),))
    oversized = _udp(40000, 5004, UDP_PAYLOAD_LIMIT + 1, df=True)
    assert len(oversized) > MTU
    assert consumer.on_tun_packet(oversized) is False
    assert consumer.counters.get("mtu_drop") == 1

    # 内核分片后的两片：首片 MF=1、非首片 offset>0，D15 两者都丢
    first = bytearray(_udp(40000, 5004, 1200))
    first[6:8] = (0x2000).to_bytes(2, "big")          # MF=1
    assert consumer.on_tun_packet(bytes(first)) is False
    later = bytearray(_udp(40000, 5004, 200))
    later[6:8] = (0x00A0).to_bytes(2, "big")          # offset != 0
    assert consumer.on_tun_packet(bytes(later)) is False
    assert consumer.counters.get("frag_drop") == 2


# ================================================================ 用例三：MySQL

def test_mysql_long_connection_reuses_one_tunnel() -> None:
    """一条长连接上 200 次小往返：共用同一条隧道，只握手一次（§5.1）。"""
    link, provider, consumer = _wire((("tcp", 3306),))
    rounds = 200

    assert consumer.on_tun_packet(_tcp(52000, 3306))  # SYN
    provider.tun.pop_written()
    assert provider.on_tun_packet(_tcp(3306, 52000, "SA", src=SERVICE_IP, dst=CONSUMER_TUN))
    consumer.tun.pop_written()

    for index in range(rounds):
        query = f"SELECT {index}".encode()
        assert consumer.on_tun_packet(_tcp(52000, 3306, "PA", query))
        assert provider.on_tun_packet(
            _tcp(3306, 52000, "PA", b"row", src=SERVICE_IP, dst=CONSUMER_TUN))

    assert link.gets == 1, "长连接不应反复握手"
    assert consumer.counters.get("tunnel_up") == 1
    assert provider.counters.get("tunnel_up") == 1
    assert len(provider.tun.pop_written()) == rounds
    assert len(consumer.tun.pop_written()) == rounds
    assert link.dropped == []


def test_mysql_second_connection_shares_the_tunnel() -> None:
    """同一 (proto,ip,port) 的第二条 TCP 连接共用隧道，内层头天然解复用（§5.1）。"""
    link, provider, consumer = _wire((("tcp", 3306),))
    assert consumer.on_tun_packet(_tcp(52000, 3306))
    assert consumer.on_tun_packet(_tcp(52001, 3306))

    assert link.gets == 1, "第二条连接不该再发 GET"
    assert consumer.tunnels.count() == 1 and provider.tunnels.count() == 1
    assert len(provider.tun.pop_written()) == 2

    # 回程按内层目的端口区分两条连接，走的是同一条隧道
    for sport in (52000, 52001):
        assert provider.on_tun_packet(
            _tcp(3306, sport, "SA", src=SERVICE_IP, dst=CONSUMER_TUN))
    assert {_inner(p)[3] for p in consumer.tun.pop_written()} == {52000, 52001}


def test_unpublished_port_is_not_reachable_without_wildcard() -> None:
    """没有通配时，未发布的端口一个包都过不去——准入的边界就在这一行（§7.3）。"""
    _link, provider, consumer = _wire((("tcp", 3306),))

    # 消费端侧：未发布的端口算不出 SID，包在本端就被丢掉
    assert consumer.on_tun_packet(_tcp(52000, 3307)) is False
    assert consumer.counters.get("sid_miss") == 1

    # 提供端侧：先按规矩建好 3306 的隧道（否则会先撞 no_tunnel_drop，测不到准入），
    # 再拿这条合法隧道去打未发布的 3307 —— 这才是 §7.3 要防的那个攻击
    assert consumer.on_tun_packet(_tcp(52000, 3306))
    provider.tun.pop_written()
    forged = bytes(build_l3_upstream(_sid("tcp", 3306), CONSUMER_NID, [], 1,
                                     _tcp(52000, 3307)))
    assert provider.handle_upstream(forged)
    assert provider.tun.pop_written() == [], "持有合法 SID 也不得打到未发布的端口"
    assert provider.counters.get("admit_drop") == 1
    assert provider.counters.get("no_tunnel_drop") == 0


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
