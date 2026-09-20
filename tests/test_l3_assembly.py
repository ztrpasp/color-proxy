"""L3 装配层测试（docs/design-l3-v2.md §1.2 / §1.3 / §5.2 / §8.4 / §10.4，里程碑 M2/M3）。

``tests/test_l3_dataplane.py`` 测的是数据面**逻辑**：直接调 ``on_tun_packet`` /
``handle_upstream``。本文件测的是把数据面接上真实世界的那一层，也就是 M2/M3 新增的
部分，这些恰好是"漏了也不报错、只是某条路径永远不发生"的那类代码：

- ``Provider._on_payload`` / ``Consumer._on_payload`` 的 **D13 分派**：先试 L3，
  SID 不属于 L3 才回落 v1；两种模式在同一进程内互不干扰；
- **tun 读线程**真的在读、真的把包交给数据面（§1.2 / §1.3）；
- **握手超时回收**真的被周期调用——不调的话首包永久滞留（§5.2 点名了这一条）；
- **下行静默重探**（§8.4 的兜底）与隧道的原子替换；
- ``mtu_drop`` 这个此前从未被递增过的计数器（§6.3）。

链路仍是假的（按首字节直接投递给对端的 ``_on_payload``），但**报文是真的 CoLoR
报文**，走的也是真的装配分派代码。不需要管理员权限、不需要 tun 设备。
"""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from colorproxy.config import Config, L3Config, L3ServiceConfig, PeerConfig, ServiceConfig
from colorproxy.consumer.config import ConsumerConfig, ConsumerL3Config
from colorproxy.consumer.consumer import Consumer
from colorproxy.consumer.messages import build_get
from colorproxy.protocol.sid import sid_hex_from_service, sid_hex_from_url
from colorproxy.provider import Provider
from colorproxy.tun.device import LoopbackTun

PROVIDER_NID = 0xA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1
CONSUMER_NID = 0xB2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2
PROVIDER_IP = "172.10.0.2"
CONSUMER_IP = "10.10.0.2"
CONSUMER_RM = "10.10.0.1"
PROVIDER_RM = "172.10.0.5"
#: §2.5 的虚服务地址：服务就绑在提供端 color0 自己的地址上，不需要弱主机开关
SERVICE_IP = "172.10.9.2"
PROVIDER_TUN = SERVICE_IP
CONSUMER_TUN = "10.99.1.1"
SERVICE_PORT = 8000
WEB_URL = f"http://{PROVIDER_IP}:8000/hello.html"
CLAMP = 1240
DEADLINE = 3.0


# ---------------------------------------------------------------- 装配

def _provider_config(**l3_kwargs) -> Config:
    return Config(
        nid=PROVIDER_NID, ipv4=PROVIDER_IP, rm_ipv4=PROVIDER_RM,
        services=[ServiceConfig(WEB_URL, PROVIDER_IP, 8000)],
        l3=L3Config(
            enabled=True, tun_ip=PROVIDER_TUN, tun_mtu=1280, mss_clamp=CLAMP,
            peer_routes=("10.99.1.0/24",),
            peers=(PeerConfig(nid=CONSUMER_NID, tun_ip=CONSUMER_TUN),),
            services=(L3ServiceConfig(proto="tcp", ip=SERVICE_IP, port=SERVICE_PORT),),
            **l3_kwargs,
        ),
    )


def _consumer_config(**l3_kwargs) -> ConsumerConfig:
    return ConsumerConfig(
        nid=CONSUMER_NID, ipv4=CONSUMER_IP, rm_ipv4=CONSUMER_RM,
        l3=ConsumerL3Config(
            enabled=True, tun_ip=CONSUMER_TUN, tun_mtu=1280, mss_clamp=CLAMP,
            capture_routes=(f"{SERVICE_IP}/32",), **l3_kwargs,
        ),
    )


class _Link:
    """假链路：把报文交给对端**装配层**的 ``_on_payload``（而不是数据面）。

    这样测到的就是 provider.py / consumer.py 里真正的 D13 分派代码。
    """

    def __init__(self) -> None:
        self.provider: Provider | None = None
        self.consumer: Consumer | None = None
        self.sent: list[tuple[str, int]] = []

    def send(self, dst_ip: str, packet) -> None:
        payload = bytes(packet)
        self.sent.append((dst_ip, payload[0]))
        # 消费端把 GET 发给 RM，RM/BR 转给提供端；这里直接投递到对端
        target = self.provider if dst_ip in (PROVIDER_IP, PROVIDER_RM, CONSUMER_RM) else self.consumer
        if dst_ip == CONSUMER_IP:
            target = self.consumer
        if target is not None:
            target._on_payload(payload)


class _Wired:
    """两端装配 + 假链路 + 两个 LoopbackTun，start/stop 成对。"""

    def __init__(self, *, provider_l3=None, consumer_l3=None) -> None:
        self.link = _Link()
        self.provider_tun = LoopbackTun(PROVIDER_TUN, mtu=1280)
        self.consumer_tun = LoopbackTun(CONSUMER_TUN, mtu=1280)

        self.provider = Provider(_provider_config(**(provider_l3 or {})), tun=self.provider_tun)
        self.consumer = Consumer(_consumer_config(**(consumer_l3 or {})), tun=self.consumer_tun)
        for end in (self.provider, self.consumer):
            end.sender = self.link
            assert end.l3 is not None
            end.l3.sender = self.link
            end.state.registered.set()  # 跳过注册，v1 已有测试覆盖

        # 域内表与服务表：正常由注册回复 + ANN 填，这里直接预置
        self.provider.state.set_domain_info([(CONSUMER_NID, CONSUMER_IP)], [])
        self.consumer.state.set_domain_info([(PROVIDER_NID, PROVIDER_IP)], [])
        for service in self.provider.state.config.l3.services:
            self.provider.state.add_l3_service(
                sid_hex_from_service(PROVIDER_NID, service.proto, service.ip, service.port),
                service,
            )
        self.provider.state.add_service(sid_hex_from_url(PROVIDER_NID, WEB_URL),
                                        self.provider.state.config.services[0])
        self.consumer.state.add_sid(
            sid_hex_from_service(PROVIDER_NID, "tcp", SERVICE_IP, SERVICE_PORT))
        self.consumer.state.add_sid(sid_hex_from_url(PROVIDER_NID, WEB_URL))
        self.link.provider, self.link.consumer = self.provider, self.consumer

    def __enter__(self) -> "_Wired":
        self.provider.l3.start()
        self.consumer.l3.start()
        return self

    def __exit__(self, *_exc) -> None:
        self.consumer.l3.stop()
        self.provider.l3.stop()


def _wait(predicate, deadline: float = DEADLINE, what: str = "") -> None:
    limit = time.monotonic() + deadline
    while time.monotonic() < limit:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError(f"等待超时（{deadline}s）：{what}")


# ---------------------------------------------------------------- 报文样本

def _client_syn(sport: int = 51000, mss_value: int = 1460) -> bytes:
    return bytes(IP(bytes(
        IP(src=CONSUMER_TUN, dst=SERVICE_IP)
        / TCP(sport=sport, dport=SERVICE_PORT, flags="S", options=[("MSS", mss_value)])
    )))


def _origin_synack(dport: int = 51000) -> bytes:
    return bytes(IP(bytes(
        IP(src=SERVICE_IP, dst=CONSUMER_TUN)
        / TCP(sport=SERVICE_PORT, dport=dport, flags="SA", options=[("MSS", 1460)])
    )))


def _l3_sid() -> str:
    return sid_hex_from_service(PROVIDER_NID, "tcp", SERVICE_IP, SERVICE_PORT)


# ---------------------------------------------------------------- 用例

def test_tun_read_thread_drives_full_handshake() -> None:
    """包只是被 inject 进 tun，其余全部由读线程 + 装配分派自己完成（M2 的核心判据）。"""
    with _Wired() as wired:
        wired.consumer_tun.inject(_client_syn())

        _wait(lambda: wired.provider_tun.pop_written() or False,
              what="首包经 GET→隧道→冲刷后注入提供端 tun")
        assert wired.consumer.l3.dataplane.tunnels.get(_l3_sid()) is not None

        wired.provider_tun.inject(_origin_synack())
        written: list[bytes] = []
        _wait(lambda: written.extend(wired.consumer_tun.pop_written()) or bool(written),
              what="回程 SYN-ACK 写回消费端 tun")
        back = IP(written[0])
        assert back.src == SERVICE_IP and back.dst == CONSUMER_TUN
        assert back[TCP].flags.SA
        assert dict(back[TCP].options)["MSS"] == CLAMP, "提供端侧也必须 clamp（§6.2）"


def test_dispatch_falls_back_to_v1_for_web_sid() -> None:
    """v1 的 HTTP 模式与 L3 在同一进程内共存：web SID 的 GET 必须走 v1 路径（D13）。"""
    with _Wired() as wired:
        web_sid = sid_hex_from_url(PROVIDER_NID, WEB_URL)
        wired.provider._on_payload(bytes(build_get(web_sid, CONSUMER_NID, 7)))

        # v1 的 handle_get 会记一条未决事务并回隧道 DATA；L3 的隧道表则不该有它
        assert wired.provider.state.pop_pending(web_sid, CONSUMER_NID) is not None, \
            "web SID 的 GET 应由 v1 handlers 处理"
        assert wired.provider.l3.dataplane.tunnels.get(web_sid, CONSUMER_NID) is None
        assert wired.provider.l3.counters.get("tunnel_up") == 0


def test_dispatch_prefers_l3_for_service_sid() -> None:
    """服务级 SID 的 GET 必须被 L3 接走，不能落进 v1 的未决事务表。"""
    with _Wired() as wired:
        sid = _l3_sid()
        wired.provider._on_payload(bytes(build_get(sid, CONSUMER_NID, 9)))

        assert wired.provider.l3.dataplane.tunnels.get(sid, CONSUMER_NID) is not None
        assert wired.provider.state.pop_pending(sid, CONSUMER_NID) is None, \
            "L3 的 SID 不应在 v1 的未决事务表里（PendingTx 是一次性的，隧道是长期的）"


def test_handshake_timeout_is_actually_swept() -> None:
    """周期任务真的在调 expire_handshakes：不调的话首包永远留在队列里（§5.2）。"""
    wired = _Wired(consumer_l3={"tunnel_timeout_sec": 0.2})
    wired.link.provider = None  # 提供端不应答，制造握手超时
    wired.consumer.l3.start()
    try:
        wired.consumer_tun.inject(_client_syn())
        counters = wired.consumer.l3.counters
        _wait(lambda: counters.get("firstpkt_dropped") >= 1, what="超时后丢弃首包队列")
        assert counters.get("firstpkt_queued") == 1
        assert wired.consumer.l3.dataplane.tunnels.get(_l3_sid()) is None
    finally:
        wired.consumer.l3.stop()


def test_handshake_retries_after_timeout() -> None:
    """超时后该 SID 退回未建立状态，下一个包会重新触发 GET（§5.2 末句）。"""
    wired = _Wired(consumer_l3={"tunnel_timeout_sec": 0.2})
    wired.link.provider = None
    wired.consumer.l3.start()
    try:
        wired.consumer_tun.inject(_client_syn())
        _wait(lambda: wired.consumer.l3.counters.get("firstpkt_dropped") >= 1,
              what="第一次握手超时")
        gets = [entry for entry in wired.link.sent if entry[1] == 0x72]
        wired.consumer_tun.inject(_client_syn(sport=51001))
        _wait(lambda: len([e for e in wired.link.sent if e[1] == 0x72]) > len(gets),
              what="超时后的下一个包应重新发 GET")
    finally:
        wired.consumer.l3.stop()


def test_redetect_resends_get_and_replaces_tunnel_atomically() -> None:
    """§8.4 的兜底：上行活跃但下行静默时重发 GET，重探期间旧隧道继续可用。"""
    with _Wired(consumer_l3={"tunnel_redetect_sec": 0.2,
                             "tunnel_timeout_sec": 5.0}) as wired:
        wired.consumer_tun.inject(_client_syn())
        _wait(lambda: wired.consumer.l3.dataplane.tunnels.get(_l3_sid()) is not None,
              what="隧道建立")
        tunnels = wired.consumer.l3.dataplane.tunnels

        # 制造"上行活跃、下行静默"：持续打上行，不回下行
        deadline = time.monotonic() + 1.5
        gets_before = len([e for e in wired.link.sent if e[1] == 0x72])
        while time.monotonic() < deadline:
            tunnels.mark_upstream(_l3_sid())
            if len([e for e in wired.link.sent if e[1] == 0x72]) > gets_before:
                break
            time.sleep(0.02)

        assert len([e for e in wired.link.sent if e[1] == 0x72]) > gets_before, \
            "下行静默超过 tunnel_redetect_sec 应重发 GET"
        assert tunnels.get(_l3_sid()) is not None, "重探期间旧隧道必须继续可用（§8.4）"
        assert wired.consumer.l3.counters.get("tunnel_up") == 1, \
            "重探成功是刷新不是新建，tunnel_up 不应再涨"


def test_oversized_df_packet_counts_mtu_drop() -> None:
    """§6.3：超过 tun MTU 且 DF=1 的内层包丢弃并计 mtu_drop（此前该计数器从未被递增）。"""
    with _Wired() as wired:
        payload = b"x" * 1400
        big = bytes(IP(bytes(
            IP(src=CONSUMER_TUN, dst=SERVICE_IP, flags="DF")
            / UDP(sport=40000, dport=SERVICE_PORT) / Raw(payload)
        )))
        assert len(big) > 1280
        wired.consumer_tun.inject(big)
        _wait(lambda: wired.consumer.l3.counters.get("mtu_drop") == 1,
              what="超长 DF 包计入 mtu_drop")
        assert wired.consumer.l3.counters.get("sid_hit") == 0, "应在查 SID 之前就丢掉"


def test_duplicate_tunnel_data_is_idempotent() -> None:
    """提供端对重发的 GET 是幂等回应的，重复的隧道 DATA 不得被误当成下行内层包。"""
    with _Wired() as wired:
        wired.consumer_tun.inject(_client_syn())
        _wait(lambda: wired.consumer.l3.dataplane.tunnels.get(_l3_sid()) is not None,
              what="隧道建立")
        wired.consumer_tun.pop_written()
        before = wired.consumer.l3.counters.snapshot()

        # 让提供端再回一次隧道 DATA（等价于 GET 重发）
        wired.provider._on_payload(bytes(build_get(_l3_sid(), CONSUMER_NID, 11)))
        after = wired.consumer.l3.counters.snapshot()
        assert after["nonipv4_drop"] == before["nonipv4_drop"], \
            "重复的隧道 DATA 不能被当成内层包解析"
        assert after["tunnel_up"] == before["tunnel_up"]
        assert wired.consumer_tun.pop_written() == []


def test_injected_tun_is_not_closed_by_stop() -> None:
    """注入的 tun 归调用方所有：stop() 不得关掉它（否则测试后续断言都读不到）。"""
    wired = _Wired()
    wired.provider.l3.start()
    wired.provider.l3.stop()
    assert wired.provider_tun.closed is False


def test_capture_route_conflict_refuses_to_start() -> None:
    """§2.4 第二道校验：同域部署会让外层包被自己的 tun 吞掉，必须拒绝启动。

    配置加载时只查得了 rm_ipv4；提供端代理的地址要到注册回复同步下来才知道，
    所以这道检查非做不可，否则症状是"对端一个包都不回"。
    """
    consumer = Consumer(_consumer_config())
    # 提供端代理的地址正好等于捕获路由覆盖的地址 —— 典型的同域部署
    consumer.state.set_domain_info([(PROVIDER_NID, SERVICE_IP)], [])
    assert consumer.state.capture_route_conflicts(), "应识别出冲突"
    try:
        consumer._assert_route_isolation()
    except RuntimeError as exc:
        assert "§2.4" in str(exc) and SERVICE_IP in str(exc)
    else:
        raise AssertionError("外层目的落进 capture_routes 时必须拒绝启动")


def test_capture_route_isolation_passes_when_cross_domain() -> None:
    """跨域部署（设计 §2.4 第 3 条的硬前提成立）时不应误报。"""
    consumer = Consumer(_consumer_config())
    consumer.state.set_domain_info([(PROVIDER_NID, PROVIDER_IP)], [(3, "10.10.0.9")])
    assert consumer.state.capture_route_conflicts() == []
    consumer._assert_route_isolation()


def test_l3_disabled_leaves_assembly_untouched() -> None:
    """``l3.enabled=false`` 时连 L3 运行期都不构造：v1 模式不需要 tun 与管理员权限。"""
    config = _provider_config()
    plain = Config(nid=config.nid, ipv4=config.ipv4, rm_ipv4=config.rm_ipv4,
                   services=config.services, l3=L3Config(enabled=False))
    provider = Provider(plain)
    assert provider.l3 is None

    consumer_config = ConsumerConfig(nid=CONSUMER_NID, ipv4=CONSUMER_IP, rm_ipv4=CONSUMER_RM)
    assert Consumer(consumer_config).l3 is None


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
