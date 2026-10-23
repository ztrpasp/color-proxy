"""消费端配置的读取与校验。

与服务端 ``colorproxy.config`` 风格一致，但消费端不发布服务（无 ``services``），
SID 表在运行期从 RM 拉取（见 ``sid_table``），故配置只含身份与监听端口。
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path

from ..l7 import SUPPORTED_APPS
from ..protocol.sid import service_canonical

#: HTTP 正向代理默认监听端口（用户在浏览器/系统里把 HTTP 代理指向它）
DEFAULT_PROXY_PORT = 8910

#: L3 段各项缺省值（对照 docs/design-l3-v2.md §9.2）
L3_DEFAULT_TUN_NAME = "color0"
L3_DEFAULT_TUN_MASK = "255.255.255.0"
L3_DEFAULT_TUN_MTU = 1280
L3_DEFAULT_MSS_CLAMP = 1240
L3_MSS_HEADROOM = 40
L3_DEFAULT_TUNNEL_TIMEOUT_SEC = 5.0
L3_DEFAULT_QUEUE_PKTS = 4
L3_DEFAULT_QUEUE_BYTES = 8192
L3_DEFAULT_UDP_FLOW_IDLE_SEC = 60.0


@dataclass(frozen=True)
class StaticSid:
    """预置的 URL→提供方 NID 映射（联调/测试用，见 ConsumerConfig.sids）。"""

    url: str
    provider_nid: int


@dataclass(frozen=True)
class StaticService:
    """预置的服务级 SID（``l3.static_services[]``，docs/design-l3-v2.md §9.2）。

    消费端**正常不需要**静态服务表：它从 tun 观察到目的三元组后自行拼串算 L_sid，
    再查 RM 下发的 SID 表拿 N_sid（§3.5 的隐私特性）。本项是 §9.2 点名的"SID 表未
    就绪时的降级路径"：没有 RM 的环境里，不预置就每个包都 ``sid_miss``，L3 一步也
    走不动。

    与 ``sids[]``（内容级，按 URL）并列而不是合并：两者的 L_sid 算法不同
    （``SHA1(url)`` vs ``SHA1("<proto>://<ip>:<port>")``），混在一个列表里只会让人
    写错哪一种。
    """

    proto: str
    ip: str
    port: int
    provider_nid: int
    desc: str = ""


@dataclass(frozen=True)
class AppService:
    """声明某个 L3 端点上跑的是什么应用（``l3.app_services[]``，D20）。

    ``app="http"`` 的端点上每个请求都要先按 URL 过一次准入：消费端解析出请求行，用
    ``SHA1(http://<ip>:<port><path>)`` 查 SID 表并发 GET，回了才放行，否则 RST。
    连接本身仍由服务级 SID 承载，所以提供端照样要发布 ``tcp://<ip>:<port>``。

    ``app="ftp"``（D21）标的是 FTP 控制端口：发往同一地址、SID 表里查不到的端口（被动数据
    连接）改走这条控制 SID，且不再单独过 D19 的准入——放不放行由提供端按 227/229 判定。
    """

    proto: str
    ip: str
    port: int
    app: str

    @property
    def endpoint(self) -> tuple[str, str, int]:
        return self.proto, self.ip, self.port


@dataclass(frozen=True)
class ConsumerL3Config:
    """消费端 L3 隧道模式配置段（``l3``，docs/design-l3-v2.md §9.2）。"""

    enabled: bool = False
    tun_name: str = L3_DEFAULT_TUN_NAME
    tun_ip: str = ""
    tun_mask: str = L3_DEFAULT_TUN_MASK
    tun_mtu: int = L3_DEFAULT_TUN_MTU
    mss_clamp: int = L3_DEFAULT_MSS_CLAMP
    #: 把候选流量导进 tun 的主机路由，**只允许 /32**（理由见 §2.4）
    capture_routes: tuple[str, ...] = ()
    tunnel_timeout_sec: float = L3_DEFAULT_TUNNEL_TIMEOUT_SEC
    firstpkt_queue_pkts: int = L3_DEFAULT_QUEUE_PKTS
    firstpkt_queue_bytes: int = L3_DEFAULT_QUEUE_BYTES
    tunnel_redetect_sec: float = 0.0
    #: 每条新连接（TCP SYN / 新 UDP 流）先发一次 GET，让 RM 的 ACL 按连接生效（D19）。
    #: false 退回 D1 的原行为：每条 SID 只在第一个包时发 GET，此后 ACL 改动对它无效。
    get_per_connection: bool = True
    #: UDP 四元组上行空闲多久算新流（D19；UDP 没有 SYN，只能这样判断）
    udp_flow_idle_sec: float = L3_DEFAULT_UDP_FLOW_IDLE_SEC
    #: 联调开关：放行 ICMP 进隧道，用 ping 做最小连通性判据（§8.2）。跑通后应关掉。
    debug_tunnel_icmp: bool = False
    #: SID 表未就绪时的降级路径（§9.2）。为空则完全依赖 RM 下发的表。
    static_services: tuple[StaticService, ...] = ()
    #: 哪些端点要做应用层解析（D20）。目前只有 ``app="http"``：逐请求的内容级准入。
    app_services: tuple[AppService, ...] = ()


@dataclass(frozen=True)
class ConsumerConfig:
    """消费端运行配置。"""

    nid: int
    ipv4: str
    rm_ipv4: str
    proxy_port: int = DEFAULT_PROXY_PORT
    #: 可选静态 SID 预载：联调时绕开"从 RM 拉取 SID 表"这一未决环节，单独验证
    #: 数据面握手（GET→隧道→ACK→响应）。为空则完全依赖 RM 下发的 SID 表。
    sids: tuple[StaticSid, ...] = ()
    l3: ConsumerL3Config = field(default_factory=ConsumerL3Config)


def load_consumer_config(path: str | Path) -> ConsumerConfig:
    """从 JSON 文件读取并校验消费端配置。

    JSON 形如::

        {
          "nid": "00112233445566778899aabbccddeeff",
          "ipv4": "10.0.1.5",
          "rm_ipv4": "10.0.0.1",
          "proxy_port": 8910,
          "sids": [
            {"url": "http://prov.local/hello.html",
             "provider_nid": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"}
          ]
        }

    ``proxy_port`` 可省略（缺省 8910）；``sids`` 可省略（缺省空，仅用 RM 下发的表）。
    ``sids[].provider_nid`` 即该 URL 提供方的 NID（=对方 config 的 ``nid``）。
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    sids = tuple(
        StaticSid(url=str(entry["url"]), provider_nid=int(str(entry["provider_nid"]), 16))
        for entry in data.get("sids", [])
    )
    rm_ipv4 = str(data["rm_ipv4"])
    return ConsumerConfig(
        nid=int(str(data["nid"]), 16),
        ipv4=str(data["ipv4"]),
        rm_ipv4=rm_ipv4,
        proxy_port=int(data.get("proxy_port", DEFAULT_PROXY_PORT)),
        sids=sids,
        l3=_load_l3(data.get("l3"), rm_ipv4=rm_ipv4),
    )


def _load_l3(data: dict | None, rm_ipv4: str) -> ConsumerL3Config:
    """读取并校验消费端 ``l3`` 段；缺省（无该段）返回 enabled=False 的空配置。

    两条校验直接对应 §2.4 的路由隔离规则，都是"配错就彻底死锁、但症状看着像别的
    问题"的那种，故一律 fail-fast：

    1. ``capture_routes`` **只允许 /32 主机路由**。写成 `172.10.0.0/24` 会把提供端
       域的 RM(`172.10.0.5`) 一起吞进 tun。
    2. 任何 capture_route 都不得覆盖 ``rm_ipv4``。一旦本域 RM 的地址落进 tun 路由，
       外层 CoLoR 包会被自己的路由表吞进 tun，链路彻底死锁。
    """
    if not data:
        return ConsumerL3Config()

    enabled = bool(data.get("enabled", True))
    tun_ip = _require_ipv4(data["tun_ip"], "l3.tun_ip") if data.get("tun_ip") else ""
    tun_mtu = int(data.get("tun_mtu", L3_DEFAULT_TUN_MTU))
    mss_clamp = int(data.get("mss_clamp", L3_DEFAULT_MSS_CLAMP))
    if tun_mtu <= 0:
        raise ValueError(f"l3.tun_mtu 必须为正：{tun_mtu}")
    if mss_clamp > tun_mtu - L3_MSS_HEADROOM:
        raise ValueError(
            f"l3.mss_clamp({mss_clamp}) 不得大于 tun_mtu−{L3_MSS_HEADROOM}"
            f"（={tun_mtu - L3_MSS_HEADROOM}），否则 MSS clamp 形同失效（§6.2）"
        )

    capture_routes: list[str] = []
    rm_address = ipaddress.IPv4Address(rm_ipv4.strip())
    for index, raw in enumerate(data.get("capture_routes", [])):
        where = f"l3.capture_routes[{index}]"
        try:
            network = ipaddress.IPv4Network(str(raw).strip(), strict=False)
        except ValueError as exc:
            raise ValueError(f"{where} 不是合法的 IPv4 网段：{raw!r}（{exc}）") from exc
        if network.prefixlen != 32:
            raise ValueError(
                f"{where}({network}) 不是 /32 主机路由。只允许 /32：粗网段会把对端域的"
                f" RM/BR 一起吞进 tun（§2.4 第 1 条）；多个提供端就多配几条 /32"
            )
        if rm_address in network:
            raise ValueError(
                f"{where}({network}) 覆盖了本域 RM({rm_ipv4})。外层 CoLoR 包会被自己的"
                f"路由表吞进 tun，链路彻底死锁（§2.4）"
            )
        capture_routes.append(str(network))

    static_services: list[StaticService] = []
    for index, entry in enumerate(data.get("static_services", [])):
        where = f"l3.static_services[{index}]"
        try:
            canonical = service_canonical(entry.get("proto"), entry.get("ip"), entry.get("port"))
        except ValueError as exc:
            raise ValueError(f"{where} 不合法：{exc}") from exc
        try:
            provider_nid = int(str(entry["provider_nid"]), 16)
        except (KeyError, ValueError) as exc:
            raise ValueError(f"{where}.provider_nid 不是合法的十六进制 NID：{exc}") from exc
        proto, rest = canonical.split("://", 1)
        ip, port = rest.rsplit(":", 1)
        static_services.append(StaticService(
            proto=proto, ip=ip, port=int(port), provider_nid=provider_nid,
            desc=str(entry.get("desc", "")),
        ))

    app_services = _load_app_services(data.get("app_services", []), capture_routes)

    udp_flow_idle_sec = float(data.get("udp_flow_idle_sec", L3_DEFAULT_UDP_FLOW_IDLE_SEC))
    if udp_flow_idle_sec <= 0:
        raise ValueError(
            f"l3.udp_flow_idle_sec({udp_flow_idle_sec}) 必须大于 0；"
            "想关掉按连接发 GET 请改 l3.get_per_connection=false"
        )

    if enabled:
        if not tun_ip:
            raise ValueError("l3.enabled 时必须配 l3.tun_ip（内层包的源地址就是它）")
        if not capture_routes:
            raise ValueError(
                "l3.enabled 时 l3.capture_routes[] 不能为空，否则没有任何流量会进 tun"
            )

    return ConsumerL3Config(
        enabled=enabled,
        tun_name=str(data.get("tun_name", L3_DEFAULT_TUN_NAME)),
        tun_ip=tun_ip,
        tun_mask=str(data.get("tun_mask", L3_DEFAULT_TUN_MASK)),
        tun_mtu=tun_mtu,
        mss_clamp=mss_clamp,
        capture_routes=tuple(capture_routes),
        tunnel_timeout_sec=float(data.get("tunnel_timeout_sec", L3_DEFAULT_TUNNEL_TIMEOUT_SEC)),
        firstpkt_queue_pkts=int(data.get("firstpkt_queue_pkts", L3_DEFAULT_QUEUE_PKTS)),
        firstpkt_queue_bytes=int(data.get("firstpkt_queue_bytes", L3_DEFAULT_QUEUE_BYTES)),
        tunnel_redetect_sec=float(data.get("tunnel_redetect_sec", 0.0)),
        get_per_connection=bool(data.get("get_per_connection", True)),
        udp_flow_idle_sec=udp_flow_idle_sec,
        debug_tunnel_icmp=bool(data.get("debug_tunnel_icmp", False)),
        static_services=tuple(static_services),
        app_services=app_services,
    )


def _load_app_services(entries: list, capture_routes: list[str]) -> tuple[AppService, ...]:
    """读取并校验 ``l3.app_services[]``（D20），全部 fail-fast。

    地址必须落在某条 ``capture_routes`` 里：不在的话这个端点的流量根本不进 tun，配了
    等于没配，而症状是"内容级管控没生效"——比报错难查得多。
    """
    networks = [ipaddress.IPv4Network(route) for route in capture_routes]
    services: list[AppService] = []
    seen: set[tuple[str, str, int]] = set()
    for index, entry in enumerate(entries):
        where = f"l3.app_services[{index}]"
        try:
            canonical = service_canonical(entry.get("proto"), entry.get("ip"), entry.get("port"))
        except ValueError as exc:
            raise ValueError(f"{where} 不合法：{exc}") from exc
        proto, rest = canonical.split("://", 1)
        ip, port_text = rest.rsplit(":", 1)
        port = int(port_text)
        app = str(entry.get("app", "")).strip().lower()
        if app not in SUPPORTED_APPS:
            raise ValueError(f"{where}.app 只能是 {' / '.join(SUPPORTED_APPS)}，收到：{app!r}")
        if proto != "tcp" or port == 0:
            raise ValueError(f"{where}：app={app} 只能用于 tcp 且端口不能是 0（通配）")
        if networks and not any(ipaddress.IPv4Address(ip) in net for net in networks):
            raise ValueError(
                f"{where}.ip({ip}) 不在任何 l3.capture_routes {capture_routes} 内："
                "这个端点的流量不会进 tun，应用层解析永远不会生效"
            )
        if (proto, ip, port) in seen:
            raise ValueError(f"{where} 重复：{canonical}")
        if app == "ftp" and any(svc.app == "ftp" and svc.ip == ip for svc in services):
            # D21：发往这个地址的未知端口回退到 FTP 控制 SID，两个 FTP 就分不清该走哪条
            raise ValueError(f"{where}：{ip} 上已经有一个 app=ftp 的端点，同一地址只能有一个")
        seen.add((proto, ip, port))
        services.append(AppService(proto=proto, ip=ip, port=port, app=app))
    return tuple(services)


def _require_ipv4(value: object, where: str) -> str:
    try:
        return str(ipaddress.IPv4Address(str(value).strip()))
    except ValueError as exc:
        raise ValueError(f"{where} 不是合法的点分 IPv4：{value!r}（{exc}）") from exc
