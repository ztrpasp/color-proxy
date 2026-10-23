"""服务端配置的读取与校验。

除 v1 的内容级 Web 服务（``services``）外，还读取 v2 的 L3 隧道模式配置段
``l3``（docs/design-l3-v2.md §9.1）。L3 段的校验一律 **fail-fast**：配错的
症状（SID 对不上、包被静默丢弃）在运行期极难定位，宁可拒绝启动。
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from .l7 import SUPPORTED_APPS
from .protocol.sid import content_url, lsid_from_url, service_canonical

#: L3 段各项的缺省值（对照 docs/design-l3-v2.md §9.1）
L3_DEFAULT_TUN_NAME = "color0"
L3_DEFAULT_TUN_MASK = "255.255.255.0"
L3_DEFAULT_TUN_MTU = 1280
L3_DEFAULT_MSS_CLAMP = 1240
#: MSS clamp 与 tun MTU 的关系：1280 − 20(IP) − 20(TCP) = 1240（§6.2）
L3_MSS_HEADROOM = 40


@dataclass(frozen=True)
class ServiceConfig:
    """一个对外发布的 Web 服务。"""

    url: str
    origin_host: str
    origin_port: int


@dataclass(frozen=True)
class L3ServiceConfig:
    """一条对外发布的 L3 服务级端点（``l3.services[]``，§9.1）。"""

    proto: str
    ip: str
    port: int
    desc: str = ""
    #: 应用层类型。``"http"``（D20）：这个端点上的资源还要按 URL 发布内容级 SID；
    #: ``"ftp"``（D21）：这是 FTP 控制端口，被动数据连接按 227/229 动态放行、走这条 SID。
    app: str = ""
    #: ``app="http"`` 时按 URL 发布的资源路径（以 ``/`` 开头、不含 query）
    paths: tuple[str, ...] = ()

    @property
    def content_urls(self) -> tuple[str, ...]:
        """按 D20 拼出的内容级 URL（``http://<ip>:<port><path>``），每条一个 SID。"""
        return tuple(content_url(self.ip, self.port, path) for path in self.paths)

    @property
    def canonical(self) -> str:
        """规范服务串（§3.1）。构造时已校验过，此处不会再抛。"""
        return service_canonical(self.proto, self.ip, self.port)

    @property
    def is_wildcard_port(self) -> bool:
        """端口 0 = 该 IP 上全部端口（§3.3，为被动 FTP 准备）。"""
        return self.port == 0

    def admits(self, proto: str, ip: str, port: int) -> bool:
        """准入校验的目的侧判据（§7.2 注入第 5 步）。

        通配端口时只比 proto + ip —— 目的粒度退化到主机级（§8.3）。
        """
        if proto != self.proto or ip != self.ip:
            return False
        return self.is_wildcard_port or port == self.port


@dataclass(frozen=True)
class PeerConfig:
    """一个已知消费端的 NID → tun 地址绑定（``l3.peers[]``，§9.1，D14）。

    这张表是 L3 回程的唯一依据，也是入向来源校验的唯一依据：取消了 rev.2 的
    ``PeerTun`` 数据面学习之后，消费端身份只能来自静态配置（§7.3）。
    """

    nid: int
    tun_ip: str
    desc: str = ""


@dataclass(frozen=True)
class L3Config:
    """L3 隧道模式配置段（``l3``，§9.1）。"""

    enabled: bool = False
    tun_name: str = L3_DEFAULT_TUN_NAME
    tun_ip: str = ""
    tun_mask: str = L3_DEFAULT_TUN_MASK
    tun_mtu: int = L3_DEFAULT_TUN_MTU
    mss_clamp: int = L3_DEFAULT_MSS_CLAMP
    peer_routes: tuple[str, ...] = ()
    weak_host: bool = True
    tunnel_refresh_sec: float = 0.0
    peers: tuple[PeerConfig, ...] = ()
    services: tuple[L3ServiceConfig, ...] = ()

    def peer_by_tun_ip(self, tun_ip: str) -> PeerConfig | None:
        for peer in self.peers:
            if peer.tun_ip == tun_ip:
                return peer
        return None


@dataclass(frozen=True)
class Config:
    """服务端运行配置。

    ``l3`` 置于末尾且有缺省值：现有代码与测试按位置构造 ``Config(nid, ipv4,
    rm_ipv4, services)``，不传 ``l3`` 即表示只跑 v1 模式。
    """

    nid: int
    ipv4: str
    rm_ipv4: str
    services: list[ServiceConfig]
    l3: L3Config = field(default_factory=L3Config)


def load_config(path: str | Path) -> Config:
    """从 JSON 文件读取并校验配置。

    JSON 形如::

        {
          "nid": "00112233445566778899aabbccddeeff",
          "ipv4": "10.0.1.6",
          "rm_ipv4": "10.0.0.1",
          "services": [
            {"url": "http://prov.local/hello.html",
             "origin_host": "127.0.0.1", "origin_port": 8000}
          ]
        }

    ``origin_host`` / ``origin_port`` 可省略，缺省取 URL 中的主机与端口。
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))

    nid = int(str(data["nid"]), 16)
    ipv4 = str(data["ipv4"])
    rm_ipv4 = str(data["rm_ipv4"])

    services: list[ServiceConfig] = []
    for entry in data.get("services", []):
        url = entry["url"]
        default_host, default_port = _default_origin(url)
        services.append(
            ServiceConfig(
                url=url,
                origin_host=entry.get("origin_host", default_host),
                origin_port=int(entry.get("origin_port", default_port)),
            )
        )
    if not services:
        raise ValueError("配置中至少需要一个 services 条目")

    l3 = _load_l3(data.get("l3"))
    _check_content_sid_collisions(services, l3)
    return Config(nid=nid, ipv4=ipv4, rm_ipv4=rm_ipv4, services=services, l3=l3)


def _check_content_sid_collisions(services: list[ServiceConfig], l3: L3Config) -> None:
    """v1 的 URL 与 L3 内容级（D20）的 URL 不得算出同一条 SID。

    两种模式用同一个 ``lsid_from_url``，而提供端按"SID 落在哪张表里"分派（D13）：撞了就
    分不清一个 GET 该走 v1（回源）还是 L3（只回隧道 DATA）。v1 的 URL 一般写的是物理地址
    （172.10.0.2），L3 的是虚服务地址（172.10.9.2），正常不会撞；撞了一定是配错了。
    """
    web = {lsid_from_url(service.url): service.url for service in services}
    for index, service in enumerate(l3.services):
        for url in service.content_urls:
            if lsid_from_url(url) in web:
                raise ValueError(
                    f"l3.services[{index}] 的内容级 URL {url} 与 services[] 里的 "
                    f"{web[lsid_from_url(url)]} 算出同一条 SID：同一条 SID 不能同时属于 v1 "
                    "与 L3（按 SID 分派，D13）。把其中一边的地址改开"
                )


def _default_origin(url: str) -> tuple[str, int]:
    parsed = urlparse(url)
    if not parsed.hostname:
        raise ValueError(f"无法从 URL 解析主机：{url}")
    return parsed.hostname, parsed.port or 80


def _load_l3(data: dict | None) -> L3Config:
    """读取并校验 ``l3`` 段；缺省（无该段）返回 enabled=False 的空配置。

    校验项对照 docs/design-l3-v2.md §9.1，全部 fail-fast。``enabled=false`` 时
    仍做格式校验（好让配置错误在开关打开前就暴露），但跳过"必须非空"一类的
    运行前提检查。
    """
    if not data:
        return L3Config()

    enabled = bool(data.get("enabled", True))
    tun_ip = _require_ipv4(data.get("tun_ip", ""), "l3.tun_ip") if data.get("tun_ip") else ""
    tun_mtu = int(data.get("tun_mtu", L3_DEFAULT_TUN_MTU))
    mss_clamp = int(data.get("mss_clamp", L3_DEFAULT_MSS_CLAMP))
    if tun_mtu <= 0:
        raise ValueError(f"l3.tun_mtu 必须为正：{tun_mtu}")
    if mss_clamp > tun_mtu - L3_MSS_HEADROOM:
        # 只减不增：clamp 大于 MTU−40 就起不到作用，服务端回大包会形成黑洞（§6.2）
        raise ValueError(
            f"l3.mss_clamp({mss_clamp}) 不得大于 tun_mtu−{L3_MSS_HEADROOM}"
            f"（={tun_mtu - L3_MSS_HEADROOM}），否则 MSS clamp 形同失效"
        )

    peer_routes = tuple(str(route) for route in data.get("peer_routes", []))
    networks = [_require_network(route, "l3.peer_routes") for route in peer_routes]

    services: list[L3ServiceConfig] = []
    seen_canonical: dict[str, int] = {}
    for index, entry in enumerate(data.get("services", [])):
        where = f"l3.services[{index}]"
        try:
            canonical = service_canonical(
                entry.get("proto"), entry.get("ip"), entry.get("port")
            )
        except ValueError as exc:
            raise ValueError(f"{where} 不合法：{exc}") from exc
        if canonical in seen_canonical:
            raise ValueError(
                f"{where} 与 l3.services[{seen_canonical[canonical]}] 的规范服务串重复"
                f"（{canonical}）——同一个串就是同一个 SID，重复发布无意义"
            )
        seen_canonical[canonical] = index
        proto, rest = canonical.split("://", 1)
        ip, port = rest.rsplit(":", 1)
        app, paths = _load_app(entry, where, proto, int(port))
        if app == "ftp" and any(svc.app == "ftp" and svc.ip == ip for svc in services):
            # 消费端按地址把未知端口回退到 FTP 控制 SID，同一地址两个 FTP 就分不清该走哪条
            raise ValueError(f"{where}：{ip} 上已经有一个 app=ftp 的端点，同一地址只能有一个（D21）")
        services.append(L3ServiceConfig(
            proto=proto, ip=ip, port=int(port), desc=str(entry.get("desc", "")),
            app=app, paths=paths,
        ))

    peers: list[PeerConfig] = []
    seen_tun_ip: dict[str, int] = {}
    seen_nid: dict[int, int] = {}
    for index, entry in enumerate(data.get("peers", [])):
        where = f"l3.peers[{index}]"
        try:
            nid = int(str(entry["nid"]), 16)
        except (KeyError, ValueError) as exc:
            raise ValueError(f"{where}.nid 不是合法的十六进制 NID：{exc}") from exc
        peer_tun_ip = _require_ipv4(entry.get("tun_ip"), f"{where}.tun_ip")

        # 每个消费端的 tun 地址必须全局唯一：提供端靠内层 dst 定位消费端，
        # 重复即两个消费端互相偷对方的回程流量（§2.2 / §7.3）。
        if peer_tun_ip in seen_tun_ip:
            raise ValueError(
                f"{where}.tun_ip({peer_tun_ip}) 与 l3.peers[{seen_tun_ip[peer_tun_ip]}] 重复；"
                "每个消费端的 tun 地址必须全局唯一（§2.2）"
            )
        if nid in seen_nid:
            raise ValueError(f"{where}.nid 与 l3.peers[{seen_nid[nid]}] 重复")
        if tun_ip and peer_tun_ip == tun_ip:
            raise ValueError(
                f"{where}.tun_ip({peer_tun_ip}) 与本机 l3.tun_ip 相同；"
                "消费端与提供端的 tun 地址不能重合"
            )
        if networks and not any(
            ipaddress.IPv4Address(peer_tun_ip) in net for net in networks
        ):
            raise ValueError(
                f"{where}.tun_ip({peer_tun_ip}) 不在任何 l3.peer_routes "
                f"{list(peer_routes)} 覆盖的网段内，回程包出不去"
            )
        seen_tun_ip[peer_tun_ip] = index
        seen_nid[nid] = index
        peers.append(
            PeerConfig(nid=nid, tun_ip=peer_tun_ip, desc=str(entry.get("desc", "")))
        )

    if enabled:
        # 缺这两张表时 L3 起不来，且症状是"隧道建得起来但一个包都过不去"（§9.1）
        if not tun_ip:
            raise ValueError("l3.enabled 时必须配 l3.tun_ip")
        if not services:
            raise ValueError("l3.enabled 时 l3.services[] 不能为空，否则没有可发布的服务")
        if not peers:
            raise ValueError(
                "l3.enabled 时 l3.peers[] 不能为空：回程与来源校验都依赖它，"
                "缺失会让每个上行包都被 src_bind_drop 丢掉（§7.3，D14）"
            )
        if not peer_routes:
            raise ValueError("l3.enabled 时必须配 l3.peer_routes（回程路由落点）")

    return L3Config(
        enabled=enabled,
        tun_name=str(data.get("tun_name", L3_DEFAULT_TUN_NAME)),
        tun_ip=tun_ip,
        tun_mask=str(data.get("tun_mask", L3_DEFAULT_TUN_MASK)),
        tun_mtu=tun_mtu,
        mss_clamp=mss_clamp,
        peer_routes=peer_routes,
        weak_host=bool(data.get("weak_host", True)),
        tunnel_refresh_sec=float(data.get("tunnel_refresh_sec", 0.0)),
        peers=tuple(peers),
        services=tuple(services),
    )


def _load_app(entry: dict, where: str, proto: str, port: int) -> tuple[str, tuple[str, ...]]:
    """读取并校验一条 L3 服务的 ``app`` / ``paths``（D20）。

    path 原样参与 SID 计算、**不做归一化**（理由见 ``protocol.sid.content_path``），所以
    这里只挡明显写错的：不以 ``/`` 开头、带 query/fragment、含空白、重复。
    """
    app = str(entry.get("app", "")).strip().lower()
    raw_paths = entry.get("paths", [])
    if not isinstance(raw_paths, list):
        raise ValueError(f"{where}.paths 必须是列表")
    if app and app not in SUPPORTED_APPS:
        raise ValueError(f"{where}.app 只能是 {' / '.join(SUPPORTED_APPS)}，收到：{app!r}")
    if raw_paths and app != "http":
        raise ValueError(f"{where} 配了 paths 但 app 不是 \"http\"：内容级 SID 目前只支持 HTTP")
    if app == "ftp" and (proto != "tcp" or port == 0):
        # D21：app=ftp 标的是**控制端口**，数据端口由 227/229 动态得出，不能也不必用通配
        raise ValueError(f"{where}.app=ftp 只能标在 tcp 的控制端口上（端口不能是 0）")
    if app != "http":
        return app, ()
    if proto != "tcp" or port == 0:
        raise ValueError(f"{where}.app=http 只能用于 tcp 且端口不能是 0（通配）")
    if not raw_paths:
        raise ValueError(
            f"{where}.app=http 时 paths 不能为空：消费端会拒绝 SID 表里没有的 URL，"
            "一条都不发布等于这个端口上的请求全部被拒"
        )
    paths: list[str] = []
    for position, raw in enumerate(raw_paths):
        path = str(raw)
        label = f"{where}.paths[{position}]"
        if not path.startswith("/"):
            raise ValueError(f"{label}({path!r}) 必须以 / 开头")
        if any(ch in path for ch in "?#") or any(ch.isspace() for ch in path):
            raise ValueError(f"{label}({path!r}) 不能含 ? # 或空白：query 本来就不参与 SID")
        if path in paths:
            raise ValueError(f"{label}({path!r}) 重复")
        paths.append(path)
    return app, tuple(paths)


def _require_ipv4(value: object, where: str) -> str:
    try:
        return str(ipaddress.IPv4Address(str(value).strip()))
    except ValueError as exc:
        raise ValueError(f"{where} 不是合法的点分 IPv4：{value!r}（{exc}）") from exc


def _require_network(value: str, where: str) -> ipaddress.IPv4Network:
    try:
        return ipaddress.IPv4Network(value.strip(), strict=False)
    except ValueError as exc:
        raise ValueError(f"{where} 不是合法的 IPv4 网段：{value!r}（{exc}）") from exc
