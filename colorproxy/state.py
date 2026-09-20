"""服务端运行期状态。

汇总注册状态、域内 Proxy/BR 表、已发布 Web 服务表与未决事务表，并提供
线程安全的读写方法。键的约定：SID 用 72 位十六进制字符串，NID/PX 用整数。
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field

from .config import Config, L3ServiceConfig, ServiceConfig


@dataclass
class PendingTx:
    """一次 Web 请求事务的上下文（GET 到达时记录，发完响应后清除）。"""

    return_ip: str        # 回送 DATA 的下一跳 IP
    pids: list[int]       # GET 携带的 PID 序列（回送时原样使用）
    seg_id: int           # 事务标识（来自 GET 的 SegID，原样回带）
    cross_domain: bool    # 是否跨域（pids 非空）
    random_num: bytes | None = None  # GET 携带的 4 字节 Random_Num，作回送 DATA 的 HMAC 种子


class ProviderState:
    """提供端共享状态。所有可变表均由 ``_lock`` 保护。"""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.nid = config.nid
        self.ipv4 = config.ipv4
        self.rm_ipv4 = config.rm_ipv4

        self.registered = threading.Event()
        self._lock = threading.Lock()
        self._peer_proxys: dict[int, str] = {}          # nid -> ip
        self._pxs: dict[int, str] = {}                  # px -> ip
        self._web_services: dict[str, ServiceConfig] = {}  # sid -> 服务
        self._pending: dict[tuple[str, int], PendingTx] = {}  # (sid, cus_nid) -> 事务

        # -- L3 隧道模式（v2）。两张表与 v1 的 _web_services 并列，模式分派靠
        # "SID 落在哪张表里"判定，不靠 load[0]（docs/design-l3-v2.md §4.1，D13）。
        self._l3_services: dict[str, L3ServiceConfig] = {}  # sid -> L3 服务
        # peers 是**静态**表：由配置在此处一次性建立，数据面永不写入（D14，§7.3）。
        # 故不需要放进 _lock 保护，建好即只读。
        self._peer_tun_ip: dict[int, str] = {p.nid: p.tun_ip for p in config.l3.peers}
        self._peer_nid_by_tun_ip: dict[str, int] = {
            p.tun_ip: p.nid for p in config.l3.peers
        }

    # -- 域内信息（注册回复填充） --------------------------------------

    def set_domain_info(
        self, proxies: list[tuple[int, str]], brs: list[tuple[int, str]]
    ) -> None:
        with self._lock:
            for nid, ip in proxies:
                if nid != self.nid:
                    self._peer_proxys[nid] = ip
            for px, ip in brs:
                self._pxs[px] = ip

    def resolve_return_ip(self, consumer_nid: int, pids: list[int]) -> str | None:
        """根据 GET 的 PID 序列确定回送 DATA 的下一跳 IP。

        - pids 为空：域内请求，查 ``peer_proxys[consumer_nid]``
        - pids 非空：跨域请求，取最后一个 PID 高 16 位作 PX，查 ``pxs[PX]``
        """
        with self._lock:
            if not pids:
                return self._peer_proxys.get(consumer_nid)
            px = pids[-1] >> 16
            return self._pxs.get(px)

    # -- 已发布 Web 服务 -----------------------------------------------

    def add_service(self, sid: str, service: ServiceConfig) -> None:
        with self._lock:
            self._web_services[sid] = service

    def get_service(self, sid: str) -> ServiceConfig | None:
        with self._lock:
            return self._web_services.get(sid)

    # -- 已发布 L3 服务（v2）--------------------------------------------------

    def add_l3_service(self, sid: str, service: L3ServiceConfig) -> None:
        with self._lock:
            self._l3_services[sid] = service

    def get_l3_service(self, sid: str) -> L3ServiceConfig | None:
        """L3 模式的分派入口：SID 命中即走 L3 路径（D13）。"""
        with self._lock:
            return self._l3_services.get(sid)

    def l3_service_count(self) -> int:
        with self._lock:
            return len(self._l3_services)

    def find_l3_service_for_endpoint(
        self, proto: str, ip: str, port: int
    ) -> tuple[str, L3ServiceConfig] | None:
        """按服务三元组反查 (sid, 服务)，含 §3.3 的通配回退。

        回送方向用它由内层**源**三元组反推 SID（§7.2 回送第 2 步，D14）：先试精确
        端口，再试同 IP 的通配项。返回 None 表示该源端点不是本机发布的服务。
        """
        with self._lock:
            exact = [
                (sid, svc) for sid, svc in self._l3_services.items()
                if svc.proto == proto and svc.ip == ip and svc.port == port
            ]
            if exact:
                return exact[0]
            wildcard = [
                (sid, svc) for sid, svc in self._l3_services.items()
                if svc.proto == proto and svc.ip == ip and svc.is_wildcard_port
            ]
            return wildcard[0] if wildcard else None

    # -- 已知消费端（静态，来自配置 l3.peers[]）-------------------------------

    def peer_tun_ip(self, consumer_nid: int) -> str | None:
        """消费端 NID → 其 tun 地址。入向来源校验用（§7.2 注入第 5 步）。"""
        return self._peer_tun_ip.get(consumer_nid)

    def peer_nid_by_tun_ip(self, tun_ip: str) -> int | None:
        """tun 地址 → 消费端 NID。回送方向定位消费端用（§7.2 回送第 3 步）。"""
        return self._peer_nid_by_tun_ip.get(tun_ip)

    # -- 未决事务 -------------------------------------------------------

    def put_pending(self, sid: str, consumer_nid: int, tx: PendingTx) -> None:
        with self._lock:
            self._pending[(sid, consumer_nid)] = tx  # 同键覆盖（v1 不支持并发）

    def pop_pending(self, sid: str, consumer_nid: int) -> PendingTx | None:
        with self._lock:
            return self._pending.pop((sid, consumer_nid), None)
