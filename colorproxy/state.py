"""服务端运行期状态。

汇总注册状态、域内 Proxy/BR 表、已发布 Web 服务表与未决事务表，并提供
线程安全的读写方法。键的约定：SID 用 72 位十六进制字符串，NID/PX 用整数。
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field

from .config import Config, ServiceConfig


@dataclass
class PendingTx:
    """一次 Web 请求事务的上下文（GET 到达时记录，发完响应后清除）。"""

    return_ip: str        # 回送 DATA 的下一跳 IP
    pids: list[int]       # GET 携带的 PID 序列（回送时原样使用）
    seg_id: int           # 事务标识（来自 GET 的 SegID，原样回带）
    cross_domain: bool    # 是否跨域（pids 非空）


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

    # -- 未决事务 -------------------------------------------------------

    def put_pending(self, sid: str, consumer_nid: int, tx: PendingTx) -> None:
        with self._lock:
            self._pending[(sid, consumer_nid)] = tx  # 同键覆盖（v1 不支持并发）

    def pop_pending(self, sid: str, consumer_nid: int) -> PendingTx | None:
        with self._lock:
            return self._pending.pop((sid, consumer_nid), None)
