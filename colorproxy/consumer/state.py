"""消费端运行期状态。

汇总注册状态、域内 Proxy/BR 表、从 RM 拉取的本域 SID 表与未决请求表，
并提供线程安全的读写。键约定：SID/L_sid 用十六进制字符串，NID/PX 用整数。

``nid`` / ``ipv4`` / ``rm_ipv4`` / ``registered`` / ``set_domain_info`` 与
``ProviderState`` 同名同义，使 ``colorproxy.registration`` 的 ``register`` /
``handle_control`` 可按鸭子类型直接复用（无需改动服务端文件）。
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field

from ..protocol.constants import NSID_LEN
from ..protocol.sid import lsid_from_url
from .config import ConsumerConfig


@dataclass
class PendingRequest:
    """一次浏览器请求在 CoLoR 侧的握手上下文。

    收包线程负责填充 ``pids`` / ``return_ip`` / ``response_buf`` 并置事件，
    发起请求的工作线程在事件上等待并推进握手（GET→隧道→ACK→响应）。
    """

    tunnel_event: threading.Event = field(default_factory=threading.Event)
    response_event: threading.Event = field(default_factory=threading.Event)
    pids: list[int] = field(default_factory=list)  # 隧道 DATA 带回的 PID 序列
    return_ip: str | None = None                    # 发 ACK 的下一跳 IP
    response_buf: bytearray = field(default_factory=bytearray)  # 拼接的 HTTP 响应


class ConsumerState:
    """消费端共享状态。所有可变表均由 ``_lock`` 保护。"""

    def __init__(self, config: ConsumerConfig) -> None:
        self.config = config
        self.nid = config.nid
        self.ipv4 = config.ipv4
        self.rm_ipv4 = config.rm_ipv4

        self.registered = threading.Event()
        self._lock = threading.Lock()
        self._peer_proxys: dict[int, str] = {}        # nid -> ip
        self._pxs: dict[int, str] = {}                # px -> ip
        self._sid_table: dict[str, str] = {}          # l_sid_hex -> sid_hex(72)
        self._pending: dict[tuple[str, int], PendingRequest] = {}
        self._sid_locks: dict[str, threading.Lock] = {}  # sid -> 串行锁

    # -- 域内信息（注册回复填充，复用 registration.handle_control） ----------

    def set_domain_info(
        self, proxies: list[tuple[int, str]], brs: list[tuple[int, str]]
    ) -> None:
        with self._lock:
            for nid, ip in proxies:
                if nid != self.nid:
                    self._peer_proxys[nid] = ip
            for px, ip in brs:
                self._pxs[px] = ip

    def resolve_provider_ip(self, provider_nid: int) -> str | None:
        """域内回址：提供方 NID -> IP。"""
        with self._lock:
            return self._peer_proxys.get(provider_nid)

    def resolve_px_ip(self, px: int) -> str | None:
        """跨域回址：PX(PID 高 16 位) -> 边界路由器 IP。"""
        with self._lock:
            return self._pxs.get(px)

    # -- 本域 SID 表（从 RM 拉取） --------------------------------------------

    def add_sid(self, sid_hex: str) -> None:
        """登记一个完整 SID（72 hex），按其 L_sid 部分建索引。"""
        with self._lock:
            self._sid_table[sid_hex[NSID_LEN * 2:]] = sid_hex

    def lookup_by_url(self, url: str) -> str | None:
        """按 ``L_sid = SHA1(去 query 后 url)`` 在本域 SID 表中查完整 SID。"""
        lsid_hex = lsid_from_url(url).hex()
        with self._lock:
            return self._sid_table.get(lsid_hex)

    def sid_count(self) -> int:
        with self._lock:
            return len(self._sid_table)

    # -- 未决请求 -------------------------------------------------------------

    def new_pending(self, sid: str, consumer_nid: int) -> PendingRequest:
        """新建并登记一次未决请求（同键覆盖，对齐服务端 last-wins）。"""
        pending = PendingRequest()
        with self._lock:
            self._pending[(sid, consumer_nid)] = pending
        return pending

    def get_pending(self, sid: str, consumer_nid: int) -> PendingRequest | None:
        with self._lock:
            return self._pending.get((sid, consumer_nid))

    def pop_pending(self, sid: str, consumer_nid: int) -> PendingRequest | None:
        with self._lock:
            return self._pending.pop((sid, consumer_nid), None)

    # -- 同 SID 串行锁（契约 §2.4：消费端自行串行同 (SID,NID_C) 请求） ---------

    def sid_lock(self, sid: str) -> threading.Lock:
        with self._lock:
            lock = self._sid_locks.get(sid)
            if lock is None:
                lock = threading.Lock()
                self._sid_locks[sid] = lock
            return lock
