"""消费端运行期状态。

汇总注册状态、域内 Proxy/BR 表、从 RM 拉取的本域 SID 表与未决请求表，
并提供线程安全的读写。键约定：SID/L_sid 用十六进制字符串，NID/PX 用整数。

``nid`` / ``ipv4`` / ``rm_ipv4`` / ``registered`` / ``set_domain_info`` 与
``ProviderState`` 同名同义，使 ``colorproxy.registration`` 的 ``register`` /
``handle_control`` 可按鸭子类型直接复用（无需改动服务端文件）。
"""
from __future__ import annotations

import ipaddress
import queue
import threading
from dataclasses import dataclass, field

from ..protocol.constants import NSID_LEN
from ..protocol.sid import lsid_from_service, lsid_from_url
from .config import ConsumerConfig


@dataclass
class PendingRequest:
    """一次浏览器请求在 CoLoR 侧的握手上下文。

    收包线程负责填充 ``pids`` / ``return_ip`` 并置 ``tunnel_event``；对响应 DATA
    则把每个分片 ``put`` 进 ``chip_queue``、末片后再 ``put(None)`` 作哨兵。发起
    请求的工作线程在隧道事件上等待，随后从 ``chip_queue`` 逐片取出**流式写回
    浏览器**（GET→隧道→ACK→逐片响应）。
    """

    tunnel_event: threading.Event = field(default_factory=threading.Event)
    pids: list[int] = field(default_factory=list)  # 隧道 DATA 带回的 PID 序列
    return_ip: str | None = None                    # 发 ACK 的下一跳 IP
    # 响应分片队列：元素为分片字节；``None`` 表末片（LAST）已到、流结束
    chip_queue: "queue.Queue[bytes | None]" = field(default_factory=queue.Queue)


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

    def lookup_by_service(self, proto: str, ip: str, port: int) -> str | None:
        """按 L3 规范服务串查完整 SID，含 §3.3 的两级回退。

        回退顺序 ``(proto,ip,port)`` → ``(proto,ip,0)``：精确服务优先，命不中再试
        该 IP 上的通配项（被动 FTP 的数据连接用临时端口，只能靠通配）。两级都不
        命中返回 None，调用方丢包并计 ``sid_miss``（§7.1 上行第 6 步）。

        SID 表只有 ``{L_sid, N_sid}``、没有明文服务地址，故消费端是**自己**按内层
        包观察到的三元组拼串算哈希再查表（§3.5 的隐私特性）。
        """
        candidates = [port] if port == 0 else [port, 0]
        # SHA1 在锁外算：哈希与共享状态无关，没必要占着锁
        lsids = [lsid_from_service(proto, ip, candidate).hex() for candidate in candidates]
        with self._lock:
            for lsid_hex in lsids:
                sid = self._sid_table.get(lsid_hex)
                if sid is not None:
                    return sid
        return None

    def sid_count(self) -> int:
        with self._lock:
            return len(self._sid_table)

    # -- §2.4 路由隔离：外层目的地址不得落进 tun 路由覆盖范围 ------------------

    def capture_route_conflicts(self) -> list[tuple[str, str]]:
        """外层目的地址里有哪些落进了 ``capture_routes``。返回 ``[(说明, 地址), ...]``。

        §2.4 的硬前提："路径一的任何外层目的地址，都不得落进路径二的 tun 路由覆盖
        范围"。一旦命中，外层 CoLoR 包会被自己的路由表吞进 tun，**链路彻底死锁**，
        而症状看着像"对端没回包"。

        配置加载时只查得了 ``rm_ipv4``（那时还不知道域内代理与 BR 的地址）；本方法
        查的是注册回复同步下来的 ``PeerProxys`` / ``PXs``，正是 §2.4 第 3 条要求的
        "启动前用实际同步下来的表再核对一遍"。最典型的命中场景是消费端与提供端被
        部署在**同一个 CoLoR 域**：此时上行 DATA 直接发往提供端代理的地址，而那个
        地址恰好被 /32 主机路由指向了 tun。
        """
        routes = self.config.l3.capture_routes
        if not routes:
            return []
        networks = [ipaddress.IPv4Network(route) for route in routes]
        with self._lock:
            candidates = [("本域 RM", self.rm_ipv4)]
            candidates += [(f"域内代理 NID={nid:032x}", ip)
                           for nid, ip in self._peer_proxys.items()]
            candidates += [(f"边界路由器 PX={px}", ip) for px, ip in self._pxs.items()]
        conflicts = []
        for label, ip in candidates:
            try:
                address = ipaddress.IPv4Address(ip)
            except ValueError:
                continue
            if any(address in network for network in networks):
                conflicts.append((label, ip))
        return conflicts

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
