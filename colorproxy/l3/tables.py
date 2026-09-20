"""L3 隧道表、首包队列与流缓存（docs/design-l3-v2.md §5 / §7 / §10.1）。

三张表的关键性质：

- **提供端的 ``L3TunnelTable``** 由握手（GET）写入，长期有效（D1），**数据面不写**。
  rev.2 的 ``PeerTun`` 数据面学习已删除，消费端身份来自静态 ``peers[]``（D14，§7.3）。
- **消费端的 ``ConsumerTunnelTable``** 以 SID 为单位，不以流为单位：同一 ``(proto,ip,port)``
  的所有连接共用一条隧道，内层 IP/TCP 头天然完成解复用（§5.1）。
- **``FlowCache``** 纯性能措施：否则每个包都要拼串 + SHA1 + 查表（§7.1 上行第 5 步）。
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

#: 流缓存里表示"查过、确实没有"的哨兵。与"没查过"区分开，避免对同一个未命中的
#: 端点反复算 SHA1——路由配宽了的时候这种包会很多。
MISS = "\x00MISS"


@dataclass
class L3Tunnel:
    """提供端侧的一条隧道（握手时记下，此后长期有效，D1）。"""

    sid: str
    consumer_nid: int
    return_ip: str           # 回送 DATA 的下一跳
    pids: list[int]          # GET 累积的 PID 序列，回送时原样使用
    seg_id: int              # GET 的 SegID，原样回带
    random_num: bytes | None  # GET 携带的 4 字节 nonce，作回送 DATA 的 HMAC 种子
    created_at: float = field(default_factory=time.monotonic)


@dataclass
class ConsumerTunnel:
    """消费端侧的一条隧道。"""

    sid: str
    rev_pids: list[int]      # 发上行 DATA 用的反向路径
    provider_nid: int
    next_hop_ip: str
    seg_id: int
    created_at: float = field(default_factory=time.monotonic)


class L3TunnelTable:
    """提供端隧道表，键 ``(sid, consumer_nid)``。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._tunnels: dict[tuple[str, int], L3Tunnel] = {}

    def put(self, tunnel: L3Tunnel) -> bool:
        """登记/刷新一条隧道。返回 True 表示新建（用于 ``tunnel_up`` 计数）。

        同键重复的 GET 是幂等的：重发隧道 DATA、覆盖回址与 PID，不新建。GET 可能
        因隧道 DATA 丢失而重发，此时新的 PID 路径才是有效的那条。
        """
        key = (tunnel.sid, tunnel.consumer_nid)
        with self._lock:
            is_new = key not in self._tunnels
            self._tunnels[key] = tunnel
            return is_new

    def get(self, sid: str, consumer_nid: int) -> L3Tunnel | None:
        with self._lock:
            return self._tunnels.get((sid, consumer_nid))

    def count(self) -> int:
        with self._lock:
            return len(self._tunnels)


class ConsumerTunnelTable:
    """消费端隧道表 + 首包队列 + 握手超时（§5.2）。

    每条 SID 三种状态：未建立 / 握手中 / 已建立。首包在握手中入队，隧道建好后按序
    冲刷；握手超时则**丢队列并记日志**——不实现这一条的话首包会永久滞留（§5.2）。
    """

    def __init__(
        self,
        queue_pkts: int = 4,
        queue_bytes: int = 8192,
        handshake_timeout: float = 5.0,
    ) -> None:
        self._lock = threading.Lock()
        self._tunnels: dict[str, ConsumerTunnel] = {}
        self._pending_since: dict[str, float] = {}
        self._queues: dict[str, list[bytes]] = {}
        self._queue_pkts = queue_pkts
        self._queue_bytes = queue_bytes
        self._handshake_timeout = handshake_timeout

    def get(self, sid: str) -> ConsumerTunnel | None:
        with self._lock:
            return self._tunnels.get(sid)

    def is_pending(self, sid: str) -> bool:
        with self._lock:
            return sid in self._pending_since

    def begin_handshake(self, sid: str, now: float | None = None) -> bool:
        """把 SID 置为"握手中"。返回 True 表示**本次调用应当发 GET**。

        已建立或已在握手中时返回 False，避免同一条 SID 上每个包都发一次 GET
        （客户端 SYN 重传时很容易撞上）。
        """
        with self._lock:
            if sid in self._tunnels or sid in self._pending_since:
                return False
            self._pending_since[sid] = now if now is not None else time.monotonic()
            self._queues.setdefault(sid, [])
            return True

    def queue_first_packet(self, sid: str, packet: bytes) -> int:
        """把首包入队，返回因超限被丢弃的包数（0 表示没丢）。

        上限是"每条 SID 4 个包或 8 KB"，先到先出、超限丢**最老**的：新的包更可能是
        客户端的重传，比陈旧的首包有用。
        """
        dropped = 0
        with self._lock:
            pending = self._queues.setdefault(sid, [])
            pending.append(bytes(packet))
            while len(pending) > self._queue_pkts or sum(map(len, pending)) > self._queue_bytes:
                if len(pending) == 1:
                    # 单个包就超过字节上限：留着它，否则这条 SID 永远发不出第一个包
                    break
                pending.pop(0)
                dropped += 1
        return dropped

    def establish(
        self, sid: str, rev_pids: list[int], provider_nid: int, next_hop_ip: str, seg_id: int
    ) -> tuple[ConsumerTunnel, list[bytes]]:
        """隧道建立：登记并返回 ``(隧道, 待冲刷的首包)``（按入队序）。"""
        tunnel = ConsumerTunnel(
            sid=sid, rev_pids=list(rev_pids), provider_nid=provider_nid,
            next_hop_ip=next_hop_ip, seg_id=seg_id,
        )
        with self._lock:
            self._tunnels[sid] = tunnel
            self._pending_since.pop(sid, None)
            queued = self._queues.pop(sid, [])
        return tunnel, queued

    def expire_handshakes(self, now: float | None = None) -> list[tuple[str, int]]:
        """回收超时的握手，返回 ``[(sid, 丢弃的首包数), ...]``。

        超时后把 SID 退回"未建立"：下一个包会重新触发 GET（§5.2）。
        """
        moment = now if now is not None else time.monotonic()
        expired: list[tuple[str, int]] = []
        with self._lock:
            for sid, since in list(self._pending_since.items()):
                if moment - since < self._handshake_timeout:
                    continue
                del self._pending_since[sid]
                expired.append((sid, len(self._queues.pop(sid, []))))
        return expired

    def count(self) -> int:
        with self._lock:
            return len(self._tunnels)


class FlowCache:
    """``(proto, ip, port) → SID | MISS`` 的有界缓存（§7.1 上行第 5 步）。

    容量到顶时整体清空而不是做 LRU：实现简单，且 L3 的端点集合本来很小（发布几条
    服务就几个键），会涨到上限的只有"路由配宽了、大量端点未命中"这种本就该修配置
    的情况。
    """

    def __init__(self, capacity: int = 4096) -> None:
        self._lock = threading.Lock()
        self._entries: dict[tuple[str, str, int], str] = {}
        self._capacity = capacity

    def get(self, key: tuple[str, str, int]) -> str | None:
        with self._lock:
            return self._entries.get(key)

    def put(self, key: tuple[str, str, int], sid: str) -> None:
        with self._lock:
            if len(self._entries) >= self._capacity:
                self._entries.clear()
            self._entries[key] = sid

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)
