"""L3 下的 HTTP 内容级准入（docs/design-l3-v2.md §8.7，D20）。

L3 隧道按 ``(proto, ip, port)`` 发布 SID，RM 的 ACL 因而只能对整个端口放行或拒绝。D20 在
**不终结 TCP** 的前提下把 HTTP 收窄到逐 URL：

1. 连接照旧由服务级 SID 承载（SYN 走 D19 的新连接准入）；
2. 每个请求的字节先**扣住**；请求行一收全就拼出 ``http://<ip>:<port><path>``，查 SID 表，
   为这条 URL SID 向 RM 发一个 GET；
3. 隧道 DATA 回来了（RM 的 ACL 放行、提供端认这条 URL）→ 放行扣住的字节，仍走服务级隧道；
   SID 表里没有这个 URL → 立刻 RST；``tunnel_timeout_sec`` 内没回 → RST。

**放行界限 H**：流内偏移 H 之前的字节都属于已准入的请求，可以放；H 是最早一个"未准入、或
请求行还没收全"的请求的起始偏移。段 ``[s, e)`` 的载荷全在 H 之前就转发，否则扣留；每次准入
或解析推进后重算 H、按顺序放出够格的扣留段。纯 ACK 不带请求字节，一律直接转发——扣住它会
耽误下行数据的确认。只带 FIN 的段排在扣留队列末尾，前面放完了它才走。

**判断不了就 RST（fail-closed）**：解析失败、URL 未发布、准入超时都复位连接。RST 给两端各发
一个：给客户端的写回 tun，给源站的经服务级隧道送过去；之后这条连接残余的上行一律丢弃。

线程：tun 读线程送新段，收包线程送准入回复，ticker 做超时。三者都可能放包，故**判定与发包
都在同一把锁里**，保证放出去的顺序就是流内顺序。

与应用层无关的部分（TCP 字段、序号运算、RST 构造）在 ``tun/tcp.py``，HTTP 解析在
``l7/http.py``，本模块只做策略与粘合。
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable

from ..consumer.config import AppService
from ..l7.http import HttpParseError, HttpRequestStream, RequestLine
from ..protocol.constants import NSID_LEN
from ..protocol.sid import content_url
from ..tun import ipv4
from ..tun.tcp import (
    TCP_FLAG_ACK,
    TCP_FLAG_RST,
    TCP_FLAG_SYN,
    build_rst,
    parse_tcp,
    seq_add,
    seq_diff,
    strip_payload,
)
from .counters import Counters

logger = logging.getLogger(__name__)

#: 每条连接最多扣留多少段 / 多少字节。等准入的这一个往返里，客户端最多发出一个初始拥塞
#: 窗口（约 10 段）外加重传，32 段 / 64 KB 足够；超出的段丢掉，客户端会重传。
HOLD_MAX_SEGMENTS = 32
HOLD_MAX_BYTES = 64 * 1024
#: 连接空闲多久后不再跟踪。要比常见的 keep-alive 超时长；就算清早了，下一个请求进来时会
#: 按"中途接手"重新开始解析，不会误伤。
CONN_IDLE_SEC = 600.0
#: 连接被 RST 后，残余上行包继续丢弃多久
RESET_LINGER_SEC = 30.0
#: 准入回复到达后这条 URL SID 仍被认领多久（吞掉迟到的重复隧道 DATA，免得落到 v1 刷 warning）
RECENT_ADMIT_SEC = 30.0
#: 同时跟踪的连接数上限
MAX_CONNS = 4096

_INF = float("inf")

#: 连接键：``(客户端地址, 客户端端口, 服务端地址, 服务端端口)``，地址为 4 字节原始形式
ConnKey = tuple[bytes, int, bytes, int]


@dataclass
class _Request:
    start: int                # 请求在流中的起始偏移
    url: str
    sid: str
    admitted: bool = False


@dataclass
class _Held:
    start: int                # 段首在流中的偏移
    data_end: int             # 载荷末尾的偏移（只带 FIN 时等于 start）
    seq_end: int              # 占用序号空间的末尾（含 FIN）
    packet: bytes

    @property
    def fin_only(self) -> bool:
        return self.data_end == self.start


@dataclass
class _Conn:
    key: ConnKey
    port_sid: str
    endpoint: tuple[str, str, int]
    base_seq: int             # 流内偏移 0 对应的 TCP 序号
    last_seen: float
    parser: HttpRequestStream = field(default_factory=HttpRequestStream)
    requests: list[_Request] = field(default_factory=list)
    held: list[_Held] = field(default_factory=list)
    held_bytes: int = 0
    fwd_end: int = 0          # 已转发到的序号空间末尾（偏移），= 源站的 RCV.NXT
    seen_end: int = 0         # 客户端发到的序号空间末尾（偏移），= 客户端的 SND.NXT
    last_ack: int | None = None  # 客户端最近一次确认的序号，= 客户端的 RCV.NXT
    reset_at: float | None = None


@dataclass
class _Admission:
    since: float
    url: str
    waiters: list[tuple[_Conn, _Request]] = field(default_factory=list)


class HttpContentGate:
    """受管 HTTP 端点的内容级准入门（D20）。

    ``forward(port_sid, packet, endpoint, is_new)`` 把一个上行包交回 L3 数据面原有的转发
    路径（含 D19）；``send_get(sid)`` 发准入 GET；``write_tun(packet)`` 把 RST 写回本机。
    """

    def __init__(
        self,
        services: Iterable[AppService],
        *,
        lookup_url: Callable[[str], str | None],
        send_get: Callable[[str], object],
        forward: Callable[[str, bytes, tuple[str, str, int], bool], object],
        write_tun: Callable[[bytes], None],
        counters: Counters,
        admit_timeout: float,
    ) -> None:
        self._endpoints = {service.endpoint for service in services if service.app == "http"}
        self._lookup_url = lookup_url
        self._send_get = send_get
        self._forward = forward
        self._write_tun = write_tun
        self.counters = counters
        self._admit_timeout = admit_timeout
        # 可重入：生产环境里准入回复来自收包线程，不会重入；但同步投递的链路（测试里的假链路）
        # 会在发 GET 的同一个调用栈里把回复送回来，普通锁会就地死锁
        self._lock = threading.RLock()
        self._conns: dict[ConnKey, _Conn] = {}
        self._admissions: dict[str, _Admission] = {}
        self._recent: dict[str, float] = {}

    # ------------------------------------------------------------ 上行（tun 读线程）

    def watches(self, endpoint: tuple[str, str, int]) -> bool:
        """这个目的端点是否受内容级准入管控。"""
        return endpoint in self._endpoints

    def on_upstream(self, packet: bytes, header: ipv4.Ipv4Header,
                    endpoint: tuple[str, str, int], port_sid: str, is_new: bool) -> bool:
        """处理一个发往受管端点的上行包：转发、扣留或丢弃。返回 False 表示丢弃。"""
        segment = parse_tcp(packet, header)
        if segment is None:
            # TCP 头残缺：里面不可能有完整的请求，交给原路径（提供端会丢掉它）
            self._forward(port_sid, packet, endpoint, is_new)
            return True
        key = (header.src, segment.sport, header.dst, segment.dport)
        now = time.monotonic()
        with self._lock:
            conn = self._conns.get(key)
            if segment.flags & (TCP_FLAG_SYN | TCP_FLAG_ACK) == TCP_FLAG_SYN:
                self._track(_Conn(key, port_sid, endpoint, seq_add(segment.seq, 1), now))
                if segment.payload_len:
                    # TCP Fast Open：SYN 里的数据会绕过请求解析，只放 SYN 本身。源站只确认
                    # SYN，客户端按普通数据重发这些字节，届时照常过准入
                    logger.debug("SYN 携带 %d 字节数据（TFO），已剥掉：%s",
                                 segment.payload_len, ipv4.format_ipv4(header.dst))
                    packet = strip_payload(packet, header, segment)
                self._forward(port_sid, packet, endpoint, is_new)
                return True
            if conn is not None and conn.reset_at is not None:
                return False  # 已复位：残余上行一律丢
            if segment.flags & TCP_FLAG_RST:
                self._conns.pop(key, None)
                self._forward(port_sid, packet, endpoint, is_new)
                return True
            if conn is None:
                if segment.is_pure_ack:
                    self._forward(port_sid, packet, endpoint, is_new)
                    return True
                # 中途接手（没见过 SYN，或空闲清理过）：从这一段起解析，是不是 HTTP 交给解析器判断
                conn = self._track(_Conn(key, port_sid, endpoint, segment.seq, now))
            return self._on_segment(conn, packet, segment, now)

    def _on_segment(self, conn: _Conn, packet: bytes, segment, now: float) -> bool:
        conn.last_seen = now
        if segment.flags & TCP_FLAG_ACK:
            conn.last_ack = segment.ack
        if segment.is_pure_ack:
            self._forward(conn.port_sid, packet, conn.endpoint, False)
            return True

        start = seq_diff(segment.seq, conn.base_seq)
        data_end = start + segment.payload_len
        seq_end = start + segment.seq_len
        if start > conn.parser.offset:
            self.counters.bump("http_ooo_drop")
            return False
        conn.seen_end = max(conn.seen_end, seq_end)

        if data_end > conn.parser.offset:
            skip = conn.parser.offset - start   # 与已解析部分重叠的前缀（重传/合并重传）
            fresh = packet[segment.payload_offset + skip:segment.payload_offset + segment.payload_len]
            try:
                events = conn.parser.feed(fresh)
            except HttpParseError as exc:
                self.counters.bump("http_parse_rst")
                logger.warning("受管 HTTP 连接上的数据无法按 HTTP/1.x 解析，RST：%s（%s）",
                               _describe(conn), exc)
                self._reset(conn, now)
                return False
            for event in events:
                self._on_request(conn, event, now)
                if conn.reset_at is not None:
                    return False
            # 解析推进也可能抬高 H（例如请求间被忽略的空行收全了），先放掉够格的扣留段
            self._release(conn)

        if self._releasable(conn, start, data_end, self._horizon(conn), front=not conn.held):
            self._send(conn, packet, seq_end)
            return True
        return self._hold(conn, _Held(start, data_end, seq_end, bytes(packet)))

    def _on_request(self, conn: _Conn, event: RequestLine, now: float) -> None:
        """一个请求行收全了：查 URL SID，发准入 GET（同一 URL 并发的请求共用一个）。"""
        self.counters.bump("http_req")
        _proto, ip, port = conn.endpoint
        url = content_url(ip, port, event.target)
        sid = self._lookup_url(url)
        if sid is None:
            self.counters.bump("http_url_miss")
            logger.info("URL 未发布到共生网络（SID 表里没有），RST：%s %s", event.method, url)
            self._reset(conn, now)
            return
        if sid[:NSID_LEN * 2] != conn.port_sid[:NSID_LEN * 2]:
            self.counters.bump("http_url_miss")
            logger.warning("URL %s 的提供方(N_sid=%s…)与承载连接的服务级 SID 不是同一个，RST",
                           url, sid[:16])
            self._reset(conn, now)
            return
        request = _Request(event.start, url, sid)
        conn.requests.append(request)
        admission = self._admissions.get(sid)
        if admission is not None:
            admission.waiters.append((conn, request))   # 单飞：同一 URL 已有 GET 在途
            return
        # 先登记再发：回复若在同一调用栈里就到了（同步链路），也能找到等它的请求
        self._admissions[sid] = _Admission(since=now, url=url, waiters=[(conn, request)])
        self._send_get(sid)
        self.counters.bump("http_admit_get")
        logger.debug("内容级准入，已发 GET：%s %s SID=%s…", event.method, url, sid[:16])

    # ------------------------------------------------------------ 准入回复（收包线程）

    def claims(self, sid: str) -> bool:
        """这条 SID 是不是本门在等（或刚等到）的 URL SID。是的话 DATA 归本门处理。"""
        with self._lock:
            return sid in self._admissions or sid in self._recent

    def on_admission_reply(self, sid: str) -> None:
        """URL SID 的隧道 DATA 到了：RM 放行了。把等它的请求标为已准入并放包。"""
        now = time.monotonic()
        with self._lock:
            self._recent[sid] = now
            admission = self._admissions.pop(sid, None)
            if admission is None:
                return  # 迟到的重复回复
            for conn, request in admission.waiters:
                if not self._alive(conn):
                    continue
                request.admitted = True
                self.counters.bump("http_admit_ok")
                self._release(conn)

    # ------------------------------------------------------------ 周期任务（ticker）

    def tick(self, now: float | None = None) -> None:
        """准入超时 → RST；清理空闲连接与过期的认领记录。由 ticker 周期调用。"""
        moment = now if now is not None else time.monotonic()
        with self._lock:
            for sid, admission in list(self._admissions.items()):
                if moment - admission.since < self._admit_timeout:
                    continue
                del self._admissions[sid]
                victims = [conn for conn, _request in admission.waiters if self._alive(conn)]
                for conn in victims:
                    self.counters.bump("http_admit_timeout")
                    self._reset(conn, moment)
                if victims:
                    logger.warning(
                        "内容级准入超时(%.1fs)：%s 提供端没回隧道 DATA（RM 的 ACL 拒绝了本消费端"
                        "访问这个 URL，或 GET 丢了），已 RST %d 条连接",
                        self._admit_timeout, admission.url, len(victims),
                    )
            for sid, at in list(self._recent.items()):
                if moment - at > RECENT_ADMIT_SEC:
                    del self._recent[sid]
            for key, conn in list(self._conns.items()):
                if conn.reset_at is not None:
                    if moment - conn.reset_at > RESET_LINGER_SEC:
                        del self._conns[key]
                elif moment - conn.last_seen > CONN_IDLE_SEC:
                    del self._conns[key]

    def conn_count(self) -> int:
        with self._lock:
            return len(self._conns)

    # ------------------------------------------------------------ 内部（均在锁内调用）

    def _track(self, conn: _Conn) -> _Conn:
        if conn.key not in self._conns and len(self._conns) >= MAX_CONNS:
            oldest = min(self._conns.values(), key=lambda c: c.last_seen)
            del self._conns[oldest.key]
        self._conns[conn.key] = conn
        return conn

    def _alive(self, conn: _Conn) -> bool:
        return conn.reset_at is None and self._conns.get(conn.key) is conn

    @staticmethod
    def _horizon(conn: _Conn) -> float:
        """放行界限 H：最早一个"未准入或请求行未收全"的请求起点；都没有则为 ∞。"""
        while len(conn.requests) > 1 and conn.requests[0].admitted:
            conn.requests.pop(0)  # 已准入的旧请求只需留最后一个，防止长连接上越积越多
        horizon = _INF
        for request in conn.requests:
            if not request.admitted:
                horizon = request.start
                break
        pending = conn.parser.pending_start
        return horizon if pending is None else min(horizon, pending)

    @staticmethod
    def _releasable(conn: _Conn, start: int, data_end: int, horizon: float, *, front: bool) -> bool:
        if data_end == start:
            return front           # 只带 FIN：前面没有扣着的才走，不能越过请求数据
        return data_end <= horizon

    def _hold(self, conn: _Conn, held: _Held) -> bool:
        if any(item.start == held.start and item.seq_end >= held.seq_end for item in conn.held):
            return True            # 扣着的段的重传：已有原件，丢掉重复的
        if len(conn.held) >= HOLD_MAX_SEGMENTS or conn.held_bytes + len(held.packet) > HOLD_MAX_BYTES:
            self.counters.bump("http_hold_drop")
            return False           # 客户端会重传
        conn.held.append(held)
        conn.held.sort(key=lambda item: (item.start, item.fin_only))
        conn.held_bytes += len(held.packet)
        return True

    def _release(self, conn: _Conn) -> None:
        horizon = self._horizon(conn)
        while conn.held:
            head = conn.held[0]
            if not self._releasable(conn, head.start, head.data_end, horizon, front=True):
                break
            conn.held.pop(0)
            conn.held_bytes -= len(head.packet)
            self._send(conn, head.packet, head.seq_end)

    def _send(self, conn: _Conn, packet: bytes, seq_end: int) -> None:
        conn.fwd_end = max(conn.fwd_end, seq_end)
        self._forward(conn.port_sid, packet, conn.endpoint, False)

    def _reset(self, conn: _Conn, now: float) -> None:
        """向两端各发一个 RST，丢掉扣着的段，此后这条连接的上行一律丢弃。"""
        conn.reset_at = now
        client_ip, client_port, server_ip, server_port = conn.key
        if conn.last_ack is not None:
            # 给客户端：seq 必须恰好是它的 RCV.NXT（= 它最近确认到的序号），否则只换来挑战 ACK
            self._write_tun(build_rst(
                server_ip, client_ip, server_port, client_port, conn.last_ack,
                seq_add(conn.base_seq, conn.seen_end), with_ack=True,
            ))
        # 给源站：seq = 它的 RCV.NXT = 我们转发到的位置
        self._forward(conn.port_sid, build_rst(
            client_ip, server_ip, client_port, server_port, seq_add(conn.base_seq, conn.fwd_end),
        ), conn.endpoint, False)
        conn.held.clear()
        conn.held_bytes = 0


def _describe(conn: _Conn) -> str:
    client_ip, client_port, server_ip, server_port = conn.key
    return (f"{ipv4.format_ipv4(client_ip)}:{client_port} → "
            f"{ipv4.format_ipv4(server_ip)}:{server_port}")
