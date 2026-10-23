"""被动 FTP 的数据连接跟随控制连接（D21，docs/design-l3-v2.md §8.8）。仅提供端。

以前被动 FTP 只能靠通配 ``tcp://ip:0`` 发布，持有这条 SID 的消费端能打到该 IP 的任意端口
（§8.3）。D21 改成防火墙里 FTP ALG 的做法：

1. 读控制连接：客户端发了 ``PASV``/``EPSV``，源站回了 227/229 → 登记一条**期望**
   ``(消费端 NID, 服务地址, 端口 p)``。**在这条回复发出之前登记**，客户端的 SYN 不可能先到；
2. 数据连接的包**带着控制连接的 SID** 从同一条隧道上来：目的端口不是控制端口，就查期望——
   第一个 SYN 把期望兑现成一条按四元组跟踪的**数据连接**，此后的包按四元组放行；
3. 回程：源站从端口 p 发出的包先查数据连接表，命中就用控制 SID 送回。

数据连接走控制 SID 还有一个好处：长下载期间控制连接一声不吭，若各走各的 SID，控制 SID 在
BR 的 ODC 表项会在 800 s 空闲后过期，最后那条 ``226`` 会被丢掉；共用一条 SID 时数据下行
一直在刷新它。

**安全上的取舍**（与 D14「数据面不写表」的关系）：期望表由**本机源站的回复**写入，不是由
上行学来的；键里的消费端身份来自静态 ``peers[]``（回复的内层目的地址）。消费端只能兑现
发给自己的期望，并且在兑现之前先过来源校验。此外：

- 只认紧跟在本连接 ``PASV``/``EPSV`` 之后的那条 227/229（命令与回复按序配对）；
- **不用 227 里的地址**，一律登记在控制连接的服务地址上（curl/ftplib 本来也忽略它）；
- 端口低于 1024、等于控制端口、或是同一地址上另一条已发布服务的端口，一律拒绝——否则能借
  FTP 的 ACL 打到 3306，绕过 MySQL 那条 SID 自己的 ACL。

字节流只做旁路观察（不扣包）：重传部分跳过；序号空洞或中途接手时让解析器重新对齐，对齐
之前不登记期望。看漏的代价只是这次数据连接被拒，客户端会报错重试。

线程：注入方向在 CoLoR 收包线程，回程在 tun 读线程，``tick`` 在 ticker 线程，共用一把锁。
"""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field

from ..config import L3ServiceConfig
from ..l7.ftp import FtpCommandStream, FtpReplyStream, parse_227, parse_229
from ..tun import ipv4
from ..tun.tcp import (
    TCP_FLAG_ACK,
    TCP_FLAG_FIN,
    TCP_FLAG_RST,
    TCP_FLAG_SYN,
    TcpSegment,
    parse_tcp,
    seq_add,
    seq_diff,
)
from .counters import Counters

logger = logging.getLogger(__name__)

#: 期望等 SYN 的时长。客户端拿到 227/229 后立刻就连；pyftpdlib 的被动监听自己也只等 30 s
EXPECT_TTL_SEC = 30.0
#: 数据连接空闲多久清掉。要比源站自己的数据连接超时长（pyftpdlib 默认 300 s）
DATA_IDLE_SEC = 600.0
#: 控制连接空闲多久不再跟踪（清早了只是下次中途接手、重新对齐）
CONTROL_IDLE_SEC = 900.0
#: 看到 RST 或两个方向都 FIN 之后再保留多久：收尾的 ACK、重传还要能过去
CLOSE_LINGER_SEC = 60.0
#: 允许登记的最小端口：1024 以下是特权端口，被动数据端口不会落在那里
MIN_DATA_PORT = 1024
#: 每条控制连接最多记多少条还没等到回复的命令（防客户端灌命令把内存撑大）
MAX_PENDING_COMMANDS = 16
#: 各表的条目上限
MAX_CONTROLS = 1024
MAX_EXPECTS = 4096
MAX_DATA_CONNS = 4096

#: 连接键：``(客户端地址, 客户端端口, 服务端地址, 服务端端口)``，地址为 4 字节原始形式
ConnKey = tuple[bytes, int, bytes, int]
#: 期望键：``(消费端 NID, 服务地址, 数据端口)``
ExpectKey = tuple[int, str, int]

#: 回复代码 → 它能回答的命令
_PASSIVE_REPLIES = {227: "PASV", 229: "EPSV"}


class _Tap:
    """把一个方向的 TCP 段还原成按序的新字节，喂给解析器。"""

    def __init__(self, parser: FtpCommandStream | FtpReplyStream, *, from_start: bool) -> None:
        self.parser = parser
        self.next_seq: int | None = None
        if not from_start:
            parser.resync()   # 没见到 SYN：不知道从流的哪里开始的

    def feed(self, packet: bytes, segment: TcpSegment) -> tuple[list, bool]:
        """返回 ``(解析结果, 这次是否失去了同步)``。"""
        data_seq = seq_add(segment.seq, 1) if segment.flags & TCP_FLAG_SYN else segment.seq
        if segment.flags & TCP_FLAG_SYN:
            self.next_seq = data_seq
        if segment.payload_len == 0:
            return [], False
        lost = False
        if self.next_seq is None:
            self.next_seq = data_seq
        skip = seq_diff(self.next_seq, data_seq)   # 本段开头已经看过的字节数
        if skip < 0:
            # 序号空洞：中间有字节没看到。跳过它们，从这一段重新对齐
            self.parser.resync()
            self.next_seq = data_seq
            skip = 0
            lost = True
        if skip >= segment.payload_len:
            return [], lost                          # 纯重传
        start = segment.payload_offset + skip
        self.next_seq = seq_add(data_seq, segment.payload_len)
        return self.parser.feed(packet[start:segment.payload_offset + segment.payload_len]), lost


@dataclass
class _Control:
    """一条被观察的控制连接。"""

    sid: str
    service: L3ServiceConfig
    consumer_nid: int
    client: _Tap
    server: _Tap
    last_seen: float
    pending: deque = field(default_factory=lambda: deque(maxlen=MAX_PENDING_COMMANDS))
    closed_at: float | None = None
    fin_client: bool = False
    fin_server: bool = False


@dataclass
class _Expect:
    sid: str
    since: float


@dataclass
class _DataConn:
    sid: str                  # 所属控制连接的 SID：数据连接的包都带着它
    last_seen: float
    closed_at: float | None = None
    fin_client: bool = False
    fin_server: bool = False


def wildcard_conflicts(services: tuple[L3ServiceConfig, ...] | list[L3ServiceConfig]) -> list[str]:
    """同一地址上既有 ``app:"ftp"`` 又发布了通配 ``:0`` 的地址（启动时告警用）。

    消费端查表是「精确 → 通配 → FTP 回退」，通配在前：数据连接会改走通配 SID，被整机放行，
    D21 的收窄就形同虚设。
    """
    ftp_ips = {svc.ip for svc in services if svc.app == "ftp"}
    return sorted({svc.ip for svc in services
                   if svc.proto == "tcp" and svc.is_wildcard_port and svc.ip in ftp_ips})


class FtpDataHelper:
    """提供端的被动 FTP 跟踪（D21）。只有配了 ``app:"ftp"`` 的端点时才构造。"""

    def __init__(self, services: tuple[L3ServiceConfig, ...] | list[L3ServiceConfig],
                 counters: Counters) -> None:
        self.counters = counters
        # 同一地址上已发布的精确端口：数据端口撞上它们就拒绝（第 3 条安全规则）
        self._published_ports: dict[tuple[str, str], set[int]] = {}
        for svc in services:
            if not svc.is_wildcard_port:
                self._published_ports.setdefault((svc.proto, svc.ip), set()).add(svc.port)
        self._lock = threading.Lock()
        self._controls: dict[ConnKey, _Control] = {}
        self._expects: dict[ExpectKey, _Expect] = {}
        self._data: dict[ConnKey, _DataConn] = {}
        self._warned_ip_mismatch = False
        for ip in wildcard_conflicts(services):
            logger.warning(
                "%s 上同时发布了 app=ftp 与通配 tcp://%s:0：消费端会优先命中通配，被动数据连接"
                "改走通配 SID、被整机放行，D21 的端口收窄不起作用。去掉 :0 那一条（§8.8）", ip, ip)

    # ------------------------------------------------ 控制连接（两个方向）

    def on_client_packet(self, inner: bytes, header: ipv4.Ipv4Header, sid: str,
                         service: L3ServiceConfig, consumer_nid: int) -> None:
        """控制连接的上行包（已过准入）：记下客户端发了哪些命令。"""
        segment = parse_tcp(inner, header)
        if segment is None:
            return
        key = (header.src, segment.sport, header.dst, segment.dport)
        now = time.monotonic()
        with self._lock:
            control = self._control_for(key, segment, sid, service, consumer_nid, now)
            if control is None:
                return
            verbs, lost = control.client.feed(inner, segment)
            if lost:
                # 看漏了命令：回复与命令的配对已经不可信，清空等下一轮
                control.pending.clear()
                self.counters.bump("ftp_resync")
            control.pending.extend(verbs)
            self._note_flags(control, segment, from_client=True, now=now)

    def on_server_packet(self, inner: bytes, header: ipv4.Ipv4Header, sid: str,
                         service: L3ServiceConfig, consumer_nid: int) -> None:
        """控制连接的回程包，**发出之前**调用：读到 227/229 就登记期望。"""
        segment = parse_tcp(inner, header)
        if segment is None:
            return
        key = (header.dst, segment.dport, header.src, segment.sport)
        now = time.monotonic()
        with self._lock:
            control = self._control_for(key, segment, sid, service, consumer_nid, now)
            if control is None:
                return
            replies, lost = control.server.feed(inner, segment)
            if lost:
                control.pending.clear()
                self.counters.bump("ftp_resync")
            for reply in replies:
                if not reply.trusted:
                    # 失步后用来对齐的那条：内容不能用，也不知道它答的是哪条命令。按 FTP
                    # 一问一答的常态，此刻已无未答命令，清空，免得此后的配对都错开一位
                    control.pending.clear()
                    continue
                if reply.code < 200:
                    continue   # 1xx 是中间回复，命令还没答完
                verb = control.pending.popleft() if control.pending else None
                expected_verb = _PASSIVE_REPLIES.get(reply.code)
                if expected_verb is not None and verb == expected_verb:
                    self._register(control, reply.code, reply.text, now)
            self._note_flags(control, segment, from_client=False, now=now)

    def _control_for(self, key: ConnKey, segment: TcpSegment, sid: str,
                     service: L3ServiceConfig, consumer_nid: int, now: float) -> _Control | None:
        control = self._controls.get(key)
        is_syn = bool(segment.flags & TCP_FLAG_SYN)
        if control is not None and is_syn and not segment.flags & TCP_FLAG_ACK \
                and control.closed_at is not None:
            control = None   # 同一四元组上的新连接：旧的状态作废
        if control is None:
            if segment.flags & TCP_FLAG_RST:
                return None
            if len(self._controls) >= MAX_CONTROLS:
                oldest = min(self._controls, key=lambda k: self._controls[k].last_seen)
                del self._controls[oldest]
            # 客户端 SYN（没有 ACK）才算从头看起；其余一律视为中途接手
            from_start = is_syn and not segment.flags & TCP_FLAG_ACK
            control = _Control(
                sid=sid, service=service, consumer_nid=consumer_nid,
                client=_Tap(FtpCommandStream(), from_start=from_start),
                server=_Tap(FtpReplyStream(), from_start=from_start),
                last_seen=now,
            )
            self._controls[key] = control
            if not from_start:
                self.counters.bump("ftp_resync")
        control.last_seen = now
        return control

    def _register(self, control: _Control, code: int, text: str, now: float) -> None:
        if code == 227:
            parsed = parse_227(text)
            port = parsed[1] if parsed is not None else None
            if parsed is not None and parsed[0] != control.service.ip and not self._warned_ip_mismatch:
                self._warned_ip_mismatch = True
                logger.warning(
                    "227 通告的地址 %s 不是服务地址 %s，按服务地址登记（客户端也应忽略它；"
                    "若客户端照 227 的地址去连会连不上，别设 --masquerade）",
                    parsed[0], control.service.ip)
        else:
            port = parse_229(text)
        if port is None:
            logger.warning("%d 回复里读不出端口，忽略：%r", code, text[:80])
            return
        service = control.service
        reason = self._reject_reason(service, port)
        if reason is not None:
            self.counters.bump("ftp_expect_reject")
            logger.warning("拒绝登记 FTP 数据端口 %s:%d（%s）：消费端=%032x",
                           service.ip, port, reason, control.consumer_nid)
            return
        key = (control.consumer_nid, service.ip, port)
        if key not in self._expects and len(self._expects) >= MAX_EXPECTS:
            oldest = min(self._expects, key=lambda k: self._expects[k].since)
            del self._expects[oldest]
        self._expects[key] = _Expect(sid=control.sid, since=now)
        self.counters.bump("ftp_expect")
        logger.debug("FTP 期望已登记：%s:%d 消费端=%032x（%d）",
                     service.ip, port, control.consumer_nid, code)

    def _reject_reason(self, service: L3ServiceConfig, port: int) -> str | None:
        if port < MIN_DATA_PORT:
            return f"低于 {MIN_DATA_PORT}"
        if port == service.port:
            return "就是控制端口本身"
        if port in self._published_ports.get((service.proto, service.ip), ()):
            return "是同一地址上另一条已发布的服务，放行它会绕过那条 SID 自己的 ACL"
        return None

    # ------------------------------------------------ 数据连接

    def admit_data(self, inner: bytes, header: ipv4.Ipv4Header, sid: str,
                   consumer_nid: int) -> bool:
        """带着控制 SID、目的端口不是控制端口的上行包：是不是一条已登记的数据连接。

        调用方已经做过来源校验（期望是一次性的，不能让伪造源地址的包把它兑现掉）。
        """
        segment = parse_tcp(inner, header)
        if segment is None:
            return False
        key = (header.src, segment.sport, header.dst, segment.dport)
        now = time.monotonic()
        with self._lock:
            conn = self._data.get(key)
            if conn is not None and conn.sid == sid:
                self._note_flags(conn, segment, from_client=True, now=now)
                return True
            if not segment.flags & TCP_FLAG_SYN or segment.flags & TCP_FLAG_ACK:
                return False
            expect_key = (consumer_nid, ipv4.format_ipv4(header.dst), segment.dport)
            expect = self._expects.get(expect_key)
            if expect is None or expect.sid != sid or now - expect.since > EXPECT_TTL_SEC:
                return False
            del self._expects[expect_key]   # 一次性：只给第一条连接
            if len(self._data) >= MAX_DATA_CONNS:
                oldest = min(self._data, key=lambda k: self._data[k].last_seen)
                del self._data[oldest]
            self._data[key] = _DataConn(sid=sid, last_seen=now)
            self.counters.bump("ftp_data_admit")
            return True

    def return_sid(self, inner: bytes, header: ipv4.Ipv4Header) -> str | None:
        """源站发往客户端的包：属于某条数据连接就返回它的（控制）SID，否则 ``None``。

        每个回程包都会经过这里（HTTP 大下载也是），所以先做不拿锁的快速排除：没有活动的
        数据连接时直接返回。读 ``len()`` 不加锁是安全的——数据连接在 SYN 放行时就已登记，
        早于源站的第一个回包。
        """
        if not self._data or header.proto != ipv4.PROTO_TCP:
            return None
        segment = parse_tcp(inner, header)
        if segment is None:
            return None
        key = (header.dst, segment.dport, header.src, segment.sport)
        now = time.monotonic()
        with self._lock:
            conn = self._data.get(key)
            if conn is None:
                return None
            self._note_flags(conn, segment, from_client=False, now=now)
            return conn.sid

    # ------------------------------------------------ 周期任务

    def tick(self, now: float | None = None) -> None:
        moment = now if now is not None else time.monotonic()
        with self._lock:
            for key, expect in list(self._expects.items()):
                if moment - expect.since > EXPECT_TTL_SEC:
                    del self._expects[key]
                    self.counters.bump("ftp_expect_expired")
            for table, idle in ((self._data, DATA_IDLE_SEC), (self._controls, CONTROL_IDLE_SEC)):
                for key, conn in list(table.items()):
                    if conn.closed_at is not None:
                        if moment - conn.closed_at > CLOSE_LINGER_SEC:
                            del table[key]
                    elif moment - conn.last_seen > idle:
                        del table[key]

    def counts(self) -> tuple[int, int, int]:
        """``(控制连接, 期望, 数据连接)`` 条目数，测试与诊断用。"""
        with self._lock:
            return len(self._controls), len(self._expects), len(self._data)

    # ------------------------------------------------ 内部（锁内）

    @staticmethod
    def _note_flags(conn: _Control | _DataConn, segment: TcpSegment, *,
                    from_client: bool, now: float) -> None:
        conn.last_seen = now
        if conn.closed_at is not None:
            return
        if segment.flags & TCP_FLAG_RST:
            conn.closed_at = now
            return
        if segment.flags & TCP_FLAG_FIN:
            if from_client:
                conn.fin_client = True
            else:
                conn.fin_server = True
            if conn.fin_client and conn.fin_server:
                conn.closed_at = now
