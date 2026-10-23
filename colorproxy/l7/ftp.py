"""FTP 控制连接的增量解析（D21，docs/design-l3-v2.md §8.8）。

被动模式下，数据端口由服务端在 227（PASV）/ 229（EPSV）回复里告诉客户端。提供端要在客户端
连过来之前知道这个端口，所以要读控制连接的两个方向：

- **客户端 → 服务端**：命令。只取动词，用来判断某条回复是在回答哪条命令；
- **服务端 → 客户端**：回复。按 RFC 959 的多行规则分帧，只认完整的最终回复行。

与 ``http.py`` 的区别：这里是**旁路观察**，不扣包、不复位。解析结果只用来登记「期望」，
看不懂就当没看见——最坏的结果是数据连接被拒（fail-closed），不会把不该放的放进来。所以
超长行、乱码都不抛异常：丢掉当前行，在下一个行尾处重新对齐。

**回复只按 CRLF 切行**（RFC 959 的行尾就是 CRLF）。客户端发不进 CRLF——它在命令里就是行尾——
但发得进裸 LF：``MKD foo\\n229 Entering Extended Passive Mode (|||3389|)`` 会被源站原样回显进
``257`` 的正文。按 LF 切行的话，后半句就成了一条「229 回复」。命令方向则宽松地按 LF 切：切错
只会让命令与回复配不上（看漏），不会多放东西。

为什么要按多行规则分帧：``STAT``、``HELP`` 这类命令的多行回复会把文件名之类的内容原样
带出来。``213-`` 与 ``213 `` 之间夹的一行 ``227 Entering Passive Mode (…)`` 只是正文，
不是回复；不分帧的话，谁能控制文件名，谁就能让代理为任意端口开洞。

用法：每个方向一个解析器，按到达顺序喂**按序的**字节。序号空洞、中途接手时调
``resync()``：解析器丢掉直到下一个行尾的字节，并把重新对齐后的第一条完整回复标成
``trusted=False``（那时不知道自己是不是落在一个多行回复的中间）。调用方不能用它的内容，
但要知道它答掉了一条命令。
"""
from __future__ import annotations

import re
from dataclasses import dataclass

#: 单行长度上限（不含行尾）。FTP 的命令与回复行都很短；超过的整行丢弃。
MAX_LINE = 2048

#: 回复行开头：三位代码（首位 1–5），后跟空格（最终行）、``-``（多行开头）或行尾
_REPLY_HEAD = re.compile(rb"([1-5][0-9][0-9])([ -]|$)")
#: 命令动词：允许前面有 Telnet 控制字节（``ABOR`` 前常带 IAC IP / IAC DM）
_VERB = re.compile(rb"[\x00-\x20\x7f-\xff]*([A-Za-z]{3,4})(?:[ \r]|$)")
#: 227 的 h1,h2,h3,h4,p1,p2。RFC 1123 4.1.2.6：不要依赖括号，扫描第一组六个数即可
_PASV = re.compile(r"(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3})")
#: 229 的 (<d><d><d><port><d>)，分隔符是 ASCII 33–126 的任意一个字符（RFC 2428 §3）
_EPSV = re.compile(r"\(([\x21-\x7e])\1\1(\d{1,5})\1\)")


@dataclass(frozen=True)
class FtpReply:
    """一条收全了的回复。多行回复只保留最后一行（``ddd `` 那行）的正文。"""

    code: int
    text: str
    #: False：失步后用来重新对齐的那一条。它可能是某个多行回复的尾巴，内容不可信
    trusted: bool = True


class _LineSplitter:
    """按行尾切行，行尾本身不留。超长行整行丢弃。

    ``strict=True`` 只认 CRLF（回复方向）；否则认 LF 并去掉行尾的 CR（命令方向）。
    """

    def __init__(self, *, strict: bool) -> None:
        self._strict = strict
        self._buf = bytearray()
        self._discarding = False   # 正在丢弃到下一个行尾（超长行，或刚 resync）
        self._pending_cr = False   # strict：上一段以 CR 结尾，可能与下一段开头的 LF 拼成行尾

    def feed(self, data: bytes) -> list[bytes]:
        lines: list[bytes] = []
        for piece in _split_keep(data):
            if piece == b"\n" and (not self._strict or self._pending_cr):
                self._pending_cr = False
                if not self._discarding:
                    line = bytes(self._buf)
                    lines.append(line if self._strict else line.rstrip(b"\r"))
                self._buf.clear()
                self._discarding = False
                continue
            if self._strict:
                if self._pending_cr:
                    self._append(b"\r")      # 前一个 CR 后面不是 LF：它属于正文
                self._pending_cr = piece == b"\r"
                if self._pending_cr:
                    continue
            self._append(piece)
        return lines

    def resync(self) -> None:
        self._buf.clear()
        self._pending_cr = False
        self._discarding = True

    def _append(self, chunk: bytes) -> None:
        if self._discarding:
            return
        self._buf += chunk
        if len(self._buf) > MAX_LINE:
            self._buf.clear()
            self._discarding = True


def _split_keep(data: bytes) -> list[bytes]:
    """把字节串切成「CR」「LF」与其余连续字节三类片段，保持顺序。"""
    return [piece for piece in re.split(rb"(\r|\n)", data) if piece]


class FtpReplyStream:
    """服务端 → 客户端方向的回复解析器。非线程安全，一条控制连接一个。"""

    def __init__(self) -> None:
        self._lines = _LineSplitter(strict=True)
        self._block: int | None = None   # 正在进行的多行回复的代码
        # 新建时视为已对齐：调用方从连接开头（SYN 之后）喂字节。中途接手的要先 resync()
        self._synced = True

    def feed(self, data: bytes) -> list[FtpReply]:
        replies: list[FtpReply] = []
        for line in self._lines.feed(data):
            reply = self._on_line(line)
            if reply is not None:
                replies.append(reply)
        return replies

    def resync(self) -> None:
        self._lines.resync()
        self._block = None
        self._synced = False

    def _on_line(self, line: bytes) -> FtpReply | None:
        head = _REPLY_HEAD.match(line)
        code = int(head.group(1)) if head else None
        final = head is not None and head.group(2) != b"-"
        if self._block is not None:
            # 多行回复中间的行：不管长什么样都是正文。只有「同一代码 + 空格」才结束它
            if code == self._block and final:
                self._block = None
                return self._emit(code, line)
            return None
        if code is None:
            # 不在多行回复里，却不是回复行：不知道自己在哪了，等下一条完整回复再对齐
            self._synced = False
            return None
        if not final:
            self._block = code
            return None
        return self._emit(code, line)

    def _emit(self, code: int, line: bytes) -> FtpReply:
        trusted = self._synced
        self._synced = True   # 失步后的第一条完整回复只用来对齐
        return FtpReply(code, line[4:].decode("latin-1"), trusted)


class FtpCommandStream:
    """客户端 → 服务端方向的命令解析器：每收全一行产出一个大写动词。"""

    def __init__(self) -> None:
        self._lines = _LineSplitter(strict=False)

    def feed(self, data: bytes) -> list[str]:
        verbs: list[str] = []
        for line in self._lines.feed(data):
            match = _VERB.match(line)
            # 认不出动词的行也要占一个位置：它多半也会换来一条回复，丢掉会让配对错位
            verbs.append(match.group(1).decode("ascii").upper() if match else "")
        return verbs

    def resync(self) -> None:
        self._lines.resync()


def parse_227(text: str) -> tuple[str, int] | None:
    """从 227 的正文里取 ``(ip, port)``；取不到或数值越界返回 ``None``。"""
    match = _PASV.search(text)
    if match is None:
        return None
    numbers = [int(group) for group in match.groups()]
    if any(number > 255 for number in numbers):
        return None
    port = numbers[4] * 256 + numbers[5]
    if port == 0:
        return None
    return ".".join(str(number) for number in numbers[:4]), port


def parse_229(text: str) -> int | None:
    """从 229 的正文里取端口；取不到或越界返回 ``None``。地址隐含为控制连接的服务端地址。"""
    match = _EPSV.search(text)
    if match is None:
        return None
    port = int(match.group(2))
    return port if 0 < port < 65536 else None
