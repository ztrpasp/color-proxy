"""HTTP/1.x 请求流的增量解析（D20）。

只解析**客户端 → 服务端**一个方向：请求的边界完全由请求头决定（Content-Length /
Transfer-Encoding），与响应无关。所以不必看下行，也不必理解响应。

用法：按到达顺序把字节喂给 ``HttpRequestStream.feed``，每当一个请求行收全就产出一条
``RequestLine``。请求行一完整就够算 SID 了，不必等整个请求头——调用方可以立刻去发
GET，同时继续把后面的字节喂进来（解析器还要靠请求头找到下一个请求从哪开始）。

**判断不了就报错（fail-closed）**。调用方拿解析结果做准入，任何"猜"都可能变成绕过：

- 不是 HTTP/1.x（TLS 握手、HTTP/2 前言、乱码）→ 报错；
- Content-Length 与 Transfer-Encoding 同时出现、CL 不合法、TE 最后一项不是 chunked
  → 报错（请求走私的经典手法，边界有歧义）；
- 请求行 / 请求头超长 → 报错；
- **Upgrade / CONNECT 不特殊处理**：当普通请求解析。服务端真的切换了协议的话，后面的
  字节不再是 HTTP，会在下一次解析时报错。若为它们开"透传"，客户端只要在请求里带一个
  ``Upgrade`` 头、而服务端并不升级，之后的请求就都绕过了检查。
"""
from __future__ import annotations

import re
from dataclasses import dataclass

#: 请求行长度上限（含 CRLF）。浏览器的 URL 一般不超过 2 KB。
MAX_REQUEST_LINE = 8 * 1024
#: 单个请求的请求头（含 trailer）总长上限
MAX_HEADER_BYTES = 64 * 1024
#: chunked 的 size 行长度上限
MAX_CHUNK_LINE = 1024
#: 方法名长度上限。用它尽早认出非 HTTP 流量（TLS 握手不会在 32 字节内出现空格）。
MAX_METHOD_LEN = 32

#: RFC 9110 的 token 字符，方法名只能由它们组成
_TOKEN = frozenset(
    b"!#$%&'*+-.^_`|~0123456789"
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)
_VERSION = re.compile(rb"HTTP/1\.[0-9]")
_DIGITS = re.compile(rb"[0-9]+")
_HEX = re.compile(rb"[0-9A-Fa-f]+")

# 状态
_LINE = "request-line"
_HEADERS = "headers"
_BODY = "body"
_CHUNK_SIZE = "chunk-size"
_CHUNK_DATA = "chunk-data"
_CHUNK_END = "chunk-crlf"
_TRAILERS = "trailers"
_ERROR = "error"


class HttpParseError(ValueError):
    """字节流不是（或不再是）可解析的 HTTP/1.x 请求流。"""


@dataclass(frozen=True)
class RequestLine:
    """一个收全了的请求行。"""

    start: int      # 请求行第一个字节在流中的偏移（请求前容忍掉的空行不算）
    method: str
    target: str     # request-target 原样（含 query），取 path 用 protocol.sid.content_path
    version: str


class HttpRequestStream:
    """单向（请求方向）HTTP/1.x 字节流的增量解析器。非线程安全，一条连接一个。"""

    def __init__(self) -> None:
        self._state = _LINE
        self._offset = 0          # 下一个待处理字节在流中的偏移
        self._line_start = 0      # 当前请求行（还没收全）从哪开始
        self._buf = bytearray()   # 行状态下攒着的半行
        self._remaining = 0       # BODY / CHUNK_DATA 还剩多少字节
        self._header_bytes = 0
        self._content_length: int | None = None
        self._chunked = False
        self._has_te = False
        self._error = ""

    # ------------------------------------------------------------ 对外

    @property
    def offset(self) -> int:
        """已经喂进来的字节数（= 下一个字节的流内偏移）。"""
        return self._offset

    @property
    def pending_start(self) -> int | None:
        """一个请求行还没收全的请求从哪开始；处在请求头或请求体中间时为 None。

        调用方拿它当放行界限：这个偏移及以后的字节属于一个"还不知道要去哪"的请求，
        不能放出去。请求之间的空闲期也属于这种情况——下一个字节就是新请求的开头。
        """
        return self._line_start if self._state == _LINE else None

    def feed(self, data: bytes) -> list[RequestLine]:
        """喂入下一段字节，返回其中收全的请求行（按出现顺序）。出错抛 ``HttpParseError``。"""
        if self._state == _ERROR:
            raise HttpParseError(self._error)
        data = bytes(data)
        events: list[RequestLine] = []
        view = memoryview(data)
        index, end = 0, len(view)
        while index < end:
            if self._state in (_BODY, _CHUNK_DATA):
                step = min(self._remaining, end - index)
                index += step
                self._offset += step
                self._remaining -= step
                if self._remaining == 0:
                    self._state = _CHUNK_END if self._state == _CHUNK_DATA else self._request_done()
                continue

            newline = data.find(b"\n", index)
            if newline < 0:
                self._buf += view[index:]
                self._offset += end - index
                self._check_partial_line()
                break
            self._buf += view[index:newline + 1]
            self._offset += newline + 1 - index
            index = newline + 1
            line = bytes(self._buf)
            self._buf.clear()
            self._check_line_length(line)
            event = self._on_line(line)
            if event is not None:
                events.append(event)
        return events

    # ------------------------------------------------------------ 行处理

    def _on_line(self, line: bytes) -> RequestLine | None:
        content = line[:-2] if line.endswith(b"\r\n") else line[:-1]
        if self._state == _LINE:
            if not content:
                # RFC 9112 §2.2：请求行前的空行应当忽略（有的客户端在 POST 体后多发一个 CRLF）
                self._line_start = self._offset
                return None
            return self._on_request_line(content)
        if self._state in (_HEADERS, _TRAILERS):
            self._header_bytes += len(line)
            if self._header_bytes > MAX_HEADER_BYTES:
                self._fail(f"请求头超过 {MAX_HEADER_BYTES} 字节")
            if content:
                self._on_header(content)
                return None
            if self._state == _TRAILERS:
                self._state = self._request_done()
            else:
                self._state = self._body_state()
            return None
        if self._state == _CHUNK_SIZE:
            self._on_chunk_size(content)
            return None
        if self._state == _CHUNK_END:
            if content:
                self._fail("chunk 数据后缺少 CRLF")
            self._state = _CHUNK_SIZE
            return None
        raise AssertionError(self._state)  # pragma: no cover

    def _on_request_line(self, content: bytes) -> RequestLine:
        parts = content.split(b" ")
        if len(parts) != 3 or not all(parts):
            self._fail(f"请求行格式不对：{content[:80]!r}")
        method, target, version = parts
        if len(method) > MAX_METHOD_LEN or not all(ch in _TOKEN for ch in method):
            self._fail(f"方法名不合法：{method[:40]!r}")
        if not _VERSION.fullmatch(version):
            self._fail(f"不是 HTTP/1.x：{version[:20]!r}")
        try:
            target_text = target.decode("utf-8")
        except UnicodeDecodeError:
            self._fail("request-target 不是合法的 UTF-8")
        start = self._line_start
        self._state = _HEADERS
        self._header_bytes = 0
        self._content_length = None
        self._chunked = False
        self._has_te = False
        return RequestLine(start=start, method=method.decode("ascii"),
                           target=target_text, version=version.decode("ascii"))

    def _on_header(self, content: bytes) -> None:
        if content[:1] in (b" ", b"\t"):
            self._fail("不支持折行的请求头（obs-fold）")
        name, colon, value = content.partition(b":")
        if not colon or not name or name != name.strip() or not all(ch in _TOKEN for ch in name):
            self._fail(f"请求头格式不对：{content[:80]!r}")
        if self._state == _TRAILERS:
            return  # trailer 不影响边界
        key = name.lower()
        value = value.strip()
        if key == b"content-length":
            values = {item.strip() for item in value.split(b",")}
            if len(values) != 1 or not _DIGITS.fullmatch(next(iter(values))):
                self._fail(f"Content-Length 不合法：{value[:40]!r}")
            length = int(next(iter(values)))
            if self._content_length is not None and self._content_length != length:
                self._fail("出现了多个不一致的 Content-Length")
            self._content_length = length
        elif key == b"transfer-encoding":
            self._has_te = True
            codings = [item.strip().lower() for item in value.split(b",") if item.strip()]
            self._chunked = bool(codings) and codings[-1] == b"chunked"
            if not self._chunked:
                self._fail(f"Transfer-Encoding 的最后一项不是 chunked，请求边界无法确定：{value[:40]!r}")

    def _body_state(self) -> str:
        if self._has_te and self._content_length is not None:
            self._fail("Content-Length 与 Transfer-Encoding 同时出现，请求边界有歧义")
        if self._chunked:
            return _CHUNK_SIZE
        if self._content_length:
            self._remaining = self._content_length
            return _BODY
        return self._request_done()

    def _on_chunk_size(self, content: bytes) -> None:
        size_text = content.split(b";", 1)[0].strip()
        if not _HEX.fullmatch(size_text) or len(size_text) > 16:
            self._fail(f"chunk 大小不合法：{content[:40]!r}")
        size = int(size_text, 16)
        if size == 0:
            self._state = _TRAILERS
        else:
            self._remaining = size
            self._state = _CHUNK_DATA

    def _request_done(self) -> str:
        self._line_start = self._offset
        return _LINE

    # ------------------------------------------------------------ 限长与报错

    def _check_partial_line(self) -> None:
        """半行也要查：尽早认出非 HTTP 流量，并防止一直不来换行的流把缓冲撑大。"""
        if self._state == _LINE and self._buf != b"\r":
            method = bytes(self._buf.split(b" ", 1)[0])
            if len(method) > MAX_METHOD_LEN or not all(ch in _TOKEN for ch in method):
                self._fail(f"不是 HTTP 请求（方法名位置是 {method[:16]!r}）")
        self._check_line_length(self._buf)

    def _check_line_length(self, line: bytes | bytearray) -> None:
        if self._state == _LINE and len(line) > MAX_REQUEST_LINE:
            self._fail(f"请求行超过 {MAX_REQUEST_LINE} 字节")
        if self._state == _CHUNK_SIZE and len(line) > MAX_CHUNK_LINE:
            self._fail(f"chunk 大小行超过 {MAX_CHUNK_LINE} 字节")
        if self._state in (_HEADERS, _TRAILERS) and self._header_bytes + len(line) > MAX_HEADER_BYTES:
            self._fail(f"请求头超过 {MAX_HEADER_BYTES} 字节")

    def _fail(self, reason: str) -> None:
        self._state = _ERROR
        self._error = reason
        self._buf.clear()
        raise HttpParseError(reason)
