"""HTTP/1.x 请求流解析与内容级 URL 规范化测试（D20）。

纯逻辑，不需要 scapy、tun 或管理员权限。
可用 ``python -m pytest tests/test_l7_http.py`` 运行，
也可直接 ``python tests/test_l7_http.py`` 运行（无需 pytest）。
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from colorproxy.l7.http import (
    MAX_HEADER_BYTES,
    MAX_REQUEST_LINE,
    HttpParseError,
    HttpRequestStream,
)
from colorproxy.protocol.sid import content_path, content_url, lsid_from_url, sid_hex_from_url

GET_HELLO = b"GET /hello.html?x=1 HTTP/1.1\r\nHost: 172.10.9.2:8000\r\n\r\n"


def _feed_all(stream: HttpRequestStream, data: bytes, step: int | None = None):
    if step is None:
        return stream.feed(data)
    events = []
    for index in range(0, len(data), step):
        events += stream.feed(data[index:index + step])
    return events


def _raises(data: bytes) -> str:
    try:
        HttpRequestStream().feed(data)
    except HttpParseError as exc:
        return str(exc)
    raise AssertionError(f"应当报错却没有：{data[:40]!r}")


# ---------------------------------------------------------------- 正常路径

def test_single_get() -> None:
    stream = HttpRequestStream()
    assert stream.pending_start == 0, "什么都没收到时，下一个请求从 0 开始"
    events = stream.feed(GET_HELLO)
    assert [(e.start, e.method, e.target, e.version) for e in events] == \
        [(0, "GET", "/hello.html?x=1", "HTTP/1.1")]
    assert stream.offset == len(GET_HELLO)
    assert stream.pending_start == len(GET_HELLO), "请求收完，下一个字节就是新请求"


def test_request_line_fed_byte_by_byte() -> None:
    stream = HttpRequestStream()
    line_end = GET_HELLO.index(b"\n") + 1
    events = _feed_all(stream, GET_HELLO[:line_end - 1], step=1)
    assert events == [] and stream.pending_start == 0, "请求行没收全时不能产出、界限停在开头"
    events = stream.feed(GET_HELLO[line_end - 1:line_end])
    assert len(events) == 1 and events[0].target == "/hello.html?x=1"
    assert stream.pending_start is None, "请求头里：界限由请求决定，不由解析器给"


def test_keep_alive_two_requests() -> None:
    second = b"GET /items.html HTTP/1.1\r\n\r\n"
    events = HttpRequestStream().feed(GET_HELLO + second)
    assert [e.start for e in events] == [0, len(GET_HELLO)]
    assert events[1].target == "/items.html"


def test_post_with_content_length_then_get() -> None:
    post = b"POST /api/items HTTP/1.1\r\nContent-Length: 11\r\n\r\nhello world"
    get = b"GET /b HTTP/1.1\r\n\r\n"
    for step in (None, 1, 7):
        events = _feed_all(HttpRequestStream(), post + get, step)
        assert [(e.method, e.start) for e in events] == [("POST", 0), ("GET", len(post))], step


def test_body_that_looks_like_a_request_is_not_parsed_as_one() -> None:
    body = b"GET /secret HTTP/1.1\r\n\r\n"
    post = b"POST /x HTTP/1.1\r\nContent-Length: %d\r\n\r\n" % len(body) + body
    events = HttpRequestStream().feed(post)
    assert [e.target for e in events] == ["/x"], "请求体里的字节不是请求"


def test_chunked_body_then_get() -> None:
    chunked = (b"POST /up HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"
               b"5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: 1\r\n\r\n")
    get = b"GET /after HTTP/1.1\r\n\r\n"
    for step in (None, 1, 3):
        stream = HttpRequestStream()
        events = _feed_all(stream, chunked + get, step)
        assert [(e.target, e.start) for e in events] == [("/up", 0), ("/after", len(chunked))], step


def test_pipelined_requests_in_one_feed() -> None:
    data = b"".join(b"GET /%d HTTP/1.1\r\n\r\n" % i for i in range(5))
    events = HttpRequestStream().feed(data)
    assert [e.target for e in events] == [f"/{i}" for i in range(5)]


def test_leading_empty_lines_are_skipped_and_not_counted_as_request_start() -> None:
    stream = HttpRequestStream()
    post = b"POST /x HTTP/1.1\r\nContent-Length: 1\r\n\r\nA"
    stream.feed(post)
    stream.feed(b"\r")
    assert stream.pending_start == len(post), "半个空行还属于下一个请求的开头"
    stream.feed(b"\n")
    assert stream.pending_start == len(post) + 2, "收全的空行要跳过，界限越过它"
    events = stream.feed(b"GET /y HTTP/1.0\n\n")
    assert events[0].start == len(post) + 2 and events[0].version == "HTTP/1.0", "也接受裸 LF"


def test_upgrade_request_is_treated_as_ordinary_request() -> None:
    upgrade = b"GET /ws HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
    stream = HttpRequestStream()
    assert [e.target for e in stream.feed(upgrade)] == ["/ws"]
    try:
        stream.feed(b"\x81\x85\x37\xfa\x21\x3d")  # 一个 WebSocket 帧
    except HttpParseError:
        pass
    else:
        raise AssertionError("升级后的非 HTTP 字节必须报错（不开透传，防绕过）")


# ---------------------------------------------------------------- 报错（fail-closed）

def test_non_http_bytes_fail_fast() -> None:
    assert _raises(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03")  # TLS ClientHello 开头
    assert _raises(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")               # h2 前言
    assert _raises(b"GET /\r\n")                                         # HTTP/0.9
    assert _raises(b"GET  / HTTP/1.1\r\n")                               # 多余空格
    assert _raises(b"G(T / HTTP/1.1\r\n")                                # 方法名非 token


def test_ambiguous_framing_fails() -> None:
    assert _raises(b"POST / HTTP/1.1\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n")
    assert _raises(b"POST / HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n")
    assert _raises(b"POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n")
    assert _raises(b"POST / HTTP/1.1\r\nContent-Length: 3, 4\r\n\r\n")
    assert _raises(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked, gzip\r\n\r\n")
    assert _raises(b"GET / HTTP/1.1\r\nHost : x\r\n\r\n")                # 冒号前有空白
    assert _raises(b"GET / HTTP/1.1\r\nA: b\r\n folded\r\n\r\n")         # obs-fold
    assert _raises(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n")
    # 相同的重复 CL 是允许的
    HttpRequestStream().feed(b"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nA")


def test_oversize_line_and_headers_fail() -> None:
    assert _raises(b"GET /" + b"a" * MAX_REQUEST_LINE)
    stream = HttpRequestStream()
    stream.feed(b"GET / HTTP/1.1\r\n")
    try:
        for _ in range(MAX_HEADER_BYTES // 100 + 2):
            stream.feed(b"X-Pad: " + b"p" * 91 + b"\r\n")
    except HttpParseError:
        pass
    else:
        raise AssertionError("请求头超限必须报错")


def test_error_is_sticky() -> None:
    stream = HttpRequestStream()
    try:
        stream.feed(b"\x16\x03")
    except HttpParseError:
        pass
    try:
        stream.feed(GET_HELLO)
    except HttpParseError:
        return
    raise AssertionError("出过错的流不能再接着解析")


# ---------------------------------------------------------------- URL 规范化

def test_content_url_and_path() -> None:
    assert content_url("172.10.9.2", 8000, "/hello.html?x=1#f") == "http://172.10.9.2:8000/hello.html"
    assert content_url("172.10.9.2", 80, "") == "http://172.10.9.2:80/", "端口恒写出、空 path 记作 /"
    assert content_path("http://other-host:1/a/b?q=1") == "/a/b", "absolute-form 只取 path"
    assert content_path("/a%2Eb/./c") == "/a%2Eb/./c", "不做归一化：变体写法查不到 SID、会被拒"


def test_content_url_sid_matches_v1_algorithm() -> None:
    """提供端按配置拼、消费端按请求拼，结果与 v1 的 sid_hex_from_url 逐字节一致。"""
    nid = 0xA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1
    from_request = content_url("172.10.9.2", 8000, "/api/items?id=3")
    from_config = content_url("172.10.9.2", 8000, "/api/items")
    assert lsid_from_url(from_request) == lsid_from_url(from_config)
    assert sid_hex_from_url(nid, from_config) == sid_hex_from_url(nid, "http://172.10.9.2:8000/api/items")


def _run_all() -> int:
    funcs = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in funcs:
        try:
            fn()
            print(f"  PASS {fn.__name__}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"  FAIL {fn.__name__}: {exc!r}")
    print(f"\n{len(funcs) - failed}/{len(funcs)} passed")
    return failed


if __name__ == "__main__":
    raise SystemExit(_run_all())
