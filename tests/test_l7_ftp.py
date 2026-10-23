"""FTP 控制连接解析的单元测试（D21，colorproxy/l7/ftp.py）。

可用 ``python -m pytest tests/test_l7_ftp.py`` 运行，
也可直接 ``python tests/test_l7_ftp.py`` 运行。
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from colorproxy.l7.ftp import (
    MAX_LINE,
    FtpCommandStream,
    FtpReply,
    FtpReplyStream,
    parse_227,
    parse_229,
)


def _replies(*chunks: bytes, stream: FtpReplyStream | None = None) -> list[FtpReply]:
    stream = stream if stream is not None else FtpReplyStream()
    out: list[FtpReply] = []
    for chunk in chunks:
        out += stream.feed(chunk)
    return out


# ---------------------------------------------------------------- 回复分帧

def test_single_line_replies_split_across_feeds() -> None:
    got = _replies(b"220 rea", b"dy\r\n229 Entering Extended Passive Mode (|||50", b"123|)\r\n")
    assert got == [FtpReply(220, "ready"),
                   FtpReply(229, "Entering Extended Passive Mode (|||50123|)")]


def test_code_without_text_and_crlf_split_across_feeds() -> None:
    assert _replies(b"200\r", b"\n226 o", b"k\r", b"\n") == [FtpReply(200, ""), FtpReply(226, "ok")]


def test_bare_lf_in_reply_is_text_not_line_end() -> None:
    """客户端能把裸 LF 塞进文件名、让源站回显出来；按 LF 切行就会凭空多出一条 229。"""
    got = _replies(b'257 "/foo\n229 Entering Extended Passive Mode (|||3389|)" created\r\n'
                   b"250 a\rb\r\n")
    assert got == [
        FtpReply(257, '"/foo\n229 Entering Extended Passive Mode (|||3389|)" created'),
        FtpReply(250, "a\rb"),
    ]


def test_multiline_block_hides_inner_reply_lookalikes() -> None:
    """``213-`` 与 ``213 `` 之间夹的 ``227 …`` 是正文，不是回复（防借文件名开洞）。"""
    got = _replies(
        b"213-Status of /:\r\n"
        b"227 Entering Passive Mode (172,10,9,2,12,234)\r\n"
        b"229 Entering Extended Passive Mode (|||3306|)\r\n"
        b"213-still inside\r\n"
        b"213 End of status\r\n"
    )
    assert got == [FtpReply(213, "End of status")]


def test_multiline_block_ends_only_on_same_code() -> None:
    got = _replies(b"211-Features:\r\n EPSV\r\n226 not the end\r\n211 End\r\n")
    assert got == [FtpReply(211, "End")]


def test_garbage_outside_block_loses_sync_until_next_reply() -> None:
    """不在多行回复里却不是回复行：失步。之后第一条完整回复只用来对齐，标成不可信。"""
    got = _replies(b"hello\r\n227 Entering Passive Mode (172,10,9,2,195,80)\r\n200 ok\r\n")
    assert got == [FtpReply(227, "Entering Passive Mode (172,10,9,2,195,80)", trusted=False),
                   FtpReply(200, "ok")]


def test_resync_discards_partial_line_and_first_reply() -> None:
    stream = FtpReplyStream()
    assert _replies(b"229 Entering", stream=stream) == []
    stream.resync()
    # 空洞之后：先丢到下一个行尾，第一条完整回复只用来对齐（可能是多行回复的尾巴）
    got = _replies(b" (|||50123|)\r\n229 (|||50124|)\r\n229 (|||50125|)\r\n", stream=stream)
    assert got == [FtpReply(229, "(|||50124|)", trusted=False), FtpReply(229, "(|||50125|)")]


def test_overlong_line_is_dropped_without_breaking_the_stream() -> None:
    got = _replies(b"200 " + b"x" * (MAX_LINE + 10) + b"\r\n", b"226 done\r\n")
    assert got == [FtpReply(226, "done")]


# ---------------------------------------------------------------- 命令

def test_command_verbs() -> None:
    stream = FtpCommandStream()
    assert stream.feed(b"pasv\r\nEPSV 1\nUSER col") == ["PASV", "EPSV"], "命令方向容忍裸 LF"
    assert stream.feed(b"or\r\n\xff\xf4\xff\xf2ABOR\r\n") == ["USER", "ABOR"]
    # 认不出动词的行也占一个位置，否则命令与回复的配对会错位
    assert stream.feed(b"\x16\x03\x01\x02\r\n12345\r\n") == ["", ""]


# ---------------------------------------------------------------- 227 / 229

def test_parse_227_with_and_without_parentheses() -> None:
    assert parse_227("Entering Passive Mode (172,10,9,2,195,80).") == ("172.10.9.2", 50000)
    assert parse_227("Entering Passive Mode 172,10,9,2,195,81") == ("172.10.9.2", 50001)


def test_parses_real_pyftpdlib_replies() -> None:
    """pyftpdlib 2.2.0 的原文（2026-10-23 本机抓的，结尾带句点）。"""
    got = _replies(b"229 Entering extended passive mode (|||3225|).\r\n"
                   b"227 Entering passive mode (127,0,0,1,12,156).\r\n")
    assert parse_229(got[0].text) == 3225
    assert parse_227(got[1].text) == ("127.0.0.1", 3228)


def test_parse_227_rejects_out_of_range() -> None:
    assert parse_227("Entering Passive Mode (172,10,9,256,195,80)") is None
    assert parse_227("Entering Passive Mode (172,10,9,2,0,0)") is None
    assert parse_227("Entering Passive Mode") is None


def test_parse_229_any_delimiter() -> None:
    assert parse_229("Entering Extended Passive Mode (|||6446|)") == 6446
    assert parse_229("Entering Extended Passive Mode (!!!6447!)") == 6447


def test_parse_229_rejects_malformed() -> None:
    assert parse_229("Entering Extended Passive Mode (|||70000|)") is None
    assert parse_229("Entering Extended Passive Mode (||6446|)") is None
    assert parse_229("Entering Extended Passive Mode (|!|6446|)") is None
    assert parse_229("Entering Extended Passive Mode") is None


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
