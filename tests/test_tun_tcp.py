"""内层 TCP 段解析、序号运算与 RST 构造测试（D20）。

样本用 scapy 构造、再用本项目的解析器读回；RST 反过来由本项目构造、交给 scapy 核对——
自己造样本自己解析，容易两边一起错。
可用 ``python -m pytest tests/test_tun_tcp.py`` 运行，
也可直接 ``python tests/test_tun_tcp.py`` 运行（无需 pytest）。
"""
from __future__ import annotations

import os
import socket
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from colorproxy.protocol.utils import verify_checksum
from colorproxy.tun import ipv4, mss
from colorproxy.tun.tcp import (
    TCP_FLAG_ACK,
    TCP_FLAG_FIN,
    TCP_FLAG_RST,
    build_rst,
    parse_tcp,
    seq_add,
    seq_diff,
    strip_payload,
)

CLIENT = "10.99.1.1"
SERVER = "172.10.9.2"


def _raw(packet) -> bytes:
    return bytes(IP(bytes(packet)))


def test_parse_data_segment_fields() -> None:
    packet = _raw(IP(src=CLIENT, dst=SERVER)
                  / TCP(sport=51000, dport=8000, seq=1000, ack=2000, flags="PA",
                        options=[("NOP", None), ("NOP", None), ("Timestamp", (1, 2))])
                  / Raw(b"GET / HTTP/1.1\r\n\r\n"))
    header = ipv4.parse_header(packet)
    segment = parse_tcp(packet, header)
    assert segment is not None
    assert (segment.sport, segment.dport, segment.seq, segment.ack) == (51000, 8000, 1000, 2000)
    assert segment.flags & TCP_FLAG_ACK and not segment.is_pure_ack
    assert packet[segment.payload_offset:segment.payload_offset + segment.payload_len] \
        == b"GET / HTTP/1.1\r\n\r\n", "TCP 选项之后才是载荷"
    assert segment.seq_len == segment.payload_len


def test_seq_len_counts_syn_and_fin() -> None:
    for flags, payload, expected in (("S", b"", 1), ("FA", b"", 1), ("FPA", b"ab", 3), ("A", b"", 0)):
        packet = _raw(IP(src=CLIENT, dst=SERVER) / TCP(flags=flags) / Raw(payload)) if payload \
            else _raw(IP(src=CLIENT, dst=SERVER) / TCP(flags=flags))
        segment = parse_tcp(packet, ipv4.parse_header(packet))
        assert segment.seq_len == expected, flags
    ack = _raw(IP(src=CLIENT, dst=SERVER) / TCP(flags="A"))
    assert parse_tcp(ack, ipv4.parse_header(ack)).is_pure_ack
    fin = _raw(IP(src=CLIENT, dst=SERVER) / TCP(flags="FA"))
    assert not parse_tcp(fin, ipv4.parse_header(fin)).is_pure_ack, "FIN 占序号，不是纯 ACK"


def test_parse_rejects_truncated_and_bad_offset() -> None:
    packet = bytearray(_raw(IP(src=CLIENT, dst=SERVER) / TCP(flags="A")))
    header = ipv4.parse_header(bytes(packet))
    packet[header.ihl + 12] = 0x40  # 数据偏移 = 16 字节 < 20
    assert parse_tcp(bytes(packet), header) is None
    packet[header.ihl + 12] = 0xF0  # 数据偏移 = 60 字节，超出包长
    assert parse_tcp(bytes(packet), header) is None
    udp = _raw(IP(src=CLIENT, dst=SERVER, proto=17) / Raw(b"\x00" * 8))
    assert parse_tcp(udp, ipv4.parse_header(udp)) is None


def test_payload_length_ignores_link_padding() -> None:
    packet = _raw(IP(src=CLIENT, dst=SERVER) / TCP(flags="A")) + b"\x00" * 6
    segment = parse_tcp(packet, ipv4.parse_header(packet))
    assert segment.payload_len == 0, "以 IP Total Length 为准，不把以太网填充当载荷"


def test_seq_arithmetic_wraps() -> None:
    assert seq_add(0xFFFFFFFF, 2) == 1
    assert seq_diff(1, 0xFFFFFFFF) == 2
    assert seq_diff(0xFFFFFFFF, 1) == -2
    assert seq_diff(5, 5) == 0


def test_build_rst_checksums_and_fields() -> None:
    client, server = socket.inet_aton(CLIENT), socket.inet_aton(SERVER)
    rst = build_rst(server, client, 8000, 51000, 0xFFFFFFF0, 12345, with_ack=True)
    header = ipv4.parse_header(rst)
    assert header is not None and header.total_length == 40
    assert verify_checksum(rst[:20]), "IP 头校验和要对"
    (carried,) = struct.unpack_from("!H", rst, 20 + 16)
    assert mss.tcp_checksum(rst, header) == carried, "TCP 校验和要对（含伪首部）"

    parsed = IP(rst)
    assert parsed.src == SERVER and parsed.dst == CLIENT
    assert parsed[TCP].sport == 8000 and parsed[TCP].dport == 51000
    assert parsed[TCP].seq == 0xFFFFFFF0 and parsed[TCP].ack == 12345
    assert parsed[TCP].flags == "RA"
    # 让 scapy 重算一遍，结果应与我们填的一致
    rebuilt = IP(rst)
    del rebuilt.chksum
    del rebuilt[TCP].chksum
    assert bytes(IP(bytes(rebuilt))) == rst

    bare = build_rst(client, server, 51000, 8000, 7)
    segment = parse_tcp(bare, ipv4.parse_header(bare))
    assert segment.flags == TCP_FLAG_RST and segment.ack == 0, "不带 ACK 时 ack 字段填 0"
    assert not segment.flags & TCP_FLAG_FIN


def test_strip_payload_keeps_options_and_fixes_checksums() -> None:
    packet = _raw(IP(src=CLIENT, dst=SERVER)
                  / TCP(sport=51000, dport=8000, seq=99, flags="S",
                        options=[("MSS", 1460), ("TFO", b"cookie12")])
                  / Raw(b"GET /secret HTTP/1.1\r\n\r\n"))
    header = ipv4.parse_header(packet)
    stripped = strip_payload(packet, header, parse_tcp(packet, header))
    new_header = ipv4.parse_header(stripped)
    segment = parse_tcp(stripped, new_header)
    assert segment.payload_len == 0 and segment.seq == 99 and segment.flags == 0x02
    assert verify_checksum(stripped[:new_header.ihl])
    (carried,) = struct.unpack_from("!H", stripped, new_header.ihl + 16)
    assert mss.tcp_checksum(stripped, new_header) == carried
    rebuilt = IP(stripped)
    del rebuilt.chksum, rebuilt.len
    del rebuilt[TCP].chksum
    assert bytes(IP(bytes(rebuilt))) == stripped, "与 scapy 重算的结果逐字节一致"
    assert ("MSS", 1460) in IP(stripped)[TCP].options, "TCP 选项原样保留"


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
