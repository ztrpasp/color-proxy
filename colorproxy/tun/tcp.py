"""内层 TCP 段的解析、序号运算与 RST 构造（D20）。

D20 的内容级准入要在不终结 TCP 的前提下读出请求、扣住请求、必要时把连接复位，于是
需要比 ``mss.py`` 多知道一点 TCP：序号、确认号、载荷在哪。本模块只做这些机械的事，
不含任何策略；与应用层无关，以后 FTP 那类需要读字节流的场景也用它。

同 ``ipv4.py`` 的约束：**不构造 scapy 对象**，残缺报文一律返回 ``None``。
"""
from __future__ import annotations

import struct
from typing import NamedTuple

from ..protocol.utils import calculate_checksum
from .ipv4 import Ipv4Header, PROTO_TCP
from .mss import TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_RST, TCP_FLAG_SYN

__all__ = [
    "TCP_FLAG_ACK", "TCP_FLAG_FIN", "TCP_FLAG_RST", "TCP_FLAG_SYN",
    "TcpSegment", "build_rst", "parse_tcp", "seq_add", "seq_diff", "strip_payload",
]

_TCP_MIN_HEADER = 20
_TCP = struct.Struct("!HHIIBBHHH")   # sport dport seq ack 数据偏移 flags 窗口 校验和 紧急指针
_IP = struct.Struct("!BBHHHBBH4s4s")
_SEQ_MOD = 1 << 32


class TcpSegment(NamedTuple):
    """一个内层 TCP 段里准入逻辑用得到的字段。"""

    sport: int
    dport: int
    seq: int
    ack: int
    flags: int
    payload_offset: int   # 载荷在原始包里的起始下标
    payload_len: int

    @property
    def seq_len(self) -> int:
        """该段占用的序号空间：载荷长度，SYN 与 FIN 各占 1。"""
        return self.payload_len + bool(self.flags & TCP_FLAG_SYN) + bool(self.flags & TCP_FLAG_FIN)

    @property
    def is_pure_ack(self) -> bool:
        """不带载荷、也不带 SYN/FIN/RST 的段（纯确认或窗口更新）。"""
        return self.payload_len == 0 and not self.flags & (TCP_FLAG_SYN | TCP_FLAG_FIN | TCP_FLAG_RST)


def parse_tcp(packet: bytes, header: Ipv4Header) -> TcpSegment | None:
    """解析内层 TCP 头。非 TCP、分片、头部残缺或数据偏移不合法时返回 ``None``。

    长度以 IP 头的 Total Length 为准，不以 ``len(packet)`` 为准：后者可能带着链路层填充。
    """
    if header.proto != PROTO_TCP or header.is_fragment:
        return None
    start = header.ihl
    if start + _TCP_MIN_HEADER > header.total_length:
        return None
    sport, dport, seq, ack, offset_byte, flags, _win, _cs, _urg = _TCP.unpack_from(packet, start)
    data_offset = (offset_byte >> 4) * 4
    if data_offset < _TCP_MIN_HEADER or start + data_offset > header.total_length:
        return None
    payload_offset = start + data_offset
    return TcpSegment(sport, dport, seq, ack, flags, payload_offset,
                      header.total_length - payload_offset)


def seq_add(seq: int, delta: int) -> int:
    """序号加法（模 2^32）。"""
    return (seq + delta) % _SEQ_MOD


def seq_diff(a: int, b: int) -> int:
    """``a - b`` 的有符号序号差，落在 ``[-2^31, 2^31)``（RFC 1982 式比较）。"""
    diff = (a - b) % _SEQ_MOD
    return diff - _SEQ_MOD if diff >= 1 << 31 else diff


def strip_payload(packet: bytes, header: Ipv4Header, segment: TcpSegment) -> bytes:
    """去掉 TCP 载荷，只留 IP 头 + TCP 头（含选项），重算长度与两层校验和。

    D20 用它处理带数据的 SYN（TCP Fast Open）：SYN 里的数据会绕过请求解析，所以只把
    SYN 本身放过去。源站不接受这份数据时只确认 SYN，客户端会按普通数据重发，届时照常
    过准入——这正是 TFO 被拒时的标准回退路径。
    """
    stripped = bytearray(packet[:segment.payload_offset])
    struct.pack_into("!H", stripped, 2, segment.payload_offset)
    struct.pack_into("!H", stripped, 10, 0)
    struct.pack_into("!H", stripped, 10, calculate_checksum(bytes(stripped[:header.ihl])))
    tcp_length = segment.payload_offset - header.ihl
    struct.pack_into("!H", stripped, header.ihl + 16, 0)
    pseudo = header.src + header.dst + bytes([0, PROTO_TCP]) + struct.pack("!H", tcp_length)
    struct.pack_into("!H", stripped, header.ihl + 16,
                     calculate_checksum(pseudo + bytes(stripped[header.ihl:])))
    return bytes(stripped)


def build_rst(src: bytes, dst: bytes, sport: int, dport: int,
              seq: int, ack: int = 0, *, with_ack: bool = False) -> bytes:
    """构造一个 40 字节的 RST 包（IPv4 + TCP，无选项、无载荷），两层校验和都已算好。

    ``src`` / ``dst`` 是 4 字节网络序地址。``with_ack=True`` 时置 ACK 位并填 ``ack``。
    RFC 5961 要求 RST 的 ``seq`` 恰好等于对端的 RCV.NXT 才会立即生效（否则只回一个
    挑战 ACK），所以调用方必须给准 ``seq``。
    """
    flags = TCP_FLAG_RST | (TCP_FLAG_ACK if with_ack else 0)
    tcp = bytearray(_TCP.pack(sport, dport, seq % _SEQ_MOD, (ack if with_ack else 0) % _SEQ_MOD,
                              5 << 4, flags, 0, 0, 0))
    pseudo = src + dst + bytes([0, PROTO_TCP]) + struct.pack("!H", len(tcp))
    struct.pack_into("!H", tcp, 16, calculate_checksum(pseudo + bytes(tcp)))

    ip = bytearray(_IP.pack(0x45, 0, 20 + len(tcp), 0, 0x4000, 64, PROTO_TCP, 0, src, dst))
    struct.pack_into("!H", ip, 10, calculate_checksum(bytes(ip)))
    return bytes(ip) + bytes(tcp)
