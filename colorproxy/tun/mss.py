"""MSS clamp 与 TCP 校验和（docs/design-l3-v2.md §6.2）。

内层 TCP 不知道隧道 MTU，必须在握手包里把 MSS 选项改小，否则两端会按 1460
协商，数据一大就撞 tun 的 1280 MTU 形成黑洞。

**两侧都必须做**：消费端改客户端发出的 ``SYN``，提供端改服务端发出的 ``SYN-ACK``。
只做一侧的表现是"连接建立了、小请求正常、一传大数据就卡死"，排查代价很高。
本模块对"任何置了 SYN 的包"一视同仁，故两端共用同一个函数。

规则（§6.2）：
- **只减不增**。已有 MSS 不大于目标值时不动——对端可能本来就在更小的路径上。
- SYN 里没有 MSS 选项则不处理。对端会退到 536 的默认值，安全。
"""
from __future__ import annotations

import struct

from ..protocol.utils import calculate_checksum
from .ipv4 import Ipv4Header, PROTO_TCP

#: TCP 标志位（相对 TCP 头偏移 13）
TCP_FLAG_FIN = 0x01
TCP_FLAG_SYN = 0x02
TCP_FLAG_RST = 0x04
TCP_FLAG_ACK = 0x10

#: TCP 选项 kind
_OPT_END = 0
_OPT_NOP = 1
_OPT_MSS = 2
_OPT_MSS_LEN = 4

#: TCP 固定头长度；校验和与选项区的相对偏移
_TCP_MIN_HEADER = 20
_OFF_DATA_OFFSET = 12
_OFF_FLAGS = 13
_OFF_CHECKSUM = 16

_UINT16 = struct.Struct("!H")


def tcp_flags(packet: bytes, header: Ipv4Header) -> int:
    """取 TCP 标志字节；非 TCP 或头部不完整返回 0。"""
    if header.proto != PROTO_TCP or header.ihl + _TCP_MIN_HEADER > len(packet):
        return 0
    return packet[header.ihl + _OFF_FLAGS]


def is_syn(packet: bytes, header: Ipv4Header) -> bool:
    """是否为握手包（SYN 或 SYN-ACK）——MSS clamp 只作用于它们。"""
    return bool(tcp_flags(packet, header) & TCP_FLAG_SYN)


def clamp_syn_mss(packet: bytearray, header: Ipv4Header, max_mss: int) -> int | None:
    """就地把 SYN/SYN-ACK 的 MSS 选项改小到 ``max_mss``，并增量修正 TCP 校验和。

    返回被替换掉的原 MSS 值；未改动（非 SYN、无 MSS 选项、原值已不大于目标值、
    报文残缺）时返回 ``None``。

    ``packet`` 必须是可变的 ``bytearray``：数据面每包都会过这里，避免整包复制。
    """
    if header.proto != PROTO_TCP:
        return None
    tcp_start = header.ihl
    if tcp_start + _TCP_MIN_HEADER > len(packet):
        return None
    if not packet[tcp_start + _OFF_FLAGS] & TCP_FLAG_SYN:
        return None

    data_offset = (packet[tcp_start + _OFF_DATA_OFFSET] >> 4) * 4
    if data_offset < _TCP_MIN_HEADER or tcp_start + data_offset > len(packet):
        return None

    mss_offset = _find_mss_option(packet, tcp_start + _TCP_MIN_HEADER, tcp_start + data_offset)
    if mss_offset is None:
        # SYN 里没有 MSS 选项：不处理，对端会用 536 默认值（§6.2）
        return None

    (old_mss,) = _UINT16.unpack_from(packet, mss_offset)
    if old_mss <= max_mss:
        return None  # 只减不增

    _UINT16.pack_into(packet, mss_offset, max_mss)
    checksum_offset = tcp_start + _OFF_CHECKSUM
    (old_checksum,) = _UINT16.unpack_from(packet, checksum_offset)
    _UINT16.pack_into(
        packet, checksum_offset, _incremental_update(old_checksum, old_mss, max_mss)
    )
    return old_mss


def _find_mss_option(packet: bytes, start: int, end: int) -> int | None:
    """在 TCP 选项区里找 MSS 选项，返回其 2 字节值的偏移。

    选项区来自对端，可能是畸形的：遇到 EOL 停止，长度字段不合法或越界即放弃，
    绝不越出 ``end``。
    """
    pointer = start
    while pointer < end:
        kind = packet[pointer]
        if kind == _OPT_END:
            return None
        if kind == _OPT_NOP:
            pointer += 1
            continue
        if pointer + 1 >= end:
            return None
        length = packet[pointer + 1]
        if length < 2 or pointer + length > end:
            return None
        if kind == _OPT_MSS and length == _OPT_MSS_LEN:
            return pointer + 2
        pointer += length
    return None


def _incremental_update(old_checksum: int, old_word: int, new_word: int) -> int:
    """改一个 16 位字后的校验和增量更新（RFC 1624 式 3：HC' = ~(~HC + ~m + m')）。

    比整包重算便宜得多，且不需要伪首部——数据面用它，测试用 ``tcp_checksum``
    整包重算来交叉验证。
    """
    total = (~old_checksum & 0xFFFF) + (~old_word & 0xFFFF) + new_word
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def tcp_checksum(packet: bytes, header: Ipv4Header) -> int:
    """按伪首部整包重算 TCP 校验和（把校验和字段视为 0）。

    数据面不用它（走增量更新），它的用途是自检与测试：对一个校验和正确的报文，
    重算结果应等于报文里携带的值。

    校验和算法与 CoLoR 头用的是同一个标准的 16 位反码和，故直接复用
    ``protocol.utils.calculate_checksum``，不再重复实现一遍。
    """
    tcp_length = header.total_length - header.ihl
    segment = bytearray(packet[header.ihl : header.ihl + tcp_length])
    _UINT16.pack_into(segment, _OFF_CHECKSUM, 0)
    pseudo = header.src + header.dst + bytes([0, PROTO_TCP]) + _UINT16.pack(tcp_length)
    return calculate_checksum(pseudo + bytes(segment))
