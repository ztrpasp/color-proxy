"""内层 IPv4 包解析（docs/design-l3-v2.md §7.1 / §7.2 的第一步）。

只做解析与判据，不改写报文。设计约束：

- **不构造 scapy 对象**。数据面逐包走这里，视频流场景每秒几千包，用
  ``struct.unpack_from`` 直接取字段（§10.3 第 2 条）。
- 解析失败一律返回 ``None``，由调用方丢包并计数——内层包来自对端隧道，
  必须当作不可信输入对待。
- ``ipaddress``/``socket.inet_ntoa`` 都比手工拼串慢，地址格式化用
  ``format_ipv4`` 并在上层按需缓存。
"""
from __future__ import annotations

import struct
from typing import NamedTuple

#: IPv4 固定头长度（不含选项）
IPV4_MIN_HEADER = 20
#: 传输层协议号
PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
#: 允许进隧道的协议（D11：ICMP 等非 TCP/UDP 不做隧道传输）
TUNNELED_PROTOCOLS = (PROTO_TCP, PROTO_UDP)

#: IP 头 flags/fragment-offset 字段（bytes 6-7）的位定义
_FLAG_DF = 0x4000  # Don't Fragment
_FLAG_MF = 0x2000  # More Fragments
_FRAG_OFFSET_MASK = 0x1FFF

_HEADER = struct.Struct("!BBHHHBBH4s4s")  # ver/ihl, tos, total_len, id, flags/off, ttl, proto, cs, src, dst
_PORTS = struct.Struct("!HH")


class Ipv4Header(NamedTuple):
    """解析出的内层 IPv4 头（只含数据面用得到的字段）。"""

    ihl: int              # 头长度（字节，已 ×4）
    total_length: int     # IP 总长（头 + 载荷）
    ident: int            # IP ID，分片重组的键之一
    proto: int
    src: bytes            # 4 字节网络序
    dst: bytes
    dont_fragment: bool   # DF
    more_fragments: bool  # MF
    frag_offset: int      # 以 8 字节为单位的分片偏移

    @property
    def is_fragment(self) -> bool:
        """是否属于一个分片序列（首片或非首片都算）。

        D15：两者一律丢弃。非首片没有传输层头、取不出端口、算不出 SID；首片虽能
        算出 SID，但后续片必被丢弃、收端无法重组，只发首片纯属浪费带宽（§7.1 第 3 步）。
        """
        return self.more_fragments or self.frag_offset != 0

    @property
    def is_tunnelable(self) -> bool:
        """协议是否允许进隧道（D11）。"""
        return self.proto in TUNNELED_PROTOCOLS

    @property
    def proto_name(self) -> str:
        """规范服务串用的协议字面量（§3.1）。非 TCP/UDP 返回空串。"""
        if self.proto == PROTO_TCP:
            return "tcp"
        if self.proto == PROTO_UDP:
            return "udp"
        return ""


def parse_header(packet: bytes) -> Ipv4Header | None:
    """解析内层 IPv4 头。非 IPv4 或长度/字段自相矛盾时返回 ``None``。

    校验项（任一不过即视为坏包）：版本号为 4；IHL ≥ 5 且头部在包内；
    Total Length 不小于头长、不超过实际字节数（允许尾部填充）。
    """
    if len(packet) < IPV4_MIN_HEADER:
        return None
    (
        ver_ihl, _tos, total_length, ident, flags_off, _ttl, proto, _cs, src, dst,
    ) = _HEADER.unpack_from(packet)

    if ver_ihl >> 4 != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < IPV4_MIN_HEADER or ihl > len(packet):
        return None
    if total_length < ihl or total_length > len(packet):
        return None

    return Ipv4Header(
        ihl=ihl,
        total_length=total_length,
        ident=ident,
        proto=proto,
        src=src,
        dst=dst,
        dont_fragment=bool(flags_off & _FLAG_DF),
        more_fragments=bool(flags_off & _FLAG_MF),
        frag_offset=flags_off & _FRAG_OFFSET_MASK,
    )


def parse_ports(packet: bytes, header: Ipv4Header) -> tuple[int, int] | None:
    """取内层 TCP/UDP 的 (src_port, dst_port)。取不到返回 ``None``。

    调用前必须已排除分片（``header.is_fragment``）：非首片没有传输层头，这里读到的
    会是净载荷字节，静默当成端口用会算出一个错的 SID（§7.1 第 3 步的由来）。
    """
    if not header.is_tunnelable:
        return None
    if header.ihl + 4 > len(packet):
        return None
    return _PORTS.unpack_from(packet, header.ihl)  # type: ignore[return-value]


def format_ipv4(address: bytes) -> str:
    """4 字节网络序 → 点分十进制。比 ``socket.inet_ntoa`` 快，且无需导入 socket。"""
    return f"{address[0]}.{address[1]}.{address[2]}.{address[3]}"


def endpoint(packet: bytes, header: Ipv4Header, *, source: bool) -> tuple[str, str, int] | None:
    """取一端的服务三元组 ``(proto, ip, port)``，即规范服务串的三个组成部分。

    ``source=False`` 取目的端（上行查 SID、入向准入校验用）；``source=True`` 取源端
    （回送方向由内层源三元组反推 SID 用，§7.2 回送第 2 步，D14）。

    返回 ``None`` 的情形：非 TCP/UDP、分片包、传输层头不完整——三者都必须丢包。
    """
    if not header.is_tunnelable or header.is_fragment:
        return None
    ports = parse_ports(packet, header)
    if ports is None:
        return None
    src_port, dst_port = ports
    if source:
        return header.proto_name, format_ipv4(header.src), src_port
    return header.proto_name, format_ipv4(header.dst), dst_port
