"""CONTROL 控制报文的手工编解码。

仅实现本服务端需要的两种子类型：
- 注册请求（Subtype=5）：终端 -> RM
- 域内同步（Subtype=6）：RM -> 终端，下发 Proxy/BR 信息

不复用 packets.py 中的声明式定义，因为 RM 同步表中条目的字段次序
（NID 在前、IP 在后）与请求报文的 IP_NID 次序不一致，手工编解码更清晰可靠。
报文布局对照 color-agent-plus 的 ProxyLib.ControlPkt。
"""
from __future__ import annotations

from .constants import COLOR_VERSION, CONTROL_FIRST_BYTE, ControlSubtype, NID_LEN
from .utils import (
    calculate_checksum,
    int_to_bytes_be,
    int_to_bytes_le,
    ipv4_to_le_bytes,
    le_bytes_to_ipv4,
)

#: 控制报文头部长度（version/type, ttl, checksum(2), header_length, subtype, data_length(2)）
CONTROL_HEADER_LENGTH = 8


def build_register(nid: int, ipv4: str, ttl: int = 64) -> bytes:
    """构造代理注册报文（Subtype=5）。

    负载 = 本机 IP(4 字节小端) + 本机 NID(16 字节大端)，共 20 字节。
    """
    data = ipv4_to_le_bytes(ipv4) + int_to_bytes_be(nid, NID_LEN)
    head = bytes([CONTROL_FIRST_BYTE, ttl])
    after_checksum = (
        bytes([CONTROL_HEADER_LENGTH, ControlSubtype.PROXY_REGISTER])
        + int_to_bytes_le(len(data), 2)
        + data
    )
    packet_zero_cs = head + b"\x00\x00" + after_checksum
    checksum = calculate_checksum(packet_zero_cs)
    return head + int_to_bytes_be(checksum, 2) + after_checksum


def parse_register_reply(payload: bytes) -> tuple[list[tuple[int, str]], list[tuple[int, str]]]:
    """解析 RM 同步报文（Subtype=6），返回 (proxies, brs)。

    - proxies: ``[(nid, ip), ...]``，每条 = NID(16 字节大端) + IP(4 字节小端)
    - brs:     ``[(px, ip), ...]``，每条 = PX(2 字节小端) + IP(4 字节小端)
    """
    pointer = CONTROL_HEADER_LENGTH

    num_proxies = payload[pointer]
    pointer += 1
    proxies: list[tuple[int, str]] = []
    for _ in range(num_proxies):
        nid = int.from_bytes(payload[pointer : pointer + NID_LEN], "big")
        pointer += NID_LEN
        ip = le_bytes_to_ipv4(payload[pointer : pointer + 4])
        pointer += 4
        proxies.append((nid, ip))

    num_brs = payload[pointer]
    pointer += 1
    brs: list[tuple[int, str]] = []
    for _ in range(num_brs):
        px = int.from_bytes(payload[pointer : pointer + 2], "little")
        pointer += 2
        ip = le_bytes_to_ipv4(payload[pointer : pointer + 4])
        pointer += 4
        brs.append((px, ip))

    return proxies, brs


def is_register_reply(payload: bytes) -> bool:
    """判断是否为合法的 RM 同步报文（Subtype=6 且校验和正确）。"""
    if len(payload) < CONTROL_HEADER_LENGTH:
        return False
    if payload[0] != CONTROL_FIRST_BYTE or payload[5] != ControlSubtype.PROXY_REGISTER_REPLY:
        return False
    return calculate_checksum(payload) == 0
