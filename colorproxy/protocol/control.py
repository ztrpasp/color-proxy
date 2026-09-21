"""CONTROL 控制报文的手工编解码。

实现本项目需要的子类型：
- 注册请求（Subtype=5）：终端 -> RM
- 域内同步（Subtype=6）：RM -> 终端，下发 Proxy/BR 信息
- SID 列表（Subtype=40）：RM -> 终端，下发本域可访问 SID 列表（消费端用）

不复用 packets.py 中的声明式定义，因为 RM 同步表中条目的字段次序
（NID 在前、IP 在后）与请求报文的 IP_NID 次序不一致，手工编解码更清晰可靠。
报文布局对照 color-agent-plus 的 ProxyLib.ControlPkt（tag=40 见 ColorMonitor.py:480-494）。
"""
from __future__ import annotations

from .constants import COLOR_VERSION, CONTROL_FIRST_BYTE, ControlSubtype, NID_LEN, SID_LEN
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


def parse_proxy_table_strict(payload: bytes) -> tuple[list[tuple[int, str]], list[tuple[int, str]]]:
    """严格解析"代理/BR 表"布局，不匹配即抛 ``ValueError``。

    与 ``parse_register_reply`` 同一布局，但额外要求解析**恰好**消耗
    ``Data_Length``(bytes 6-7 小端) 个字节。用于处理布局未经证实的子类型
    （如新代理通知 tag=8）：宁可报错让调用方打印原始字节，也不要把乱码
    当成 NID→IP 写进表里。
    """
    data_length = int.from_bytes(payload[6:8], "little")
    end = CONTROL_HEADER_LENGTH + data_length
    if end > len(payload):
        raise ValueError(f"Data_Length({data_length}) 超出报文实际长度({len(payload)})")

    pointer = CONTROL_HEADER_LENGTH
    entries: list[list[tuple[int, str]]] = []
    for id_len, byteorder in ((NID_LEN, "big"), (2, "little")):
        if pointer >= end:
            raise ValueError("负载在计数字段处提前结束")
        count = payload[pointer]
        pointer += 1
        group: list[tuple[int, str]] = []
        for _ in range(count):
            if pointer + id_len + 4 > end:
                raise ValueError("负载在条目中途结束，条目数与 Data_Length 不一致")
            ident = int.from_bytes(payload[pointer : pointer + id_len], byteorder)
            pointer += id_len
            group.append((ident, le_bytes_to_ipv4(payload[pointer : pointer + 4])))
            pointer += 4
        entries.append(group)

    if pointer != end:
        raise ValueError(f"解析后剩余 {end - pointer} 字节未消耗，布局不匹配")
    return entries[0], entries[1]


def trim_to_declared_length(payload: bytes) -> bytes:
    """按报文自述长度（``Header_Length + Data_Length``）截去尾部多余字节。

    校验和覆盖整个 CONTROL 报文，多一个字节就算不过。而收到的字节**可能比报文长**：
    短报文（一个代理、没有 BR 的 tag=6 就只有 30 字节）会被网卡补到以太网最小帧，
    scapy 把那几个填充字节一并算进 ``bytes(pkt.payload)``。参考实现
    color-agent-plus 用的是"长度对不上就整包丢弃"，这里选择截齐再校验——
    丢弃意味着注册永远不成功，而症状只是"RM 不回复"，极难定位。

    自述长度大于实际收到的字节数时原样返回：那是真的截断，应当让校验和去拦。
    """
    if len(payload) < CONTROL_HEADER_LENGTH:
        return payload
    declared = payload[4] + int.from_bytes(payload[6:8], "little")
    if CONTROL_HEADER_LENGTH <= declared < len(payload):
        return payload[:declared]
    return payload


def checksum_ok(payload: bytes) -> bool:
    """CONTROL 报文的校验和是否正确（先按自述长度截齐）。"""
    return calculate_checksum(trim_to_declared_length(payload)) == 0


def _is_control_subtype(payload: bytes, subtype: int) -> bool:
    if len(payload) < CONTROL_HEADER_LENGTH:
        return False
    if payload[0] != CONTROL_FIRST_BYTE or payload[5] != subtype:
        return False
    return checksum_ok(payload)


def is_proxy_notify(payload: bytes) -> bool:
    """判断是否为合法的新代理通知报文（Subtype=8 且校验和正确）。"""
    return _is_control_subtype(payload, ControlSubtype.PROXY_NOTIFY)


def is_register_reply(payload: bytes) -> bool:
    """判断是否为合法的 RM 同步报文（Subtype=6 且校验和正确）。"""
    return _is_control_subtype(payload, ControlSubtype.PROXY_REGISTER_REPLY)


def is_sid_list(payload: bytes) -> bool:
    """判断是否为合法的 RM 本域 SID 列表报文（Subtype=40 且校验和正确）。"""
    return _is_control_subtype(payload, ControlSubtype.SID_LIST_UPDATE)


def parse_sid_list(payload: bytes) -> list[str]:
    """解析 RM 本域 SID 列表报文（Subtype=40），返回完整 SID(72 hex) 列表。

    负载为裸的 SID 拼接，每 ``SID_LEN`` (36) 字节一个完整 SID（NSID‖LSID），
    按 ``Data_Length``(bytes 6-7 小端) 取负载范围、整 36 字节切分，末尾不足一个
    SID 的残余忽略。对照 color-agent-plus/ColorMonitor.py:484-487。
    """
    data_length = int.from_bytes(payload[6:8], "little")
    data = payload[CONTROL_HEADER_LENGTH : CONTROL_HEADER_LENGTH + data_length]
    return [
        data[off : off + SID_LEN].hex()
        for off in range(0, len(data) - SID_LEN + 1, SID_LEN)
    ]
