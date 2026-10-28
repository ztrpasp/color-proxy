"""CONTROL 控制报文的手工编解码。

实现本项目需要的子类型：
- 注册请求（Subtype=5）：终端 -> RM
- 域内同步（Subtype=6）：RM -> 终端，下发 Proxy/BR 信息
- 新代理通知（Subtype=8）：RM -> 域内其他终端，转发新注册代理的 IP/NID
- SID 列表（Subtype=40）：RM -> 终端，下发本域可访问 SID 列表（消费端用）

**代理条目一律是 IP 在前、NID 在后**，与注册请求（Subtype=5）的载荷相同。依据是 RM 源码
``src/packets/ctrl.c``：the-new-rm-master、the-rm-server、the-rm-server-web 三个版本都先写
``ip_addr`` 再写 ``nid``。那段代码上方的注释写着 ``[NID IP]``，与代码相反，以代码为准。
tag=8 是 RM 把新代理的注册载荷原样转发，所以布局也一样。

2026-10-28 之前，这里照抄了 color-agent-plus 的 ``ProxyLib.ControlPkt``，按 NID 在前解析。
结果同域回址在两端都查不到；跨域只用 BR 表，没有受影响。color-agent-plus 自己的 scapy 定义
``CoLoRpacket.IP_NID`` 其实是对的，只是没被用来填表。

仍然手工编解码而不用 scapy：tag=6 是「条目数 + 两张变长表」的结构，校验前还要按自述长度
截掉以太网填充（见 ``trim_to_declared_length``）。tag=40 的布局见 color-agent-plus 的
ColorMonitor.py:480-494。
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
#: 代理条目 = IP(4 字节小端) + NID(16 字节大端)。tag=6 的每个表项、tag=8 的整个载荷都是它
PROXY_ENTRY_LENGTH = 4 + NID_LEN
#: BR 条目 = PX(2 字节小端) + IP(4 字节小端)
BR_ENTRY_LENGTH = 2 + 4


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


def _parse_proxy_entry(payload: bytes, offset: int) -> tuple[int, str]:
    """从 ``offset`` 处取一个代理条目（IP 在前、NID 在后），返回 ``(nid, ip)``。"""
    ip = le_bytes_to_ipv4(payload[offset : offset + 4])
    nid = int.from_bytes(payload[offset + 4 : offset + PROXY_ENTRY_LENGTH], "big")
    return nid, ip


def _declared_end(payload: bytes) -> int:
    """负载结束位置（头长 + ``Data_Length``）。自述长度超出实际收到的字节数时抛 ``ValueError``。"""
    data_length = int.from_bytes(payload[6:8], "little")
    end = CONTROL_HEADER_LENGTH + data_length
    if end > len(payload):
        raise ValueError(f"Data_Length({data_length}) 超出报文实际长度({len(payload)})")
    return end


def _read_count(payload: bytes, pointer: int, end: int, entry_length: int) -> int:
    """读 ``pointer`` 处的条目数，并确认后面放得下这么多条目。"""
    if pointer >= end:
        raise ValueError("负载在条目数字段处提前结束")
    count = payload[pointer]
    if pointer + 1 + count * entry_length > end:
        raise ValueError(f"条目数 {count} 与 Data_Length 不一致")
    return count


def parse_register_reply(payload: bytes) -> tuple[list[tuple[int, str]], list[tuple[int, str]]]:
    """解析 RM 同步报文（Subtype=6），返回 (proxies, brs)。

    负载 = 代理数(1) + 代理条目 × n + BR 数(1) + BR 条目 × m：

    - proxies: ``[(nid, ip), ...]``，每条 = IP(4 字节小端) + NID(16 字节大端)
    - brs:     ``[(px, ip), ...]``，每条 = PX(2 字节小端) + IP(4 字节小端)

    条目数与 ``Data_Length`` 对不上时抛 ``ValueError``，不把越界读到的字节当成表项。
    """
    end = _declared_end(payload)
    pointer = CONTROL_HEADER_LENGTH

    num_proxies = _read_count(payload, pointer, end, PROXY_ENTRY_LENGTH)
    pointer += 1
    proxies: list[tuple[int, str]] = []
    for _ in range(num_proxies):
        proxies.append(_parse_proxy_entry(payload, pointer))
        pointer += PROXY_ENTRY_LENGTH

    num_brs = _read_count(payload, pointer, end, BR_ENTRY_LENGTH)
    pointer += 1
    brs: list[tuple[int, str]] = []
    for _ in range(num_brs):
        px = int.from_bytes(payload[pointer : pointer + 2], "little")
        brs.append((px, le_bytes_to_ipv4(payload[pointer + 2 : pointer + BR_ENTRY_LENGTH])))
        pointer += BR_ENTRY_LENGTH

    return proxies, brs


def parse_proxy_notify(payload: bytes) -> tuple[int, str]:
    """解析新代理通知（Subtype=8），返回 ``(nid, ip)``。

    有代理来注册时，RM 把那份注册载荷原样转发给域内其他代理（ctrl.c 里的
    ``CONTROL_SYN_CONFIG_PROXY``）：IP(4 字节小端) + NID(16 字节大端)，共 20 字节，
    **没有条目数字段**。color-agent-plus 的 ``ProxyLib.ControlPkt`` 也是按这个布局解析的。

    ``Data_Length`` 不是 20 时抛 ``ValueError``：宁可学不到，也不把乱码当成 NID→IP 写进表。
    """
    end = _declared_end(payload)
    if end - CONTROL_HEADER_LENGTH != PROXY_ENTRY_LENGTH:
        raise ValueError(
            f"Data_Length 应为 {PROXY_ENTRY_LENGTH}，实为 {end - CONTROL_HEADER_LENGTH}"
        )
    return _parse_proxy_entry(payload, CONTROL_HEADER_LENGTH)


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
