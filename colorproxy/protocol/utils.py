"""CoLoR 报文通用编解码工具。"""
from __future__ import annotations


def calculate_checksum(data: bytes) -> int:
    """计算 CoLoR 16 位反码和校验和。

    算法对照 color-agent-plus 的 CalculateCS：以大端 2 字节为一个字累加，
    末尾折叠进位两次，再按位取反。校验通过的条件是对「含校验和字段」的
    覆盖区再次计算结果为 0。
    """
    total = 0
    for i in range(0, len(data) - 1, 2):
        total += (data[i] << 8) | data[i + 1]
    if len(data) % 2:
        total += data[-1] << 8
    total = (total >> 16) + (total & 0xFFFF)
    total = (total >> 16) + (total & 0xFFFF)
    return total ^ 0xFFFF


def verify_checksum(data: bytes) -> bool:
    """校验覆盖区（含校验和字段）是否合法。"""
    return calculate_checksum(data) == 0


def int_to_bytes_be(value: int, length: int) -> bytes:
    """整数转大端字节串。"""
    return value.to_bytes(length, "big")


def int_to_bytes_le(value: int, length: int) -> bytes:
    """整数转小端字节串。"""
    return value.to_bytes(length, "little")


def ipv4_to_le_bytes(ipv4: str) -> bytes:
    """点分 IPv4 转 4 字节小端序（即按八位组逆序），与参考实现一致。"""
    return bytes(int(octet) for octet in reversed(ipv4.split(".")))


def le_bytes_to_ipv4(data: bytes) -> str:
    """4 字节小端序还原为点分 IPv4。"""
    return ".".join(str(byte) for byte in reversed(data))
