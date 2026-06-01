"""SID 的生成与表示。

SID = N_sid(提供方 NID, 16 字节) ‖ L_sid(完整 URL 的 SHA1, 20 字节)，
统一以 72 位十六进制字符串作为内存中的键（与参考实现的 AnnSidUnits 约定一致）。
"""
from __future__ import annotations

import hashlib

from .constants import LSID_LEN, NID_LEN, NSID_LEN


def lsid_from_url(url: str) -> bytes:
    """L_sid = SHA1(完整 URL)，返回 20 字节。"""
    return hashlib.sha1(url.encode("utf-8")).digest()


def nid_to_bytes(nid: int) -> bytes:
    """NID 整数转 16 字节大端。"""
    return nid.to_bytes(NID_LEN, "big")


def sid_hex(nsid: bytes, lsid: bytes) -> str:
    """由 N_sid / L_sid 字节拼接出 72 位十六进制 SID 字符串。"""
    return nsid.hex() + lsid.hex()


def sid_hex_from_url(provider_nid: int, url: str) -> str:
    """由提供方 NID 与 URL 直接生成 SID 十六进制字符串。"""
    return sid_hex(nid_to_bytes(provider_nid), lsid_from_url(url))


def split_sid_hex(sid: str) -> tuple[bytes, bytes]:
    """将 72 位十六进制 SID 拆为 (nsid_bytes, lsid_bytes)。"""
    nsid = bytes.fromhex(sid[: NSID_LEN * 2])
    lsid = bytes.fromhex(sid[NSID_LEN * 2 :])
    return nsid, lsid


def sid_hex_from_packet(nsid: bytes, lsid: bytes) -> str:
    """由报文中解析出的 NSID/LSID 字节生成 SID 字符串（长度容错）。"""
    return nsid.rjust(NSID_LEN, b"\x00").hex() + lsid.rjust(LSID_LEN, b"\x00").hex()
