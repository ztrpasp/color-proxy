"""SID 的生成与表示。

SID = N_sid(提供方 NID, 16 字节) ‖ L_sid(去 query 后 URL 的 SHA1, 20 字节)，
统一以 72 位十六进制字符串作为内存中的键（与参考实现的 AnnSidUnits 约定一致）。

注意：SID 标识的是"资源"，故计算 L_sid 时只取 scheme/host/path，去掉 query 与
fragment——同一 path、不同查询参数命中同一 SID。query 仍会在请求传输链路（CoLoR
载荷与回源 TCP）中原样保留，只是不参与 SID 哈希。
"""
from __future__ import annotations

import hashlib
from urllib.parse import urlsplit, urlunsplit

from .constants import LSID_LEN, NID_LEN, NSID_LEN


def _canonical_for_sid(url: str) -> str:
    """计算 SID 用的规整 URL：保留 scheme/host/path，去掉 query 与 fragment。"""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def lsid_from_url(url: str) -> bytes:
    """L_sid = SHA1(去 query/fragment 后的 URL)，返回 20 字节。"""
    return hashlib.sha1(_canonical_for_sid(url).encode("utf-8")).digest()


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
