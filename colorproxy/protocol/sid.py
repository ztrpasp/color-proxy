"""SID 的生成与表示。

SID = N_sid(提供方 NID, 16 字节) ‖ L_sid(20 字节)，统一以 72 位十六进制字符串
作为内存中的键（与参考实现的 AnnSidUnits 约定一致）。L_sid 有两种粒度：

- **内容级**（v1，HTTP 模式）：``SHA1(去 query/fragment 后的 URL)``。
  SID 标识的是"资源"，故只取 scheme/host/path——同一 path、不同查询参数命中同一
  SID。query 仍会在请求传输链路（CoLoR 载荷与回源 TCP）中原样保留，只是不参与哈希。
- **服务级**（v2，L3 隧道模式）：``SHA1("<proto>://<ipv4>:<port>")``，见
  ``service_canonical``（docs/design-l3-v2.md §3.1，D12）。

两种粒度的哈希域按 scheme 天然隔离：内容级恒为 http/https，服务级恒为 tcp/udp。
"""
from __future__ import annotations

import hashlib
import ipaddress
from urllib.parse import urlsplit, urlunsplit

from .constants import LSID_LEN, NID_LEN, NSID_LEN

#: 服务级规范串允许的协议字面量（§3.1：协议必须入串，tcp/udp 是两个不同的服务）
SERVICE_PROTOCOLS = ("tcp", "udp")


def _canonical_for_sid(url: str) -> str:
    """计算 SID 用的规整 URL：保留 scheme/host/path，去掉 query 与 fragment。"""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def lsid_from_url(url: str) -> bytes:
    """L_sid = SHA1(去 query/fragment 后的 URL)，返回 20 字节。"""
    return hashlib.sha1(_canonical_for_sid(url).encode("utf-8")).digest()


def service_canonical(proto: str, ipv4: str, port: int) -> str:
    """服务级规范串 = ``<proto>://<ipv4>:<port>``（docs/design-l3-v2.md §3.1，D12）。

    示例：``tcp://172.10.0.2:8000``。两端必须逐字符一致，否则 SHA1 不匹配，因此
    **归一化集中在本函数**，两端一律经由它拼串：

    - ``proto``：小写字面量 tcp/udp，其余一律拒绝（`tcp://…:21` 与 `udp://…:21`
      是两个不同的服务）；
    - ``ipv4``：经 ``ipaddress.IPv4Address`` 归一化，``172.010.0.2`` 一类前导零写法
      被直接拒绝；
    - ``port``：十进制整数，``0`` 表示通配该 IP 上的全部端口（§3.3）。

    不合法即抛 ``ValueError``，由配置加载在启动时 fail-fast。这类错误的症状是
    "SID 永远对不上"（哈希一个字节不同就全不同），放到运行期查代价极高。
    """
    key = str(proto).strip().lower()
    if key not in SERVICE_PROTOCOLS:
        raise ValueError(
            f"服务协议只能是 {' / '.join(SERVICE_PROTOCOLS)}（小写），收到：{proto!r}"
        )
    try:
        ip = str(ipaddress.IPv4Address(str(ipv4).strip()))
    except ValueError as exc:  # AddressValueError 亦为 ValueError 子类
        raise ValueError(f"服务 IP 不是合法的点分 IPv4：{ipv4!r}（{exc}）") from exc
    try:
        port_num = int(port)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"服务端口不是整数：{port!r}") from exc
    if not 0 <= port_num <= 65535:
        raise ValueError(f"服务端口越界：{port_num}（应在 0–65535，0 表示通配）")
    return f"{key}://{ip}:{port_num}"


def lsid_from_service(proto: str, ipv4: str, port: int) -> bytes:
    """L_sid = SHA1(规范服务串)，返回 20 字节（§3.2；测试向量见 §3.4）。"""
    return hashlib.sha1(service_canonical(proto, ipv4, port).encode("ascii")).digest()


def nid_to_bytes(nid: int) -> bytes:
    """NID 整数转 16 字节大端。"""
    return nid.to_bytes(NID_LEN, "big")


def sid_hex(nsid: bytes, lsid: bytes) -> str:
    """由 N_sid / L_sid 字节拼接出 72 位十六进制 SID 字符串。"""
    return nsid.hex() + lsid.hex()


def sid_hex_from_url(provider_nid: int, url: str) -> str:
    """由提供方 NID 与 URL 直接生成 SID 十六进制字符串。"""
    return sid_hex(nid_to_bytes(provider_nid), lsid_from_url(url))


def sid_hex_from_service(provider_nid: int, proto: str, ipv4: str, port: int) -> str:
    """由提供方 NID 与服务三元组直接生成服务级 SID 十六进制字符串（§3.2）。"""
    return sid_hex(nid_to_bytes(provider_nid), lsid_from_service(proto, ipv4, port))


def split_sid_hex(sid: str) -> tuple[bytes, bytes]:
    """将 72 位十六进制 SID 拆为 (nsid_bytes, lsid_bytes)。"""
    nsid = bytes.fromhex(sid[: NSID_LEN * 2])
    lsid = bytes.fromhex(sid[NSID_LEN * 2 :])
    return nsid, lsid


def sid_hex_from_packet(nsid: bytes, lsid: bytes) -> str:
    """由报文中解析出的 NSID/LSID 字节生成 SID 字符串（长度容错）。"""
    return nsid.rjust(NSID_LEN, b"\x00").hex() + lsid.rjust(LSID_LEN, b"\x00").hex()
