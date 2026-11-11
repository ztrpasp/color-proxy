"""Linux 上的 tun 设备（docs/design-l3-v2.md §10.2）：``/dev/net/tun`` + ``TUNSETIFF``。

与 ``device_win.WintunDevice`` 同一套接口（``TunDevice`` 的 read/write/close，外加装配层
用到的 open/configure/add_route），由 ``tun/factory.py`` 在 Linux 上选用，``l3/`` 一行不改。

- 建网卡：``IFF_TUN | IFF_NO_PI``，读写的都是不带以太头、不带 4 字节包信息头的纯 IP 包，
  与 Wintun 语义一致。
- 地址、MTU、路由用 iproute2 的 ``ip`` 命令配。进程需要 ``CAP_NET_ADMIN``；在容器里即
  ``cap_add: NET_ADMIN`` 并把 ``/dev/net/tun`` 挂进来。
- 网卡是非持久的：fd 一关，内核就把网卡连同地址、路由一起删掉，不会像 Wintun 那样留下
  半开的适配器。

Windows 才有的几件事（弱主机开关、防火墙、``check_local_address``）在 Linux 上不需要：
Linux 默认就是弱主机模型，``l3/service.py`` 在非 Windows 平台上已跳过这些检查。
"""
from __future__ import annotations

import fcntl
import ipaddress
import logging
import os
import select
import struct
import subprocess

logger = logging.getLogger(__name__)

#: <linux/if_tun.h>
TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

#: 网卡名上限（IFNAMSIZ 含结尾的 NUL）
IFNAMSIZ = 16
#: 单次读的缓冲：tun 一次 read 只返回一个包，65535 足够任何 IPv4 包
MAX_IP_PACKET_SIZE = 0xFFFF

TUN_CLONE_DEVICE = "/dev/net/tun"


def mask_to_prefixlen(mask: str) -> int:
    """``255.255.255.0`` → ``24``。不连续的掩码直接报错，不猜。"""
    return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen


def pack_ifreq(name: str, flags: int) -> bytes:
    """``struct ifreq`` 里 TUNSETIFF 用到的部分：16 字节网卡名 + 2 字节 flags。"""
    encoded = name.encode("ascii")
    if not encoded or len(encoded) >= IFNAMSIZ:
        raise ValueError(f"tun 网卡名须为 1–{IFNAMSIZ - 1} 个 ASCII 字符，收到 {name!r}")
    return struct.pack(f"{IFNAMSIZ}sH", encoded, flags)


class LinuxTunDevice:
    """``/dev/net/tun`` 上的一个 L3 tun 网卡。"""

    def __init__(self, name: str, mtu: int) -> None:
        pack_ifreq(name, 0)  # 提前校验网卡名，open() 之前就报错
        self._name = name
        self._mtu = mtu
        self._fd: int | None = None
        self._routes: list[str] = []

    # ---------------------------------------------------------------- 属性

    @property
    def name(self) -> str:
        return self._name

    @property
    def mtu(self) -> int:
        return self._mtu

    @property
    def fileno(self) -> int | None:
        return self._fd

    # ---------------------------------------------------------------- 生命周期

    def open(self) -> None:
        """建网卡、设 MTU 并拉起。失败时不留下打开的 fd。"""
        try:
            fd = os.open(TUN_CLONE_DEVICE, os.O_RDWR | os.O_CLOEXEC)
        except FileNotFoundError as exc:
            raise OSError(
                exc.errno,
                f"{TUN_CLONE_DEVICE} 不存在。容器里要用 devices 把它挂进来，宿主机上先 modprobe tun",
            ) from exc
        try:
            fcntl.ioctl(fd, TUNSETIFF, pack_ifreq(self._name, IFF_TUN | IFF_NO_PI))
            os.set_blocking(fd, False)
        except OSError as exc:
            os.close(fd)
            raise OSError(
                exc.errno,
                f"TUNSETIFF({self._name!r}) 失败：{exc.strerror}。"
                "最常见原因是缺 CAP_NET_ADMIN（容器里 cap_add: NET_ADMIN）",
            ) from exc
        self._fd = fd
        try:
            _ip("link", "set", "dev", self._name, "mtu", str(self._mtu), "up")
        except Exception:
            self.close()
            raise
        logger.info("tun 网卡 %s 已就绪（/dev/net/tun，MTU=%d）", self._name, self._mtu)

    def configure(self, ip: str, mask: str) -> None:
        """配地址与 MTU。用 replace，重复调用不会报"地址已存在"。"""
        prefixlen = mask_to_prefixlen(mask)
        _ip("addr", "replace", f"{ip}/{prefixlen}", "dev", self._name)
        _ip("link", "set", "dev", self._name, "mtu", str(self._mtu))
        logger.info("已配置 %s：%s/%d MTU=%d", self._name, ip, prefixlen, self._mtu)

    def add_route(self, cidr: str) -> None:
        """加一条指向本网卡的路由（消费端只允许 /32，已由配置加载强制，§2.4）。"""
        _ip("route", "replace", cidr, "dev", self._name)
        self._routes.append(cidr)
        logger.info("已加路由 %s → %s", cidr, self._name)

    def close(self) -> None:
        """关 fd。内核随之删掉网卡和它上面的地址、路由。可重复调用。"""
        fd, self._fd = self._fd, None
        self._routes.clear()
        if fd is not None:
            os.close(fd)
            logger.info("tun 网卡 %s 已删除", self._name)

    # ---------------------------------------------------------------- 读写

    def read(self, timeout: float | None = None) -> bytes | None:
        """读一个完整内层 IP 包；``timeout`` 秒内没有包返回 ``None``（``None`` 表示一直等）。"""
        fd = self._fd
        if fd is None:
            raise OSError("tun 未打开或已关闭")
        packet = self._read_nowait(fd)
        if packet is not None:
            return packet
        ready, _, _ = select.select([fd], [], [], timeout)
        if self._fd != fd:
            # 等待期间被 close()：fd 号可能已被别的文件复用，不能再读
            raise OSError("tun 已关闭")
        if not ready:
            return None
        return self._read_nowait(fd)

    @staticmethod
    def _read_nowait(fd: int) -> bytes | None:
        try:
            return os.read(fd, MAX_IP_PACKET_SIZE)
        except BlockingIOError:
            return None

    def write(self, packet: bytes) -> None:
        """把一个完整内层 IP 包交给本机协议栈。

        内核队列满时抛 ``BlockingIOError``，与 Wintun 发送环满的语义相同：调用方计数后继续。
        """
        fd = self._fd
        if fd is None:
            raise OSError("tun 未打开或已关闭")
        length = len(packet)
        if length == 0 or length > MAX_IP_PACKET_SIZE:
            raise ValueError(f"内层包长度非法：{length}")
        os.write(fd, packet)


def _ip(*args: str) -> None:
    """跑一条 ``ip`` 命令，失败时把 stderr 带进异常。"""
    command = ["ip", *args]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except FileNotFoundError as exc:
        raise OSError(exc.errno, "找不到 ip 命令，请安装 iproute2") from exc
    if result.returncode != 0:
        raise OSError(f"{' '.join(command)} 失败：{result.stderr.strip() or result.returncode}")
