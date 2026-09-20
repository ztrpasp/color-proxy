"""tun 设备抽象（docs/design-l3-v2.md §10.1 / §10.2）。

数据面只依赖本模块的 ``TunDevice`` 接口，平台实现（Wintun / ``/dev/net/tun``）各自
满足它。好处有两个：

1. §7.1 / §7.2 的全部逻辑（含 §7.3 的准入校验）可以用 ``LoopbackTun`` 在纯内存里
   跑通，不需要管理员权限、不需要 wintun.dll、不需要真网卡；
2. Wintun 与 Linux tun 的语义本就一致（都是纯 L3、无以太头），接口能真正共用，
   只有 ``device_*.py`` 不同。
"""
from __future__ import annotations

import queue
import threading
from typing import Protocol


class TunDevice(Protocol):
    """tun 设备的最小接口：读一个完整 IP 包、写一个完整 IP 包。

    读写的都是**内层**报文（路径二，§1.1），永远不含以太头。
    """

    @property
    def name(self) -> str: ...

    @property
    def mtu(self) -> int: ...

    def read(self, timeout: float | None = None) -> bytes | None:
        """读一个完整内层 IP 包；超时返回 ``None``。"""
        ...

    def write(self, packet: bytes) -> None:
        """把一个完整内层 IP 包交给协议栈（提供端据此注入，§1.4）。"""
        ...

    def close(self) -> None: ...


class LoopbackTun:
    """内存 tun，供离线测试与单机回环（M1c）使用。

    两个方向分开，不会自己读到自己写的包——真 tun 也是这个语义：

    - ``inject(packet)``：模拟"协议栈发出一个包"，数据面会从 ``read()`` 读到它；
    - ``write(packet)``：数据面注入的包落进 ``sent``，测试用 ``pop_written()`` 取。
    """

    def __init__(self, name: str = "color0", mtu: int = 1280) -> None:
        self._name = name
        self._mtu = mtu
        self._inbound: queue.Queue[bytes] = queue.Queue()
        self._written: list[bytes] = []
        self._lock = threading.Lock()
        self.closed = False

    @property
    def name(self) -> str:
        return self._name

    @property
    def mtu(self) -> int:
        return self._mtu

    # -- 数据面侧 ----------------------------------------------------------

    def read(self, timeout: float | None = None) -> bytes | None:
        try:
            return self._inbound.get(timeout=timeout) if timeout else self._inbound.get_nowait()
        except queue.Empty:
            return None

    def write(self, packet: bytes) -> None:
        if self.closed:
            raise OSError("tun 已关闭")
        with self._lock:
            self._written.append(bytes(packet))

    def close(self) -> None:
        self.closed = True

    # -- 测试侧 ------------------------------------------------------------

    def inject(self, packet: bytes) -> None:
        """模拟本机协议栈发出一个包，数据面会读到它。"""
        self._inbound.put(bytes(packet))

    def pop_written(self) -> list[bytes]:
        """取出并清空数据面写进 tun 的包。"""
        with self._lock:
            written, self._written = self._written, []
        return written
