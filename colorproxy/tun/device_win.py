"""Wintun 封装（Windows，docs/design-l3-v2.md §10.2，D7）。

函数签名逐条照 ``include/wintun.h`` 声明，不凭记忆。Wintun 是 WireGuard 项目出品的
L3 tun 驱动：签名驱动、无独立安装程序（``wintun.dll`` 自带驱动、进程内创建适配器）、
基于环形缓冲零拷贝。选它而不选 tap-windows6（二层、要自己处理 ARP/以太头、要单独装
驱动）或 WinDivert（不是 tun，与 Linux 的 ``/dev/net/tun`` 完全不共用代码）。

**需要管理员权限**：创建适配器、配地址、配路由都要。非提权进程连
``WintunCreateAdapter`` 都会失败（ERROR_ACCESS_DENIED）。

读是阻塞事件驱动，**必须单独一个线程读**，不要和 CoLoR 收包线程混在一起（§1.2/§1.3）。
"""
from __future__ import annotations

import ctypes
import logging
import subprocess
from ctypes import wintypes
from pathlib import Path

logger = logging.getLogger(__name__)
_wintun_logger = logging.getLogger(f"{__name__}.driver")

#: 环形缓冲容量：必须是 2 的幂，且在 [128 KiB, 64 MiB] 之内（wintun.h）
WINTUN_MIN_RING_CAPACITY = 0x20000
WINTUN_MAX_RING_CAPACITY = 0x4000000
DEFAULT_RING_CAPACITY = 0x400000  # 4 MiB
#: 单个 IP 包上限（wintun.h WINTUN_MAX_IP_PACKET_SIZE）
WINTUN_MAX_IP_PACKET_SIZE = 0xFFFF

#: WintunReceivePacket / WintunAllocateSendPacket 可能返回的 GetLastError 值
ERROR_INVALID_DATA = 13
ERROR_HANDLE_EOF = 38
ERROR_BUFFER_OVERFLOW = 111
ERROR_NO_MORE_ITEMS = 259

#: WaitForSingleObject
_WAIT_OBJECT_0 = 0x00000000
_WAIT_TIMEOUT = 0x00000102
_INFINITE = 0xFFFFFFFF

#: wintun.dll 的候选位置。§10.2 要求与主程序同目录；bin/amd64/ 是官方压缩包的布局。
_DLL_CANDIDATES = ("wintun.dll", "bin/amd64/wintun.dll", "bin/wintun.dll")

_WINTUN_LOGGER_CALLBACK = ctypes.WINFUNCTYPE(None, ctypes.c_int, ctypes.c_ulonglong, wintypes.LPCWSTR)
_LOG_LEVELS = (logging.INFO, logging.WARNING, logging.ERROR)
#: 保住回调对象的引用，否则会被 GC 回收、驱动回调时进程直接崩
_logger_callback_ref: object | None = None


class NET_LUID(ctypes.Structure):
    """``ifdef.h`` 的 NET_LUID：一个 64 位整数（联合体的 Value 成员）。"""

    _fields_ = [("Value", ctypes.c_ulonglong)]


def find_wintun_dll(root: Path | None = None) -> Path:
    """在候选位置里找 ``wintun.dll``。找不到时报错并说清该放哪。"""
    base = root if root is not None else Path(__file__).resolve().parents[2]
    for relative in _DLL_CANDIDATES:
        candidate = base / relative
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        f"未找到 wintun.dll。请从 https://www.wintun.net/ 下载后放到 {base} 下的任一位置："
        f"{'、'.join(_DLL_CANDIDATES)}（架构须与 Python 一致，64 位 Python 用 bin/amd64/）"
    )


class Wintun:
    """``wintun.dll`` 的 ctypes 绑定。一个进程加载一次即可。"""

    def __init__(self, dll_path: Path | None = None) -> None:
        self.dll_path = dll_path if dll_path is not None else find_wintun_dll()
        # WINAPI = stdcall，故用 WinDLL；use_last_error 让 GetLastError 可靠
        self._dll = ctypes.WinDLL(str(self.dll_path), use_last_error=True)
        self._bind()
        logger.info("已加载 %s", self.dll_path)

    def _bind(self) -> None:
        dll = self._dll
        handle = ctypes.c_void_p

        dll.WintunCreateAdapter.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p]
        dll.WintunCreateAdapter.restype = handle
        dll.WintunOpenAdapter.argtypes = [wintypes.LPCWSTR]
        dll.WintunOpenAdapter.restype = handle
        dll.WintunCloseAdapter.argtypes = [handle]
        dll.WintunCloseAdapter.restype = None
        dll.WintunGetAdapterLUID.argtypes = [handle, ctypes.POINTER(NET_LUID)]
        dll.WintunGetAdapterLUID.restype = None
        dll.WintunGetRunningDriverVersion.argtypes = []
        dll.WintunGetRunningDriverVersion.restype = wintypes.DWORD
        dll.WintunSetLogger.argtypes = [_WINTUN_LOGGER_CALLBACK]
        dll.WintunSetLogger.restype = None

        dll.WintunStartSession.argtypes = [handle, wintypes.DWORD]
        dll.WintunStartSession.restype = handle
        dll.WintunEndSession.argtypes = [handle]
        dll.WintunEndSession.restype = None
        dll.WintunGetReadWaitEvent.argtypes = [handle]
        dll.WintunGetReadWaitEvent.restype = wintypes.HANDLE

        dll.WintunReceivePacket.argtypes = [handle, ctypes.POINTER(wintypes.DWORD)]
        dll.WintunReceivePacket.restype = ctypes.POINTER(ctypes.c_ubyte)
        dll.WintunReleaseReceivePacket.argtypes = [handle, ctypes.POINTER(ctypes.c_ubyte)]
        dll.WintunReleaseReceivePacket.restype = None
        dll.WintunAllocateSendPacket.argtypes = [handle, wintypes.DWORD]
        dll.WintunAllocateSendPacket.restype = ctypes.POINTER(ctypes.c_ubyte)
        dll.WintunSendPacket.argtypes = [handle, ctypes.POINTER(ctypes.c_ubyte)]
        dll.WintunSendPacket.restype = None

    @property
    def dll(self) -> ctypes.WinDLL:
        return self._dll

    def driver_version(self) -> int:
        """已加载驱动的版本号；驱动未加载时返回 0（此时 GetLastError=ERROR_FILE_NOT_FOUND）。"""
        return int(self._dll.WintunGetRunningDriverVersion())

    def route_driver_log(self) -> None:
        """把 Wintun 自己的日志接进 Python logging。

        适配器创建失败的真正原因（驱动安装、签名、设备实例冲突）只会出现在这里，
        M1b 阶段没有它基本是盲调。
        """
        global _logger_callback_ref

        def _sink(level: int, _timestamp: int, message: str) -> None:
            _wintun_logger.log(_LOG_LEVELS[level] if 0 <= level < 3 else logging.INFO, "%s", message)

        _logger_callback_ref = _WINTUN_LOGGER_CALLBACK(_sink)
        self._dll.WintunSetLogger(_logger_callback_ref)


class WintunDevice:
    """``TunDevice`` 的 Windows 实现：一个 Wintun 适配器 + 一个会话。

    生命周期按 §10.2 的启动顺序：创建适配器 → 配地址/MTU → 配路由 → （提供端）开弱主机
    开关 → 放行防火墙 → 再开始收发；退出时删除路由与适配器。本类负责前三步与读写，
    弱主机开关按 §9.1 只**检查并告警**、不擅自改系统配置。
    """

    def __init__(
        self,
        name: str = "color0",
        mtu: int = 1280,
        *,
        tunnel_type: str = "CoLoR",
        ring_capacity: int = DEFAULT_RING_CAPACITY,
        wintun: Wintun | None = None,
    ) -> None:
        if not WINTUN_MIN_RING_CAPACITY <= ring_capacity <= WINTUN_MAX_RING_CAPACITY:
            raise ValueError(
                f"ring_capacity 须在 [{WINTUN_MIN_RING_CAPACITY:#x}, {WINTUN_MAX_RING_CAPACITY:#x}]"
            )
        if ring_capacity & (ring_capacity - 1):
            raise ValueError(f"ring_capacity 须为 2 的幂，收到 {ring_capacity:#x}")

        self._name = name
        self._mtu = mtu
        self._tunnel_type = tunnel_type
        self._ring_capacity = ring_capacity
        self._wintun = wintun if wintun is not None else Wintun()
        self._adapter: ctypes.c_void_p | None = None
        self._session: ctypes.c_void_p | None = None
        self._read_event: wintypes.HANDLE | None = None
        self._luid: int | None = None
        self._routes: list[str] = []

    # ---------------------------------------------------------------- 属性

    @property
    def name(self) -> str:
        return self._name

    @property
    def mtu(self) -> int:
        return self._mtu

    @property
    def luid(self) -> int | None:
        return self._luid

    # ---------------------------------------------------------------- 生命周期

    def open(self) -> None:
        """创建适配器并开启会话。失败时抛出带 Windows 错误码的 OSError。"""
        dll = self._wintun.dll
        adapter = dll.WintunCreateAdapter(self._name, self._tunnel_type, None)
        if not adapter:
            code = ctypes.get_last_error()
            raise OSError(
                code,
                f"WintunCreateAdapter({self._name!r}) 失败：{ctypes.FormatError(code)}。"
                "最常见原因是进程未以管理员权限运行",
            )
        self._adapter = ctypes.c_void_p(adapter)

        luid = NET_LUID()
        dll.WintunGetAdapterLUID(self._adapter, ctypes.byref(luid))
        self._luid = int(luid.Value)

        session = dll.WintunStartSession(self._adapter, self._ring_capacity)
        if not session:
            code = ctypes.get_last_error()
            self._close_adapter()
            raise OSError(code, f"WintunStartSession 失败：{ctypes.FormatError(code)}")
        self._session = ctypes.c_void_p(session)
        self._read_event = dll.WintunGetReadWaitEvent(self._session)
        logger.info("Wintun 适配器 %s 已就绪（LUID=%#x，环形缓冲 %d KiB）",
                    self._name, self._luid, self._ring_capacity // 1024)

    def configure(self, ip: str, mask: str) -> None:
        """配地址与 MTU（§10.2：适配器创建后不会自动配 IP）。"""
        _netsh("interface", "ipv4", "set", "address",
               f"name={self._name}", "static", ip, mask)
        _netsh("interface", "ipv4", "set", "subinterface",
               self._name, f"mtu={self._mtu}", "store=active")
        logger.info("已配置 %s：%s/%s MTU=%d", self._name, ip, mask, self._mtu)

    def add_route(self, cidr: str) -> None:
        """加一条指向本设备的路由。

        §2.4 的硬性要求：消费端**只配 /32 主机路由**——粗网段会把对端域的 RM/BR
        一起吞进 tun，外层 CoLoR 包被自己的路由表吞掉，链路彻底死锁。该约束在
        配置加载时已强制（``consumer/config.py``），这里只负责下发。
        """
        _netsh("interface", "ipv4", "add", "route", cidr, f"interface={self._name}",
               "store=active")
        self._routes.append(cidr)
        logger.info("已加路由 %s → %s", cidr, self._name)

    def close(self) -> None:
        """删路由、结束会话、删除适配器。可重复调用。"""
        for cidr in reversed(self._routes):
            try:
                _netsh("interface", "ipv4", "delete", "route", cidr,
                       f"interface={self._name}", "store=active")
            except OSError:
                logger.warning("删除路由 %s 失败（可能随适配器一起消失了）", cidr)
        self._routes.clear()

        if self._session is not None:
            self._wintun.dll.WintunEndSession(self._session)
            self._session = None
            self._read_event = None
        self._close_adapter()

    def _close_adapter(self) -> None:
        if self._adapter is not None:
            self._wintun.dll.WintunCloseAdapter(self._adapter)
            self._adapter = None
            logger.info("Wintun 适配器 %s 已删除", self._name)

    # ---------------------------------------------------------------- 读写

    def read(self, timeout: float | None = None) -> bytes | None:
        """读一个完整内层 IP 包；超时返回 ``None``。

        Wintun 的读是环形缓冲 + 事件驱动：``WintunReceivePacket`` 立即返回，取不到
        时置 ``ERROR_NO_MORE_ITEMS``，需在读事件上等。返回的指针指向驱动的环形缓冲，
        **必须**用 ``WintunReleaseReceivePacket`` 归还，否则环很快耗尽。
        """
        if self._session is None:
            raise OSError("tun 会话未开启，请先 open()")
        dll = self._wintun.dll
        deadline_ms = _INFINITE if timeout is None else max(0, int(timeout * 1000))

        while True:
            size = wintypes.DWORD(0)
            packet = dll.WintunReceivePacket(self._session, ctypes.byref(size))
            if packet:
                try:
                    return bytes(ctypes.cast(
                        packet, ctypes.POINTER(ctypes.c_ubyte * size.value)
                    ).contents)
                finally:
                    dll.WintunReleaseReceivePacket(self._session, packet)

            code = ctypes.get_last_error()
            if code == ERROR_NO_MORE_ITEMS:
                if _wait_for_event(self._read_event, deadline_ms) == _WAIT_TIMEOUT:
                    return None
                continue
            if code == ERROR_HANDLE_EOF:
                raise OSError(code, "Wintun 适配器正在终止（ERROR_HANDLE_EOF）")
            raise OSError(code, f"WintunReceivePacket 失败：{ctypes.FormatError(code)}")

    def write(self, packet: bytes) -> None:
        """把一个完整内层 IP 包交给本机协议栈（§1.4 的 ``write(tun)`` 注入）。

        环满时抛 ``BlockingIOError``：这是丢包而非致命错误，调用方应计数后继续
        （数据面本就是尽力而为，堵住整条路更糟）。
        """
        if self._session is None:
            raise OSError("tun 会话未开启，请先 open()")
        length = len(packet)
        if length == 0 or length > WINTUN_MAX_IP_PACKET_SIZE:
            raise ValueError(f"内层包长度非法：{length}")

        dll = self._wintun.dll
        buffer = dll.WintunAllocateSendPacket(self._session, length)
        if not buffer:
            code = ctypes.get_last_error()
            if code == ERROR_BUFFER_OVERFLOW:
                raise BlockingIOError(code, "Wintun 发送环已满，丢弃该包")
            raise OSError(code, f"WintunAllocateSendPacket 失败：{ctypes.FormatError(code)}")
        # 分配成功后必须 send，否则这一格永远不释放、环会逐渐耗尽
        ctypes.memmove(buffer, packet, length)
        dll.WintunSendPacket(self._session, buffer)


def _wait_for_event(event: wintypes.HANDLE | None, timeout_ms: int) -> int:
    if event is None:
        raise OSError("读事件不可用")
    return ctypes.windll.kernel32.WaitForSingleObject(event, timeout_ms)


def _netsh(*args: str) -> str:
    """跑一条 netsh 命令，失败抛 OSError（带 netsh 自己的输出，便于定位）。"""
    command = ("netsh", *args)
    logger.debug("执行：%s", " ".join(command))
    result = subprocess.run(command, capture_output=True, text=True, encoding="mbcs", errors="replace")
    if result.returncode != 0:
        raise OSError(
            f"命令失败（退出码 {result.returncode}）：{' '.join(command)}\n"
            f"{result.stdout.strip()} {result.stderr.strip()}".strip()
        )
    return result.stdout


def interface_state(interface: str) -> dict[str, object | None]:
    """读取接口的索引、MTU 与弱主机模型开关（§2.3 / §2.6 第 2 条）。

    **不解析 netsh 的输出**：netsh 是本地化的，中文 Windows 打印的是「弱主机发送 /
    弱主机接收」而不是 weakhostsend/weakhostreceive，按英文键名解析会永远匹配不到，
    症状是"开关明明开了、程序还一直告警"。PowerShell 的 ``Get-NetIPInterface`` 返回
    结构化对象，属性名与枚举值（Enabled/Disabled）都与语言无关，故用它。

    取不到的项为 ``None``（调用方按"未确认"处理，不要当成"已关闭"）。
    """
    unknown: dict[str, object | None] = {
        "index": None, "mtu": None, "weak_host_send": None, "weak_host_receive": None,
    }
    quoted = interface.replace("'", "''")
    # 用 -join 而不是格式串：反引号转义在 PowerShell 的**单引号**串里不生效，
    # 写 '{0}`t{1}' 会原样输出 "`t" 而不是制表符（踩过一次）。
    script = (
        f"$i = Get-NetIPInterface -InterfaceAlias '{quoted}' -AddressFamily IPv4 "
        "-ErrorAction Stop | Select-Object -First 1; "
        "($i.InterfaceIndex, $i.WeakHostSend, $i.WeakHostReceive, $i.NlMtu) -join '|'"
    )
    try:
        result = subprocess.run(
            ("powershell", "-NoProfile", "-NonInteractive", "-Command", script),
            capture_output=True, text=True, encoding="mbcs", errors="replace",
        )
    except OSError as exc:
        logger.warning("无法执行 PowerShell 查询接口 %s：%s", interface, exc)
        return unknown
    if result.returncode != 0:
        logger.warning("查询接口 %s 失败（接口不存在？）：%s", interface,
                       (result.stderr or result.stdout).strip().splitlines()[:1])
        return unknown

    fields = result.stdout.strip().split("|")
    if len(fields) != 4:
        logger.warning("接口 %s 的查询结果无法解析：%r", interface, result.stdout)
        return unknown
    index, send, receive, mtu = fields
    return {
        "index": int(index) if index.isdigit() else None,
        "mtu": int(mtu) if mtu.isdigit() else None,
        "weak_host_send": send.strip().lower() == "enabled",
        "weak_host_receive": receive.strip().lower() == "enabled",
    }


def check_local_address(ip: str) -> tuple[bool, str, str | None]:
    """某个地址是否真的配在本机某个接口上、且处于可用状态。

    这一条设计的 §11 M1b 没列，但在开发机上最容易先撞到：按 D9 发布的是提供端**物理
    网卡地址**，若本机根本没有这个地址，内层包递上来后既不是本机地址、也没有转发
    目标，会被直接丢弃——症状和弱主机模型丢弃一模一样，但病因完全不同。

    也查 ``AddressState``：刚加上的地址若处于 Tentative/Duplicate（DAD 未通过），
    存在但不可用，症状同样是静默丢包。

    返回 ``(是否可用, 说明, 持有该地址的接口别名)``。持有者别名也是
    ``warn_if_weak_host_disabled`` 要检查的"服务地址所在的那张网卡"。
    """
    quoted = ip.replace("'", "''")
    script = (
        f"$a = Get-NetIPAddress -IPAddress '{quoted}' -AddressFamily IPv4 -ErrorAction Stop"
        " | Select-Object -First 1; ($a.InterfaceAlias, $a.AddressState) -join '|'"
    )
    try:
        result = subprocess.run(
            ("powershell", "-NoProfile", "-NonInteractive", "-Command", script),
            capture_output=True, text=True, encoding="mbcs", errors="replace",
        )
    except OSError as exc:
        return False, f"无法执行 PowerShell 查询 {ip}：{exc}", None
    output = (result.stdout or result.stderr).strip()
    if result.returncode != 0 or "|" not in output:
        return False, f"{ip} 不在本机任何接口上", None
    alias, address_state = (part.strip() for part in output.split("|", 1))
    if address_state.lower() != "preferred":
        return False, f"{ip} 在 {alias} 上但状态是 {address_state}（非 Preferred，不可用）", alias
    return True, f"{ip} 配在 {alias}（{address_state}）", alias


def warn_if_weak_host_disabled(interface: str, service_interface: str | None = None) -> bool:
    """启动自检：相关接口的两个开关都确认开启返回 True，否则打印告警与命令（§2.3，D9）。

    **必须同时检查两张网卡**（§2.3 的 rev.3 实测修正）：tun 接口，以及服务地址所在的
    那张网卡。只打开 tun 一侧是不够的——2026-09-20 的 M1b 实测里，包连 TCP 协议栈都
    进不去（连 RST 都不回），而症状与防火墙拦截、源站只听回环一模一样。
    ``service_interface`` 为 None 时只检查 tun 一侧，但仍会在告警里提醒另一侧。

    按 §9.1：只**检查并告警**，不自动改系统配置——改主机模型影响整机网络行为，
    应由部署者显式执行。
    """
    labels = {"weak_host_send": "weakhostsend", "weak_host_receive": "weakhostreceive"}
    targets = [interface] + ([service_interface] if service_interface else [])
    incomplete: list[tuple[str, list[str]]] = []
    for alias in targets:
        state = interface_state(alias)
        missing = [labels[key] for key in labels if state[key] is not True]
        if missing:
            incomplete.append((alias, missing))
    if not incomplete:
        return True

    commands = "\n".join(
        f'  netsh interface ipv4 set interface "{alias}" {switch}=enabled'
        for alias, missing in incomplete for switch in missing
    )
    # 两种方案的理由不同，说错了会把人引向错误的排查方向
    reason = (
        "内层包目的是物理网卡地址却从 tun 递上来、回程源地址属于物理网卡却要从 tun 发出，"
        "两个方向都违反 Windows 默认的强主机模型。注意**两张网卡都要开**：tun 与服务"
        "地址所在的那张（§2.3，D9）"
        if service_interface else
        "服务地址就绑在 tun 自己身上（§2.5，D18），理论上强主机模型已满足；但 M1b 唯一"
        "成功的那组实验里 tun 的这两个开关是开着的，尚未隔离出它们是否必需。开着是已知"
        "可行的配置"
    )
    logger.warning(
        "弱主机模型开关未确认开启：%s。%s。不开时包会被静默丢弃（症状与防火墙拦截、"
        "源站只听 127.0.0.1 一模一样，极难区分）。请以管理员执行：\n%s",
        "；".join(f"{alias} 缺 {'/'.join(missing)}" for alias, missing in incomplete),
        reason, commands,
    )
    return False
