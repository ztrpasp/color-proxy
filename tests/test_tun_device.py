"""tun 设备测试：LoopbackTun 语义与 Wintun 绑定（docs/design-l3-v2.md §10.2）。

Wintun 部分**不创建适配器**（那要管理员权限，见 tools/l3_m1b_inject.py），只验证能
做到的部分：DLL 找得到、12 个导出全部解析、驱动版本可查、参数校验生效、本地化无关的
接口查询不会崩。缺 wintun.dll 或非 Windows 时自动跳过。

可用 ``python -m pytest tests/test_tun_device.py`` 运行，
也可直接 ``python tests/test_tun_device.py`` 运行（无需 pytest）。
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from colorproxy.tun.device import LoopbackTun

_SKIPPED: list[str] = []


def _wintun_available() -> bool:
    if sys.platform != "win32":
        _SKIPPED.append("非 Windows")
        return False
    try:
        from colorproxy.tun.device_win import find_wintun_dll

        find_wintun_dll()
        return True
    except FileNotFoundError as exc:
        _SKIPPED.append(str(exc).split("。")[0])
        return False


# ---------------------------------------------------------------- LoopbackTun

def test_loopback_separates_directions() -> None:
    """两个方向必须分开：数据面不能读到自己写进去的包（真 tun 也是这个语义）。"""
    tun = LoopbackTun("color0", mtu=1280)
    assert tun.name == "color0" and tun.mtu == 1280

    tun.write(b"\x45outbound")
    assert tun.read() is None, "写出去的包不该又被自己读到"
    assert tun.pop_written() == [b"\x45outbound"]
    assert tun.pop_written() == [], "取过一次就该清空"

    tun.inject(b"\x45inbound")
    assert tun.read() == b"\x45inbound"
    assert tun.read() is None


def test_loopback_read_is_fifo_and_write_rejects_after_close() -> None:
    tun = LoopbackTun()
    for index in range(3):
        tun.inject(bytes([0x45, index]))
    assert [tun.read()[1] for _ in range(3)] == [0, 1, 2]

    tun.close()
    assert tun.closed
    try:
        tun.write(b"\x45x")
    except OSError:
        return
    raise AssertionError("关闭后写入应当报错")


# ---------------------------------------------------------------- Wintun 绑定

def test_wintun_dll_loads_and_exports_resolve() -> None:
    if not _wintun_available():
        return
    from colorproxy.tun.device_win import Wintun, find_wintun_dll

    path = find_wintun_dll()
    assert path.is_file() and path.suffix == ".dll"

    wintun = Wintun(path)
    expected = [
        "WintunCreateAdapter", "WintunOpenAdapter", "WintunCloseAdapter",
        "WintunGetAdapterLUID", "WintunGetRunningDriverVersion", "WintunSetLogger",
        "WintunStartSession", "WintunEndSession", "WintunGetReadWaitEvent",
        "WintunReceivePacket", "WintunReleaseReceivePacket",
        "WintunAllocateSendPacket", "WintunSendPacket",
    ]
    for symbol in expected:
        function = getattr(wintun.dll, symbol)
        assert function.argtypes is not None, f"{symbol} 未声明 argtypes"

    # 驱动未加载时返回 0，这本身是合法结果；只要求调用不炸
    assert isinstance(wintun.driver_version(), int)


def test_wintun_driver_log_can_be_routed() -> None:
    """接上驱动日志不应抛异常，且回调对象要被持有（否则被 GC 后驱动回调会崩进程）。"""
    if not _wintun_available():
        return
    from colorproxy.tun import device_win

    device_win.Wintun().route_driver_log()
    assert device_win._logger_callback_ref is not None


def test_wintun_device_validates_ring_capacity() -> None:
    """环形缓冲容量必须是 2 的幂且在 [128 KiB, 64 MiB]（wintun.h 的硬性要求）。"""
    if not _wintun_available():
        return
    from colorproxy.tun.device_win import (
        DEFAULT_RING_CAPACITY,
        WINTUN_MAX_RING_CAPACITY,
        WINTUN_MIN_RING_CAPACITY,
        WintunDevice,
    )

    assert WINTUN_MIN_RING_CAPACITY <= DEFAULT_RING_CAPACITY <= WINTUN_MAX_RING_CAPACITY
    assert DEFAULT_RING_CAPACITY & (DEFAULT_RING_CAPACITY - 1) == 0

    for bad in (0x1000, WINTUN_MAX_RING_CAPACITY * 2, 0x300000):
        try:
            WintunDevice(ring_capacity=bad)
        except ValueError:
            continue
        raise AssertionError(f"ring_capacity={bad:#x} 应当被拒绝")

    # 合法值：只构造不 open()，不碰系统
    device = WintunDevice("color0", mtu=1280)
    assert device.name == "color0" and device.mtu == 1280 and device.luid is None


def test_wintun_read_write_require_open_session() -> None:
    if not _wintun_available():
        return
    from colorproxy.tun.device_win import WintunDevice

    device = WintunDevice("color0")
    for call in (lambda: device.read(timeout=0.01), lambda: device.write(b"\x45x")):
        try:
            call()
        except OSError:
            continue
        raise AssertionError("未 open() 就读写应当报错")


def test_interface_state_is_locale_independent_and_degrades() -> None:
    """查不存在的接口时全部返回 None，不抛异常、也不误报成"已关闭"。

    这里特意不解析 netsh 的本地化输出：中文 Windows 打印的是「弱主机发送」而不是
    weakhostsend，按英文键名解析会永远匹配不到，症状是"开关明明开了还一直告警"。
    """
    if not _wintun_available():
        return
    from colorproxy.tun.device_win import interface_state

    state = interface_state("color0_definitely_absent")
    assert set(state) == {"index", "mtu", "weak_host_send", "weak_host_receive"}
    assert all(value is None for value in state.values())


def _run_all() -> int:
    funcs = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in funcs:
        try:
            fn()
            print(f"  PASS {fn.__name__}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"  FAIL {fn.__name__}: {exc!r}")
    if _SKIPPED:
        print(f"  （Wintun 相关断言已跳过：{_SKIPPED[0]}）")
    print(f"\n{len(funcs) - failed}/{len(funcs)} passed")
    return failed


if __name__ == "__main__":
    raise SystemExit(_run_all())
