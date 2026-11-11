"""Linux tun 设备测试（colorproxy/tun/device_linux.py，docs/design-l3-v2.md §10.2）。

两部分：

- 纯逻辑（任何平台都跑）：掩码换前缀、``ifreq`` 打包、``open_tun`` 在 Linux 上选中
  ``LinuxTunDevice`` 并按"建网卡 → 配地址 → 加路由"的顺序调用；
- 真网卡回环（只在 Linux + 有 ``CAP_NET_ADMIN`` + 有 ``/dev/net/tun`` 时跑，比如终端容器里）：
  建一个 tun，本机 UDP 发往对端地址 → 从 tun 读出（路径二上行）；再往 tun 写一个包 →
  本机 UDP socket 收到（提供端注入）。没有条件时自动跳过。

可用 ``python -m pytest tests/test_tun_linux.py`` 运行，
也可直接 ``python tests/test_tun_linux.py`` 运行（无需 pytest）。
"""
from __future__ import annotations

import os
import socket
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from colorproxy.tun import device_linux, factory
from colorproxy.tun.device_linux import LinuxTunDevice, mask_to_prefixlen, pack_ifreq

_SKIPPED: list[str] = []

_TEST_IF = "cptest0"
_LOCAL_IP = "10.233.7.1"
_PEER_IP = "10.233.7.2"


# ---------------------------------------------------------------- 纯逻辑

def test_mask_to_prefixlen() -> None:
    assert mask_to_prefixlen("255.255.255.0") == 24
    assert mask_to_prefixlen("255.255.255.255") == 32
    assert mask_to_prefixlen("255.255.0.0") == 16
    try:
        mask_to_prefixlen("255.0.255.0")
    except ValueError:
        pass
    else:
        raise AssertionError("不连续的掩码应当报错")


def test_pack_ifreq_layout_and_name_limit() -> None:
    ifr = pack_ifreq("color0", device_linux.IFF_TUN | device_linux.IFF_NO_PI)
    assert len(ifr) == 18
    assert ifr[:16] == b"color0" + b"\x00" * 10
    assert struct.unpack_from("H", ifr, 16)[0] == 0x1001
    for bad in ("", "x" * 16, "名字"):
        try:
            pack_ifreq(bad, 0)
        except (ValueError, UnicodeEncodeError):
            continue
        raise AssertionError(f"非法网卡名 {bad!r} 应当被拒绝")


def test_factory_uses_linux_device_in_order() -> None:
    """open_tun 在 Linux 上选 LinuxTunDevice，且严格按 open → configure → add_route。"""
    if not sys.platform.startswith("linux"):
        _SKIPPED.append("factory 分支：非 Linux")
        return
    calls: list[tuple] = []

    class FakeDevice:
        def __init__(self, name: str, mtu: int) -> None:
            calls.append(("init", name, mtu))

        def open(self) -> None:
            calls.append(("open",))

        def configure(self, ip: str, mask: str) -> None:
            calls.append(("configure", ip, mask))

        def add_route(self, cidr: str) -> None:
            calls.append(("route", cidr))

        def close(self) -> None:
            calls.append(("close",))

    original = device_linux.LinuxTunDevice
    device_linux.LinuxTunDevice = FakeDevice  # factory 在函数内 import，替换模块属性即可
    try:
        factory.open_tun(name="color0", ip="10.99.1.1", mask="255.255.255.0", mtu=1200,
                         routes=["10.10.9.2/32"])
    finally:
        device_linux.LinuxTunDevice = original
    assert calls == [
        ("init", "color0", 1200),
        ("open",),
        ("configure", "10.99.1.1", "255.255.255.0"),
        ("route", "10.10.9.2/32"),
    ], calls


def test_read_write_after_close_raise() -> None:
    tun = LinuxTunDevice(_TEST_IF, mtu=1200)
    for op in (lambda: tun.read(0), lambda: tun.write(b"\x45" + b"\x00" * 19)):
        try:
            op()
        except OSError:
            continue
        raise AssertionError("未打开的 tun 读写应当抛 OSError")
    tun.close()  # 未打开时 close 也不应报错


# ---------------------------------------------------------------- 真网卡

def _can_create_tun() -> bool:
    if not sys.platform.startswith("linux"):
        _SKIPPED.append("真网卡：非 Linux")
        return False
    if not os.path.exists(device_linux.TUN_CLONE_DEVICE):
        _SKIPPED.append("真网卡：没有 /dev/net/tun")
        return False
    probe = LinuxTunDevice(_TEST_IF, mtu=1200)
    try:
        probe.open()
    except OSError as exc:
        _SKIPPED.append(f"真网卡：{exc}")
        return False
    probe.close()
    return True


def _ipv4_checksum(header: bytes) -> int:
    total = sum(struct.unpack(f"!{len(header) // 2}H", header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _udp_packet(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload  # IPv4 下 UDP 校验和可为 0
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0x1234, 0x4000, 64, 17, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    header = header[:10] + struct.pack("!H", _ipv4_checksum(header)) + header[12:]
    return header + udp


def test_real_tun_both_directions() -> None:
    if not _can_create_tun():
        return
    tun = LinuxTunDevice(_TEST_IF, mtu=1200)
    tun.open()
    try:
        tun.configure(_LOCAL_IP, "255.255.255.0")
        tun.add_route(f"{_PEER_IP}/32")

        # 上行：本机发往对端的包应当从 tun 读出来
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sender.sendto(b"uplink", (_PEER_IP, 40001))
        sender.close()
        packet = None
        for _ in range(20):  # 跳过可能的其它噪声包
            packet = tun.read(timeout=1.0)
            if packet and packet[9] == 17 and packet[16:20] == socket.inet_aton(_PEER_IP):
                break
        assert packet is not None, "1 秒内没从 tun 读到本机发出的 UDP 包"
        assert packet[0] >> 4 == 4 and packet.endswith(b"uplink"), packet.hex()

        # 下行：写进 tun 的包应当被本机协议栈收下（提供端注入就是这条路）
        receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        receiver.bind((_LOCAL_IP, 40002))
        receiver.settimeout(2.0)
        tun.write(_udp_packet(_PEER_IP, _LOCAL_IP, 40003, 40002, b"downlink"))
        data, addr = receiver.recvfrom(2048)
        receiver.close()
        assert data == b"downlink" and addr == (_PEER_IP, 40003), (data, addr)

    finally:
        tun.close()
    assert not os.path.exists(f"/sys/class/net/{_TEST_IF}"), "关 fd 后网卡应当随之消失"


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
    for reason in _SKIPPED:
        print(f"  （已跳过：{reason}）")
    print(f"\n{len(funcs) - failed}/{len(funcs)} passed")
    return failed


if __name__ == "__main__":
    raise SystemExit(_run_all())
