"""按平台打开 tun 设备（docs/design-l3-v2.md §10.2 的启动顺序）。

装配层只调 ``open_tun()``，**不直接 import ``device_win`` / ``device_linux``**。两个好处：

1. 离线测试可以往 ``ProviderL3Service`` / ``ConsumerL3Service`` 注入 ``LoopbackTun``，
   整条装配路径（分派、读线程、计数器、超时回收）都能在没有管理员权限、没有
   wintun.dll 的机器上跑；
2. 平台差异只在这里分支：Windows 用 Wintun（``device_win``），Linux 用
   ``/dev/net/tun``（``device_linux``）。``l3/`` 与 ``tun/ipv4.py`` / ``tun/mss.py`` 全部
   共用（两者语义一致：纯 L3、无以太头）。

启动顺序按 §10.2：创建适配器 → 配地址/MTU → 配路由 → （提供端）确认弱主机开关 →
放行防火墙 → 再开始收发。本函数负责前三步；弱主机开关按 §9.1 只检查告警，见
``l3/service.py``。
"""
from __future__ import annotations

import logging
import sys
from typing import Iterable

from .device import TunDevice

logger = logging.getLogger(__name__)


def open_tun(
    *,
    name: str,
    ip: str,
    mask: str,
    mtu: int,
    routes: Iterable[str] = (),
) -> TunDevice:
    """创建并配好一个 tun 设备。失败时保证不留下半开的适配器。

    ``routes`` 是要指向本设备的网段：消费端传 ``capture_routes``（只允许 /32，
    §2.4 第 1 条，已由配置加载强制），提供端传 ``peer_routes``。
    """
    if sys.platform == "win32":
        from .device_win import WintunDevice  # 延迟导入：非 Windows 上 import 即失败

        device = WintunDevice(name=name, mtu=mtu)
    elif sys.platform.startswith("linux"):
        from .device_linux import LinuxTunDevice

        device = LinuxTunDevice(name=name, mtu=mtu)
    else:
        raise RuntimeError(
            f"L3 隧道模式只实现了 Windows(Wintun) 与 Linux(/dev/net/tun)，当前平台是 {sys.platform}"
        )

    device.open()
    try:
        device.configure(ip, mask)
        for cidr in routes:
            device.add_route(cidr)
    except Exception:
        # 配置失败就把适配器删干净：留一个没地址没路由的 color0 在系统里，
        # 下次启动会以"适配器已存在"的形式报另一个错，把人引向错误方向
        device.close()
        raise
    return device
