"""M1b 注入验证：不接 CoLoR，单独验证提供端的"注入 → 源站 → 回程"这一段。

docs/design-l3-v2.md §11 把 M1b 单列为"本轮最重要的调整"，因为下面四件事的故障症状
**完全一样**（包写进去了、抓包看得见、就是没响应）：

1. 弱主机模型开关未开（§2.3，D9）
2. Windows 防火墙把 Wintun 适配器归为"公用网络"并拦掉入站（§2.6 第 3 条）
3. 源站只监听 127.0.0.1（§2.6 第 4 条）
4. 回程路由没配（内层 dst 回不到 color0）

混在 CoLoR 链路里调会极其痛苦，所以本脚本把这一段单独跑通，并且**逐个检查这四件事**，
让报告能直接指出是哪一件。

做的事：起 tun → 配地址/MTU/路由 → 写进去一个伪造的 TCP SYN
（src=消费端 tun 地址，dst=已发布的服务）→ 看能否从 tun 读回 SYN-ACK。

用法（**必须以管理员身份运行**）::

    python tools/l3_m1b_inject.py                    # 用 config.json 的第一条 tcp 服务
    python tools/l3_m1b_inject.py --port 8000
    python tools/l3_m1b_inject.py --config config.json --timeout 5
"""
from __future__ import annotations

import argparse
import ctypes
import logging
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.inet import IP, TCP

from colorproxy.config import load_config
from colorproxy.tun import ipv4
from colorproxy.tun.device_win import (
    WintunDevice,
    Wintun,
    interface_state,
    warn_if_weak_host_disabled,
)

logger = logging.getLogger("m1b")


def _powershell(script: str) -> tuple[int, str]:
    result = subprocess.run(
        ("powershell", "-NoProfile", "-NonInteractive", "-Command", script),
        capture_output=True, text=True, encoding="mbcs", errors="replace",
    )
    return result.returncode, (result.stdout or result.stderr).strip()


def check_listener(port: int) -> tuple[bool, str]:
    """§2.6 第 4 条：源站到底听在哪个地址上。只听 127.0.0.1 的话包到了也没人收。"""
    code, output = _powershell(
        f"(Get-NetTCPConnection -LocalPort {port} -State Listen -ErrorAction SilentlyContinue"
        " | Select-Object -ExpandProperty LocalAddress) -join ','"
    )
    if code != 0 or not output:
        return False, f"没有任何进程监听 :{port}"
    addresses = [item.strip() for item in output.split(",") if item.strip()]
    usable = [a for a in addresses if a in ("0.0.0.0", "::") or not a.startswith("127.")]
    if not usable:
        return False, f"只监听在 {addresses}——回环地址收不到从 tun 递上来的包"
    return True, f"监听在 {addresses}"


def check_firewall(alias: str) -> tuple[bool, str]:
    """§2.6 第 3 条：Wintun 适配器在 Windows 眼里是新网卡，NLA 大概率归为"公用网络"。"""
    code, output = _powershell(
        f"(Get-NetConnectionProfile -InterfaceAlias '{alias}' -ErrorAction Stop)"
        ".NetworkCategory"
    )
    if code != 0:
        return False, "拿不到网络类别（NLA 可能还没归类完，稍等再看）"
    category = output.strip()
    if category.lower() == "public":
        return False, f"归为 {category}（公用网络），入站几乎全拦"
    return True, f"归为 {category}"


def build_syn(src: str, dst: str, dport: int, sport: int, mss: int) -> bytes:
    """造一个校验和正确的 TCP SYN。src 是消费端的 tun 地址（本机并不持有它）。"""
    return bytes(IP(bytes(
        IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", options=[("MSS", mss)])
    )))


def wait_for_reply(device: WintunDevice, src: str, dst: str, dport: int, sport: int,
                   timeout: float) -> tuple[str, bytes | None]:
    """等回程包。返回 ('synack'|'rst'|'timeout'|'other', 原始包)。

    收到 RST 是个**好消息**：说明注入、投递、回程路由这条链路是通的，只是那个端口
    上没人监听——能把"投递坏了"和"服务没起"彻底分开。
    """
    deadline = time.monotonic() + timeout
    seen: list[str] = []
    while time.monotonic() < deadline:
        packet = device.read(timeout=max(0.05, deadline - time.monotonic()))
        if packet is None:
            continue
        header = ipv4.parse_header(packet)
        if header is None or header.proto != ipv4.PROTO_TCP:
            seen.append(f"非 TCP(proto={header.proto if header else '?'})")
            continue
        ports = ipv4.parse_ports(packet, header)
        if ipv4.format_ipv4(header.src) != dst or ports != (dport, sport):
            seen.append(f"无关包 {ipv4.format_ipv4(header.src)}:{ports}")
            continue
        flags = IP(packet)[TCP].flags
        if flags.S and flags.A:
            return "synack", packet
        if flags.R:
            return "rst", packet
        seen.append(f"标志={flags}")
    if seen:
        logger.info("期间读到 %d 个不相关的包：%s", len(seen), seen[:5])
    return "timeout", None


def main() -> int:
    parser = argparse.ArgumentParser(description="M1b：提供端注入验证（不接 CoLoR）")
    parser.add_argument("--config", default="config.json", help="提供端配置（默认 config.json）")
    parser.add_argument("--port", type=int, help="目标服务端口（默认取 l3.services 第一条 tcp）")
    parser.add_argument("--sport", type=int, default=51000, help="伪造的客户端源端口")
    parser.add_argument("--timeout", type=float, default=5.0, help="等待回程包的秒数")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("！必须以管理员身份运行：创建 Wintun 适配器、配地址、配路由都需要提权。")
        print("  在管理员 PowerShell 里执行：python tools/l3_m1b_inject.py")
        return 2

    config = load_config(args.config)
    l3 = config.l3
    if not l3.services:
        print(f"！{args.config} 的 l3.services[] 为空，没有可测的服务。")
        return 2
    if not l3.peers:
        print(f"！{args.config} 的 l3.peers[] 为空，没有可用作内层源地址的消费端 tun 地址。")
        return 2

    port = args.port
    if port is None:
        tcp_services = [s for s in l3.services if s.proto == "tcp" and s.port != 0]
        if not tcp_services:
            print("！l3.services[] 里没有具体端口的 tcp 服务，请用 --port 指定。")
            return 2
        port = tcp_services[0].port
    service_ip = l3.services[0].ip
    inner_src = l3.peers[0].tun_ip

    print("=" * 72)
    print(f"M1b 注入验证：{inner_src} → {service_ip}:{port}（经 {l3.tun_name}，不接 CoLoR）")
    print("=" * 72)

    # --- 先查不依赖 tun 的那一件：源站监听地址 -----------------------------
    listener_ok, listener_note = check_listener(port)
    print(f"[{'OK' if listener_ok else '!!'}] 源站监听（§2.6 第 4 条）：{listener_note}")

    wintun = Wintun()
    wintun.route_driver_log()   # 适配器创建失败的真正原因只会出现在驱动日志里
    device = WintunDevice(l3.tun_name, mtu=l3.tun_mtu, wintun=wintun)
    weak_ok = firewall_ok = False
    try:
        device.open()
        device.configure(l3.tun_ip, l3.tun_mask)
        for cidr in l3.peer_routes:
            device.add_route(cidr)

        state = interface_state(l3.tun_name)
        print(f"[--] 接口状态：index={state['index']} mtu={state['mtu']}")
        if state["mtu"] not in (None, l3.tun_mtu):
            print(f"[!!] MTU 是 {state['mtu']}，期望 {l3.tun_mtu}（§2.6 第 2 条）")

        weak_ok = warn_if_weak_host_disabled(l3.tun_name)
        print(f"[{'OK' if weak_ok else '!!'}] 弱主机模型（§2.3，D9）："
              f"{'两个开关都已开启' if weak_ok else '未确认开启，见上面的告警'}")

        firewall_ok, firewall_note = check_firewall(l3.tun_name)
        print(f"[{'OK' if firewall_ok else '!!'}] 防火墙/网络类别（§2.6 第 3 条）：{firewall_note}")

        syn = build_syn(inner_src, service_ip, port, args.sport, l3.mss_clamp)
        print(f"\n注入 TCP SYN（{len(syn)} 字节，MSS={l3.mss_clamp}）…")
        device.write(syn)

        verdict, packet = wait_for_reply(
            device, inner_src, service_ip, port, args.sport, args.timeout
        )
        print()
        if verdict == "synack":
            print("=" * 72)
            print("✅ 通过：读回了 SYN-ACK。注入、投递、源站、回程路由四件事都成立。")
            print(f"   {IP(packet).summary()}")
            print("   下一步做 M1c（两个 tun + UDP 代替 CoLoR），或直接进 M2 接入 CoLoR。")
            print("=" * 72)
            return 0
        if verdict == "rst":
            print("=" * 72)
            print("⚠ 收到 RST：**投递链路是通的**（注入 → 协议栈 → 回程路由都成立），")
            print(f"   只是 {service_ip}:{port} 上没有进程监听，或监听地址不对。")
            print(f"   起一个最小源站再跑一次：python -m http.server {port} --bind 0.0.0.0")
            print("=" * 72)
            return 1
        print("=" * 72)
        print("❌ 超时：没读回 SYN-ACK 也没读回 RST。按下面的顺序查（症状完全一样，逐个排除）：")
        for ok, name, hint in (
            (weak_ok, "弱主机模型开关", "见上面 warn_if_weak_host_disabled 打印的两条 netsh 命令"),
            (firewall_ok, "防火墙/网络类别",
             f'Set-NetConnectionProfile -InterfaceAlias "{l3.tun_name}" -NetworkCategory Private；'
             f'New-NetFirewallRule -DisplayName "color-tun" -Direction Inbound '
             f'-InterfaceAlias "{l3.tun_name}" -Action Allow'),
            (listener_ok, "源站监听地址", f"python -m http.server {port} --bind 0.0.0.0"),
        ):
            print(f"   [{'OK' if ok else '!!'}] {name}：{'已满足' if ok else hint}")
        print(f"   [??] 回程路由：确认 {l3.peer_routes} 指向 {l3.tun_name}（route print）")
        print("   包一路被丢在 WFP 上时，症状与强主机丢弃一模一样，先把上面 !! 的都解决。")
        print("=" * 72)
        return 1
    finally:
        device.close()
        print("已清理：适配器与路由都已删除。")


if __name__ == "__main__":
    raise SystemExit(main())
