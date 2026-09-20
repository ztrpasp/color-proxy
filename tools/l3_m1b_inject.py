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


#: --configure 时加的入站放行规则名（退出时删掉）
FIREWALL_RULE = "color-tun-m1b"


def enable_weak_host(alias: str) -> bool:
    """给刚创建的 color0 打开两个弱主机开关（§2.3，D9）。

    **只有 --configure 时才调，且只作用于本脚本自己创建的 tun 接口。**
    代理进程永远不做这件事（§9.1 明确要求只检查告警、不改系统配置）：改主机模型影响
    整机网络行为。这里之所以要代劳，是因为 color0 由本脚本创建、退出即删，开关挂在它
    身上，手工设置根本来不及。适配器删除后这两个设置随之消失，不留残留。
    """
    ok = True
    for switch in ("weakhostreceive", "weakhostsend"):
        try:
            _netsh_set(alias, switch)
        except OSError as exc:
            logger.warning("打开 %s 失败：%s", switch, exc)
            ok = False
    return ok


def _netsh_set(alias: str, switch: str) -> None:
    result = subprocess.run(
        ("netsh", "interface", "ipv4", "set", "interface", alias, f"{switch}=enabled"),
        capture_output=True, text=True, encoding="mbcs", errors="replace",
    )
    if result.returncode != 0:
        raise OSError(f"{result.stdout.strip()} {result.stderr.strip()}".strip())


def allow_firewall(alias: str) -> bool:
    """把 tun 的网络类别设为 Private 并加一条入站放行（§2.6 第 3 条）。

    Wintun 适配器在 Windows 眼里是新网卡，NLA 大概率归为"公用网络"，入站几乎全拦；
    包会被正常投递到 IP 层然后死在 WFP 上，**症状和强主机丢弃一模一样**。
    退出时删掉规则（见 remove_firewall_rule）。
    """
    ok = True
    # NLA 可能还没给新适配器归类，重试几次
    for attempt in range(5):
        code, output = _powershell(
            f"Set-NetConnectionProfile -InterfaceAlias '{alias}' "
            "-NetworkCategory Private -ErrorAction Stop"
        )
        if code == 0:
            break
        if attempt == 4:
            logger.warning("设置网络类别失败（NLA 还没归类？）：%s", output.splitlines()[:1])
            ok = False
        time.sleep(0.5)

    code, output = _powershell(
        f"New-NetFirewallRule -DisplayName '{FIREWALL_RULE}' -Direction Inbound "
        f"-InterfaceAlias '{alias}' -Action Allow -ErrorAction Stop | Out-Null"
    )
    if code != 0:
        logger.warning("添加入站放行规则失败：%s", output.splitlines()[:1])
        ok = False
    return ok


def remove_firewall_rule() -> None:
    _powershell(
        f"Remove-NetFirewallRule -DisplayName '{FIREWALL_RULE}' -ErrorAction SilentlyContinue"
    )


def list_adapters() -> list[str]:
    """列出本机可用的 IPv4 接口别名，供"该把服务地址加到哪张网卡"参考。"""
    code, output = _powershell(
        "(Get-NetIPInterface -AddressFamily IPv4 -ConnectionState Connected"
        " | Where-Object { $_.InterfaceAlias -notlike 'Loopback*' }"
        " | Select-Object -ExpandProperty InterfaceAlias) -join '|'"
    )
    if code != 0 or not output:
        return []
    return [item.strip() for item in output.split("|") if item.strip()]


def check_local_address(ip: str) -> tuple[bool, str, str | None]:
    """目标服务地址是否真的配在本机某个接口上、且处于可用状态。

    这一条设计的 §11 M1b 没列，但在开发机上最容易先撞到：按 D9 发布的是提供端**物理
    网卡地址**（172.10.0.2），若本机根本没有这个地址，内层包递上来后既不是本机地址、
    也没有转发目标，会被直接丢弃——症状和弱主机模型丢弃一模一样，但病因完全不同。

    也查 ``AddressState``：刚加上的地址若处于 Tentative/Duplicate（DAD 未通过），
    存在但不可用，症状同样是静默丢包。

    返回 ``(是否可用, 说明, 持有该地址的接口别名)``。
    """
    code, output = _powershell(
        f"$a = Get-NetIPAddress -IPAddress '{ip}' -AddressFamily IPv4 -ErrorAction Stop"
        " | Select-Object -First 1; ($a.InterfaceAlias, $a.AddressState) -join '|'"
    )
    if code != 0 or "|" not in output:
        return False, f"{ip} 不在本机任何接口上", None
    alias, address_state = (part.strip() for part in output.split("|", 1))
    if address_state.lower() != "preferred":
        return False, f"{ip} 在 {alias} 上但状态是 {address_state}（非 Preferred，不可用）", alias
    return True, f"{ip} 配在 {alias}（{address_state}）", alias


def half_open_connections(port: int) -> list[str]:
    """查目标端口上的非 Listen 连接。

    这是把问题一刀切开的判据：注入后若出现 ``SynReceived``，说明 SYN **已经进了 TCP
    协议栈**（注入、投递、WFP 入站、监听地址全都成立），问题只在回程；若什么都没有，
    说明 SYN 根本没被协议栈接受。
    """
    code, output = _powershell(
        f"(Get-NetTCPConnection -LocalPort {port} -ErrorAction SilentlyContinue"
        " | Where-Object { $_.State -ne 'Listen' } | ForEach-Object"
        ' { "$($_.LocalAddress):$($_.LocalPort)<-$($_.RemoteAddress):$($_.RemotePort) $($_.State)" })'
        " -join '|'"
    )
    if code != 0 or not output:
        return []
    return [item.strip() for item in output.split("|") if item.strip()]


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
    """等回程包。返回 ('synack'|'rst'|'timeout', 原始包)。

    收到 RST 是个**好消息**：说明注入、投递、回程路由这条链路是通的，只是那个端口
    上没人监听——能把"投递坏了"和"服务没起"彻底分开。
    """
    deadline = time.monotonic() + timeout
    seen: dict[str, int] = {}
    while time.monotonic() < deadline:
        packet = device.read(timeout=max(0.05, deadline - time.monotonic()))
        if packet is None:
            continue
        header = ipv4.parse_header(packet)
        if header is None:
            # 区分 IPv6 与真正的坏包：新接口上大量 IPv6 RS/MLD 是正常噪声，
            # 早先笼统报成 "proto=?" 会误导排查方向
            version = (packet[0] >> 4) if packet else 0
            seen[f"IPv{version}" if version in (4, 6) else f"坏包(首字节0x{packet[0]:02x})"] = (
                seen.get(f"IPv{version}" if version in (4, 6) else f"坏包(首字节0x{packet[0]:02x})", 0) + 1
            )
            continue
        if header.proto != ipv4.PROTO_TCP:
            seen[f"IPv4/proto={header.proto}"] = seen.get(f"IPv4/proto={header.proto}", 0) + 1
            continue
        ports = ipv4.parse_ports(packet, header)
        if ipv4.format_ipv4(header.src) != dst or ports != (dport, sport):
            key = f"无关 TCP {ipv4.format_ipv4(header.src)}:{ports}"
            seen[key] = seen.get(key, 0) + 1
            continue
        flags = IP(packet)[TCP].flags
        if flags.S and flags.A:
            return "synack", packet
        if flags.R:
            return "rst", packet
        seen[f"本流但标志={flags}"] = seen.get(f"本流但标志={flags}", 0) + 1
    if seen:
        summary = "、".join(f"{key}×{count}" for key, count in sorted(seen.items()))
        logger.info("期间从 tun 读到的其它包：%s", summary)
        logger.info("（IPv6 是新接口的 RS/MLD 噪声，属正常；出现它说明 tun 读通路是活的）")
    return "timeout", None


def attempt(device: WintunDevice, inner_src: str, dst: str, port: int, sport: int,
            mss: int, timeout: float) -> tuple[str, bytes | None]:
    """注入一个 SYN 并等回应。"""
    syn = build_syn(inner_src, dst, port, sport, mss)
    print(f"注入 TCP SYN：{inner_src}:{sport} → {dst}:{port}（{len(syn)} 字节，MSS={mss}）…")
    device.write(syn)
    return wait_for_reply(device, inner_src, dst, port, sport, timeout)


def main() -> int:
    parser = argparse.ArgumentParser(description="M1b：提供端注入验证（不接 CoLoR）")
    parser.add_argument("--config", default="config.json", help="提供端配置（默认 config.json）")
    parser.add_argument("--port", type=int, help="目标服务端口（默认取 l3.services 第一条 tcp）")
    parser.add_argument("--sport", type=int, default=51000, help="伪造的客户端源端口")
    parser.add_argument("--timeout", type=float, default=5.0, help="等待回程包的秒数")
    parser.add_argument(
        "--configure", action="store_true",
        help="替本次测试准备 color0：开两个弱主机开关 + 网络类别设 Private + 加入站放行"
             "（只作用于本脚本创建的 tun，退出时随适配器一起消失；代理进程永不做这些）",
    )
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

    # --- 先查两件不依赖 tun 的：目标地址在不在本机、源站听在哪 --------------
    address_ok, address_note, service_alias = check_local_address(service_ip)
    service_alias = service_alias or "<目标地址所在网卡>"
    print(f"[{'OK' if address_ok else '!!'}] 目标地址归属：{address_note}")
    if not address_ok:
        print(f"     按 D9，发布的是提供端物理网卡地址。本机没有 {service_ip} 的话，内层包")
        print("     递上来既不是本机地址、也没有转发目标，会被直接丢弃——症状与弱主机丢弃相同。")
        print(f"     补一个地址即可（挑一张 host-only / 内网网卡，不影响外部连通性）：")
        print(f'       netsh interface ipv4 add address "<网卡名>" {service_ip} 255.255.255.0')
        print(f'       netsh interface ipv4 delete address "<网卡名>" {service_ip}   # 测完清理')
        candidates = list_adapters()
        if candidates:
            print(f"     本机候选网卡：{candidates}")

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

        if args.configure:
            # color0 由本脚本创建、退出即删，开关挂在它身上，手工设置来不及，故代劳。
            # 代理进程永远不做这件事（§9.1）。
            print(f"[--] --configure：准备 {l3.tun_name} 的弱主机开关与防火墙…")
            enable_weak_host(l3.tun_name)
            allow_firewall(l3.tun_name)

        weak_ok = warn_if_weak_host_disabled(l3.tun_name)
        print(f"[{'OK' if weak_ok else '!!'}] 弱主机模型（§2.3，D9）："
              f"{'两个开关都已开启' if weak_ok else '未确认开启，见上面的告警'}")

        firewall_ok, firewall_note = check_firewall(l3.tun_name)
        print(f"[{'OK' if firewall_ok else '!!'}] 防火墙/网络类别（§2.6 第 3 条）：{firewall_note}")

        print()
        verdict, packet = attempt(
            device, inner_src, service_ip, port, args.sport, l3.mss_clamp, args.timeout
        )
        print()
        if verdict == "synack":
            print("=" * 72)
            print("✅ 通过：读回了 SYN-ACK。注入、跨网卡投递、源站、回程路由全都成立。")
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

        # ---- 失败后的两个决定性判据 --------------------------------------
        print("-" * 72)
        print("SYN 没有回应。下面两步把「没进协议栈」和「回不来」分开：")

        half_open = half_open_connections(port)
        if half_open:
            print(f"[>>] 协议栈里出现了半开连接：{half_open}")
            print("     → SYN **已经进了 TCP 协议栈**（注入/跨网卡投递/WFP 入站/监听地址全成立），")
            print(f"        问题只在回程：SYN-ACK 的源地址是 {service_ip}（属于 {service_alias}），")
            print(f"        要从 {l3.tun_name} 发出，需要 {l3.tun_name} 的 weakhostsend；")
            print(f"        并确认 {l3.peer_routes} 指向 {l3.tun_name}（route print）。")
        else:
            print(f"[>>] 协议栈里没有 :{port} 上的半开连接 → SYN 没被协议栈接受。")

        # 跨网卡投递到底要哪一端的 weakhost，设计文档只写了"在 color0 上打开"，
        # 实测比推断可靠，所以把两端都摆出来
        if address_ok:
            here = interface_state(l3.tun_name)
            peer = interface_state(service_alias)
            print("[>>] 两端的弱主机开关：")
            print(f"       {l3.tun_name}（收包侧）      recv={here['weak_host_receive']} "
                  f"send={here['weak_host_send']}")
            print(f"       {service_alias}（地址持有侧） recv={peer['weak_host_receive']} "
                  f"send={peer['weak_host_send']}")

        # A/B：改用 color0 自己的地址。源站 bind 0.0.0.0，所以它也在听这个地址。
        print(f"\n[A/B] 改用 {l3.tun_name} 自己的地址 {l3.tun_ip} 再注入一次"
              "（这条路径不需要跨网卡投递，即 §2.5 的虚服务地址方案）…")
        alt_verdict, _alt = attempt(
            device, inner_src, l3.tun_ip, port, args.sport + 1, l3.mss_clamp, args.timeout
        )
        print()
        print("=" * 72)
        if alt_verdict in ("synack", "rst"):
            print(f"🔍 定位完成：发到 {l3.tun_ip}（tun 自己的地址）有回应（{alt_verdict}），")
            print(f"   发到 {service_ip}（{service_alias} 的地址）没有回应。")
            print("   → tun 读写、注入、WFP 入站、源站、回程路由**全都是好的**，")
            print("     唯一不成立的是**跨网卡投递**，即 §1.4 第二行那一跳。")
            print()
            print("   两条路可选：")
            print(f"   (a) 把弱主机开关也打到目标地址所在的网卡上，再试一次：")
            print(f'         netsh interface ipv4 set interface "{service_alias}" '
                  "weakhostreceive=enabled")
            print(f'         netsh interface ipv4 set interface "{service_alias}" '
                  "weakhostsend=enabled")
            print("   (b) 直接走 §2.5 的备用方案：把服务发布在 tun 自己的地址上，")
            print(f'         即 l3.services[].ip 改成 {l3.tun_ip}，两个弱主机开关都不需要。')
            print("       代价只是对外发布的是虚地址而非物理地址，其余契约完全相同。")
        else:
            print("❌ 两个目标地址都没有回应 → 问题比「跨网卡投递」更靠前。")
            print("   已排除的：目标地址存在且 Preferred、源站监听 0.0.0.0、")
            print(f"   {l3.tun_name} 的两个弱主机开关已开、网络类别为 Private。")
            print("   接下来用 pktmon 看包死在哪个组件（管理员）：")
            print("     pktmon start --capture --drop-only --pkt-size 128")
            print("     python tools/l3_m1b_inject.py --configure")
            print("     pktmon stop && pktmon format PktMon.etl -o drops.txt")
            print("   drops.txt 会直接写出丢包组件与原因（WFP / IP 层等），贴出来即可继续定位。")
        print("=" * 72)
        return 1
    finally:
        if args.configure:
            remove_firewall_rule()
        device.close()
        print("已清理：适配器与路由都已删除"
              + ("，入站放行规则也已删除。" if args.configure else "。")
              + "（弱主机开关随适配器一起消失，不留残留）")


if __name__ == "__main__":
    raise SystemExit(main())
