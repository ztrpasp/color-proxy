"""M1c 回环验证：真 tun + 真两端数据面，中间用 UDP 直连代替 CoLoR。

docs/design-l3-v2.md §11 给 M1c 的定位是"tun 设备、地址规划、MTU、MSS 与 CoLoR 完全
正交，先用 UDP 把内层链路跑通"。数据面的**逻辑**已由 tests/test_l3_dataplane.py 端到
端覆盖，所以 M1c 的增量价值全在**真 tun + 真内核路径**：MTU 生效、真实 SYN/SYN-ACK
经过 clamp、内核路由选择、Wintun 的读写在持续流量下不出错。

--------------------------------------------------------------------------------
为什么不是"两个 tun 一台机器"（设计 §7 的原话）
--------------------------------------------------------------------------------

因为**同一个内核上两个内层端点都是本机地址**，流量根本不会进隧道：

- 客户端 ``connect("172.10.9.2", 8000)``：按 §2.5 这就是提供端 color0 自己的地址。
  只要提供端的 tun 起着，这个地址就是本机地址，内核直接投给本地协议栈，
  ``172.10.9.2/32 → colorC`` 那条路由根本轮不上。
- 就算正向侥幸走了隧道，源站回程的目的 ``10.99.1.1`` 又是消费端 color0 自己的地址，
  同样环回，直接落回客户端的 socket。

后果比"不通"更坏：**TCP 连接会建成功，看起来 M1c 通过了，实际上一个包都没经过隧道。**
D9 的物理地址方案也一样（``172.10.0.2`` 同样是本机地址）。要跑真正的单流 M1c 必须有
**两个内核**（两台机器 / 两个 VM），见下面的 ``--peer``。

--------------------------------------------------------------------------------
所以本脚本把 M1c 拆成两半，每一半只保留**一个**真实端点
--------------------------------------------------------------------------------

两半都跑**真的两端数据面**（``ProviderL3Service`` / ``ConsumerL3Service``，即 M2 的
装配层）与**真的 CoLoR 报文**，只有一侧的 tun 换成 ``LoopbackTun``——换掉的恰好是那个
会制造"第二个本机地址"的端点，于是环回短路不可能发生，也就不会出现假通过。

============ 半 P（``--role provider``）：验证提供端这一侧 ============
    真 colorP(172.10.9.2/24) + 真源站(本进程起的 http.server)
    消费端是真 L3Consumer，但 tun 是 LoopbackTun，客户端是用户态最小 TCP
    判据：**一次完整的 HTTP 请求-响应**穿过真 tun、真内核注入、真源站，
          且源站真实 SYN-ACK 的 MSS 已被提供端 clamp 到 1240

============ 半 C（``--role consumer``）：验证消费端这一侧 ============
    真 colorC(10.99.1.1/24) + 真客户端(本进程的普通 socket，走内核 TCP)
    提供端是真 L3Provider，但 tun 是 LoopbackTun，源站是用户态最小 TCP
    判据：客户端 ``connect()`` 完成并拿到 HTTP 响应，且**内核真实 SYN 的 MSS
          已被消费端 clamp 到 1240**、内核确实按 capture_routes 把包送进了 tun

两半**不能同时跑**（同时起两个 tun 就又回到本机地址短路了），``--role both``
是依次跑。

============ 两机版（``--peer``）：设计原本设想的那个 M1c ============
    有第二台机器/VM 时：提供端机器上 ``--role provider --peer <消费端IP>``，
    消费端机器上 ``--role consumer --peer <提供端IP>``，两侧 tun 都是真的，
    中间仍是 UDP。这才是完整的单流 M1c。

用法（**必须以管理员身份运行**）::

    python tools/l3_m1c_loopback.py                      # 依次跑两半
    python tools/l3_m1c_loopback.py --role consumer      # 只跑半 C
    python tools/l3_m1c_loopback.py --role provider --peer 10.10.0.2 --udp-port 47150
"""
from __future__ import annotations

import argparse
import ctypes
import http.server
import logging
import os
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.inet import IP, TCP

from colorproxy.config import load_config
from colorproxy.consumer.config import load_consumer_config
from colorproxy.consumer.state import ConsumerState
from colorproxy.l3.service import ConsumerL3Service, ProviderL3Service
from colorproxy.protocol.sid import sid_hex_from_service
from colorproxy.state import ProviderState
from colorproxy.tun import ipv4
from colorproxy.tun.device import LoopbackTun

# 控制台编码兜底：中文 Windows 控制台默认 GBK，打印非 ASCII 标记会抛 UnicodeEncodeError
# 把整个脚本带崩（输出被重定向到管道时尤其容易撞上）。诊断脚本不该因为一个字符死掉。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(errors="replace")
    except (AttributeError, OSError):
        pass

logger = logging.getLogger("m1c")

#: 半 P / 半 C 各自用的 UDP 端口（单机模式两半是依次跑的，可以复用同一对）
DEFAULT_UDP_PORT = 47150
#: 用户态最小 TCP 端点等对端包的上限（秒）
TCP_STEP_TIMEOUT = 5.0
#: 一整半的整体超时（秒）
HALF_TIMEOUT = 25.0
FIREWALL_RULE = "color-tun-m1c"


# ---------------------------------------------------------------- 系统环境

def _powershell(script: str) -> tuple[int, str]:
    result = subprocess.run(
        ("powershell", "-NoProfile", "-NonInteractive", "-Command", script),
        capture_output=True, text=True, encoding="mbcs", errors="replace",
    )
    return result.returncode, (result.stdout or result.stderr).strip()


def allow_firewall(alias: str) -> None:
    """把 tun 归为 Private 并加一条入站放行（§2.6 第 3 条）。

    Wintun 适配器在 Windows 眼里是新网卡，NLA 大概率归为"公用网络"、入站几乎全拦；
    包会被正常投递到 IP 层然后死在 WFP 上，**症状和强主机丢弃一模一样**。
    """
    for attempt in range(5):
        code, output = _powershell(
            f"Set-NetConnectionProfile -InterfaceAlias '{alias}' "
            "-NetworkCategory Private -ErrorAction Stop"
        )
        if code == 0:
            break
        if attempt == 4:
            logger.warning("设置网络类别失败（NLA 还没给新适配器归类？）：%s",
                           output.splitlines()[:1])
        time.sleep(1.0)
    _powershell(
        f"New-NetFirewallRule -DisplayName '{FIREWALL_RULE}' -Direction Inbound "
        f"-InterfaceAlias '{alias}' -Action Allow -ErrorAction SilentlyContinue | Out-Null"
    )


def remove_firewall_rule() -> None:
    _powershell(
        f"Remove-NetFirewallRule -DisplayName '{FIREWALL_RULE}' -ErrorAction SilentlyContinue"
    )


# ---------------------------------------------------------------- UDP 代替 CoLoR

class UdpColorSender:
    """按目的 IP 把 CoLoR 报文经 UDP 送到对端，代替 ``ColorSender``（§11 M1c）。

    接口与 ``ColorSender.send`` 一致，所以两端数据面一行都不用改。报文本身仍是**真的
    CoLoR 报文**（经 packets.py 构建与解析），换掉的只是承载它的那一跳。
    """

    def __init__(self, routes: dict[str, tuple[str, int]], default: tuple[str, int] | None = None):
        self._routes = routes
        self._default = default
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sent = 0
        self.unroutable: list[str] = []

    def send(self, dst_ip: str, color) -> None:
        endpoint = self._routes.get(dst_ip, self._default)
        if endpoint is None:
            self.unroutable.append(dst_ip)
            logger.warning("UDP 链路没有 %s 的去处，丢弃一个 CoLoR 报文", dst_ip)
            return
        self._sock.sendto(bytes(color), endpoint)
        self.sent += 1

    def close(self) -> None:
        self._sock.close()


class UdpColorReceiver(threading.Thread):
    """收 UDP 上的 CoLoR 报文，交给装配层的 ``_on_payload`` 等价物。"""

    def __init__(self, port: int, on_payload, name: str = "UdpColorRecv") -> None:
        super().__init__(name=name, daemon=True)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.settimeout(0.5)
        self._sock.bind(("127.0.0.1", port) if port else ("", 0))
        self._on_payload = on_payload
        self._stop = threading.Event()
        self.received = 0

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                payload, _ = self._sock.recvfrom(65535)
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                break
            self.received += 1
            try:
                self._on_payload(payload)
            except Exception:  # noqa: BLE001
                logger.exception("处理 CoLoR 报文时异常（已忽略该包）")

    def stop(self) -> None:
        self._stop.set()
        self._sock.close()


def bind_any_udp(port: int) -> int:
    """确认端口可用；被占用时报得明白些。"""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.bind(("127.0.0.1", port))
    except OSError as exc:
        raise SystemExit(f"UDP 端口 {port} 不可用（{exc}），换一个 --udp-port") from exc
    finally:
        probe.close()
    return port


# ---------------------------------------------------------------- 用户态最小 TCP

class MiniTcp:
    """只够跑一条连接、一次请求-响应的用户态 TCP 端点。

    用在**被 LoopbackTun 换掉的那一侧**：半 P 里它是客户端，半 C 里它是源站。真实的
    那一侧永远是内核 TCP，所以 MSS clamp、序号、重传这些判据测的都是真东西——这里
    只需要一个"能把对话进行下去"的对端，不追求完整的 TCP 实现。

    不实现：重传、窗口、乱序、选项协商。一次对话丢一个包就会卡住，由上层超时兜底。
    """

    def __init__(self, tun: LoopbackTun, local_ip: str, peer_ip: str,
                 local_port: int, peer_port: int) -> None:
        self.tun = tun
        self.local_ip, self.peer_ip = local_ip, peer_ip
        self.local_port, self.peer_port = local_port, peer_port
        self.seq = 1000
        self.ack = 0
        self.peer_mss: int | None = None
        self.data = b""
        self.finished = False
        # 已从 tun 取出、还没被 _recv 消费的包。``pop_written()`` 是"取出并清空"，
        # 一次可能带回好几个包（例如对端的 ACK 紧跟着数据包），不缓冲就会丢掉后面的。
        self._backlog: list = []

    # -- 收发原语 ---------------------------------------------------------

    def _send(self, flags: str, payload: bytes = b"", mss: int | None = None) -> None:
        options = [("MSS", mss)] if mss is not None else []
        packet = IP(src=self.local_ip, dst=self.peer_ip) / TCP(
            sport=self.local_port, dport=self.peer_port, flags=flags,
            seq=self.seq, ack=self.ack, options=options,
        )
        if payload:
            packet = packet / payload
        self.tun.inject(bytes(IP(bytes(packet))))
        self.seq += len(payload) + (1 if "S" in flags or "F" in flags else 0)

    def _recv(self, timeout: float = TCP_STEP_TIMEOUT):
        """从 tun 取下一个属于本连接的 TCP 包。返回 scapy 的 IP 包或 None。"""
        deadline = time.monotonic() + timeout
        while True:
            while self._backlog:
                packet = self._backlog.pop(0)
                if packet[TCP].dport != self.local_port:
                    continue
                payload_len = len(bytes(packet[TCP].payload))
                advance = payload_len + (1 if packet[TCP].flags.S or packet[TCP].flags.F else 0)
                if advance:  # 纯 ACK 不推进确认号
                    self.ack = packet[TCP].seq + advance
                return packet
            if time.monotonic() >= deadline:
                return None
            for raw in self.tun.pop_written():
                header = ipv4.parse_header(raw)
                if header is not None and header.proto == ipv4.PROTO_TCP:
                    self._backlog.append(IP(raw))
            if not self._backlog:
                time.sleep(0.005)

    # -- 两种角色 ---------------------------------------------------------

    def client_request(self, request: bytes, mss: int = 1460) -> bytes | None:
        """客户端角色：SYN → 等 SYN-ACK → ACK + 请求 → 收响应。返回响应体。"""
        self._send("S", mss=mss)
        synack = self._recv()
        if synack is None or not (synack[TCP].flags.S and synack[TCP].flags.A):
            logger.error("没等到 SYN-ACK（收到：%s）",
                         synack[TCP].flags if synack is not None else "无")
            return None
        self.peer_mss = dict(synack[TCP].options).get("MSS")
        self._send("A")
        self._send("PA", request)

        body = b""
        deadline = time.monotonic() + TCP_STEP_TIMEOUT
        while time.monotonic() < deadline:
            packet = self._recv(timeout=1.0)
            if packet is None:
                continue
            body += bytes(packet[TCP].payload)
            self._send("A")
            if packet[TCP].flags.F:
                self._send("FA")
                break
            if b"\r\n\r\n" in body and len(body.split(b"\r\n\r\n", 1)[1]) > 0:
                # 源站可能不主动关连接，拿到完整响应体即可收工
                break
        self.data = body
        self._send("R")  # 收工，别在源站上留半开连接
        return body or None

    def serve_once(self, response: bytes, mss: int = 1460) -> bool:
        """源站角色：等 SYN → SYN-ACK → 等请求 → 回响应 + FIN。"""
        syn = self._recv(timeout=TCP_STEP_TIMEOUT * 2)
        if syn is None or not syn[TCP].flags.S:
            logger.error("源站侧没等到 SYN")
            return False
        self.peer_mss = dict(syn[TCP].options).get("MSS")
        self.peer_port = syn[TCP].sport
        self.local_port = syn[TCP].dport
        self._send("SA", mss=mss)

        deadline = time.monotonic() + TCP_STEP_TIMEOUT
        while time.monotonic() < deadline:
            packet = self._recv(timeout=1.0)
            if packet is None:
                continue
            payload = bytes(packet[TCP].payload)
            if payload:
                self.data = payload
                self._send("A")
                self._send("PA", response)
                self._send("FA")
                self.finished = True
                return True
            if packet[TCP].flags.F or packet[TCP].flags.R:
                break
        logger.error("源站侧没等到请求数据")
        return False


# ---------------------------------------------------------------- 状态装配

def _provider_state(config, consumer_nid: int, consumer_ipv4: str) -> ProviderState:
    """建提供端状态，并把 l3.services[] 按 ANN 的方式登记进 _l3_services。"""
    state = ProviderState(config)
    state.set_domain_info([(consumer_nid, consumer_ipv4)], [])
    for service in config.l3.services:
        state.add_l3_service(
            sid_hex_from_service(config.nid, service.proto, service.ip, service.port), service
        )
    state.registered.set()
    return state


def _consumer_state(config, provider_config, provider_ipv4: str) -> ConsumerState:
    """建消费端状态，并把提供端发布的 SID 预载（真机上这一步由 RM 下发）。"""
    state = ConsumerState(config)
    state.set_domain_info([(provider_config.nid, provider_ipv4)], [])
    for service in provider_config.l3.services:
        state.add_sid(sid_hex_from_service(
            provider_config.nid, service.proto, service.ip, service.port))
    state.registered.set()
    return state


class _OriginServer(http.server.ThreadingHTTPServer):
    """最小源站：绑 0.0.0.0，保证从 tun 递上来的包收得到（§2.6 第 4 条）。"""

    daemon_threads = True
    allow_reuse_address = True


class _OriginHandler(http.server.BaseHTTPRequestHandler):
    BODY = b"m1c-ok\n"

    def do_GET(self) -> None:  # noqa: N802 BaseHTTPRequestHandler 的约定
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(self.BODY)))
        self.end_headers()
        self.wfile.write(self.BODY)

    def log_message(self, fmt: str, *args) -> None:
        logger.debug("源站: " + fmt, *args)


# ---------------------------------------------------------------- 半 P / 半 C

def _pick_service(config):
    """取第一条非通配的 TCP 服务作为被测服务。"""
    for service in config.l3.services:
        if service.proto == "tcp" and service.port != 0:
            return service
    raise SystemExit("config.json 的 l3.services[] 里没有可用的精确 TCP 服务")


def run_provider_half(provider_config, consumer_config, udp_port: int,
                      peer: str | None) -> bool:
    """半 P：真 colorP + 真源站，消费端侧的 tun 换成 LoopbackTun。"""
    service = _pick_service(provider_config)
    consumer_tun_ip = consumer_config.l3.tun_ip
    print(f"\n=== 半 P：真 tun {provider_config.l3.tun_name}"
          f"({provider_config.l3.tun_ip}) + 真源站 {service.canonical} ===")
    if service.ip != provider_config.l3.tun_ip:
        print(f"  注意：服务地址 {service.ip} 不是 tun 自己的地址（D9 方案），"
              "需要四个弱主机开关，见设计 §2.3")

    origin = _OriginServer(("0.0.0.0", service.port), _OriginHandler)
    threading.Thread(target=origin.serve_forever, daemon=True, name="Origin").start()
    print(f"  源站已在 0.0.0.0:{service.port} 起好")

    provider_state = _provider_state(provider_config, consumer_config.nid, consumer_config.ipv4)
    consumer_state = _consumer_state(consumer_config, provider_config, provider_config.ipv4)

    provider_ep = ("127.0.0.1", udp_port)
    consumer_ep = (peer, udp_port) if peer else ("127.0.0.1", udp_port + 1)
    to_provider = UdpColorSender({}, default=provider_ep)
    to_consumer = UdpColorSender({}, default=consumer_ep)

    provider = ProviderL3Service(provider_state, to_consumer)
    consumer = ConsumerL3Service(consumer_state, to_provider,
                                 tun=LoopbackTun(consumer_tun_ip, mtu=consumer_config.l3.tun_mtu))
    recv_p = UdpColorReceiver(udp_port, lambda p: _feed_provider(provider, p), "UdpRecv(P)")
    recv_c = UdpColorReceiver(udp_port + 1, lambda p: _feed_consumer(consumer, p), "UdpRecv(C)")

    ok = False
    try:
        provider.start()
        allow_firewall(provider_config.l3.tun_name)
        consumer.start()
        recv_p.start()
        recv_c.start()

        client = MiniTcp(consumer.tun, consumer_tun_ip, service.ip, 51001, service.port)
        print("  用户态客户端发起一次 HTTP 请求（经真 tun 注入真源站）…")
        body = client.client_request(b"GET / HTTP/1.0\r\nHost: m1c\r\n\r\n")

        clamp = provider_config.l3.mss_clamp
        rewrote = provider.counters.get("mss_clamped") > 0
        ok = bool(body and b"m1c-ok" in body)
        _report_half(ok, provider, consumer, [
            # 注意判据的措辞：源站的 SYN-ACK 是内核按 colorP 的 MTU(1280) 发出的，
            # 内核自己就会填 MSS=1240，所以 clamp 多半是**空操作**。这里真正验证的是
            # "tun MTU 生效了"，而不是"clamp 改写了字节"——把两者混为一谈会让人在
            # clamp 没触发时误以为出了问题（clamp 只减不增，§6.2）。
            (f"源站真实 SYN-ACK 的 MSS ≤ {clamp}（tun MTU 生效）",
             client.peer_mss is not None and client.peer_mss <= clamp,
             f"MSS={client.peer_mss}；提供端 clamp "
             f"{'改写过' if rewrote else '未触发（内核已按 MTU 填对，正常）'}"),
            ("HTTP 响应体正确", ok, repr(body[:60]) if body else "没拿到响应"),
        ])
    finally:
        recv_c.stop(); recv_p.stop()
        consumer.stop(); provider.stop()
        origin.shutdown(); origin.server_close()
        to_provider.close(); to_consumer.close()
        remove_firewall_rule()
    return ok


def run_consumer_half(provider_config, consumer_config, udp_port: int,
                      peer: str | None) -> bool:
    """半 C：真 colorC + 真客户端（内核 TCP），提供端侧的 tun 换成 LoopbackTun。"""
    service = _pick_service(provider_config)
    print(f"\n=== 半 C：真 tun {consumer_config.l3.tun_name}"
          f"({consumer_config.l3.tun_ip}) + 真客户端 socket ===")
    print(f"  捕获路由 {list(consumer_config.l3.capture_routes)} → "
          f"{consumer_config.l3.tun_name}，目标 {service.canonical}")

    provider_state = _provider_state(provider_config, consumer_config.nid, consumer_config.ipv4)
    consumer_state = _consumer_state(consumer_config, provider_config, provider_config.ipv4)

    provider_ep = (peer, udp_port) if peer else ("127.0.0.1", udp_port)
    consumer_ep = ("127.0.0.1", udp_port + 1)
    to_provider = UdpColorSender({}, default=provider_ep)
    to_consumer = UdpColorSender({}, default=consumer_ep)

    provider = ProviderL3Service(provider_state, to_consumer,
                                 tun=LoopbackTun(provider_config.l3.tun_ip,
                                                 mtu=provider_config.l3.tun_mtu))
    consumer = ConsumerL3Service(consumer_state, to_provider)
    recv_p = UdpColorReceiver(udp_port, lambda p: _feed_provider(provider, p), "UdpRecv(P)")
    recv_c = UdpColorReceiver(udp_port + 1, lambda p: _feed_consumer(consumer, p), "UdpRecv(C)")

    result: dict[str, object] = {}
    origin = MiniTcp(provider.tun, service.ip, consumer_config.l3.tun_ip,
                     service.port, 0)

    def _client() -> None:
        """真客户端：普通 socket，全程走内核 TCP 与内核路由选择。"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TCP_STEP_TIMEOUT * 2)
        try:
            sock.connect((service.ip, service.port))
            result["connected"] = True
            sock.sendall(b"GET / HTTP/1.0\r\nHost: m1c\r\n\r\n")
            result["body"] = sock.recv(4096)
        except OSError as exc:
            result["error"] = str(exc)
        finally:
            sock.close()

    ok = False
    try:
        consumer.start()
        allow_firewall(consumer_config.l3.tun_name)
        provider.start()
        recv_p.start()
        recv_c.start()

        print("  真客户端 connect() 中（内核按 capture_routes 把包送进 tun）…")
        client_thread = threading.Thread(target=_client, daemon=True, name="RealClient")
        client_thread.start()
        origin.serve_once(b"HTTP/1.0 200 OK\r\nContent-Length: 7\r\n\r\nm1c-ok\n")
        client_thread.join(TCP_STEP_TIMEOUT)

        body = result.get("body") or b""
        clamp = consumer_config.l3.mss_clamp
        rewrote = consumer.counters.get("mss_clamped") > 0
        ok = b"m1c-ok" in body
        _report_half(ok, provider, consumer, [
            # 同半 P：内核按 colorC 的 MTU(1280) 发 SYN，MSS 本来就是 1240，clamp 多半
            # 是空操作。这一条真正验证的是 tun MTU 生效 + 内核确实选了 colorC 出去。
            (f"内核真实 SYN 的 MSS ≤ {clamp}（tun MTU 生效、包确实从 tun 出去）",
             origin.peer_mss is not None and origin.peer_mss <= clamp,
             f"MSS={origin.peer_mss}；消费端 clamp "
             f"{'改写过' if rewrote else '未触发（内核已按 MTU 填对，正常）'}"),
            ("客户端 connect() 完成", bool(result.get("connected")),
             str(result.get("error", ""))),
            ("客户端收到响应体", ok, repr(body[:60]) if body else "没收到"),
        ])
    finally:
        recv_c.stop(); recv_p.stop()
        provider.stop(); consumer.stop()
        to_provider.close(); to_consumer.close()
        remove_firewall_rule()
    return ok


def run_dry_run(provider_config, consumer_config, udp_port: int) -> bool:
    """空跑：两侧 tun 都用 ``LoopbackTun``，客户端与源站都是用户态最小 TCP。

    **不需要管理员权限、不碰系统配置**，因此能在真机之前先验证脚本自身：UDP 链路、
    两端数据面的装配分派、``MiniTcp`` 两个角色、MSS clamp 两侧都生效。

    明确**不验证**的部分（那正是半 P / 半 C 存在的理由）：Wintun 的创建与读写、
    地址/路由/MTU 下发、内核的注入与路由选择、真实源站。空跑通过不代表真机会通。
    """
    service = _pick_service(provider_config)
    print(f"\n=== 空跑（两侧 tun 均为 LoopbackTun，不验证内核路径）目标 {service.canonical} ===")

    provider_state = _provider_state(provider_config, consumer_config.nid, consumer_config.ipv4)
    consumer_state = _consumer_state(consumer_config, provider_config, provider_config.ipv4)
    to_provider = UdpColorSender({}, default=("127.0.0.1", udp_port))
    to_consumer = UdpColorSender({}, default=("127.0.0.1", udp_port + 1))

    provider = ProviderL3Service(
        provider_state, to_consumer,
        tun=LoopbackTun(provider_config.l3.tun_ip, mtu=provider_config.l3.tun_mtu))
    consumer = ConsumerL3Service(
        consumer_state, to_provider,
        tun=LoopbackTun(consumer_config.l3.tun_ip, mtu=consumer_config.l3.tun_mtu))
    recv_p = UdpColorReceiver(udp_port, lambda p: _feed_provider(provider, p), "UdpRecv(P)")
    recv_c = UdpColorReceiver(udp_port + 1, lambda p: _feed_consumer(consumer, p), "UdpRecv(C)")

    ok = False
    try:
        provider.start()
        consumer.start()
        recv_p.start()
        recv_c.start()

        origin = MiniTcp(provider.tun, service.ip, consumer_config.l3.tun_ip, service.port, 0)
        client = MiniTcp(consumer.tun, consumer_config.l3.tun_ip, service.ip, 51001, service.port)
        served: dict[str, bool] = {}
        origin_thread = threading.Thread(
            target=lambda: served.update(
                ok=origin.serve_once(b"HTTP/1.0 200 OK\r\nContent-Length: 7\r\n\r\nm1c-ok\n")),
            daemon=True, name="MiniOrigin")
        origin_thread.start()

        body = client.client_request(b"GET / HTTP/1.0\r\nHost: m1c\r\n\r\n")
        origin_thread.join(TCP_STEP_TIMEOUT)

        ok = bool(body and b"m1c-ok" in body)
        _report_half(ok, provider, consumer, [
            ("消费端把客户端 SYN 的 MSS clamp 了",
             origin.peer_mss == consumer_config.l3.mss_clamp,
             f"MSS={origin.peer_mss}（期望 {consumer_config.l3.mss_clamp}）"),
            ("提供端把源站 SYN-ACK 的 MSS clamp 了",
             client.peer_mss == provider_config.l3.mss_clamp,
             f"MSS={client.peer_mss}（期望 {provider_config.l3.mss_clamp}）"),
            ("CoLoR 报文经 UDP 往返", recv_p.received > 0 and recv_c.received > 0,
             f"提供端收 {recv_p.received} 个、消费端收 {recv_c.received} 个"),
            ("HTTP 响应体正确", ok, repr(body[:60]) if body else "没拿到响应"),
        ])
    finally:
        recv_c.stop(); recv_p.stop()
        consumer.stop(); provider.stop()
        to_provider.close(); to_consumer.close()
    return ok


def _feed_provider(service: ProviderL3Service, payload: bytes) -> None:
    """把 UDP 上收到的 CoLoR 报文按装配层的判据交给提供端数据面（D13）。"""
    from colorproxy.messages import is_ack
    from colorproxy.protocol.constants import DATA_FIRST_BYTE, GET_FIRST_BYTE

    dataplane = service.dataplane
    if dataplane is None:
        return
    if payload[0] == GET_FIRST_BYTE:
        dataplane.handle_get(payload)
    elif payload[0] == DATA_FIRST_BYTE and is_ack(payload):
        dataplane.handle_upstream(payload)


def _feed_consumer(service: ConsumerL3Service, payload: bytes) -> None:
    from colorproxy.protocol.constants import DATA_FIRST_BYTE

    dataplane = service.dataplane
    if dataplane is None:
        return
    if payload[0] == DATA_FIRST_BYTE:
        dataplane.handle_data(payload)


def _report_half(ok: bool, provider: ProviderL3Service, consumer: ConsumerL3Service,
                 checks: list[tuple[str, bool, str]]) -> None:
    print()
    for label, passed, detail in checks:
        print(f"  {'[PASS]' if passed else '[FAIL]'} {label}" + (f"（{detail}）" if detail else ""))
    print(f"  提供端计数器：{provider.counters.format_line()}")
    print(f"  消费端计数器：{consumer.counters.format_line()}")
    print(f"  {'[PASS] 本半通过' if ok else '[FAIL] 本半未通过'}")


# ---------------------------------------------------------------- 入口

def main() -> int:
    parser = argparse.ArgumentParser(
        description="M1c：真 tun + 真两端数据面，UDP 代替 CoLoR",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="单机只能分两半跑（同一内核上两个内层端点都是本机地址会环回短路，"
               "见模块文档）；有第二台机器时用 --peer 跑完整单流。",
    )
    parser.add_argument("--role", choices=("provider", "consumer", "both"), default="both")
    parser.add_argument("--config", default="config.json")
    parser.add_argument("--consumer-config", default="config-consumer.json")
    parser.add_argument("--udp-port", type=int, default=DEFAULT_UDP_PORT,
                        help=f"代替 CoLoR 的 UDP 端口（默认 {DEFAULT_UDP_PORT}，"
                             "消费端侧用 +1）")
    parser.add_argument("--peer", help="两机版：对端机器的 IP（不给则单机分半跑）")
    parser.add_argument("--dry-run", action="store_true",
                        help="两侧 tun 都用 LoopbackTun：不需要管理员、不碰系统，"
                             "只验证脚本自身与两端数据面，**不验证内核路径**")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if not args.dry_run and sys.platform == "win32" \
            and not ctypes.windll.shell32.IsUserAnAdmin():
        print("[FAIL] 需要管理员权限：创建 Wintun 适配器、配地址与路由都要提权。"
              "请在管理员 PowerShell 里重跑。")
        return 2

    provider_config = load_config(args.config)
    consumer_config = load_consumer_config(args.consumer_config)
    if not provider_config.l3.services:
        raise SystemExit("config.json 的 l3.services[] 为空")
    if consumer_config.l3.tun_ip != provider_config.l3.peers[0].tun_ip:
        print(f"[FAIL] 两份配置对不齐：消费端 l3.tun_ip={consumer_config.l3.tun_ip}，"
              f"提供端 l3.peers[0].tun_ip={provider_config.l3.peers[0].tun_ip}。"
              "不一致时隧道建得起来但每个上行包都会被 src_bind_drop 拦掉（设计 §9.2，D14）")
        return 2

    bind_any_udp(args.udp_port)
    if not args.peer:
        bind_any_udp(args.udp_port + 1)

    if args.dry_run:
        ok = run_dry_run(provider_config, consumer_config, args.udp_port)
        print("\n================ M1c 空跑小结 ================")
        print(f"  {'[PASS]' if ok else '[FAIL]'} 空跑（不验证 tun 与内核路径，"
              "真机仍须以管理员跑 --role both）")
        return 0 if ok else 1

    results: list[tuple[str, bool]] = []
    if args.role in ("provider", "both"):
        results.append(("半 P（提供端侧）",
                        run_provider_half(provider_config, consumer_config,
                                          args.udp_port, args.peer)))
    if args.role in ("consumer", "both"):
        if args.role == "both":
            print("\n（两半不能同时跑：同时起两个 tun 就又回到本机地址短路了，故依次跑）")
            time.sleep(1.0)
        results.append(("半 C（消费端侧）",
                        run_consumer_half(provider_config, consumer_config,
                                          args.udp_port, args.peer)))

    print("\n================ M1c 小结 ================")
    for label, ok in results:
        print(f"  {'[PASS]' if ok else '[FAIL]'} {label}")
    return 0 if all(ok for _, ok in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
