"""进程内端到端联调：浏览器 → 消费端 → (路由) → 提供端 → 真实源站 → 回程。

把**消费端**与**提供端**两套真实业务代码 + 真实源站 HTTP 服务接在一起，仅用一个
按目的 IP 转发的桩"网络"替换 raw socket 传输层与 RM/BR（走域内路径，无 PID）。
据此验证两端在**线缆字节层面互通**：消费端构造的 GET/ACK 能被提供端解析、
提供端构造的隧道/响应 DATA 能被消费端解析——这是真实环境联调前的最强离线保障。

不依赖管理员权限 / Npcap / 真实 RM。运行：``python tests/test_e2e_inproc.py``
"""
from __future__ import annotations

import os
import socket
import sys
import threading
import time
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from colorproxy import handlers as provider_handlers
from colorproxy.config import Config, ServiceConfig
from colorproxy.consumer import handlers as consumer_handlers
from colorproxy.consumer.config import ConsumerConfig
from colorproxy.consumer.proxy import ProxyServer
from colorproxy.consumer.state import ConsumerState
from colorproxy.messages import is_ack
from colorproxy.protocol.sid import sid_hex_from_url
from colorproxy.state import ProviderState
from tools.origin_server import _OriginHandler

PROVIDER_NID = 0xA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1
CONSUMER_NID = 0xB2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2
RM_IP, PROVIDER_IP, CONSUMER_IP = "10.0.0.1", "10.0.1.6", "10.0.1.5"
URL = "http://prov.local/hello.html"


class _Sender:
    """按目的 IP 把报文投递到对端业务代码（替代 raw socket + RM/BR，仅域内）。"""

    def __init__(self, net: "_Net", side: str) -> None:
        self._net = net
        self._side = side

    def send(self, dst_ip: str, color) -> None:
        self._net.route(self._side, dst_ip, bytes(color))


class _Net:
    def __init__(self, provider_state: ProviderState, consumer_state: ConsumerState) -> None:
        self.provider_state = provider_state
        self.consumer_state = consumer_state
        self.provider_sender = _Sender(self, "provider")
        self.consumer_sender = _Sender(self, "consumer")

    def route(self, side: str, dst_ip: str, raw: bytes) -> None:
        if side == "consumer":
            # 消费端发出：GET 经 RM 转给提供端；ACK 直达提供端
            if dst_ip == RM_IP and not is_ack(raw):
                provider_handlers.handle_get(self.provider_state, self.provider_sender, raw)
            elif dst_ip == PROVIDER_IP:
                provider_handlers.handle_ack(self.provider_state, self.provider_sender, raw)
        elif side == "provider" and dst_ip == CONSUMER_IP:
            # 提供端发出：隧道 / 响应 DATA 回到消费端
            consumer_handlers.handle_data(self.consumer_state, raw)


def _start_origin() -> tuple[ThreadingHTTPServer, int]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _OriginHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def main() -> int:
    origin, origin_port = _start_origin()
    sid = sid_hex_from_url(PROVIDER_NID, URL)

    service = ServiceConfig(url=URL, origin_host="127.0.0.1", origin_port=origin_port)
    provider_state = ProviderState(Config(PROVIDER_NID, PROVIDER_IP, RM_IP, [service]))
    provider_state.registered.set()
    provider_state.set_domain_info([(CONSUMER_NID, CONSUMER_IP)], [])
    provider_state.add_service(sid, service)

    consumer_state = ConsumerState(ConsumerConfig(CONSUMER_NID, CONSUMER_IP, RM_IP, 0))
    consumer_state.registered.set()
    consumer_state.set_domain_info([(PROVIDER_NID, PROVIDER_IP)], [])
    consumer_state.add_sid(sid)

    net = _Net(provider_state, consumer_state)
    proxy = ProxyServer(0, consumer_state, net.consumer_sender)
    port = proxy.server_address[1]
    threading.Thread(target=proxy.serve_forever, daemon=True).start()

    try:
        client = socket.create_connection(("127.0.0.1", port), timeout=10)
        client.sendall(
            (f"GET {URL} HTTP/1.1\r\nHost: prov.local\r\nUser-Agent: e2e\r\n\r\n").encode("latin-1")
        )
        client.settimeout(10)
        received = b""
        deadline = time.time() + 10
        while time.time() < deadline:
            chunk = client.recv(4096)
            if not chunk:
                break
            received += chunk

        assert received, "浏览器侧未收到任何响应"
        head = received.split(b"\r\n", 1)[0]
        assert b"200" in head, f"状态行非 200：{head!r}"
        assert b"color-proxy origin OK" in received, "响应体与源站不一致"
        print("  PASS 浏览器 → 消费端 → 提供端 → 源站 → 回程（两端线缆互通，响应一致）")
        print("\n进程内端到端验证通过")
        return 0
    except AssertionError as exc:
        print(f"  FAIL: {exc}")
        return 1
    finally:
        proxy.shutdown()
        proxy.server_close()
        origin.shutdown()
        origin.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
