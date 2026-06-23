"""进程内端到端联调：浏览器 → 消费端 → (路由) → 提供端 → 真实源站 → 回程。

把**消费端**与**提供端**两套真实业务代码 + 真实源站 HTTP 服务接在一起，仅用一个
按目的 IP 转发的桩"网络"替换 raw socket 传输层与 RM/BR（走域内路径，无 PID）。
据此验证两端在**线缆字节层面互通**：消费端构造的 GET/ACK 能被提供端解析、
提供端构造的隧道/响应 DATA 能被消费端解析——这是真实环境联调前的最强离线保障。

不依赖管理员权限 / Npcap / 真实 RM。运行：``python tests/test_e2e_inproc.py``
"""
from __future__ import annotations

import json
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
from colorproxy.protocol.constants import RESPONSE_CHIP_SIZE
from colorproxy.protocol.sid import sid_hex_from_url
from colorproxy.state import ProviderState
from tools.origin_server import _SHOWCASE_HTML, _OriginHandler

PROVIDER_NID = 0xA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1
CONSUMER_NID = 0xB2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2
RM_IP, PROVIDER_IP, CONSUMER_IP = "10.0.0.1", "10.0.1.6", "10.0.1.5"
HELLO_URL = "http://prov.local/hello.html"
SHOWCASE_URL = "http://prov.local/showcase.html"
ITEMS_PAGE_URL = "http://prov.local/items.html"
ITEMS_URL = "http://prov.local/api/items"


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


def _roundtrip(port: int, method: str, url: str, body: bytes = b"") -> bytes:
    """开一条到代理的新连接（v1 不复用），发一个请求，读到 EOF 返回全部字节。"""
    head = f"{method} {url} HTTP/1.1\r\nHost: prov.local\r\nUser-Agent: e2e\r\n".encode("latin-1")
    if body:
        head += (b"Content-Type: application/json\r\n"
                 b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n")
    request = head + b"\r\n" + body

    client = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        client.sendall(request)
        client.settimeout(10)
        received = b""
        deadline = time.time() + 10
        while time.time() < deadline:
            chunk = client.recv(4096)
            if not chunk:
                break
            received += chunk
        return received
    finally:
        client.close()


def _split_response(received: bytes) -> tuple[bytes, bytes]:
    """拆出 (状态行, body)。"""
    assert received, "浏览器侧未收到任何响应"
    head, _, body = received.partition(b"\r\n\r\n")
    return head.split(b"\r\n", 1)[0], body


def main() -> int:
    origin, origin_port = _start_origin()

    # 三条服务都回源到同一个真实源站，仅 URL（即 SID）不同
    services = [
        ServiceConfig(url=u, origin_host="127.0.0.1", origin_port=origin_port)
        for u in (HELLO_URL, SHOWCASE_URL, ITEMS_PAGE_URL, ITEMS_URL)
    ]
    provider_state = ProviderState(Config(PROVIDER_NID, PROVIDER_IP, RM_IP, services))
    provider_state.registered.set()
    provider_state.set_domain_info([(CONSUMER_NID, CONSUMER_IP)], [])

    consumer_state = ConsumerState(ConsumerConfig(CONSUMER_NID, CONSUMER_IP, RM_IP, 0))
    consumer_state.registered.set()
    consumer_state.set_domain_info([(PROVIDER_NID, PROVIDER_IP)], [])

    for service in services:
        sid = sid_hex_from_url(PROVIDER_NID, service.url)
        provider_state.add_service(sid, service)
        consumer_state.add_sid(sid)

    net = _Net(provider_state, consumer_state)
    proxy = ProxyServer(0, consumer_state, net.consumer_sender)
    port = proxy.server_address[1]
    threading.Thread(target=proxy.serve_forever, daemon=True).start()

    failed = 0
    try:
        # 1) 小页面：两端线缆互通、响应一致
        status, body = _split_response(_roundtrip(port, "GET", HELLO_URL))
        assert b"200" in status, f"hello 状态行非 200：{status!r}"
        assert b"color-proxy origin OK" in body, "hello 响应体与源站不一致"
        print("  PASS hello.html：浏览器 → 消费端 → 提供端 → 源站 → 回程")

        # 2) 大页面：响应跨多个 DATA 分片后逐字节完整重组
        status, body = _split_response(_roundtrip(port, "GET", SHOWCASE_URL))
        assert b"200" in status, f"showcase 状态行非 200：{status!r}"
        assert len(_SHOWCASE_HTML) > RESPONSE_CHIP_SIZE, "showcase 不够大，无法验证分片"
        assert body == _SHOWCASE_HTML, "showcase 重组后与源站不一致（分片/重组有误）"
        chips = -(-len(_SHOWCASE_HTML) // RESPONSE_CHIP_SIZE)
        print(f"  PASS showcase.html：{len(body)} 字节 / 约 {chips} 个分片完整重组")

        # 3) 交互控制台页：自包含、能经代理取回
        status, body = _split_response(_roundtrip(port, "GET", ITEMS_PAGE_URL))
        assert b"200" in status and b"/api/items" in body and b"<script" in body, \
            f"items.html 取回异常：{status!r}"
        print(f"  PASS items.html：{len(body)} 字节，交互控制台页可经代理取回")

        # 4) CRUD + query 透传：id 走 ?id=N，不入 SID 但原样到达源站
        status, body = _split_response(_roundtrip(port, "POST", ITEMS_URL, b'{"name":"alpha"}'))
        assert b"201" in status, f"POST 状态行非 201：{status!r}"
        item_id = json.loads(body)["id"]
        print(f"  PASS POST /api/items → 201 创建 id={item_id}")

        status, body = _split_response(_roundtrip(port, "GET", f"{ITEMS_URL}?id={item_id}"))
        got = json.loads(body)
        assert b"200" in status and got["id"] == item_id and got["name"] == "alpha", \
            f"GET ?id={item_id} 不符：{status!r} {got}"
        print(f"  PASS GET /api/items?id={item_id} → 200（query 透传到源站）")

        status, body = _split_response(_roundtrip(port, "PUT", f"{ITEMS_URL}?id={item_id}", b'{"name":"beta"}'))
        got = json.loads(body)
        assert b"200" in status and got["name"] == "beta", f"PUT 不符：{status!r} {got}"
        print(f"  PASS PUT /api/items?id={item_id} → 200 更新")

        status, body = _split_response(_roundtrip(port, "DELETE", f"{ITEMS_URL}?id={item_id}"))
        assert b"200" in status and json.loads(body)["deleted"] == item_id, f"DELETE 不符：{status!r}"
        print(f"  PASS DELETE /api/items?id={item_id} → 200 删除")

        status, _ = _split_response(_roundtrip(port, "GET", f"{ITEMS_URL}?id={item_id}"))
        assert b"404" in status, f"删除后再取应 404：{status!r}"
        print(f"  PASS GET /api/items?id={item_id} → 404（已删除）")

        print("\n进程内端到端验证通过")
    except AssertionError as exc:
        failed = 1
        print(f"  FAIL: {exc}")
    finally:
        proxy.shutdown()
        proxy.server_close()
        origin.shutdown()
        origin.server_close()
    return failed


if __name__ == "__main__":
    raise SystemExit(main())
