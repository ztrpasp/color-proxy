"""流式 cut-through 的 TTFB 验证：浏览器首字节应远早于整份响应完成。

复用与 ``test_e2e_inproc`` 相同的进程内桩网络（真实 provider/consumer 业务代码 +
真实源站），源站走新增的 ``/slow`` 分段涓流端点（段间 sleep，模拟"源站产字节
慢"）。据此验证：
- **首字节远早于末字节**——存储转发下二者几乎同时（都要等整份下载完），流式
  cut-through 下首字节在源站还在涓流时就已到达浏览器；
- body 逐字节完整重组，与源站产出一致。

不依赖管理员权限 / Npcap / 真实 RM。运行：``python tests/test_streaming_ttfb.py``
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
from colorproxy.protocol.constants import RESPONSE_CHIP_SIZE
from colorproxy.protocol.sid import sid_hex_from_url
from colorproxy.state import ProviderState
from tools.origin_server import _OriginHandler, slow_body

PROVIDER_NID = 0xA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1
CONSUMER_NID = 0xB2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2
RM_IP, PROVIDER_IP, CONSUMER_IP = "10.0.0.1", "10.0.1.6", "10.0.1.5"
SLOW_URL = "http://prov.local/slow"

#: 涓流参数：20 段 × 4KB ≈ 80KB，段间 50ms → 整份下载约 (20-1)×0.05 ≈ 0.95s
SEGMENTS, SEG_SIZE, DELAY = 20, 4096, 0.05
_TRICKLE_SECONDS = (SEGMENTS - 1) * DELAY


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
            if dst_ip == RM_IP and not is_ack(raw):
                provider_handlers.handle_get(self.provider_state, self.provider_sender, raw)
            elif dst_ip == PROVIDER_IP:
                provider_handlers.handle_ack(self.provider_state, self.provider_sender, raw)
        elif side == "provider" and dst_ip == CONSUMER_IP:
            consumer_handlers.handle_data(self.consumer_state, raw)


def _start_origin() -> tuple[ThreadingHTTPServer, int]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _OriginHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def _timed_roundtrip(port: int, url: str) -> tuple[bytes, float, float]:
    """发一个请求，返回 (完整字节, 首字节耗时, 末字节耗时)（秒，相对请求发出）。"""
    request = (f"GET {url} HTTP/1.1\r\nHost: prov.local\r\nUser-Agent: ttfb\r\n\r\n"
               ).encode("latin-1")
    client = socket.create_connection(("127.0.0.1", port), timeout=15)
    received = bytearray()
    t_first: float | None = None
    try:
        client.settimeout(15)
        t0 = time.perf_counter()
        client.sendall(request)
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            if t_first is None:
                t_first = time.perf_counter() - t0
            received += chunk
        t_last = time.perf_counter() - t0
        return bytes(received), (t_first if t_first is not None else t_last), t_last
    finally:
        client.close()


def main() -> int:
    origin, origin_port = _start_origin()

    services = [ServiceConfig(url=SLOW_URL, origin_host="127.0.0.1", origin_port=origin_port)]
    provider_state = ProviderState(Config(PROVIDER_NID, PROVIDER_IP, RM_IP, services))
    provider_state.registered.set()
    provider_state.set_domain_info([(CONSUMER_NID, CONSUMER_IP)], [])

    consumer_state = ConsumerState(ConsumerConfig(CONSUMER_NID, CONSUMER_IP, RM_IP, 0))
    consumer_state.registered.set()
    consumer_state.set_domain_info([(PROVIDER_NID, PROVIDER_IP)], [])

    sid = sid_hex_from_url(PROVIDER_NID, SLOW_URL)
    provider_state.add_service(sid, services[0])
    consumer_state.add_sid(sid)

    net = _Net(provider_state, consumer_state)
    proxy = ProxyServer(0, consumer_state, net.consumer_sender)
    port = proxy.server_address[1]
    threading.Thread(target=proxy.serve_forever, daemon=True).start()

    failed = 0
    try:
        received, t_first, t_last = _timed_roundtrip(port, SLOW_URL)
        _, _, body = received.partition(b"\r\n\r\n")
        expected = slow_body(SEGMENTS, SEG_SIZE)

        assert len(expected) > RESPONSE_CHIP_SIZE, "涓流总量不足以跨分片，无法验证"
        assert body == expected, f"body 重组与源站不一致（{len(body)} vs {len(expected)} 字节）"
        print(f"  PASS 完整性：{len(body)} 字节 / 约 {-(-len(body) // RESPONSE_CHIP_SIZE)} 片逐字节一致")

        # 流式判据：首字节应在源站仍在涓流时就到达，且明显早于末字节。
        # 存储转发下 t_first ≈ t_last（都要等整份下载完），gap ≈ 0。
        gap = t_last - t_first
        print(f"  首字节 t_first={t_first:.3f}s  末字节 t_last={t_last:.3f}s  "
              f"间隔 gap={gap:.3f}s（源站涓流约 {_TRICKLE_SECONDS:.2f}s）")
        assert t_first < _TRICKLE_SECONDS * 0.5, \
            f"首字节过晚（{t_first:.3f}s），疑似仍在存储转发"
        assert gap > _TRICKLE_SECONDS * 0.4, \
            f"首末间隔过小（{gap:.3f}s），疑似仍在存储转发"
        print("  PASS 流式 cut-through：首字节远早于整份响应完成")

        print("\n流式 TTFB 验证通过")
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
