"""桩消费端 + 本地源站：验证服务端 GET -> 隧道 -> ACK -> 响应 业务闭环。

本测试不依赖 RM/BR、不需要管理员权限或 Npcap：它绕过原始套接字传输层，
直接把「消费端构造的报文」喂给服务端 handlers，并用 FakeSender 捕获服务端
回送的报文；源站用本机 http.server。可用于在普通开发环境验证业务逻辑。

运行：``python tests/stub_consumer.py``
"""
from __future__ import annotations

import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.packet import Raw

from colorproxy import handlers
from colorproxy.config import Config, ServiceConfig
from colorproxy.protocol.constants import (
    LoadFlag,
    WEB_MSG_TYPE_MASK,
    WebMsgType,
)
from colorproxy.protocol.packets import ColorData, ColorGet
from colorproxy.protocol.sid import lsid_from_url, nid_to_bytes, sid_hex_from_url
from colorproxy.state import ProviderState

PROVIDER_NID = 0xA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1
CONSUMER_NID = 0xB2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2
CONSUMER_IP = "127.0.0.1"
TX = 0x0BADC0DE
URL_PATH = "/hello.html"
HELLO_BODY = b"<html><body>hello from CoLoR provider</body></html>"

# GET Flags：A(0x08)+S(0x10)；DATA Flags：B(0x40)+S(0x02)
_GET_FLAGS_AS = 0x18
_DATA_FLAGS_BS = 0x42


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(HELLO_BODY)))
        self.end_headers()
        self.wfile.write(HELLO_BODY)

    def log_message(self, *args):  # 静默
        pass


class FakeSender:
    """记录服务端要发送的报文，不真正上网。"""

    def __init__(self) -> None:
        self.sent: list[tuple[str, bytes]] = []
        self._lock = threading.Lock()

    def send(self, dst_ip: str, color) -> None:
        with self._lock:
            self.sent.append((dst_ip, bytes(color)))

    def snapshot(self) -> list[tuple[str, bytes]]:
        with self._lock:
            return list(self.sent)


def _start_origin() -> tuple[ThreadingHTTPServer, int]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def _build_state(origin_port: int) -> tuple[ProviderState, str]:
    url = f"http://prov.local{URL_PATH}"
    service = ServiceConfig(url=url, origin_host="127.0.0.1", origin_port=origin_port)
    config = Config(nid=PROVIDER_NID, ipv4="10.0.1.6", rm_ipv4="10.0.0.1", services=[service])
    state = ProviderState(config)
    state.registered.set()
    state.set_domain_info([(CONSUMER_NID, CONSUMER_IP)], [])  # 域内：消费端 NID -> IP
    sid = sid_hex_from_url(PROVIDER_NID, url)
    state.add_service(sid, service)
    return state, url


def _build_get(url: str) -> bytes:
    return bytes(ColorGet(
        Flags=_GET_FLAGS_AS,
        NSID=nid_to_bytes(PROVIDER_NID),
        LSID=lsid_from_url(url),
        NID=nid_to_bytes(CONSUMER_NID),
        Segment_ID=TX,
        PID_List=[],
    ))


def _build_ack(url: str) -> bytes:
    http_request = (
        f"GET http://prov.local{URL_PATH} HTTP/1.1\r\n"
        "Host: prov.local\r\n"
        "User-Agent: stub-consumer\r\n\r\n"
    ).encode("latin-1")
    load = bytes([WebMsgType.HTTP_REQUEST | LoadFlag.LAST]) + http_request
    ack = ColorData(
        Flags=_DATA_FLAGS_BS,
        NSID=nid_to_bytes(PROVIDER_NID),
        LSID=lsid_from_url(url),
        Destination_NID=nid_to_bytes(PROVIDER_NID),  # nid_pro
        Source_NID=nid_to_bytes(CONSUMER_NID),       # nid_cus（第二个 NID）
        Segment_ID=TX,
        PID_List=[],
    )
    return bytes(ack / Raw(load))


def _reassemble_response(sender: FakeSender) -> bytes | None:
    """从 FakeSender 捕获的 RESPONSE 分片按序拼接，遇 LAST 结束。"""
    body = b""
    seen_last = False
    for _, raw in sender.snapshot():
        if raw[0] != 0x73:  # 仅看 DATA
            continue
        data = ColorData(raw)
        load = bytes(data.payload)
        if not load or (load[0] & WEB_MSG_TYPE_MASK) != WebMsgType.HTTP_RESPONSE:
            continue
        body += load[1:]
        if load[0] & LoadFlag.LAST:
            seen_last = True
    return body if seen_last else None


def main() -> int:
    origin, port = _start_origin()
    try:
        state, url = _build_state(port)
        sender = FakeSender()

        # 1) 消费端发 GET -> 服务端应回隧道 DATA
        handlers.handle_get(state, sender, _build_get(url))
        tunnel = [raw for _, raw in sender.snapshot() if raw[0] == 0x73]
        assert tunnel, "未收到隧道 DATA"
        load0 = bytes(ColorData(tunnel[0]).payload)[0]
        assert (load0 & WEB_MSG_TYPE_MASK) == WebMsgType.TUNNEL, "首个 DATA 不是隧道包"
        assert load0 & LoadFlag.LAST, "隧道包未置 LAST"
        print("  PASS GET -> 隧道 DATA")

        # 2) 消费端发 ACK(带 HTTP 请求) -> 服务端回源 -> 回响应 DATA
        handlers.handle_ack(state, sender, _build_ack(url))
        deadline = time.time() + 5.0
        response = None
        while time.time() < deadline:
            response = _reassemble_response(sender)
            if response is not None:
                break
            time.sleep(0.05)
        assert response is not None, "未收到完整 HTTP 响应（缺 LAST 分片）"
        assert b"200" in response.split(b"\r\n", 1)[0], "响应状态行非 200"
        assert HELLO_BODY in response, "响应体与源站不一致"
        print("  PASS ACK -> 回源 -> 响应 DATA（响应体一致）")

        print("\n业务闭环验证通过")
        return 0
    except AssertionError as exc:
        print(f"  FAIL: {exc}")
        return 1
    finally:
        origin.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
