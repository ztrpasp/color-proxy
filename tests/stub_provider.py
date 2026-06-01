"""桩提供端 + 桩 RM：验证消费端 浏览器 -> GET -> 隧道 -> ACK -> 响应 -> 写回 业务闭环。

本测试不依赖真实 RM/BR、不需要管理员权限或 Npcap：它启动消费端的 HTTP 正向代理
（真实本地 socket），用 FakeSender 捕获消费端发出的 GET/ACK，并把"提供端应回送的
隧道 DATA / 响应 DATA"直接喂给消费端 handlers，最后校验响应被正确写回浏览器连接。
走域内路径（无 PID），结果确定。是 tests/stub_consumer.py 的镜像。

运行：``python tests/stub_provider.py``
"""
from __future__ import annotations

import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from colorproxy.consumer import handlers
from colorproxy.consumer.config import ConsumerConfig
from colorproxy.consumer.proxy import ProxyServer
from colorproxy.consumer.state import ConsumerState
from colorproxy.messages import build_data_packet  # 服务端构造 DATA（复用）
from colorproxy.protocol.constants import (
    LoadFlag,
    WEB_MSG_TYPE_MASK,
    WebMsgType,
)
from colorproxy.protocol.packets import ColorData, ColorGet
from colorproxy.protocol.sid import lsid_from_url, nid_to_bytes, sid_hex_from_url

PROVIDER_NID = 0xA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1
CONSUMER_NID = 0xB2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2
PROVIDER_IP = "10.0.1.6"
URL = "http://prov.local/hello.html"
HTTP_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/html\r\n"
    b"Content-Length: 51\r\n"
    b"Connection: close\r\n\r\n"
    b"<html><body>hello from CoLoR provider</body></html>"
)


class FakeSender:
    """记录消费端要发送的报文，不真正上网。"""

    def __init__(self) -> None:
        self.sent: list[tuple[str, bytes]] = []
        self._lock = threading.Lock()

    def send(self, dst_ip: str, color) -> None:
        with self._lock:
            self.sent.append((dst_ip, bytes(color)))

    def snapshot(self) -> list[tuple[str, bytes]]:
        with self._lock:
            return list(self.sent)


def _build_state() -> ConsumerState:
    config = ConsumerConfig(nid=CONSUMER_NID, ipv4="10.0.1.5", rm_ipv4="10.0.0.1", proxy_port=0)
    state = ConsumerState(config)
    state.registered.set()
    state.set_domain_info([(PROVIDER_NID, PROVIDER_IP)], [])  # 域内：提供方 NID -> IP
    state.add_sid(sid_hex_from_url(PROVIDER_NID, URL))        # 本域 SID 表
    return state


def _wait_for(sender: FakeSender, first_byte: int, predicate, timeout=5.0):
    """轮询 FakeSender，返回首个满足条件的捕获报文字节。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        for _, raw in sender.snapshot():
            if raw[0] == first_byte and predicate(raw):
                return raw
        time.sleep(0.02)
    return None


def _inject_tunnel(state: ConsumerState, sid: str, seg_id: int) -> None:
    tunnel = build_data_packet(
        PROVIDER_NID, sid, CONSUMER_NID, pids=[], seg_id=seg_id,
        load=bytes([WebMsgType.TUNNEL | LoadFlag.LAST]),
    )
    handlers.handle_data(state, bytes(tunnel))


def _inject_response(state: ConsumerState, sid: str, seg_id: int) -> None:
    chip = 20  # 故意分多片，校验拼接与 LAST 逻辑
    chips = [HTTP_RESPONSE[i:i + chip] for i in range(0, len(HTTP_RESPONSE), chip)]
    for index, part in enumerate(chips):
        flag = WebMsgType.HTTP_RESPONSE | (LoadFlag.LAST if index == len(chips) - 1 else 0)
        pkt = build_data_packet(PROVIDER_NID, sid, CONSUMER_NID, pids=[], seg_id=seg_id,
                                load=bytes([flag]) + part)
        handlers.handle_data(state, bytes(pkt))


def main() -> int:
    state = _build_state()
    sender = FakeSender()
    sid = sid_hex_from_url(PROVIDER_NID, URL)
    server = ProxyServer(0, state, sender)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    request = (
        f"GET {URL} HTTP/1.1\r\n"
        "Host: prov.local\r\n"
        "User-Agent: stub-browser\r\n\r\n"
    ).encode("latin-1")

    try:
        client = socket.create_connection(("127.0.0.1", port), timeout=5)
        client.sendall(request)

        # 1) 消费端应发 GET（NSID=提供方NID，LSID=SHA1(url)）
        get_raw = _wait_for(sender, 0x72,
                            lambda r: bytes(ColorGet(r).LSID) == lsid_from_url(URL))
        assert get_raw is not None, "未捕获到 GET"
        get = ColorGet(get_raw)
        assert bytes(get.NSID) == nid_to_bytes(PROVIDER_NID), "GET 的 NSID 非提供方 NID"
        assert bytes(get.NID) == nid_to_bytes(CONSUMER_NID), "GET 的请求者 NID 非消费端"
        seg_id = int(get.Segment_ID)
        print("  PASS 浏览器请求 -> GET")

        # 2) 桩提供端回隧道 DATA -> 消费端应发 B=1 ACK（载完整 HTTP 请求）
        _inject_tunnel(state, sid, seg_id)
        ack_raw = _wait_for(sender, 0x73, lambda r: ColorData(r).Flags.B == 1)
        assert ack_raw is not None, "未捕获到 B=1 ACK"
        ack = ColorData(ack_raw)
        assert bytes(ack.Destination_NID) == nid_to_bytes(PROVIDER_NID), "ACK Destination_NID 非提供方"
        assert bytes(ack.Source_NID) == nid_to_bytes(CONSUMER_NID), "ACK Source_NID 非消费端"
        load = bytes(ack.payload)
        assert (load[0] & WEB_MSG_TYPE_MASK) == WebMsgType.HTTP_REQUEST, "ACK load[0] 非 HTTP_REQUEST"
        assert load[0] & LoadFlag.LAST, "ACK 未置 LAST"
        assert load[1:] == request, "ACK 携带的 HTTP 请求与原始不一致"
        print("  PASS 隧道 DATA -> B=1 ACK（携带正确 HTTP 请求）")

        # 3) 桩提供端回响应 DATA（多片）-> 消费端应把响应写回浏览器
        _inject_response(state, sid, seg_id)
        client.settimeout(5)
        received = b""
        while len(received) < len(HTTP_RESPONSE):
            chunk = client.recv(4096)
            if not chunk:
                break
            received += chunk
        assert received == HTTP_RESPONSE, "写回浏览器的响应与提供端不一致"
        print("  PASS 响应 DATA -> 写回浏览器（响应一致）")

        print("\n业务闭环验证通过")
        return 0
    except AssertionError as exc:
        print(f"  FAIL: {exc}")
        return 1
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
