"""HTTP 正向代理 + 单请求握手编排（消费端核心流程）。

监听固定端口接收浏览器/系统代理设置的 HTTP 连接，对每个请求：
解析完整 URL → 查本域 SID 表 → 发 GET 等隧道 → 发 ACK(载 HTTP 请求) 等响应
→ 把响应原样写回浏览器。每个浏览器连接处理一个请求后关闭（v1 不复用连接）。
"""
from __future__ import annotations

import itertools
import logging
import socketserver
import threading

from .messages import build_ack, build_get
from .state import ConsumerState

logger = logging.getLogger(__name__)

#: 等待隧道 DATA / 响应 DATA 的超时（秒）；超时向浏览器回 504
TUNNEL_TIMEOUT = 5.0
RESPONSE_TIMEOUT = 10.0
#: 单个 HTTP 请求行/请求头读取上限（v1 假设请求可单包装下）
_MAX_REQUEST_BYTES = 64 * 1024

# 事务标识（GET 的 SegID，提供端原样回带；v1 仅用于日志/对账）
_seg_counter = itertools.count(1)
_seg_lock = threading.Lock()


def _next_seg_id() -> int:
    with _seg_lock:
        return next(_seg_counter) & 0xFFFFFFFF


def orchestrate_request(
    state: ConsumerState, sender, url: str, raw_request: bytes
) -> bytes:
    """跑完一次"先拉后推"握手，返回要写回浏览器的字节。

    未命中 SID 表 → 502；隧道/响应超时 → 504；无法定回址 → 502。
    """
    sid = state.lookup_by_url(url)
    if sid is None:
        logger.info("URL 未发布到共生网络，回 502：%s", url)
        return _error_response(502, "Bad Gateway: URL not published to CoLoR network")

    # 同 (SID, 本机NID) 请求串行（契约 §2.4，对齐服务端 last-wins）
    with state.sid_lock(sid):
        seg_id = _next_seg_id()
        pending = state.new_pending(sid, state.nid)
        try:
            sender.send(state.rm_ipv4, build_get(sid, state.nid, seg_id))
            logger.info("已发 GET：SID=%s… SegID=%d url=%s", sid[:16], seg_id, url)

            if not pending.tunnel_event.wait(TUNNEL_TIMEOUT):
                logger.warning("等待隧道 DATA 超时，回 504：SID=%s…", sid[:16])
                return _error_response(504, "Gateway Timeout: no tunnel from provider")
            if pending.return_ip is None:
                logger.warning("无法确定回址，回 502：SID=%s…", sid[:16])
                return _error_response(502, "Bad Gateway: cannot resolve return path")

            ack = build_ack(sid, state.nid, pending.pids, seg_id, raw_request)
            sender.send(pending.return_ip, ack)
            logger.info("已发 ACK(B=1) 推 HTTP 请求：SID=%s… 回址=%s", sid[:16], pending.return_ip)

            if not pending.response_event.wait(RESPONSE_TIMEOUT):
                logger.warning("等待响应 DATA 超时，回 504：SID=%s…", sid[:16])
                return _error_response(504, "Gateway Timeout: no response from provider")
            return bytes(pending.response_buf)
        finally:
            state.pop_pending(sid, state.nid)


def _read_http_request(rfile) -> tuple[bytes, str, str] | None:
    """从浏览器连接读出一个完整 HTTP 请求，返回 (原始字节, URL, 方法)。

    支持正向代理的绝对 URI 请求行（``GET http://h/p HTTP/1.1``）；缺绝对 URI
    时按 Host 首部重建 URL。读取失败/空请求返回 None。
    """
    request_line = rfile.readline(_MAX_REQUEST_BYTES)
    if not request_line:
        return None
    parts = request_line.split()
    if len(parts) < 3:
        return None
    method, target = parts[0].decode("latin-1"), parts[1].decode("latin-1")

    header_lines: list[bytes] = []
    content_length, host = 0, None
    while True:
        line = rfile.readline(_MAX_REQUEST_BYTES)
        if not line or line in (b"\r\n", b"\n"):
            break
        header_lines.append(line)
        name, _, value = line.partition(b":")
        key = name.strip().lower()
        if key == b"content-length":
            content_length = int(value.strip() or b"0")
        elif key == b"host":
            host = value.strip().decode("latin-1")

    body = rfile.read(content_length) if content_length else b""
    raw_request = request_line + b"".join(header_lines) + b"\r\n" + body

    if target.lower().startswith(("http://", "https://")):
        url = target
    elif method == "CONNECT":
        url = target  # host:port，HTTPS，不支持
    else:
        url = f"http://{host}{target}" if host else target
    return raw_request, url, method


def _error_response(code: int, message: str) -> bytes:
    reason = {502: "Bad Gateway", 504: "Gateway Timeout", 501: "Not Implemented"}.get(code, "Error")
    body = message.encode("utf-8")
    return (
        f"HTTP/1.1 {code} {reason}\r\n".encode("ascii")
        + b"Content-Type: text/plain; charset=utf-8\r\n"
        + b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
        + b"Connection: close\r\n\r\n" + body
    )


class _ProxyHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:  # 每个浏览器连接一个请求，处理后关闭
        try:
            parsed = _read_http_request(self.rfile)
        except (OSError, ValueError):
            return
        if parsed is None:
            return
        raw_request, url, method = parsed
        if method == "CONNECT":
            self.wfile.write(_error_response(501, "HTTPS (CONNECT) not supported in v1"))
            return
        response = orchestrate_request(self.server.state, self.server.sender, url, raw_request)
        try:
            self.wfile.write(response)
        except OSError:
            pass


class ProxyServer(socketserver.ThreadingTCPServer):
    """监听浏览器 HTTP 连接的多线程正向代理服务器。"""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, port: int, state: ConsumerState, sender) -> None:
        super().__init__(("0.0.0.0", port), _ProxyHandler)
        self.state = state
        self.sender = sender
