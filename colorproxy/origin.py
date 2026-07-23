"""回源与响应发送（state C / D）。

每个 HTTP 请求由一个 ``OriginWorker`` 线程处理：对每个请求新建一条到真实
Web 服务器的 TCP 连接，发送（规整后的）请求，**边从源站读、边把已到达的字节
按分片封装成 DATA 报文 best-effort 地发回消费端**（流式 cut-through，无重传）。

相比早先的"读满整份响应再分片发"（存储转发），流式把浏览器首字节时延（TTFB）
从"整份源站下载时间"降到"约一个源站往返 + 首片"，并把提供端内存占用从"整份
响应"降到"一个分片量级"。契约不变：分片只有 ``LAST`` 结束标志、无序号，仍假设
按序到达、不丢包（乱序/丢包下响应会损坏，属 v1 已知限制）。
"""
from __future__ import annotations

import logging
import socket
import threading
from urllib.parse import urlsplit

from .config import ServiceConfig
from .messages import build_data_packet
from .protocol.constants import RESPONSE_CHIP_SIZE, LoadFlag, WebMsgType
from .state import PendingTx, ProviderState
from .transport.sender import ColorSender

logger = logging.getLogger(__name__)

#: 回源连接与读取的超时（秒）
ORIGIN_TIMEOUT = 10.0
#: 一些会改变连接语义、不应原样转发给源站的逐跳首部
_HOP_BY_HOP_HEADERS = (b"connection", b"proxy-connection", b"keep-alive")


class OriginWorker(threading.Thread):
    """回源取响应并**边收边发**回消费端（流式 cut-through）。"""

    def __init__(
        self,
        state: ProviderState,
        sender: ColorSender,
        sid: str,
        consumer_nid: int,
        tx: PendingTx,
        service: ServiceConfig,
        http_request: bytes,
    ) -> None:
        super().__init__(name="OriginWorker", daemon=True)
        self._state = state
        self._sender = sender
        self._sid = sid
        self._consumer_nid = consumer_nid
        self._tx = tx
        self._service = service
        self._http_request = http_request
        self._chips_sent = 0
        self._bytes_sent = 0

    def run(self) -> None:
        self._stream()

    # -- state C+D：边回源边发响应（best-effort，无重传） ----------------

    def _stream(self) -> None:
        """从源站流式读取，读到满一片就立即发一片，读到 EOF 再收尾。

        为保证"恰好一个末片(LAST)"，循环里**只在缓冲 > 一个分片时**才发（严格
        大于，确保被发出的片后面一定还有字节 → 一定非末片）；剩余尾部由
        ``_flush_last`` 在 EOF/错误时统一收尾并标 LAST。
        """
        host, port = self._service.origin_host, self._service.origin_port
        request = _normalize_request(self._http_request, f"{host}:{port}")
        buf = bytearray()
        try:
            with socket.create_connection((host, port), timeout=ORIGIN_TIMEOUT) as conn:
                conn.settimeout(ORIGIN_TIMEOUT)
                conn.sendall(request)
                while True:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                    while len(buf) > RESPONSE_CHIP_SIZE:
                        self._send_chip(bytes(buf[:RESPONSE_CHIP_SIZE]), last=False)
                        del buf[:RESPONSE_CHIP_SIZE]
        except OSError as exc:
            logger.warning("回源失败 %s:%s：%s", host, port, exc)
            if self._chips_sent == 0:
                # 首字节前失败：把 502 当整份响应流式发回（消费端无需特判）
                self._flush_last(bytearray(_bad_gateway(exc)))
                return
            # 已发出若干片后中途失败：用已到达的尾部收尾（best-effort 截断）
        self._flush_last(buf)

    def _flush_last(self, buf: bytearray) -> None:
        """把剩余缓冲发完，仅最后一片标 LAST；空缓冲也发一个空末片。"""
        if not buf:
            self._send_chip(b"", last=True)
        else:
            while len(buf) > RESPONSE_CHIP_SIZE:
                self._send_chip(bytes(buf[:RESPONSE_CHIP_SIZE]), last=False)
                del buf[:RESPONSE_CHIP_SIZE]
            self._send_chip(bytes(buf), last=True)
        logger.info("已发回 HTTP 响应：SID=%s… 共 %d 片 / %d 字节",
                    self._sid[:16], self._chips_sent, self._bytes_sent)

    def _send_chip(self, chip: bytes, last: bool) -> None:
        flag = WebMsgType.HTTP_RESPONSE | (LoadFlag.LAST if last else 0)
        packet = build_data_packet(
            self._state.nid, self._sid, self._consumer_nid,
            self._tx.pids, self._tx.seg_id, bytes([flag]) + chip,
            hmac_seed=self._tx.random_num,
        )
        self._sender.send(self._tx.return_ip, packet)
        self._chips_sent += 1
        self._bytes_sent += len(chip)


def _normalize_request(raw_request: bytes, host_port: str) -> bytes:
    """把转发来的 HTTP 请求规整为源站可直接处理的形式。

    - 请求行的绝对 URI（``GET http://h/p``）改为源站形式（``GET /p``）
    - 删除逐跳首部并强制 ``Connection: close``，确保源站读完即关闭
    - 缺少 Host 首部时补齐
    """
    head, sep, body = raw_request.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    if not lines or not lines[0]:
        return raw_request

    request_line, header_lines = lines[0], lines[1:]
    request_line, url_host = _to_origin_form(request_line)

    kept = [line for line in header_lines
            if line.split(b":", 1)[0].strip().lower() not in _HOP_BY_HOP_HEADERS]
    if not any(line.split(b":", 1)[0].strip().lower() == b"host" for line in kept):
        kept.append(b"Host: " + (url_host or host_port).encode("latin-1"))
    kept.append(b"Connection: close")

    return request_line + b"\r\n" + b"\r\n".join(kept) + (sep + body if sep else b"\r\n\r\n")


def _to_origin_form(request_line: bytes) -> tuple[bytes, str | None]:
    """请求行绝对 URI 转源站形式，返回 (新请求行, URL 中的 host 或 None)。"""
    parts = request_line.split(b" ")
    if len(parts) != 3:
        return request_line, None
    method, target, version = parts
    lowered = target.lower()
    if not (lowered.startswith(b"http://") or lowered.startswith(b"https://")):
        return request_line, None
    split = urlsplit(target.decode("latin-1"))
    path = split.path or "/"
    if split.query:
        path += "?" + split.query
    return method + b" " + path.encode("latin-1") + b" " + version, split.netloc


def _bad_gateway(reason: object) -> bytes:
    """源站不可达时合成 502 响应，避免浏览器一直等待。"""
    body = f"502 Bad Gateway: {reason}".encode("utf-8")
    return (
        b"HTTP/1.1 502 Bad Gateway\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
        b"Connection: close\r\n\r\n" + body
    )
