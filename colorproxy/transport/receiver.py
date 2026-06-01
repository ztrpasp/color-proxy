"""CoLoR 报文接收器。

在本机 IP 上开一个原始套接字（IP 协议号 150），Windows 下开启 ``SIO_RCVALL``
接收所有入站 IP 包；过滤出协议号 150 且目的为本机的报文，把 CoLoR 负载字节
回调给上层处理（对照 ColorMonitor.Monitor）。
"""
from __future__ import annotations

import socket
import threading
from typing import Callable

from scapy.layers.inet import IP

from ..protocol.constants import IP_PROTO_COLOR

#: 单次接收缓冲区大小（足以容纳一个以太网 MTU 之内的 IP 包）
_RECV_BUFFER = 65535


class ColorReceiver(threading.Thread):
    """后台线程：持续接收 CoLoR 报文并回调 ``on_payload(payload: bytes)``。"""

    def __init__(self, bind_ip: str, on_payload: Callable[[bytes], None]) -> None:
        super().__init__(name="ColorReceiver", daemon=True)
        self._bind_ip = bind_ip
        self._on_payload = on_payload
        self._sock: socket.socket | None = None
        self._running = False

    def start(self) -> None:
        self._sock = self._open_socket()
        self._running = True
        super().start()

    def _open_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, IP_PROTO_COLOR)
        sock.bind((self._bind_ip, 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        if hasattr(socket, "SIO_RCVALL"):  # Windows 专有
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        return sock

    def run(self) -> None:
        assert self._sock is not None
        while self._running:
            try:
                raw, _ = self._sock.recvfrom(_RECV_BUFFER)
            except OSError:
                if self._running:
                    raise
                break
            packet = IP(raw)
            if packet.proto != IP_PROTO_COLOR or packet.dst != self._bind_ip:
                continue
            payload = bytes(packet.payload)
            if payload:
                self._on_payload(payload)

    def stop(self) -> None:
        self._running = False
        if self._sock is not None:
            if hasattr(socket, "SIO_RCVALL"):
                try:
                    self._sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except OSError:
                    pass
            self._sock.close()
