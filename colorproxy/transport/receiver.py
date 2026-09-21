"""CoLoR 报文接收器。

在本机 IP 上开一个原始套接字（IP 协议号 150），Windows 下开启 ``SIO_RCVALL``
接收所有入站 IP 包；过滤出协议号 150 且目的为本机的报文，把 CoLoR 负载字节
回调给上层处理（对照 ColorMonitor.Monitor）。
"""
from __future__ import annotations

import logging
import socket
import threading
from typing import Callable

from scapy.layers.inet import IP

from ..protocol.constants import IP_PROTO_COLOR

logger = logging.getLogger(__name__)

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
        #: 收到并交给上层的 CoLoR 报文数
        self.delivered = 0
        #: 协议号对但目的地址不是本进程绑定地址、因而被丢弃的报文数
        self.other_dst = 0
        self._warned_other_dst = False

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
            if packet.proto != IP_PROTO_COLOR:
                continue
            if packet.dst != self._bind_ip:
                self._note_other_dst(packet.dst)
                continue
            payload = bytes(packet.payload)
            if payload:
                self.delivered += 1
                self._on_payload(payload)

    def _note_other_dst(self, dst: str) -> None:
        """记下"协议号对、地址不对"的报文，并提示一次。

        这是"对端明明回了、我这边却什么都没收到"的头号成因：``ipv4`` 配成了本机
        另一张网卡的地址时，绑定和过滤都用那个地址，真正到达的回复被这里悄悄丢掉。
        混杂模式下也可能是邻居的 CoLoR 流量，故只提示一次、不当错误。
        """
        self.other_dst += 1
        if self._warned_other_dst:
            return
        self._warned_other_dst = True
        logger.warning(
            "收到发往 %s 的 CoLoR 报文，但本进程绑定的是 %s，已丢弃（同类只提示一次）。"
            "若 %s 也是本机地址，说明配置里的 ipv4 指向了另一张网卡——"
            "RM 的回复会一直被丢在这里",
            dst, self._bind_ip, dst,
        )

    def stop(self) -> None:
        self._running = False
        if self._sock is not None:
            if hasattr(socket, "SIO_RCVALL"):
                try:
                    self._sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except OSError:
                    pass
            self._sock.close()
