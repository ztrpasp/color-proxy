"""CoLoR 报文发送器。

经 scapy 在二层封装 ``Ether/IP(proto=150)/<CoLoR>`` 后用 ``sendp`` 发出，
并缓存目的 IP 对应的 MAC 与出口网卡，避免每包重复解析（对照 ProxyLib.SendIpv4）。
"""
from __future__ import annotations

import threading
from typing import Union

from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw
from scapy.sendrecv import sendp

from ..protocol.constants import IP_PROTO_COLOR

Payload = Union[Packet, bytes]


class ColorSender:
    """按目的 IP 发送 CoLoR 报文。线程安全。"""

    def __init__(self) -> None:
        self._cache: dict[str, tuple[str, str]] = {}  # dst_ip -> (mac, iface)
        self._lock = threading.Lock()

    def send(self, dst_ip: str, color: Payload) -> None:
        """向 ``dst_ip`` 发送一个 CoLoR 报文。

        ``color`` 可以是 scapy 报文对象（如 ColorData/ColorAnnounce），
        也可以是已序列化的原始字节（如 control.build_register 的结果）。
        """
        mac, iface = self._resolve(dst_ip)
        color_layer = color if isinstance(color, Packet) else Raw(color)
        frame = Ether(dst=mac) / IP(dst=dst_ip, proto=IP_PROTO_COLOR) / color_layer
        sendp(frame, iface=iface, verbose=False)

    def _resolve(self, dst_ip: str) -> tuple[str, str]:
        with self._lock:
            if dst_ip not in self._cache:
                template = Ether() / IP(dst=dst_ip, proto=IP_PROTO_COLOR)
                mac = template[Ether].dst
                iface = IP(dst=dst_ip).route()[0]
                self._cache[dst_ip] = (mac, iface)
            return self._cache[dst_ip]
