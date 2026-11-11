"""CoLoR 报文发送器。

经 scapy 在二层封装 ``Ether/IP(proto=150)/<CoLoR>`` 后用 ``sendp`` 发出，
并缓存目的 IP 对应的 MAC 与出口网卡，避免每包重复解析（对照 ProxyLib.SendIpv4）。
"""
from __future__ import annotations

import logging
import threading
from typing import Union

from scapy.layers.inet import IP
from scapy.layers.l2 import Ether, getmacbyip
from scapy.packet import Packet, Raw
from scapy.sendrecv import sendp

from ..protocol.constants import IP_PROTO_COLOR

logger = logging.getLogger(__name__)

Payload = Union[Packet, bytes]

#: ARP 解析不出来时 scapy 回落的目的 MAC（包会被当广播发出去）
_BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


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

    def describe(self, dst_ip: str) -> str:
        """一行"这个目的地址会怎么发出去"，供注册失败等诊断路径引用。"""
        try:
            mac, iface = self._resolve(dst_ip)
        except Exception as exc:  # noqa: BLE001 诊断路径不该再抛
            return f"无法解析到 {dst_ip} 的出口（{exc}）"
        suffix = "（ARP 未解析到，包会被当广播发出）" if mac == _BROADCAST_MAC else ""
        return f"{dst_ip} 经网卡 {iface}，下一跳 MAC {mac}{suffix}"

    def _resolve(self, dst_ip: str) -> tuple[str, str]:
        with self._lock:
            if dst_ip not in self._cache:
                # 显式解析下一跳的 MAC：scapy 2.8 起 Ether().dst 推迟到组帧时才解析，
                # 读出来是 None，缓存就失效了（每次发包都重新解析，ARP 缓存过期时还会
                # 阻塞一次），解析失败时的广播告警也永远不会触发
                iface, _src, gateway = IP(dst=dst_ip).route()
                next_hop = gateway if gateway and gateway != "0.0.0.0" else dst_ip
                mac = getmacbyip(next_hop) or _BROADCAST_MAC
                self._cache[dst_ip] = (mac, iface)
                self._log_resolution(dst_ip, mac, iface)
            return self._cache[dst_ip]

    @staticmethod
    def _log_resolution(dst_ip: str, mac: str, iface: str) -> None:
        """首次解析出口时打一行。

        解析结果是"包到底发去哪了"的唯一线索，出错时的症状（对端毫无反应）与
        地址配错、二层不通完全一样。MAC 解析不出来尤其要单独喊一声：scapy 会
        悄悄回落到广播地址照发不误，日志里看着一切正常。
        """
        if mac == _BROADCAST_MAC:
            logger.warning(
                "解析不到 %s 的 MAC，将以广播发出（网卡 %s）。"
                "该地址多半配错了或二层不可达——先 ping 一下、看 arp -a 有没有它",
                dst_ip, iface,
            )
        else:
            logger.info("CoLoR 出口：%s 经网卡 %s，下一跳 MAC %s", dst_ip, iface, mac)
