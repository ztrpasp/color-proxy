"""CoLoR 报文的 scapy 声明式定义（GET / DATA / ANNOUNCE）。

字段布局移植自参考实现 color-agent-plus 的 CoLoRProtocol/CoLoRpacket.py，
并做了两点必要修正与精简：

1. ``ColorData.Source_NID`` 的出现条件扩展到 ``B == 1``：ACK(B=1) 报文在线上
   含两个 NID（Destination_NID=提供方、第二个=消费端），原定义遗漏了第二个。
2. ``ColorData`` 的 ``PID_Pointer`` 在构建时自动回填（= 有效 PID 数），原定义未填。

并移除了 ESS 加密及攻击/ODC 等本服务端用不到的类型；HMAC 以精简形式在
``ColorData.post_build`` 中实现（C 置位时按无密钥 MD5 取末 4 字节回填，见下）。
CONTROL 报文因 RM 同步表的字段次序与声明式定义不一致，改在 control.py 中手工编解码。
"""
from __future__ import annotations

from scapy.fields import (
    BitField,
    ByteField,
    ConditionalField,
    FieldLenField,
    FieldListField,
    FlagsField,
    LEIntField,
    LEShortField,
    PacketListField,
    StrFixedLenField,
    StrLenField,
    XStrFixedLenField,
    XShortField,
)
from scapy.packet import Packet

from .constants import COLOR_VERSION, PacketType
from .utils import calc_hmac, calculate_checksum, int_to_bytes_be, int_to_bytes_le

# DATA 报文标志位顺序（低位在前），与参考实现 (F<<7|B<<6|R<<5|M<<4|Q<<3|C<<2|S<<1|r) 一致
_DATA_FLAGS = "rSCQMRBF"


class ColorGet(Packet):
    """GET 请求报文。本服务端仅用于解析消费端发来的请求。"""

    name = "ColorGet"
    fields_desc = [
        BitField("Version", COLOR_VERSION, 4, tot_size=1),
        BitField("Type", PacketType.GET, 4, end_tot_size=1),
        ByteField("TTL", 64),
        LEShortField("Packet_Length", None),
        XShortField("Checksum", None),
        LEShortField("MTU", None),
        FieldLenField("PID_Num", None, fmt="B", count_of="PID_List"),
        FlagsField("Flags", 8, 8, "rCRASQKF"),
        LEShortField("Minimal_PID_CP", None),
        StrFixedLenField("NSID", b"", 16),
        StrFixedLenField("LSID", b"", 20),
        StrFixedLenField("NID", b"", 16),
        ConditionalField(
            FieldLenField("Public_Key_Length", None, fmt="<H", length_of="Public_Key"),
            lambda pkt: pkt.Flags.K,
        ),
        ConditionalField(
            StrLenField("Public_Key", b"", length_from=lambda pkt: pkt.Public_Key_Length),
            lambda pkt: pkt.Flags.K,
        ),
        ConditionalField(
            FieldLenField("QoS_Length", None, fmt="B", length_of="QoS_Requirements"),
            lambda pkt: pkt.Flags.Q,
        ),
        ConditionalField(
            StrLenField("QoS_Requirements", b"", length_from=lambda pkt: pkt.QoS_Length),
            lambda pkt: pkt.Flags.Q,
        ),
        ConditionalField(StrFixedLenField("HMAC", b"", 16), lambda pkt: pkt.Flags.C),
        ConditionalField(LEIntField("Segment_ID", None), lambda pkt: pkt.Flags.S),
        FieldListField("PID_List", [], LEIntField("", None), count_from=lambda pkt: pkt.PID_Num),
        ConditionalField(StrFixedLenField("Random_Num", b"", 4), lambda pkt: pkt.Flags.R),
    ]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        if self.Packet_Length is None:
            pkt = pkt[:2] + int_to_bytes_le(len(pkt), 2) + pkt[4:]
        if self.Checksum is None:
            pkt = pkt[:4] + int_to_bytes_be(calculate_checksum(pkt), 2) + pkt[6:]
        return pkt + pay


class ColorData(Packet):
    """DATA 数据报文（B=0）及其 ACK 子类型（B=1）。

    本服务端用它构建隧道/响应 DATA（B=0）并解析消费端推送的 ACK（B=1）。
    """

    name = "ColorData"
    fields_desc = [
        BitField("Version", COLOR_VERSION, 4, tot_size=1),
        BitField("Type", PacketType.DATA, 4, end_tot_size=1),
        ByteField("TTL", 64),
        LEShortField("Packet_Length", None),
        XShortField("Checksum", None),
        ByteField("Header_Length", None),
        ByteField("PID_Pointer", None),
        FieldLenField(
            "PID_Num", None, fmt="B", count_of="PID_List",
            adjust=lambda pkt, x: x - (1 if pkt.Flags.R else 0),
        ),
        FlagsField("Flags", 0, 8, _DATA_FLAGS),
        ConditionalField(LEShortField("Minimal_PID_CP", None), lambda pkt: pkt.Flags.M),
        StrFixedLenField("NSID", b"", 16),
        StrFixedLenField("LSID", b"", 20),
        StrFixedLenField("Destination_NID", b"", 16),
        # B=0,R=1 时为 Source_NID(提供方)；B=1 时为第二个 NID(消费端)。两种情况下均额外占 16 字节。
        ConditionalField(
            StrFixedLenField("Source_NID", b"", 16),
            lambda pkt: (not pkt.Flags.B and pkt.Flags.R) or pkt.Flags.B,
        ),
        ConditionalField(
            FieldLenField("QoS_Length", None, fmt="B", length_of="QoS_Requirements"),
            lambda pkt: pkt.Flags.Q,
        ),
        ConditionalField(
            StrLenField("QoS_Requirements", b"", length_from=lambda pkt: pkt.QoS_Length),
            lambda pkt: pkt.Flags.Q,
        ),
        ConditionalField(StrFixedLenField("HMAC", b"", 4), lambda pkt: pkt.Flags.C),
        ConditionalField(LEIntField("Segment_ID", None), lambda pkt: pkt.Flags.S),
        FieldListField(
            "PID_List", [], LEIntField("", None),
            count_from=lambda pkt: pkt.PID_Num + (1 if pkt.Flags.R else 0),
        ),
    ]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        if self.Header_Length is None:
            pkt = pkt[:6] + int_to_bytes_be(len(pkt), 1) + pkt[7:]
        if self.PID_Pointer is None:
            pid_pointer = len(self.PID_List) - (1 if self.Flags.R else 0)
            pkt = pkt[:7] + int_to_bytes_be(pid_pointer, 1) + pkt[8:]
        if self.Packet_Length is None:
            pkt = pkt[:2] + int_to_bytes_le(len(pkt) + len(pay), 2) + pkt[4:]
        if self.Flags.C:
            # C 置位时重算 HMAC（MD5 取末 4 字节），种子为此前置于 HMAC 字段的 Random_Num。
            # 算法/偏移对照参考实现 color-agent-plus CoLoRpacket.ColorData.post_build。
            # 必须在校验和之前计算，使校验和覆盖最终 HMAC 字节。
            has_source_nid = bool(self.Flags.R) and not bool(self.Flags.B)
            hmac_start = 10 + 2 * (1 if self.Flags.M else 0)
            hmac_offset = 62 + 2 * (1 if self.Flags.M else 0) + 16 * (1 if has_source_nid else 0)
            if self.Flags.Q:
                hmac_offset += self.QoS_Length + 1
            seed = (
                pkt[hmac_start:hmac_offset]
                + b"\x00\x00\x00\x00"
                + pkt[hmac_offset + 4:]
                + pay
                + pkt[hmac_offset:hmac_offset + 4]  # 当前存放的是 Random_Num 种子
            )
            digest = calc_hmac(seed)[-4:]
            pkt = pkt[:hmac_offset] + digest + pkt[hmac_offset + 4:]
        if self.Checksum is None:
            # DATA 校验和仅覆盖包头，不含负载
            pkt = pkt[:4] + int_to_bytes_be(calculate_checksum(pkt), 2) + pkt[6:]
        return pkt + pay


class StrategyUnit(Packet):
    """通告策略单元。"""

    name = "StrategyUnit"
    fields_desc = [
        ByteField("Type", 0),
        FieldLenField("Length", None, fmt="B", length_of="Value"),
        StrLenField("Value", b"", length_from=lambda pkt: pkt.Length),
    ]

    def extract_padding(self, s: bytes):
        return b"", s


class AnnounceUnit(Packet):
    """通告单元：声明一个 SID 及其策略。"""

    name = "AnnounceUnit"
    fields_desc = [
        BitField("N", 1, 1, tot_size=1),
        BitField("L", 1, 1),
        BitField("I", 1, 1),
        BitField("AM", 1, 2),  # 1=注册, 2=更新, 3=注销
        BitField("r", 0, 3, end_tot_size=1),
        ByteField("Unit_Length", None),
        FieldLenField("Strategy_Num", None, fmt="B", count_of="Strategy_Unit_List"),
        ConditionalField(XStrFixedLenField("NSID", b"", 16), lambda pkt: pkt.N == 1),
        ConditionalField(XStrFixedLenField("LSID", b"", 20), lambda pkt: pkt.L == 1),
        ConditionalField(XStrFixedLenField("NID", b"", 16), lambda pkt: pkt.I == 1),
        PacketListField(
            "Strategy_Unit_List", [], StrategyUnit,
            count_from=lambda pkt: pkt.Strategy_Num,
        ),
    ]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        if self.Unit_Length is None:
            pkt = pkt[:1] + int_to_bytes_be(len(pkt), 1) + pkt[2:]
        return pkt + pay

    def extract_padding(self, s: bytes):
        return b"", s


class ColorAnnounce(Packet):
    """ANN 通告报文。本服务端用于向 RM 发布 Web 服务对应的 SID。"""

    name = "ColorAnnounce"
    fields_desc = [
        BitField("Version", COLOR_VERSION, 4, tot_size=1),
        BitField("Type", PacketType.ANNOUNCE, 4, end_tot_size=1),
        ByteField("TTL", 64),
        LEShortField("Packet_Length", None),
        XShortField("Checksum", None),
        FlagsField("Flags", 0, 8, "rrrrCPKF"),
        BitField("Unit_Num", None, 4, tot_size=1),
        BitField("PX_Num", None, 4, end_tot_size=1),
        PacketListField(
            "Announce_Unit_List", [], AnnounceUnit,
            count_from=lambda pkt: pkt.Unit_Num,
        ),
    ]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        if self.Packet_Length is None:
            pkt = pkt[:2] + int_to_bytes_le(len(pkt), 2) + pkt[4:]
        if self.Unit_Num is None and self.PX_Num is None:
            byte = (len(self.Announce_Unit_List) << 4) | 0
            pkt = pkt[:7] + int_to_bytes_be(byte, 1) + pkt[8:]
        if self.Checksum is None:
            pkt = pkt[:4] + int_to_bytes_be(calculate_checksum(pkt), 2) + pkt[6:]
        return pkt + pay
