"""CoLoR 协议常量。

字段定义与取值对照参考实现 color-agent-plus（CoLoRProtocol/CoLoRpacket.py、
Frontend/ProxyLib.py），此处仅作整理与精简。
"""
from enum import IntEnum

#: CoLoR 报文承载于该 IP 协议号之上
IP_PROTO_COLOR = 150
#: 协议版本号（报文首字节高 4 位）
COLOR_VERSION = 7


class PacketType(IntEnum):
    """报文类型（报文首字节低 4 位）。"""

    ANNOUNCE = 1
    GET = 2
    DATA = 3
    CONTROL = 4


# 报文首字节 = (COLOR_VERSION << 4) | PacketType
ANNOUNCE_FIRST_BYTE = (COLOR_VERSION << 4) | PacketType.ANNOUNCE  # 0x71
GET_FIRST_BYTE = (COLOR_VERSION << 4) | PacketType.GET            # 0x72
DATA_FIRST_BYTE = (COLOR_VERSION << 4) | PacketType.DATA          # 0x73
CONTROL_FIRST_BYTE = (COLOR_VERSION << 4) | PacketType.CONTROL    # 0x74


class ControlSubtype(IntEnum):
    """控制报文子类型（仅列出本项目使用的几种）。"""

    PROXY_REGISTER = 5        # 终端 -> RM：代理注册
    PROXY_REGISTER_REPLY = 6  # RM -> 终端：下发域内 Proxy/BR 信息
    #: RM -> 域内其他终端：新代理加入通知，载荷是新代理的注册载荷原样转发（IP + NID，20 字节）。
    #: RM 源码里叫 CONTROL_SYN_CONFIG_PROXY，解析见 control.parse_proxy_notify。
    PROXY_NOTIFY = 8
    SID_LIST_UPDATE = 40      # RM -> 终端：下发/更新本域可访问 SID 列表（裸 36B SID 拼接）


# 各标识长度（字节）
NID_LEN = 16   # 节点标识
NSID_LEN = 16  # SID 的 NID 部分
LSID_LEN = 20  # SID 的 Label 部分
SID_LEN = NSID_LEN + LSID_LEN            # 完整 SID 字节长度 = 36
SID_HEX_LEN = SID_LEN * 2                # SID 十六进制字符串长度 = 72


class LoadFlag(IntEnum):
    """DATA 报文负载首字节 load[0] 的低位标志（沿用参考实现 DataFlag）。"""

    LAST = 0x01  # 最后一个分片


class WebMsgType(IntEnum):
    """load[0] 高 4 位（bit4-7）标识报文用途（本项目扩展）。

    v1 只用高 2 位（掩码 0x30，四个取值已占满）；v2 的 L3 隧道模式把掩码扩宽到
    0xF0 并新增 IP_UPSTREAM / IP_DOWNSTREAM，v1 的三个取值原样不变、向后兼容
    （docs/design-l3-v2.md §4.1）。

    注意 ``TUNNEL`` 由 v1 与 L3 两种模式**共用**：两者靠"该 SID 在哪张服务表里"
    区分，不靠这个字节（D13，见下 WEB_MSG_TYPE_MASK 的说明）。
    """

    TUNNEL = 0x10         # 隧道建立：P->C，空内容，仅用于回送 PID 序列（v1/L3 共用）
    HTTP_REQUEST = 0x20   # HTTP 请求：C->P
    HTTP_RESPONSE = 0x30  # HTTP 响应：P->C
    IP_UPSTREAM = 0x40    # L3 上行：C->P，载荷为恰好一个完整内层 IPv4 包
    IP_DOWNSTREAM = 0x50  # L3 下行：P->C，载荷为恰好一个完整内层 IPv4 包


#: 用于从 load[0] 提取 WebMsgType 的掩码（v2 由 0x30 扩宽到 0xF0，见 §4.1）。
#:
#: 掩码必须扩宽：在旧的 0x30 之下 ``0x51 & 0x30 == 0x10``，L3 下行会被误判成
#: 隧道包。扩宽后 v1 的三个取值结果不变（``0x11/0x21/0x31`` 仍得 ``0x10/0x20/0x30``）。
#:
#: 但它**不是模式分派的判据**（D13）：提供端 ACK 路径上的类型校验是 cd9348b
#: 刻意取消的（"宽松放行"），说明该字节在真机上曾对不上。两端一律先按 SID 查
#: 服务/隧道表决定走哪条路径，本掩码只用于宽松校验 + 计数，不符时照常处理。
WEB_MSG_TYPE_MASK = 0xF0

#: HTTP 响应单个 DATA 报文的负载分片大小（字节）
RESPONSE_CHIP_SIZE = 1200
