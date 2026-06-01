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
    """控制报文子类型（仅列出本服务端使用的两种）。"""

    PROXY_REGISTER = 5        # 终端 -> RM：代理注册
    PROXY_REGISTER_REPLY = 6  # RM -> 终端：下发域内 Proxy/BR 信息


# 各标识长度（字节）
NID_LEN = 16   # 节点标识
NSID_LEN = 16  # SID 的 NID 部分
LSID_LEN = 20  # SID 的 Label 部分
SID_HEX_LEN = (NSID_LEN + LSID_LEN) * 2  # SID 十六进制字符串长度 = 72


class LoadFlag(IntEnum):
    """DATA 报文负载首字节 load[0] 的低位标志（沿用参考实现 DataFlag）。"""

    LAST = 0x01  # 最后一个分片


class WebMsgType(IntEnum):
    """load[0] 高 2 位（bit4-5）标识 Web 报文用途（本项目扩展）。"""

    TUNNEL = 0x10         # 隧道建立：P->C，空内容，仅用于回送 PID 序列
    HTTP_REQUEST = 0x20   # HTTP 请求：C->P
    HTTP_RESPONSE = 0x30  # HTTP 响应：P->C


#: 用于从 load[0] 提取 WebMsgType 的掩码
WEB_MSG_TYPE_MASK = 0x30

#: HTTP 响应单个 DATA 报文的负载分片大小（字节）
RESPONSE_CHIP_SIZE = 1200
