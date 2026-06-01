"""构造服务端要发送的 CoLoR DATA 报文（隧道 / HTTP 响应）。

被 handlers 与 origin 复用，单独成模块以避免循环依赖。
"""
from __future__ import annotations

from scapy.packet import Raw

from .protocol.packets import ColorData
from .protocol.sid import nid_to_bytes, split_sid_hex

#: DATA 报文 Flags 字节中的 B 位（bit6），用于区分 ACK(B=1) 与数据(B=0)
_FLAGS_BYTE_INDEX = 9
_B_FLAG_MASK = 0x40

# DATA 报文 Flags 各位（名称顺序 "rSCQMRBF"，低位在前）。
# 注意：必须在构造时整体赋值 Flags，不能用 pkt.Flags.X = True（scapy 会跨实例共享该可变值）。
_FLAG_SEGMENT_ID = 0x02  # S：含 Segment_ID
_FLAG_REVERSE_PATH = 0x20  # R：跨域/反向路径


def is_ack(payload: bytes) -> bool:
    """判断一个 DATA 报文（首字节 0x73）是否为 ACK（B=1）。"""
    return len(payload) > _FLAGS_BYTE_INDEX and bool(payload[_FLAGS_BYTE_INDEX] & _B_FLAG_MASK)


def build_data_packet(
    provider_nid: int,
    sid: str,
    consumer_nid: int,
    pids: list[int],
    seg_id: int,
    load: bytes,
) -> ColorData:
    """构造一个发往消费端的 DATA 报文（B=0）。

    - 跨域（``pids`` 非空）：置 R=1，带 Source_NID(本机) 与 ``pids + [保留 0]``
    - 域内（``pids`` 为空）：R=0，无 Source_NID 与 PID 列表

    回送路径处理对照 ColorMonitor.SendingThread 的发送逻辑。
    """
    nsid, lsid = split_sid_hex(sid)
    flags = _FLAG_SEGMENT_ID | (_FLAG_REVERSE_PATH if pids else 0)
    fields = {
        "Flags": flags,
        "NSID": nsid,
        "LSID": lsid,
        "Destination_NID": nid_to_bytes(consumer_nid),
        "Segment_ID": seg_id,
    }
    if pids:  # 跨域：带 Source_NID(本机) 与 PID 序列（末尾追加保留 PID）
        fields["Source_NID"] = nid_to_bytes(provider_nid)
        fields["PID_List"] = list(pids) + [0]
    return ColorData(**fields) / Raw(load)
