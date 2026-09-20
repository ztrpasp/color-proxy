"""构造消费端要发送的 CoLoR 报文（GET / B=1 ACK）。

字节布局移植自 ``tests/stub_consumer.py`` 的 ``_build_get`` / ``_build_ack``
（服务端测试已验证其与服务端解析端一致）。SID 列表请求复用 GET，仅把 SID 置空。

注意：scapy 的 ``Flags`` 必须在构造时整体赋整数值（不能 ``pkt.Flags.X = True``，
会跨实例共享可变标志对象，见 docs/软件说明书.md §4）。
"""
from __future__ import annotations

from scapy.packet import Raw

from ..protocol.constants import LoadFlag, NSID_LEN, WebMsgType
from ..protocol.packets import ColorData, ColorGet
from ..protocol.sid import nid_to_bytes, split_sid_hex

# GET Flags 各位（名称序 "rCRASQKF"，低位在前）：A=bit3、S=bit4。
_GET_FLAG_ANSWER = 0x08   # A：请求应答（参考实现 GET 默认置位）
_GET_FLAG_SEGMENT = 0x10  # S：含 Segment_ID（放事务标识 tx）
_GET_FLAGS = _GET_FLAG_ANSWER | _GET_FLAG_SEGMENT  # 0x18

# DATA Flags 各位（名称序 "rSCQMRBF"，低位在前）：S=bit1、B=bit6。
_DATA_FLAG_SEGMENT = 0x02  # S：含 Segment_ID
_DATA_FLAG_ACK = 0x40      # B：B=1 即 ACK（消费端经此通道推 HTTP 请求）
_ACK_FLAGS = _DATA_FLAG_ACK | _DATA_FLAG_SEGMENT  # 0x42

#: 全零哨兵 SID（72 hex）：向 RM 拉取本域 SID 列表用
_SENTINEL_SID = "0" * ((NSID_LEN + 20) * 2)


def build_get(sid: str, consumer_nid: int, seg_id: int | None) -> ColorGet:
    """构造一个 GET 报文（无 payload、无 PID）。

    ``sid`` 为查表得到的完整 SID(72 hex)：N_sid→NSID(提供方)、L_sid→LSID。
    途经 RM/BR 时 PID 会被累积，消费端自身不填 PID。

    ``seg_id`` 非 None 时置 S 标志并在 ``Segment_ID`` 放事务标识（提供端原样回带）；
    为 None 时不置 S、不含 Segment_ID（哨兵 SID 列表请求用，与参考实现
    ``download_SID_list_from_local_RM`` 的字节布局对齐）。
    """
    nsid, lsid = split_sid_hex(sid)
    fields = {
        "Flags": _GET_FLAGS if seg_id is not None else _GET_FLAG_ANSWER,
        "NSID": nsid,
        "LSID": lsid,
        "NID": nid_to_bytes(consumer_nid),
        "PID_List": [],
    }
    if seg_id is not None:
        fields["Segment_ID"] = seg_id
    return ColorGet(**fields)


def build_sid_list_request(consumer_nid: int) -> ColorGet:
    """构造拉取本域 SID 列表的哨兵 GET（NSID/LSID 全零、A=1、S=0、r=0）。

    参考实现以 ``Get('0'*36, 2)`` 向本域 RM 请求 SID 列表
    （color-agent-plus/src/Frontend/sidListWindow.py:124-126）。其中 ``'0'*36``
    长度不匹配 GetPkt 的 72/32/40 任何分支，故 N_sid/L_sid 均留 -1、packing 时
    写成全零 NSID(16)+LSID(20)——与此处全零哨兵字节一致。
    """
    return build_get(_SENTINEL_SID, consumer_nid, seg_id=None)


def build_upstream(
    sid: str,
    consumer_nid: int,
    pids: list[int],
    seg_id: int,
    load: bytes,
) -> ColorData:
    """构造一个上行 ``DATA(B=1)``。v1 的 HTTP 请求与 v2 的 L3 内层包共用它。

    - ``Destination_NID`` = 提供方 NID（取自 SID 的 N_sid）
    - ``Source_NID``      = 消费端 NID（B=1 线上的第二个 NID）
    - ``PID_List``        = 反向路径（域内为空）
    - ``load``            = ``[类型位|LAST] + 内容``，由调用方拼好
    """
    nsid, lsid = split_sid_hex(sid)
    fields = {
        "Flags": _ACK_FLAGS,
        "NSID": nsid,
        "LSID": lsid,
        "Destination_NID": nsid,                      # 提供方 NID == N_sid
        "Source_NID": nid_to_bytes(consumer_nid),     # 消费端 NID（第二个 NID）
        "Segment_ID": seg_id,
    }
    if pids:
        fields["PID_List"] = list(pids)
    return ColorData(**fields) / Raw(load)


def build_ack(
    sid: str,
    consumer_nid: int,
    pids: list[int],
    seg_id: int,
    http_request: bytes,
) -> ColorData:
    """构造携带 HTTP 请求的 B=1 ACK（v1 内容级模式）。"""
    load = bytes([WebMsgType.HTTP_REQUEST | LoadFlag.LAST]) + http_request
    return build_upstream(sid, consumer_nid, pids, seg_id, load)


def build_l3_upstream(
    sid: str,
    consumer_nid: int,
    pids: list[int],
    seg_id: int,
    inner_packet: bytes,
) -> ColorData:
    """构造承载一个完整内层 IPv4 包的上行 DATA（v2 L3 模式，§4.3）。

    一个 DATA 恰好承载一个内层包，不做聚合；``LAST`` 恒置 1（§4.2）。
    """
    load = bytes([WebMsgType.IP_UPSTREAM | LoadFlag.LAST]) + inner_packet
    return build_upstream(sid, consumer_nid, pids, seg_id, load)


def reverse_path_for_ack(recv_pids: list[int]) -> list[int]:
    """由隧道 DATA 带回的 PID 序列推出 ACK 的反向路径 PID 序列。

    - 域内（``recv_pids`` 为空）→ 空（ACK 不带 PID、R=0）。
    - 跨域 → 去掉 BR 在入域时置于**首位**的保留/返回 PID（``recv_pids[0]``），
      其余按到达序反向，即 ``recv_pids[1:][::-1]``。

    注意保留位的位置：服务端在隧道 DATA 的 PID 列**尾部**追加保留位(0)（见
    colorproxy/messages.py build_data_packet，对齐参考实现 DataPkt B=0/R=1）。
    但 DATA 经真实 BR 反向路由后，消费端收到的 PID 列**首位**才是 BR 入域校验
    （verify_pid_inbound）所用的保留/返回 PID——故按首位（而非尾部）剥离。
    对齐参考实现 ``RecvDataPkt.PIDs[1:][::-1]``：
    color-agent-plus/src/Frontend/ColorMonitor.py:224,290-296,385-389。
    """
    return recv_pids[1:][::-1]
