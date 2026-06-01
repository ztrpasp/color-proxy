"""处理收到的 DATA 报文（消费端侧握手的两步 + RM 的 SID 列表回送）。

分发判据（对照 color-agent-plus/src/Frontend/ColorMonitor.py:224-228,390-406）：
- 小写 ``r`` 标志置位 → RM 回送的 SID 列表条目（交 sid_table 登记）。
- ``r`` 未置位 → 握手/响应 DATA，按 ``load[0]`` 的 WebMsgType 细分：
  - TUNNEL        → 提取 PID、定回址，置 tunnel 事件（state A 的回应）。
  - HTTP_RESPONSE → 按到达序拼接分片，遇 LAST 置 response 事件（state D）。
"""
from __future__ import annotations

import logging

from ..protocol.constants import LoadFlag, WEB_MSG_TYPE_MASK, WebMsgType
from ..protocol.packets import ColorData
from ..protocol.sid import sid_hex_from_packet
from ..protocol.utils import verify_checksum
from . import sid_table
from .messages import reverse_path_for_ack
from .state import ConsumerState

logger = logging.getLogger(__name__)


def handle_data(state: ConsumerState, payload: bytes) -> None:
    """DATA(首字节 0x73) 总入口：校验和后按 r / load[0] 分发。"""
    header_length = payload[6]
    if not verify_checksum(payload[:header_length]):
        return
    data = ColorData(payload)
    if data.Flags.B:  # B=1 ACK 是消费端发出的，不应在此接收
        return
    if data.Flags.r:  # RM 回送的本域 SID 列表条目
        sid_table.handle_sid_list_entry(state, data)
        return

    load = bytes(data.payload)
    if not load:
        return
    web_type = load[0] & WEB_MSG_TYPE_MASK
    if web_type == WebMsgType.TUNNEL:
        _handle_tunnel(state, data)
    elif web_type == WebMsgType.HTTP_RESPONSE:
        _handle_response(state, data, load)


def _handle_tunnel(state: ConsumerState, data: ColorData) -> None:
    """state A 的回应：从隧道 DATA 取 PID 序列、定回址，唤醒等待线程。"""
    sid = sid_hex_from_packet(bytes(data.NSID), bytes(data.LSID))
    pending = state.get_pending(sid, state.nid)
    if pending is None:
        logger.warning("收到隧道 DATA 但无匹配未决请求，忽略：SID=%s…", sid[:16])
        return

    recv_pids = list(data.PID_List)
    if data.Flags.R and recv_pids:
        # 跨域：下一跳为消费端侧边界路由器（取首个真实 PID 的高 16 位作 PX）。
        # 跨域 PID 布局需 S4 验证，见 messages.reverse_path_for_ack 注释。
        return_ip = state.resolve_px_ip(recv_pids[0] >> 16)
    else:
        # 域内：下一跳为提供方代理（提供方 NID = SID 的 N_sid）。
        provider_nid = int.from_bytes(bytes(data.NSID), "big")
        return_ip = state.resolve_provider_ip(provider_nid)

    pending.return_ip = return_ip
    pending.pids = reverse_path_for_ack(recv_pids)
    pending.tunnel_event.set()
    logger.info("收到隧道 DATA：SID=%s… 回址=%s", sid[:16], return_ip)


def _handle_response(state: ConsumerState, data: ColorData, load: bytes) -> None:
    """state D：拼接响应分片，遇 LAST 唤醒等待线程。"""
    sid = sid_hex_from_packet(bytes(data.NSID), bytes(data.LSID))
    pending = state.get_pending(sid, state.nid)
    if pending is None:
        logger.warning("收到响应 DATA 但无匹配未决请求，忽略：SID=%s…", sid[:16])
        return

    pending.response_buf += load[1:]
    if load[0] & LoadFlag.LAST:
        pending.response_event.set()
        logger.info("响应接收完成：SID=%s… 共 %d 字节", sid[:16], len(pending.response_buf))
