"""本域 SID 表：向 RM 拉取并登记。

参考实现以一个全零 SID 的 GET 向本域 RM 请求 SID 列表，RM 逐条回送 DATA，
每条 DATA 的包头携带一个完整 SID（``color-agent-plus`` 中该回送 DATA 置
小写 ``r`` 标志、负载为 RM 自定义的 JSON）。本消费端**只取包头里的 SID**
（``NSID‖LSID``）入表，不解析 RM 的负载格式——以此把对 RM 回送格式的耦合
降到最低。RM 的触发条件与回送格式需在 S4 真实环境验证。
"""
from __future__ import annotations

import logging

from ..protocol.packets import ColorData
from ..protocol.sid import sid_hex_from_packet
from .messages import build_sid_list_request
from .state import ConsumerState

logger = logging.getLogger(__name__)

#: 拉取 SID 列表的哨兵 GET 所用事务标识（仅日志/对账，固定值即可）
_SID_LIST_SEG_ID = 0


def request_sid_list(state: ConsumerState, sender) -> None:
    """向 RM 发送拉取本域 SID 列表的哨兵 GET。"""
    get = build_sid_list_request(state.nid, _SID_LIST_SEG_ID)
    sender.send(state.rm_ipv4, get)
    logger.info("已向 RM(%s) 请求本域 SID 列表", state.rm_ipv4)


def handle_sid_list_entry(state: ConsumerState, data: ColorData) -> None:
    """登记一条 RM 回送的 SID（取包头 NSID‖LSID 组成完整 SID）。"""
    sid = sid_hex_from_packet(bytes(data.NSID), bytes(data.LSID))
    if sid == "0" * len(sid):  # 全零哨兵/占位，忽略
        return
    state.add_sid(sid)
    logger.info("登记本域 SID：%s…（当前共 %d 条）", sid[:16], state.sid_count())
