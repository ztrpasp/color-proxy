"""本域 SID 表：向 RM 拉取并登记。

消费端以一个全零 SID 的哨兵 GET 向本域 RM 请求 SID 列表，RM 用**一个 CONTROL
报文（Subtype=40）一次性下发整张表**——负载是裸的、每 36 字节一个完整 SID
（``NSID‖LSID``）的拼接。本模块负责发哨兵 GET、并把 CONTROL(40) 里的 SID 入表。

对照参考实现 color-agent-plus：
- 哨兵 GET：``Frontend/sidListWindow.py:124-126`` 的 ``Get('0'*36, 2)``。
- 回送解析：``Frontend/ColorMonitor.py:480-494`` 收 ``ControlPkt.tag==40`` 后按
  36 字节切负载取每个 SID。
（参考实现还会对每个 SID 再发"摘要 GET"换取 DATA(r=1) 的 JSON 服务简介，那只用于
人读的服务描述；跑代理只需 SID 集合，故本消费端不取摘要。）
"""
from __future__ import annotations

import logging

from ..protocol import control
from ..protocol.constants import SID_HEX_LEN
from .messages import build_sid_list_request
from .state import ConsumerState

logger = logging.getLogger(__name__)

#: 全零哨兵/占位 SID（72 hex），不入表
_ZERO_SID = "0" * SID_HEX_LEN


def request_sid_list(state: ConsumerState, sender) -> None:
    """向 RM 发送拉取本域 SID 列表的哨兵 GET（NSID/LSID 全零）。"""
    sender.send(state.rm_ipv4, build_sid_list_request(state.nid))
    logger.info("已向 RM(%s) 请求本域 SID 列表", state.rm_ipv4)


def register_sid_list_control(state: ConsumerState, payload: bytes) -> None:
    """把 RM 下发的 CONTROL(Subtype=40) 报文里的 SID 全部登记入本域 SID 表。

    非 SID 列表报文（如注册同步 Subtype=6）直接忽略，便于在收包分发处对所有
    CONTROL 报文无脑调用本函数。
    """
    if not control.is_sid_list(payload):
        return
    added = 0
    for sid in control.parse_sid_list(payload):
        if sid == _ZERO_SID:  # 全零哨兵/占位，忽略
            continue
        state.add_sid(sid)
        added += 1
    logger.info(
        "收到 RM 本域 SID 列表：新登记 %d 条（当前共 %d 条）", added, state.sid_count()
    )
