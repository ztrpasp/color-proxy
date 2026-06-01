"""向资源管理器 (RM) 注册并接收域内信息同步。"""
from __future__ import annotations

import logging

from .protocol import control
from .state import ProviderState
from .transport.sender import ColorSender

logger = logging.getLogger(__name__)

#: 注册重试间隔（秒）与最大次数
REGISTER_INTERVAL = 1.0
REGISTER_MAX_RETRIES = 3


def register(state: ProviderState, sender: ColorSender) -> bool:
    """向 RM 发送注册报文并等待同步回复，成功返回 True。"""
    packet = control.build_register(state.nid, state.ipv4)
    for attempt in range(1, REGISTER_MAX_RETRIES + 1):
        logger.info("向 RM(%s) 发送注册报文（第 %d 次）", state.rm_ipv4, attempt)
        sender.send(state.rm_ipv4, packet)
        if state.registered.wait(REGISTER_INTERVAL):
            logger.info("代理注册完成")
            return True
    logger.error("代理注册失败：未收到 RM 同步回复")
    return False


def handle_control(state: ProviderState, payload: bytes) -> None:
    """处理 CONTROL 报文：仅识别 RM 同步回复（Subtype=6）。"""
    if not control.is_register_reply(payload):
        return
    proxies, brs = control.parse_register_reply(payload)
    state.set_domain_info(proxies, brs)
    state.registered.set()
    logger.info("收到 RM 同步：%d 个域内代理，%d 个边界路由器", len(proxies), len(brs))
