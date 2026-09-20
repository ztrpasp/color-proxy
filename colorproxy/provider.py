"""提供端装配：收包分发 + 注册 + 发布。"""
from __future__ import annotations

import logging

from . import handlers, publish, registration
from .config import Config
from .messages import is_ack
from .protocol.constants import CONTROL_FIRST_BYTE, DATA_FIRST_BYTE, GET_FIRST_BYTE
from .state import ProviderState
from .transport.receiver import ColorReceiver
from .transport.sender import ColorSender

logger = logging.getLogger(__name__)


class Provider:
    """共生网络 Web 代理服务端。"""

    def __init__(self, config: Config) -> None:
        self.state = ProviderState(config)
        self.sender = ColorSender()
        self.receiver = ColorReceiver(config.ipv4, self._on_payload)
        # 常驻注册线程：每轮重注册后重发 ANN，使 RM 重启后自动恢复（§9.3 第 3 条）。
        # publish_services 幂等（ANN 以 AM=1 覆盖同一条 SID），可安全重复调用。
        self.keeper = registration.RegistrationKeeper(
            self.state, self.sender,
            on_registered=lambda: publish.publish_services(self.state, self.sender),
        )

    def start(self) -> None:
        """启动收包、向 RM 注册并发布服务。首次注册失败抛出异常。"""
        self.receiver.start()
        self.keeper.start()
        if not self.keeper.wait_first():
            raise RuntimeError("无法向 RM 注册，服务端启动失败")
        logger.info(
            "服务端就绪：Web 服务 %d 条，L3 服务 %d 条",
            len(self.state.config.services), self.state.l3_service_count(),
        )

    def stop(self) -> None:
        self.keeper.stop()
        self.receiver.stop()

    def _on_payload(self, payload: bytes) -> None:
        """收包回调（运行在接收线程）。按首字节分发。"""
        first_byte = payload[0]
        try:
            if first_byte == CONTROL_FIRST_BYTE:
                registration.handle_control(self.state, payload)
            elif not self.state.registered.is_set():
                return  # 注册完成前忽略业务报文
            elif first_byte == GET_FIRST_BYTE:
                handlers.handle_get(self.state, self.sender, payload)
            elif first_byte == DATA_FIRST_BYTE and is_ack(payload):
                # 仅处理 B=1（消费端推送 HTTP 请求）；B=0 数据是消费端职责
                handlers.handle_ack(self.state, self.sender, payload)
        except Exception:  # noqa: BLE001 单个坏包不应拖垮收包线程
            logger.exception("处理报文时发生异常（已忽略该包）")
