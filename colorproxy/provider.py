"""提供端装配：收包分发 + 注册 + 发布 + L3 隧道运行期。

两种模式在同一进程内共存，**按 SID 落在哪张服务表里分派**（docs/design-l3-v2.md
§4.1，D13），不按 ``load[0]``：``L3Provider`` 的两个入口在 SID 不属于 L3 时返回
``False``，此时才回落到 v1 的 ``handlers``。
"""
from __future__ import annotations

import logging

from . import handlers, publish, registration
from .config import Config
from .l3.service import ProviderL3Service
from .messages import is_ack
from .protocol.constants import CONTROL_FIRST_BYTE, DATA_FIRST_BYTE, GET_FIRST_BYTE
from .state import ProviderState
from .transport.receiver import ColorReceiver
from .transport.sender import ColorSender
from .tun.device import TunDevice

logger = logging.getLogger(__name__)


class Provider:
    """共生网络 Web 代理服务端。"""

    def __init__(self, config: Config, tun: TunDevice | None = None) -> None:
        self.state = ProviderState(config)
        self.sender = ColorSender()
        self.receiver = ColorReceiver(config.ipv4, self._on_payload)
        # L3 未启用时根本不构造：v1 模式下不需要 tun、不需要管理员权限。
        # ``tun`` 参数供离线测试注入 LoopbackTun（见 tests/test_l3_assembly.py）。
        self.l3: ProviderL3Service | None = (
            ProviderL3Service(self.state, self.sender, tun=tun)
            if config.l3.enabled else None
        )
        # 常驻注册线程：每轮重注册后重发 ANN，使 RM 重启后自动恢复（§9.3 第 3 条）。
        # publish_services 幂等（ANN 以 AM=1 覆盖同一条 SID），可安全重复调用。
        self.keeper = registration.RegistrationKeeper(
            self.state, self.sender,
            on_registered=lambda: publish.publish_services(self.state, self.sender),
        )

    def start(self) -> None:
        """启动 tun、收包、向 RM 注册并发布服务。首次注册失败抛出异常。

        tun 先于收包起来：注册一成功就会发 ANN，ANN 一发出去消费端就可能发 GET 过来，
        此时 tun 必须已经能写，否则第一条隧道的首包会白丢。
        """
        if self.l3 is not None:
            self.l3.start()
        self.receiver.start()
        self.keeper.start()
        if not self.keeper.wait_first():
            raise RuntimeError("无法向 RM 注册，服务端启动失败")
        logger.info(
            "服务端就绪：Web 服务 %d 条，L3 服务 %d 条（L3 隧道模式%s）",
            len(self.state.config.services), self.state.l3_service_count(),
            "已启用" if self.l3 is not None else "未启用",
        )

    def stop(self) -> None:
        self.keeper.stop()
        self.receiver.stop()
        if self.l3 is not None:
            self.l3.stop()

    def _on_payload(self, payload: bytes) -> None:
        """收包回调（运行在接收线程）。按首字节分发。"""
        first_byte = payload[0]
        try:
            if first_byte == CONTROL_FIRST_BYTE:
                registration.handle_control(self.state, payload)
            elif not self.state.registered.is_set():
                return  # 注册完成前忽略业务报文
            elif first_byte == GET_FIRST_BYTE:
                # 先试 L3：SID 不在 _l3_services 里时返回 False，再回落 v1（D13）
                if not self._l3_handles(lambda dp: dp.handle_get(payload)):
                    handlers.handle_get(self.state, self.sender, payload)
            elif first_byte == DATA_FIRST_BYTE and is_ack(payload):
                # 仅处理 B=1（消费端推送 HTTP 请求或 L3 上行内层包）；B=0 是消费端职责
                if not self._l3_handles(lambda dp: dp.handle_upstream(payload)):
                    handlers.handle_ack(self.state, self.sender, payload)
        except Exception:  # noqa: BLE001 单个坏包不应拖垮收包线程
            logger.exception("处理报文时发生异常（已忽略该包）")

    def _l3_handles(self, call) -> bool:
        """把报文交给 L3 数据面试一次；L3 未启用或该 SID 不属于 L3 时返回 False。"""
        if self.l3 is None or self.l3.dataplane is None:
            return False
        return bool(call(self.l3.dataplane))
