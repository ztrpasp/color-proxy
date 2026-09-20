"""消费端装配：收包分发 + 注册 + 拉取 SID 表 + 起 HTTP 正向代理。"""
from __future__ import annotations

import logging
import time

from .. import registration
from ..protocol.constants import CONTROL_FIRST_BYTE, DATA_FIRST_BYTE
from ..protocol.sid import sid_hex_from_url
from ..transport.receiver import ColorReceiver
from ..transport.sender import ColorSender
from . import handlers, sid_table
from .config import ConsumerConfig
from .proxy import ProxyServer
from .state import ConsumerState

logger = logging.getLogger(__name__)

#: 发出 SID 列表请求后，等待 RM 回送条目的收集窗口（秒）
SID_LIST_COLLECT_WINDOW = 1.5


class Consumer:
    """共生网络 Web 代理消费端（浏览器侧正向代理）。"""

    def __init__(self, config: ConsumerConfig) -> None:
        self.config = config
        self.state = ConsumerState(config)
        self.sender = ColorSender()
        self.receiver = ColorReceiver(config.ipv4, self._on_payload)
        self.proxy: ProxyServer | None = None
        # 常驻注册线程（§9.3 第 3 条）。消费端不发布服务，故无 on_registered 回调；
        # 周期性重注册的收益在于 RM 重启后能重新拿到域内代理表。
        self.keeper = registration.RegistrationKeeper(self.state, self.sender)

    def start(self) -> None:
        """启动收包、向 RM 注册、拉取本域 SID 表，并建好正向代理。"""
        self.receiver.start()
        self.keeper.start()
        if not self.keeper.wait_first():
            raise RuntimeError("无法向 RM 注册，消费端启动失败")
        self._preload_static_sids()
        sid_table.request_sid_list(self.state, self.sender)
        time.sleep(SID_LIST_COLLECT_WINDOW)
        logger.info("本域 SID 表已就绪：%d 条", self.state.sid_count())
        self.proxy = ProxyServer(self.config.proxy_port, self.state, self.sender)
        logger.info("HTTP 正向代理就绪，监听端口 %d", self.config.proxy_port)

    def serve_forever(self) -> None:
        """阻塞运行正向代理（处理浏览器请求）。"""
        assert self.proxy is not None, "请先调用 start()"
        self.proxy.serve_forever()

    def stop(self) -> None:
        if self.proxy is not None:
            self.proxy.shutdown()
            self.proxy.server_close()
        self.keeper.stop()
        self.receiver.stop()

    def _preload_static_sids(self) -> None:
        """把配置里的静态 SID 预载入本域 SID 表（联调用，见 config.sids）。"""
        for entry in self.config.sids:
            self.state.add_sid(sid_hex_from_url(entry.provider_nid, entry.url))
        if self.config.sids:
            logger.info("已预载 %d 条静态 SID（联调用）", len(self.config.sids))

    def _on_payload(self, payload: bytes) -> None:
        """收包回调（运行在接收线程）。按首字节分发。"""
        first_byte = payload[0]
        try:
            if first_byte == CONTROL_FIRST_BYTE:
                # 注册同步(Subtype=6) 与本域 SID 列表(Subtype=40) 都走 CONTROL，
                # 各自按子类型自判，互不影响。
                registration.handle_control(self.state, payload)
                sid_table.register_sid_list_control(self.state, payload)
            elif not self.state.registered.is_set():
                return  # 注册完成前忽略业务报文
            elif first_byte == DATA_FIRST_BYTE:
                # 隧道/响应 DATA 与 RM 回送的 SID 列表条目，细分见 handlers
                handlers.handle_data(self.state, payload)
            # 0x71 ANN / 0x72 GET 是提供端职责，消费端忽略
        except Exception:  # noqa: BLE001 单个坏包不应拖垮收包线程
            logger.exception("处理报文时发生异常（已忽略该包）")
