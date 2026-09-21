"""消费端装配：收包分发 + 注册 + 拉取 SID 表 + HTTP 正向代理 + L3 隧道运行期。

v1 的 HTTP 正向代理（:8910）与 v2 的 L3 隧道在同一进程内并存、互不干扰：前者的入口
是浏览器的代理设置，后者的入口是 tun 设备 + 主机路由。收到 ``DATA(B=0)`` 时**按 SID
落在哪张表里分派**（docs/design-l3-v2.md §4.1，D13）。
"""
from __future__ import annotations

import logging
import time

from .. import registration
from ..l3.service import ConsumerL3Service
from ..protocol.constants import CONTROL_FIRST_BYTE, DATA_FIRST_BYTE
from ..protocol.sid import service_canonical, sid_hex_from_service, sid_hex_from_url
from ..transport.receiver import ColorReceiver
from ..transport.sender import ColorSender
from ..tun.device import TunDevice
from . import handlers, sid_table
from .config import ConsumerConfig
from .proxy import ProxyServer
from .state import ConsumerState

logger = logging.getLogger(__name__)

#: 发出 SID 列表请求后，等待 RM 回送条目的收集窗口（秒）
SID_LIST_COLLECT_WINDOW = 1.5


class Consumer:
    """共生网络 Web 代理消费端（浏览器侧正向代理）。"""

    def __init__(self, config: ConsumerConfig, tun: TunDevice | None = None) -> None:
        self.config = config
        self.state = ConsumerState(config)
        self.sender = ColorSender()
        self.receiver = ColorReceiver(config.ipv4, self._on_payload)
        self.proxy: ProxyServer | None = None
        # L3 未启用时根本不构造。``tun`` 供离线测试注入 LoopbackTun。
        self.l3: ConsumerL3Service | None = (
            ConsumerL3Service(self.state, self.sender, tun=tun)
            if config.l3.enabled else None
        )
        # 注册线程。消费端不发布服务，故无回调；默认注册一次即停
        # （周期性重注册连带的重复 ANN 会被 RM 拒，见 registration 模块说明）。
        self.keeper = registration.RegistrationKeeper(self.state, self.sender)

    def start(self) -> None:
        """启动收包、向 RM 注册、拉取本域 SID 表，并建好正向代理。"""
        self.receiver.start()
        self.keeper.start()
        if not self.keeper.wait_first():
            raise RuntimeError(registration.failure_message(
                "消费端", self.state, self.keeper, self.sender))
        self._preload_static_sids()
        sid_table.request_sid_list(self.state, self.sender)
        time.sleep(SID_LIST_COLLECT_WINDOW)
        logger.info("本域 SID 表已就绪：%d 条", self.state.sid_count())
        # tun 在 SID 表就绪后才起：路由一加上，客户端的包立刻就会进来，而 SID 表
        # 还没到的话每个包都会被计成 sid_miss 并丢掉（症状是"刚启动那几秒不通"）。
        if self.l3 is not None:
            self._assert_route_isolation()
            self.l3.start()
            logger.info("L3 隧道就绪：%s(%s)，捕获路由 %s",
                        self.config.l3.tun_name, self.config.l3.tun_ip,
                        list(self.config.l3.capture_routes))
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
        if self.l3 is not None:
            self.l3.stop()

    def _assert_route_isolation(self) -> None:
        """起 tun 之前用**实际同步下来的**域内表再核对一遍 §2.4，命中则拒绝启动。

        配置加载时只能查 ``rm_ipv4``；域内代理与 BR 的地址要到注册回复之后才知道。
        这道检查必须在加路由**之前**做：路由一旦加上去，外层包就已经开始被吞进 tun 了。
        """
        conflicts = self.state.capture_route_conflicts()
        if not conflicts:
            return
        detail = "；".join(f"{label} {ip}" for label, ip in conflicts)
        raise RuntimeError(
            f"拒绝启动 L3：以下外层目的地址落进了 l3.capture_routes "
            f"{list(self.config.l3.capture_routes)} —— {detail}。"
            "外层 CoLoR 包会被自己的路由表吞进 tun，链路彻底死锁（设计 §2.4）。"
            "命中域内代理通常意味着消费端与提供端在同一个 CoLoR 域，"
            "此时必须改用 §2.5 的虚服务地址方案（服务地址取提供端 color0 自己的地址）"
        )

    def _preload_static_sids(self) -> None:
        """把配置里的静态 SID 预载入本域 SID 表（联调用）。

        两种粒度分开预载，因为 L_sid 的算法不同（§0.2）：``sids[]`` 走
        ``SHA1(url)``，``l3.static_services[]`` 走 ``SHA1("<proto>://<ip>:<port>")``。
        两者进的是同一张表——哈希域按 scheme 天然隔离，不会撞（§3.1，D12）。
        """
        for entry in self.config.sids:
            self.state.add_sid(sid_hex_from_url(entry.provider_nid, entry.url))
        if self.config.sids:
            logger.info("已预载 %d 条内容级静态 SID（按 URL，联调用）", len(self.config.sids))

        for service in self.config.l3.static_services:
            sid = sid_hex_from_service(
                service.provider_nid, service.proto, service.ip, service.port)
            self.state.add_sid(sid)
            logger.info("已预载服务级静态 SID：%s%s (SID=%s…)",
                        service_canonical(service.proto, service.ip, service.port),
                        f" [{service.desc}]" if service.desc else "", sid[:16])

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
                # 先试 L3：SID 不在 L3 隧道/待建表里时返回 False，再回落 v1（D13）。
                # 隧道/响应 DATA 与 RM 回送的 SID 列表条目的细分见 handlers。
                if self.l3 is None or self.l3.dataplane is None \
                        or not self.l3.dataplane.handle_data(payload):
                    handlers.handle_data(self.state, payload)
            # 0x71 ANN / 0x72 GET 是提供端职责，消费端忽略
        except Exception:  # noqa: BLE001 单个坏包不应拖垮收包线程
            logger.exception("处理报文时发生异常（已忽略该包）")
