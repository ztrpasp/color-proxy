"""向资源管理器 (RM) 注册并接收域内信息同步。

提供端与消费端共用本模块：``RegistrationKeeper`` 与 ``handle_control`` 只依赖
``nid`` / ``ipv4`` / ``rm_ipv4`` / ``registered`` / ``set_domain_info``，两端的
State 都按鸭子类型满足（见 ``consumer/state.py`` 的模块说明）。

v1 只在启动时注册一次（3 次重试）就不再理会，RM 重启后既不会重新注册、也不会
重发 ANN，服务静默失联（docs/design-l3-v2.md §9.3 第 3 条）。L3 模式下隧道长期
有效、暴露窗口更长，故改为**常驻线程**：周期性重注册并重发 ANN。
"""
from __future__ import annotations

import logging
import threading
from typing import Callable, Protocol

from .protocol import control
from .transport.sender import ColorSender

logger = logging.getLogger(__name__)

#: 未注册成功时的重试间隔（秒）与"首次注册"判定的重试次数
REGISTER_INTERVAL = 1.0
REGISTER_MAX_RETRIES = 3
#: 已注册后的重注册间隔（秒）。每轮重发注册报文并重发 ANN，使 RM 重启后自动恢复。
#: 也是"学到后启动的对端"的最坏时延上界（见 handle_control 关于 tag=8 的说明）。
REGISTER_REFRESH_SEC = 30.0


class _RegistrableState(Protocol):
    """本模块对 State 的最小要求（提供端/消费端各自满足）。"""

    nid: int
    ipv4: str
    rm_ipv4: str
    registered: threading.Event

    def set_domain_info(
        self, proxies: list[tuple[int, str]], brs: list[tuple[int, str]]
    ) -> None: ...


class RegistrationKeeper(threading.Thread):
    """常驻注册线程：首次注册 + 周期性重注册与重发布。

    ``on_registered`` 在每轮注册报文发出后被调用（提供端传 ANN 重发布）。它必须是
    **幂等**的：ANN 以 AM=1(注册) 重复发送，RM 侧覆盖同一条 SID，重发无副作用。
    """

    def __init__(
        self,
        state: _RegistrableState,
        sender: ColorSender,
        on_registered: Callable[[], None] | None = None,
        refresh_sec: float = REGISTER_REFRESH_SEC,
        retry_sec: float = REGISTER_INTERVAL,
    ) -> None:
        super().__init__(name="RegistrationKeeper", daemon=True)
        self._state = state
        self._sender = sender
        self._on_registered = on_registered
        self._refresh_sec = refresh_sec
        self._retry_sec = retry_sec
        self._stop = threading.Event()
        self._first_round_done = threading.Event()

    def wait_first(self, timeout: float | None = None) -> bool:
        """阻塞等待首次注册成功。返回 False 表示超时（线程仍在后台继续重试）。

        ``timeout`` 为 None 时用 ``retry_sec * REGISTER_MAX_RETRIES``，与 v1 一次性
        ``register()`` 的等待窗口一致。注意超时**不代表放弃**：v1 是 3 次不成就抛错
        退出，现在调用方可以选择继续（线程会一直重试），只是启动期仍按原语义拒绝启动。
        """
        if timeout is None:
            timeout = self._retry_sec * REGISTER_MAX_RETRIES
        self._first_round_done.wait(timeout)
        return self._state.registered.is_set()

    def run(self) -> None:
        while not self._stop.is_set():
            self._send_register()
            if not self._state.registered.is_set():
                # 尚未注册：短间隔重试，直到 RM 回应或进程退出
                self._state.registered.wait(self._retry_sec)
            if self._state.registered.is_set() and self._on_registered is not None:
                try:
                    self._on_registered()
                except Exception:  # noqa: BLE001 重发布失败不应弄死注册线程
                    logger.exception("重发布服务失败（已忽略，下轮重试）")
            self._first_round_done.set()
            if self._state.registered.is_set():
                self._stop.wait(self._refresh_sec)

    def stop(self) -> None:
        self._stop.set()

    def _send_register(self) -> None:
        packet = control.build_register(self._state.nid, self._state.ipv4)
        action = "重注册" if self._state.registered.is_set() else "注册"
        logger.info("向 RM(%s) 发送%s报文", self._state.rm_ipv4, action)
        try:
            self._sender.send(self._state.rm_ipv4, packet)
        except Exception:  # noqa: BLE001 发不出去（网卡未就绪等）不应弄死线程
            logger.exception("发送%s报文失败（已忽略，下轮重试）", action)


def handle_control(state: _RegistrableState, payload: bytes) -> None:
    """处理 CONTROL 报文：RM 同步回复（Subtype=6）与新代理通知（Subtype=8）。

    **tag=8 的载荷布局未经证实**：本仓库没有参考实现，技术文档只记载了子类型编号
    （`docs/PRD-v1.md §报文类型`）。因此这里按"与 tag=6 相同的代理/BR 表布局"
    严格尝试解析（RM 大概率复用同一个序列化器），解析不干净就**只打印原始字节、
    不改动任何表**——把乱码当 NID→IP 写进表会造成回址错误，比学不到更难查。
    真机上第一次收到时，从日志里的 hex 就能确认布局并补完这个分支。

    顺带说明：§9.3 第 4 条担心的症状（后启动的一方学不到先启动方的 NID→IP）其实
    已由 ``RegistrationKeeper`` 的周期性重注册兜住——每次 tag=6 回复都带回**当前
    完整**的域内代理表，最坏时延一个 ``REGISTER_REFRESH_SEC``。tag=8 只是让这个
    过程更及时，不是唯一出路。
    """
    if control.is_register_reply(payload):
        proxies, brs = control.parse_register_reply(payload)
        state.set_domain_info(proxies, brs)
        state.registered.set()
        logger.info("收到 RM 同步：%d 个域内代理，%d 个边界路由器", len(proxies), len(brs))
        return

    if control.is_proxy_notify(payload):
        try:
            proxies, brs = control.parse_proxy_table_strict(payload)
        except (ValueError, IndexError) as exc:
            logger.warning(
                "收到新代理通知(tag=8) 但布局与 tag=6 不符（%s），已忽略。"
                "请把这行原始字节反馈以补完解析：%s",
                exc, payload.hex(),
            )
            return
        state.set_domain_info(proxies, brs)
        logger.info(
            "收到新代理通知(tag=8)：%d 个域内代理，%d 个边界路由器（按 tag=6 布局解析）",
            len(proxies), len(brs),
        )
