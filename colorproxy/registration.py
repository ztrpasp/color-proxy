"""向资源管理器 (RM) 注册并接收域内信息同步。

提供端与消费端共用本模块：``RegistrationKeeper`` 与 ``handle_control`` 只依赖
``nid`` / ``ipv4`` / ``rm_ipv4`` / ``registered`` / ``set_domain_info``，两端的
State 都按鸭子类型满足（见 ``consumer/state.py`` 的模块说明）。

**注册次数（2026-09-21 真机修正）**：上一轮为了"RM 重启后自动恢复"（设计 §9.3
第 3 条）把注册改成了每 30 s 一轮的常驻线程，每轮还重发一遍 ANN。真机上这条是错的
——RM 对同一条 SID 的第二次 AM=1 会报 ``unable to insert into sid_table``，等于每半
分钟给 RM 刷一屏错误。现在默认**注册一次**（未成功则按 ``REGISTER_INTERVAL`` 一直
重试），与参考实现 color-agent-plus 一致；``REGISTER_REFRESH_SEC > 0`` 时才周期性重
注册，且重注册轮走的是 ``on_refresh``（ANN 用 AM=2 更新），不再重发 AM=1。
"""
from __future__ import annotations

import logging
import threading
from typing import Callable, Protocol

from .protocol import control
from .protocol.constants import CONTROL_FIRST_BYTE, ControlSubtype
from .transport.sender import ColorSender

logger = logging.getLogger(__name__)

#: 未注册成功时的重试间隔（秒）与"首次注册"判定的重试次数（参考实现 RTO=1，重传 3 次）
REGISTER_INTERVAL = 1.0
REGISTER_MAX_RETRIES = 3
#: 已注册后的重注册间隔（秒）。**默认 0 = 注册成功后不再重复注册**（见模块说明）。
#: 若某天确认 RM 会老化终端/SID 表项，把它改成大于 0 的值即可恢复周期性刷新：
#: 那条路径重发注册报文并调 ``on_refresh``（提供端用 AM=2 更新已通告的 SID）。
REGISTER_REFRESH_SEC = 0.0


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
    """注册线程：首次注册（未成功则一直重试），以及可选的周期性重注册。

    - ``on_registered``：首次注册成功后调**一次**（提供端传"发布服务"）。
    - ``on_refresh``：仅当 ``refresh_sec > 0`` 时每个重注册轮调一次（提供端传
      ``publish.refresh_services``，即 AM=2 更新）。默认关闭，故默认不会被调到。
    """

    def __init__(
        self,
        state: _RegistrableState,
        sender: ColorSender,
        on_registered: Callable[[], None] | None = None,
        on_refresh: Callable[[], None] | None = None,
        refresh_sec: float = REGISTER_REFRESH_SEC,
        retry_sec: float = REGISTER_INTERVAL,
    ) -> None:
        super().__init__(name="RegistrationKeeper", daemon=True)
        self._state = state
        self._sender = sender
        self._on_registered = on_registered
        self._on_refresh = on_refresh
        self._refresh_sec = refresh_sec
        self._retry_sec = retry_sec
        self._stop = threading.Event()
        self._first_round_done = threading.Event()
        #: 已发出的注册报文数，注册失败时的诊断要用（见 failure_hint）
        self.attempts = 0

    def wait_first(self, timeout: float | None = None) -> bool:
        """阻塞等待首次注册成功。返回 False 表示超时（线程仍在后台继续重试）。

        ``timeout`` 为 None 时用 ``retry_sec * REGISTER_MAX_RETRIES``，与 v1 一次性
        ``register()`` 的等待窗口一致（发满 3 个注册报文都没回应才算失败）。超时
        **不代表放弃**：线程会一直重试，只是启动期仍按原语义拒绝启动。
        """
        if timeout is None:
            timeout = self._retry_sec * REGISTER_MAX_RETRIES
        self._first_round_done.wait(timeout)
        return self._state.registered.is_set()

    def run(self) -> None:
        # 阶段一：首次注册。收到 RM 同步(tag=6) 前一直重试；发满 REGISTER_MAX_RETRIES
        # 次就放行 wait_first，让调用方按原语义判失败（线程自己继续重试）。
        while not self._stop.is_set() and not self._state.registered.is_set():
            self._send_register()
            self._state.registered.wait(self._retry_sec)
            if self.attempts >= REGISTER_MAX_RETRIES:
                self._first_round_done.set()
        if self._stop.is_set():
            self._first_round_done.set()
            return

        self._run_callback(self._on_registered, "发布服务")
        self._first_round_done.set()

        # 阶段二：可选的周期性重注册。默认 refresh_sec=0，线程到此结束——注册报文与
        # ANN 各只发一次，RM 侧不会再收到重复的 SID 注册（2026-09-21 真机修正）。
        if self._refresh_sec <= 0:
            logger.info(
                "注册完成（共发出 %d 个注册报文），按 REGISTER_REFRESH_SEC=0 不再重复注册",
                self.attempts,
            )
            return
        while not self._stop.wait(self._refresh_sec):
            self._send_register()
            self._run_callback(self._on_refresh, "刷新服务")

    def stop(self) -> None:
        self._stop.set()

    def _run_callback(self, callback: Callable[[], None] | None, label: str) -> None:
        if callback is None:
            return
        try:
            callback()
        except Exception:  # noqa: BLE001 回调失败不应弄死注册线程
            logger.exception("%s失败（已忽略）", label)

    def _send_register(self) -> None:
        packet = control.build_register(self._state.nid, self._state.ipv4)
        action = "重注册" if self._state.registered.is_set() else "注册"
        logger.info("向 RM(%s) 发送%s报文（本机 %s，NID=%032x）", self._state.rm_ipv4,
                    action, self._state.ipv4, self._state.nid)
        try:
            self._sender.send(self._state.rm_ipv4, packet)
            self.attempts += 1
        except Exception:  # noqa: BLE001 发不出去（网卡未就绪等）不应弄死线程
            logger.exception("发送%s报文失败（已忽略，下轮重试）", action)


def failure_message(
    role: str,
    state: _RegistrableState,
    keeper: RegistrationKeeper,
    sender: ColorSender | None = None,
) -> str:
    """注册失败时抛给调用方的完整说明：一句结论 + 一份可照着查的清单。"""
    return f"无法向 RM 注册，{role}启动失败。\n" + failure_hint(state, keeper, sender)


def failure_hint(
    state: _RegistrableState,
    keeper: RegistrationKeeper,
    sender: ColorSender | None = None,
) -> str:
    """注册失败时的一段可直接照着查的诊断文字。

    "发了 N 个包、没有任何回应"这个症状本身不含信息量，而它的几个成因（RM 地址配错、
    本机 ipv4 配成了到不了 RM 的那张网卡、二层不通、RM 没在跑）在日志里长得一模一样。
    2026-09-21 真机上消费端就卡在第一种：``rm_ipv4`` 写了 ``10.10.0.1``、实际是
    ``10.10.0.5``，包发出去了，RM 那边一行日志都没有。
    """
    lines = [
        f"已发出 {keeper.attempts} 个注册报文(CONTROL tag=5) 给 RM({state.rm_ipv4})，"
        "未收到同步回复(tag=6)。",
    ]
    if sender is not None:
        lines.append(f"发送路径：{sender.describe(state.rm_ipv4)}")
    lines += [
        "逐条核对：",
        f"  1. rm_ipv4={state.rm_ipv4} 是不是本域 RM 的真实地址（最常见的一条）；",
        f"  2. ipv4={state.ipv4} 是不是本机**能到 RM 的那张网卡**的地址——它既是收包"
        "套接字的绑定地址，也是 RM 回复时用的目的地址，写错了包发得出去、回不来；",
        f"  3. 二层可达：ping {state.rm_ipv4}、看 arp -a 里有没有它的 MAC"
        "（解析不到时 scapy 会把包当广播发出，RM 多半收不到）；",
        "  4. RM 进程在不在、它那边有没有收到本次注册的日志；",
        "  5. 本机防火墙有没有拦掉 IP 协议号 150 的入站包。",
    ]
    return "\n".join(lines)


#: 已提示过的未知 CONTROL 子类型，避免刷屏（见 handle_control）
_reported_subtypes: set[int] = set()


def handle_control(state: _RegistrableState, payload: bytes) -> None:
    """处理 CONTROL 报文：RM 同步回复（Subtype=6）与新代理通知（Subtype=8）。

    **tag=8 的载荷布局未经证实**：本仓库没有参考实现，技术文档只记载了子类型编号
    （`docs/PRD-v1.md §报文类型`）。因此这里按"与 tag=6 相同的代理/BR 表布局"
    严格尝试解析（RM 大概率复用同一个序列化器），解析不干净就**只打印原始字节、
    不改动任何表**——把乱码当 NID→IP 写进表会造成回址错误，比学不到更难查。
    真机上第一次收到时，从日志里的 hex 就能确认布局并补完这个分支。

    其余子类型（RM 的保密注册挑战 tag=20/21 等本项目未实现的流程）**每种打一行**
    再忽略：不打的话，"RM 明明回了、终端却一直说没收到"在日志里完全没有痕迹。
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
        return

    report_unhandled_control(payload)


def report_unhandled_control(payload: bytes) -> None:
    """未处理的 CONTROL 报文：每种子类型只提示一次（校验和不通过的单列一类）。"""
    if len(payload) < control.CONTROL_HEADER_LENGTH or payload[0] != CONTROL_FIRST_BYTE:
        return
    subtype = payload[5]
    if subtype == ControlSubtype.SID_LIST_UPDATE:
        return  # 本域 SID 列表由 consumer/sid_table 处理，不是"没人管"的报文
    if control.checksum_ok(payload):
        key = subtype
        detail = f"未实现的 CONTROL 子类型 tag={subtype}"
    else:
        key = -subtype
        detail = f"CONTROL 子类型 tag={subtype} 的校验和不通过（报文被截断？长度字段对不上？）"
    if key in _reported_subtypes:
        return
    _reported_subtypes.add(key)
    logger.warning("%s，已忽略（同类只提示一次）。原始字节：%s", detail, payload.hex())
