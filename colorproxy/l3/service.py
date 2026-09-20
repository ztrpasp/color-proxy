"""L3 隧道模式的运行期装配（docs/design-l3-v2.md §1.2 / §1.3 / §10.2 / §10.4）。

``l3/provider.py`` 与 ``l3/consumer.py`` 是**纯数据面**：给它们一个包，它们决定怎么
处理。本模块负责把数据面接上真实世界的三件事，两端各一个类：

1. **tun 设备**：按 §10.2 的顺序创建、配地址/MTU/路由，退出时拆干净；
2. **tun 读线程**：Wintun 的读是阻塞事件驱动，必须单独一个线程，不能和 CoLoR
   收包线程混在一起（§1.2 / §1.3）；
3. **周期任务**：计数器日志（§10.4）、握手超时回收（§5.2）、下行静默重探（§8.4）。

其中握手超时回收**不调就是 bug**：握手失败后首包会永久滞留在队列里（§5.2 明确
点名了这一条）。故它和读线程一样由 ``start()`` 统一拉起，不给调用方漏掉的机会。
"""
from __future__ import annotations

import logging
import sys
import threading
import time
from typing import Callable, Sequence

from ..transport.sender import ColorSender
from ..tun.device import TunDevice
from ..tun.factory import open_tun
from .consumer import L3Consumer
from .counters import Counters
from .provider import L3Provider

logger = logging.getLogger(__name__)

#: 计数器快照的打印周期（秒，§10.4「每 5 s 一行」）
COUNTER_LOG_SEC = 5.0
#: 握手超时的扫描周期上限（秒）。必须明显小于 tunnel_timeout_sec，否则首包在队列里
#: 多待将近一个扫描周期，"5 秒超时"就名不副实。
EXPIRE_SCAN_MAX_SEC = 1.0
#: tun 读线程每次 read 的等待上限（秒）。只影响 stop() 的响应速度，不影响吞吐。
TUN_READ_POLL_SEC = 0.5


class TunPump(threading.Thread):
    """tun 读线程：读一个完整内层包交给 ``handler``（§1.2 / §1.3 的 TunRead 线程）。

    单个坏包不应拖垮整条读路径，故 ``handler`` 的异常一律记日志后继续——数据面本
    来就是尽力而为，读线程死掉是彻底失联，比丢一个包严重得多。
    """

    def __init__(
        self,
        tun: TunDevice,
        handler: Callable[[bytes], object],
        name: str = "L3TunRead",
        poll_sec: float = TUN_READ_POLL_SEC,
    ) -> None:
        super().__init__(name=name, daemon=True)
        self._tun = tun
        self._handler = handler
        self._poll_sec = poll_sec
        self._stop = threading.Event()

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                packet = self._tun.read(timeout=self._poll_sec)
            except OSError as exc:
                if self._stop.is_set():
                    break  # close() 期间的 ERROR_HANDLE_EOF，正常退出
                logger.error("tun 读失败，读线程退出：%s", exc)
                break
            if not packet:
                continue
            try:
                self._handler(packet)
            except Exception:  # noqa: BLE001 单个坏包不应拖垮读线程
                logger.exception("处理 tun 包时发生异常（已忽略该包）")

    def stop(self) -> None:
        self._stop.set()


class Ticker(threading.Thread):
    """周期性执行一组回调。计数器日志、握手超时回收、下行重探都挂在它上面。"""

    def __init__(
        self,
        interval_sec: float,
        tasks: Sequence[Callable[[], None]],
        name: str = "L3Ticker",
    ) -> None:
        super().__init__(name=name, daemon=True)
        self._interval = interval_sec
        self._tasks = list(tasks)
        self._stop = threading.Event()

    def run(self) -> None:
        while not self._stop.wait(self._interval):
            for task in self._tasks:
                try:
                    task()
                except Exception:  # noqa: BLE001 一个任务出错不应停掉其余的
                    logger.exception("L3 周期任务 %s 执行失败（已忽略，下轮重试）",
                                     getattr(task, "__name__", task))

    def stop(self) -> None:
        self._stop.set()


class _CounterLog:
    """每 ``COUNTER_LOG_SEC`` 打一行计数器快照，**内容没变就不打**。

    §10.4 要的是"出问题时能看出是哪一类丢包"，不是刷屏。空闲时逐行重复同一份快照
    会把真正有信息量的那几行埋掉，所以只在快照变化时打印。
    """

    def __init__(self, counters: Counters, label: str) -> None:
        self._counters = counters
        self._label = label
        self._previous: dict[str, int] | None = None

    def __call__(self) -> None:
        snapshot = self._counters.snapshot()
        if snapshot == self._previous:
            return
        self._previous = snapshot
        logger.info("[%s 计数器] %s", self._label, self._counters.format_line())


class _L3ServiceBase:
    """两端共有的生命周期：tun → 数据面 → 读线程 → 周期任务，以及反序拆除。"""

    _pump_name = "L3TunRead"
    _ticker_name = "L3Ticker"

    def __init__(self, sender: ColorSender, tun: TunDevice | None, counters: Counters | None):
        self.sender = sender
        self.counters = counters if counters is not None else Counters()
        #: 注入的 tun 由调用方负责关闭（测试的 LoopbackTun 还要被读取断言）
        self._owns_tun = tun is None
        self._tun = tun
        self._pump: TunPump | None = None
        self._ticker: Ticker | None = None

    @property
    def tun(self) -> TunDevice:
        assert self._tun is not None, "请先调用 start()"
        return self._tun

    def _open_tun(self) -> TunDevice:
        raise NotImplementedError

    def _build_dataplane(self) -> Callable[[bytes], object]:
        """建好数据面，返回 tun 读线程要调的那个入口。"""
        raise NotImplementedError

    def _periodic_tasks(self) -> list[Callable[[], None]]:
        raise NotImplementedError

    def _tick_interval(self) -> float:
        return COUNTER_LOG_SEC

    def start(self) -> None:
        if self._tun is None:
            self._tun = self._open_tun()
        on_tun_packet = self._build_dataplane()
        self._pump = TunPump(self._tun, on_tun_packet, name=self._pump_name)
        self._pump.start()
        self._ticker = Ticker(self._tick_interval(), self._periodic_tasks(),
                              name=self._ticker_name)
        self._ticker.start()

    def stop(self) -> None:
        """按启动的反序停掉。可重复调用。"""
        if self._ticker is not None:
            self._ticker.stop()
            self._ticker = None
        if self._pump is not None:
            self._pump.stop()
            self._pump = None
        if self._tun is not None and self._owns_tun:
            self._tun.close()
            self._tun = None


class ProviderL3Service(_L3ServiceBase):
    """提供端的 L3 运行期（§1.2）。

    ``Provider`` 只与本类打交道：``l3.enabled`` 为假时根本不构造它。
    """

    _pump_name = "L3TunRead(provider)"
    _ticker_name = "L3Ticker(provider)"

    def __init__(self, state, sender: ColorSender, tun: TunDevice | None = None,
                 counters: Counters | None = None) -> None:
        super().__init__(sender, tun, counters)
        self.state = state
        self.config = state.config.l3
        self.dataplane: L3Provider | None = None

    def _open_tun(self) -> TunDevice:
        return open_tun(
            name=self.config.tun_name, ip=self.config.tun_ip,
            mask=self.config.tun_mask, mtu=self.config.tun_mtu,
            routes=self.config.peer_routes,
        )

    def _build_dataplane(self) -> Callable[[bytes], object]:
        self.dataplane = L3Provider(self.state, self.tun, self.sender, self.counters)
        self._check_host_model()
        if self.config.tunnel_refresh_sec > 0:
            # §8.4 的"重发 GET 刷新 PID"是**消费端**动作（只有消费端会发 GET）。
            # 这个配置项落在提供端段里是设计文档的笔误，实现的是消费端的
            # l3.tunnel_redetect_sec；留在这里静默不生效会让人以为兜底开着。
            logger.warning(
                "l3.tunnel_refresh_sec=%.1f 在提供端无效：重发 GET 是消费端动作，"
                "请改用消费端配置的 l3.tunnel_redetect_sec（§8.4）",
                self.config.tunnel_refresh_sec,
            )
        return self.dataplane.on_tun_packet

    def _periodic_tasks(self) -> list[Callable[[], None]]:
        return [_CounterLog(self.counters, "L3/提供端")]

    def _check_host_model(self) -> None:
        """§2.3 / §2.5：服务地址不在 tun 自己身上时，才需要那四个弱主机开关。

        §2.5 的虚服务地址方案把服务绑在 color0 自己的地址上，内层包目的正是收包网卡
        自己的地址，强主机模型天然满足，**一个开关都不需要**（§2.3 对照实验第一行已
        实测确认）。只有 D9 的物理地址方案才要检查，且**两张网卡都要查**。
        """
        if self._tun is not None and not self._owns_tun:
            return  # 注入的 tun（离线测试），没有对应的真实接口可查
        if sys.platform != "win32":
            return

        offsite = sorted({svc.ip for svc in self.config.services if svc.ip != self.config.tun_ip})
        if not offsite:
            logger.info(
                "服务地址全部绑在 %s(%s) 自己身上（§2.5 虚服务地址方案），"
                "不需要弱主机模型开关", self.config.tun_name, self.config.tun_ip,
            )
            return
        if not self.config.weak_host:
            logger.warning(
                "服务地址 %s 不在 %s 上，但 l3.weak_host=false，已跳过检查。"
                "D9 方案下内层包会被强主机模型静默丢弃（§2.3）",
                offsite, self.config.tun_name,
            )
            return

        from ..tun.device_win import check_local_address, warn_if_weak_host_disabled

        for ip in offsite:
            usable, detail, alias = check_local_address(ip)
            if not usable:
                logger.warning(
                    "发布的服务地址不可用：%s。包递上来后既不是本机地址、又无转发目标，"
                    "会被直接丢弃（症状与弱主机丢弃、防火墙拦截完全一样）", detail,
                )
                continue
            logger.info("服务地址核对：%s", detail)
            warn_if_weak_host_disabled(self.config.tun_name, alias)


class ConsumerL3Service(_L3ServiceBase):
    """消费端的 L3 运行期（§1.3）。

    周期任务比提供端多两个：握手超时回收（§5.2，**不调首包会永久滞留**）与下行静默
    重探（§8.4 的兜底，默认关闭）。
    """

    _pump_name = "L3TunRead(consumer)"
    _ticker_name = "L3Ticker(consumer)"

    def __init__(self, state, sender: ColorSender, tun: TunDevice | None = None,
                 counters: Counters | None = None) -> None:
        super().__init__(sender, tun, counters)
        self.state = state
        self.config = state.config.l3
        self.dataplane: L3Consumer | None = None

    def _open_tun(self) -> TunDevice:
        return open_tun(
            name=self.config.tun_name, ip=self.config.tun_ip,
            mask=self.config.tun_mask, mtu=self.config.tun_mtu,
            routes=self.config.capture_routes,
        )

    def _build_dataplane(self) -> Callable[[bytes], object]:
        self.dataplane = L3Consumer(self.state, self.tun, self.sender,
                                    self.config, self.counters)
        return self.dataplane.on_tun_packet

    def _tick_interval(self) -> float:
        # 超时回收要比 tunnel_timeout_sec 细得多，否则"5 秒超时"名不副实
        return min(EXPIRE_SCAN_MAX_SEC, max(0.1, self.config.tunnel_timeout_sec / 2))

    def _periodic_tasks(self) -> list[Callable[[], None]]:
        assert self.dataplane is not None
        tasks: list[Callable[[], None]] = [self.dataplane.expire_handshakes]
        if self.config.tunnel_redetect_sec > 0:
            tasks.append(self.dataplane.redetect_silent_tunnels)
        # 计数器按 COUNTER_LOG_SEC 打，但 ticker 周期更短，故自己节流
        tasks.append(_Throttled(_CounterLog(self.counters, "L3/消费端"), COUNTER_LOG_SEC))
        return tasks


class _Throttled:
    """把一个回调节流到指定周期（ticker 周期比它短时用）。"""

    def __init__(self, task: Callable[[], None], interval_sec: float) -> None:
        self._task = task
        self._interval = interval_sec
        self._next = 0.0

    def __call__(self) -> None:
        now = time.monotonic()
        if now < self._next:
            return
        self._next = now + self._interval
        self._task()
