"""L3 数据面计数器（docs/design-l3-v2.md §10.4）。

L3 模式的故障大多表现为**静默丢包**，没有计数器几乎无法定位：包进了 tun、抓包看得
见、就是没响应，而"被准入校验拦了"和"路由把不该进的流量导进了 tun"要采取的行动完全
不同。因此每个丢包分支都必须落在一个**独立**的计数器上，不许共用一个 ``drop``。
"""
from __future__ import annotations

import threading

#: 全部计数器名及其含义（§10.4）。顺序即打印顺序。
COUNTER_HELP: dict[str, str] = {
    "tun_rx": "从 tun 读到的内层包数",
    "tun_tx": "写进 tun 的内层包数",
    "colr_tx": "发出的 CoLoR DATA 数",
    "colr_rx": "收到的 CoLoR DATA 数",
    "tunnel_up": "已建立的隧道数",
    "sid_hit": "SID 查表命中",
    "sid_miss": "算出的 SID 不在表中：路由把不该进的流量导进了 tun；回送方向则是源服务未发布",
    "admit_drop": "目的准入校验失败：发布的服务与实际访问的 ip:port 不一致（§7.3）",
    "src_bind_drop": "内层源地址与 peers[] 不符：消费端 tun 地址配错，或 peers[] 漏配（§7.3）",
    "no_peer_drop": "回程按内层 dst 查不到 peers[] 条目",
    "no_tunnel_drop": "查不到隧道：隧道已静默失效（§8.4），或 peers[] 与 NID 对不上",
    "frag_drop": "内层包被分片（D15）：内层 UDP 数据报超过 1252 字节",
    "mtu_drop": "内层包超过 tun MTU（§6.3，D3 拓扑下近乎不触发）",
    "nonipv4_drop": "非 IPv4 或 IPv4 头自相矛盾",
    "nonunicast_drop": "本机往 tun 上发的广播/组播噪声（mDNS/SSDP/NetBIOS/IGMP）：正常现象，不是配置错误",
    "proto_drop": "非 TCP/UDP，不进隧道（D11）",
    "load0_mismatch": "load[0] 类型位与 SID 所属模式不符；不影响转发，只作诊断（D13）",
    "mss_clamped": "改写过 MSS 的握手包数",
    "firstpkt_queued": "隧道未建立时入队的首包数",
    "firstpkt_dropped": "首包队列超限或握手失败而丢弃的包数",
}


class Counters:
    """线程安全的计数器集合。

    ``bump`` 在数据面逐包调用，故走一把普通锁 + 字典自增；真要更快就得换成
    per-thread 累加，但那是 M5 的事，现在这点开销远不及 scapy。
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._values: dict[str, int] = dict.fromkeys(COUNTER_HELP, 0)

    def bump(self, name: str, delta: int = 1) -> None:
        assert name in COUNTER_HELP, f"未登记的计数器：{name}（请先加进 COUNTER_HELP）"
        with self._lock:
            self._values[name] += delta

    def get(self, name: str) -> int:
        with self._lock:
            return self._values[name]

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._values)

    def format_line(self, *, only_nonzero: bool = True) -> str:
        """一行文本快照，供每 5 s 打一条日志用（§10.4）。"""
        values = self.snapshot()
        items = [
            f"{name}={value}" for name, value in values.items()
            if value or not only_nonzero
        ]
        return " ".join(items) if items else "（全零）"
