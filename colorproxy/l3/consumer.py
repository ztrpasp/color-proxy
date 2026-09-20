"""消费端 L3 数据面：上行与下行（docs/design-l3-v2.md §7.1）。

消费端不需要明文服务表：从 tun 读到包后，用观察到的 ``(proto, dst_ip, dst_port)``
自己拼规范服务串并 SHA1，再拿 L_sid 去 RM 下发的 SID 表里查 N_sid（§3.5 的隐私特性）。

注：与 ``l3/provider.py`` 一样，报文构造仍走 scapy，M5 再去（§10.3 第 1 条）。
"""
from __future__ import annotations

import itertools
import logging
import threading

from ..consumer.config import ConsumerL3Config
from ..consumer.messages import build_get, build_l3_upstream, reverse_path_for_ack
from ..consumer.state import ConsumerState
from ..protocol.constants import WEB_MSG_TYPE_MASK, WebMsgType
from ..protocol.packets import ColorData
from ..protocol.sid import sid_hex_from_packet
from ..transport.sender import ColorSender
from ..tun import ipv4, mss
from ..tun.device import TunDevice
from .counters import Counters
from .tables import FlowCache, MISS, ConsumerTunnelTable

logger = logging.getLogger(__name__)


class L3Consumer:
    """消费端的 L3 隧道数据面。

    三个入口：``on_tun_packet``（客户端进程发出的包）、``handle_tunnel``（隧道 DATA）、
    ``handle_downstream``（下行内层包）。调用方按 SID 分派到这里（D13）。
    """

    def __init__(
        self,
        state: ConsumerState,
        tun: TunDevice,
        sender: ColorSender,
        config: ConsumerL3Config | None = None,
        counters: Counters | None = None,
    ) -> None:
        self.state = state
        self.tun = tun
        self.sender = sender
        self.config = config if config is not None else state.config.l3
        self.counters = counters if counters is not None else Counters()
        self.tunnels = ConsumerTunnelTable(
            queue_pkts=self.config.firstpkt_queue_pkts,
            queue_bytes=self.config.firstpkt_queue_bytes,
            handshake_timeout=self.config.tunnel_timeout_sec,
        )
        self.flows = FlowCache()
        self._seg_ids = itertools.count(1)
        self._seg_lock = threading.Lock()

    # ------------------------------------------------------------ 上行（§7.1）

    def on_tun_packet(self, inner: bytes) -> bool:
        """从 color0 读到一个客户端发出的包：算 SID → 封上行 DATA 或入首包队列。

        返回 False 表示该包被丢弃（原因已计数）。
        """
        self.counters.bump("tun_rx")
        header = ipv4.parse_header(inner)
        if header is None:
            self.counters.bump("nonipv4_drop")
            return False

        endpoint = self._endpoint_for_lookup(inner, header)
        if endpoint is None:
            return False

        sid = self._lookup_sid(endpoint)
        if sid is None:
            self.counters.bump("sid_miss")
            logger.warning("SID 未命中，丢弃：%s（路由把不该进 tun 的流量导进来了？）", endpoint)
            return False
        self.counters.bump("sid_hit")

        payload = self._clamped(inner, header)
        tunnel = self.tunnels.get(sid)
        if tunnel is not None:
            self._send_upstream(sid, tunnel.rev_pids, tunnel.seg_id, tunnel.next_hop_ip, payload)
            return True
        return self._queue_and_handshake(sid, payload, endpoint)

    def _endpoint_for_lookup(
        self, inner: bytes, header: ipv4.Ipv4Header
    ) -> tuple[str, str, int] | None:
        """取查表用的目的三元组，并在此处完成协议与分片两道过滤（§7.1 第 2、3 步）。"""
        if header.is_fragment:
            # D15：首片与非首片一律丢。非首片取不出端口；首片虽能算 SID，但后续片
            # 必被丢、收端无法重组，只发首片是浪费带宽。
            self.counters.bump("frag_drop")
            logger.warning(
                "内层包被分片(MF=%s off=%d)，丢弃：内层 UDP 数据报须 ≤ %d 字节（§7.1 第 3 步）",
                header.more_fragments, header.frag_offset, self.config.tun_mtu - 28,
            )
            return None

        if not header.is_tunnelable:
            if self.config.debug_tunnel_icmp and header.proto == ipv4.PROTO_ICMP:
                # 联调开关：放行 ICMP、端口按 0 处理，让 ping 能作最小连通性判据（§8.2）。
                # 提供端需发布对应的 tcp/udp 通配 SID 才查得到，跑通后应关掉。
                return "tcp", ipv4.format_ipv4(header.dst), 0
            self.counters.bump("proto_drop")
            return None

        return ipv4.endpoint(inner, header, source=False)

    def _lookup_sid(self, endpoint: tuple[str, str, int]) -> str | None:
        """查流缓存，未命中则拼串算 SHA1 查 SID 表（含 §3.3 两级回退）后写回缓存。"""
        cached = self.flows.get(endpoint)
        if cached is not None:
            return None if cached == MISS else cached
        sid = self.state.lookup_by_service(*endpoint)
        self.flows.put(endpoint, sid if sid is not None else MISS)
        return sid

    def _queue_and_handshake(
        self, sid: str, payload: bytes, endpoint: tuple[str, str, int]
    ) -> bool:
        """隧道未建立：首包入队，必要时发 GET（§5.2）。"""
        dropped = self.tunnels.queue_first_packet(sid, payload)
        self.counters.bump("firstpkt_queued")
        if dropped:
            self.counters.bump("firstpkt_dropped", dropped)

        if self.tunnels.begin_handshake(sid):
            with self._seg_lock:
                seg_id = next(self._seg_ids)
            self.sender.send(self.state.rm_ipv4, build_get(sid, self.state.nid, seg_id))
            self.counters.bump("colr_tx")
            logger.info("L3 隧道未建立，已发 GET：服务=%s SID=%s… SegID=%d",
                        endpoint, sid[:16], seg_id)
        return True

    # --------------------------------------------------- 隧道 DATA（§5 ②）

    def handle_tunnel(self, payload: bytes) -> bool:
        """收到 ``load[0]=0x10`` 的隧道 DATA：存隧道并冲刷首包队列。

        返回 False 表示这个 SID 不在 L3 待建表里（调用方应交给 v1 路径）。
        """
        data = ColorData(payload)
        sid = sid_hex_from_packet(bytes(data.NSID), bytes(data.LSID))
        if not self.tunnels.is_pending(sid):
            return False

        recv_pids = list(data.PID_List)
        if data.Flags.R:
            # 跨域：下一跳 PX 取首个真实 PID 的高 16 位（与 v1 一致）
            next_hop = self.state.resolve_px_ip(recv_pids[1] >> 16) if len(recv_pids) >= 2 else None
        else:
            next_hop = self.state.resolve_provider_ip(int.from_bytes(bytes(data.NSID), "big"))
        if next_hop is None:
            logger.warning("隧道 DATA 无法确定下一跳，忽略：SID=%s…", sid[:16])
            return True

        seg_id = int(data.Segment_ID) if data.Flags.S else 0
        tunnel, queued = self.tunnels.establish(
            sid, reverse_path_for_ack(recv_pids),
            int.from_bytes(bytes(data.NSID), "big"), next_hop, seg_id,
        )
        self.counters.bump("tunnel_up")
        logger.info("L3 隧道已建立：SID=%s… 下一跳=%s，冲刷首包 %d 个",
                    sid[:16], next_hop, len(queued))
        for packet in queued:
            self._send_upstream(sid, tunnel.rev_pids, tunnel.seg_id, tunnel.next_hop_ip, packet)
        return True

    # ------------------------------------------------------------ 下行（§7.1）

    def handle_downstream(self, payload: bytes) -> bool:
        """收到 ``load[0]=0x50`` 的下行 DATA：校验目的地址后写进 tun。

        返回 False 表示这个 SID 不在 L3 隧道表里（调用方应交给 v1 路径）。
        """
        data = ColorData(payload)
        sid = sid_hex_from_packet(bytes(data.NSID), bytes(data.LSID))
        if self.tunnels.get(sid) is None:
            return False
        self.counters.bump("colr_rx")

        load = bytes(data.payload)
        if not load:
            return True
        if load[0] & WEB_MSG_TYPE_MASK != WebMsgType.IP_DOWNSTREAM:
            self.counters.bump("load0_mismatch")

        inner = load[1:]
        header = ipv4.parse_header(inner)
        if header is None:
            self.counters.bump("nonipv4_drop")
            return True

        # 防对端串流：下行包的目的必须是本机 tun 地址
        dst_ip = ipv4.format_ipv4(header.dst)
        if dst_ip != self.config.tun_ip:
            self.counters.bump("admit_drop")
            logger.warning("下行内层包目的 %s 不是本机 tun 地址 %s，丢弃",
                           dst_ip, self.config.tun_ip)
            return True

        self.tun.write(self._clamped(inner, header))
        self.counters.bump("tun_tx")
        return True

    # ---------------------------------------------------------------- 公共

    def expire_handshakes(self) -> None:
        """回收超时的握手并丢弃其首包队列（§5.2）。

        不实现这一条的话，握手失败后首包会永久滞留在队列里。
        """
        for sid, dropped in self.tunnels.expire_handshakes():
            if dropped:
                self.counters.bump("firstpkt_dropped", dropped)
            logger.warning(
                "L3 隧道握手超时(%.1fs)：SID=%s… 丢弃首包 %d 个，该 SID 退回未建立状态，"
                "下一个包会重新发 GET",
                self.config.tunnel_timeout_sec, sid[:16], dropped,
            )

    def _send_upstream(
        self, sid: str, pids: list[int], seg_id: int, next_hop_ip: str, inner: bytes
    ) -> None:
        self.sender.send(
            next_hop_ip, build_l3_upstream(sid, self.state.nid, pids, seg_id, inner)
        )
        self.counters.bump("colr_tx")

    def _clamped(self, inner: bytes, header: ipv4.Ipv4Header) -> bytes:
        """需要时改写 MSS（§6.2）。消费端改的是客户端发出的 SYN。"""
        if not mss.is_syn(inner, header):
            return inner
        mutable = bytearray(inner)
        old = mss.clamp_syn_mss(mutable, header, self.config.mss_clamp)
        if old is None:
            return inner
        self.counters.bump("mss_clamped")
        logger.debug("MSS clamp：%d → %d", old, self.config.mss_clamp)
        return bytes(mutable)
