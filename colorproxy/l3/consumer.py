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
from ..protocol.utils import verify_checksum
from ..transport.sender import ColorSender
from ..tun import ipv4, mss
from ..tun.device import TunDevice
from .content import HttpContentGate
from .counters import Counters
from .tables import FLOW_ADMITTED, MISS, ConsumerTunnelTable, FlowCache, UdpFlowTable

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
        self.udp_flows = UdpFlowTable(idle_sec=self.config.udp_flow_idle_sec)
        self._seg_ids = itertools.count(1)
        self._seg_lock = threading.Lock()
        # 本网段的定向广播地址，用来识别 NetBIOS 一类的本机噪声（见 _endpoint_for_lookup）
        self._broadcast = ipv4.subnet_broadcast(self.config.tun_ip, self.config.tun_mask)
        # D20：配了 app=http 的端点才有内容级准入门；没配就是 None，数据面与以前完全一样
        http_services = [svc for svc in self.config.app_services if svc.app == "http"]
        self.content: HttpContentGate | None = HttpContentGate(
            http_services,
            lookup_url=self.state.lookup_by_url,
            send_get=self._send_get,
            forward=self._dispatch_upstream,
            write_tun=self._write_tun,
            counters=self.counters,
            admit_timeout=self.config.tunnel_timeout_sec,
        ) if http_services else None

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
        is_new = self._is_new_connection(inner, header, sid)
        if self.content is not None and self.content.watches(endpoint):
            # D20：受管 HTTP 端点的包先过内容级准入门，由它决定转发、扣留还是丢弃；
            # 要转发的仍经下面的 _dispatch_upstream（含 D19）
            return self.content.on_upstream(payload, header, endpoint, sid, is_new)
        return self._dispatch_upstream(sid, payload, endpoint, is_new)

    def _dispatch_upstream(
        self, sid: str, payload: bytes, endpoint: tuple[str, str, int], is_new: bool
    ) -> bool:
        """把一个上行包交给服务级隧道：未建立则排队握手，新连接先准入（D19），否则直接发。"""
        tunnel = self.tunnels.get(sid)
        if tunnel is None:
            # 首建隧道：这次 GET 本身就过了 RM 的 ACL
            return self._queue_and_handshake(sid, payload, endpoint)
        if is_new:
            return self._queue_and_admit(sid, payload, endpoint)
        self._send_upstream(sid, tunnel.rev_pids, tunnel.seg_id, tunnel.next_hop_ip, payload)
        self.tunnels.mark_upstream(sid)
        return True

    def _write_tun(self, packet: bytes) -> None:
        """把本端构造的包（D20 的 RST）写回 tun，交给本机协议栈。"""
        self.tun.write(packet)
        self.counters.bump("tun_tx")

    def _is_new_connection(self, inner: bytes, header: ipv4.Ipv4Header, sid: str) -> bool:
        """这个包是否要先过一次 GET（D19）。

        RM 的 ACL 只检查 GET。隧道按 SID 共用、长期有效（D1），若只在第一个包时发 GET，
        RM 之后改的 ACL 对这个 SID 就再也管不到了。所以每条新连接都要重发 GET：

        - TCP：``SYN=1 且 ACK=0``。不需要流表——连接建好之前客户端发不出别的包。
        - UDP：查 ``UdpFlowTable``。正在等 GET 回复的流，后续包也算"新"，一样入队。

        UDP 在首建隧道时也要登记，否则隧道建好后它的下一个包会被当成新流再发一次 GET。
        """
        if not self.config.get_per_connection:
            return False
        if header.proto == ipv4.PROTO_TCP:
            return mss.is_initial_syn(inner, header)
        if header.proto != ipv4.PROTO_UDP:
            return False  # debug_tunnel_icmp 放进来的 ICMP：不做准入
        ports = ipv4.parse_ports(inner, header)
        if ports is None:
            return False
        key = (header.src, ports[0], header.dst, ports[1])
        return self.udp_flows.classify(key, sid) != FLOW_ADMITTED

    def _endpoint_for_lookup(
        self, inner: bytes, header: ipv4.Ipv4Header
    ) -> tuple[str, str, int] | None:
        """取查表用的目的三元组，并在此处完成协议与分片两道过滤（§7.1 第 2、3 步）。"""
        if ipv4.is_multicast(header.dst) or header.dst == ipv4.LIMITED_BROADCAST \
                or (self._broadcast is not None and header.dst == self._broadcast):
            # 本机往 tun 上发的广播/组播（mDNS/SSDP/NetBIOS）。隧道是点对点的，它们
            # 本来就不该进去。**单独计数、不打 warning**：并进 sid_miss 会把"路由把
            # 不该进的流量导进了 tun"这个诊断淹掉（M1c 真机上每秒好几个）。
            self.counters.bump("nonunicast_drop")
            return None

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

        if header.total_length > self.config.tun_mtu and header.dont_fragment:
            # §6.3：超过 tun MTU 且 DF=1。D3 拓扑下近乎不触发（内核在写进 color0 之前
            # 就已按接口 MTU 处理完了），真出现说明开了 IP 转发在替别的主机转发流量。
            # ICMP 3/4 按 D16 降级为可选，此处只丢弃 + 计数，不构造 ICMP。
            self.counters.bump("mtu_drop")
            logger.warning("内层包 %d 字节 > tun MTU %d 且 DF=1，丢弃（§6.3）",
                           header.total_length, self.config.tun_mtu)
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
            seg_id = self._send_get(sid)
            logger.info("L3 隧道未建立，已发 GET：服务=%s SID=%s… SegID=%d",
                        endpoint, sid[:16], seg_id)
        return True

    def _queue_and_admit(
        self, sid: str, payload: bytes, endpoint: tuple[str, str, int]
    ) -> bool:
        """隧道已在、来了新连接：首包入队，必要时为这条 SID 重发 GET（D19）。

        GET 的回复到达时 ``_on_tunnel`` 原子替换隧道并冲刷队列；RM 的 ACL 拒绝时 GET
        被丢、没有回复，超时后 ``expire_handshakes`` 丢掉这些包。已有连接始终走旧隧道，
        两种结果都不影响它们。同一条 SID 同时只有一个 GET 在途，并发的新连接共用它。
        """
        dropped = self.tunnels.queue_first_packet(sid, payload)
        self.counters.bump("firstpkt_queued")
        if dropped:
            self.counters.bump("firstpkt_dropped", dropped)

        if self.tunnels.begin_refresh(sid):
            seg_id = self._send_get(sid)
            self.counters.bump("admit_get")
            # DEBUG：浏览器一次开好几条连接，INFO 会刷屏；次数看 admit_get 计数器
            logger.debug("新连接准入，已发 GET：服务=%s SID=%s… SegID=%d",
                         endpoint, sid[:16], seg_id)
        return True

    def _send_get(self, sid: str) -> int:
        """向本域 RM 发一个 GET（握手与重探共用），返回本次用的 SegID。"""
        with self._seg_lock:
            seg_id = next(self._seg_ids)
        self.sender.send(self.state.rm_ipv4, build_get(sid, self.state.nid, seg_id))
        self.counters.bump("colr_tx")
        return seg_id

    # ------------------------------------------------- 下行总入口（§1.3 / §7.1）

    def handle_data(self, payload: bytes) -> bool:
        """收到 ``DATA(B=0)`` 的 L3 总入口。返回 False 表示应交回 v1 路径。

        分派严格按 §1.3 的两级判据：

        1. **跨模式**看 SID 落在哪张表里（D13）——SID 既不在 L3 隧道表也不在待建表，
           就不是 L3 的包，原样交回 v1；
        2. **L3 内部**才看 ``load[0]``：``0x10`` 是隧道 DATA、其余按下行内层包处理。
           这一层不违背 D13：SID 已经唯一确定了模式，``load[0]`` 只在两张都属于本
           模式的路径之间选一条，选错的后果是计一次 ``nonipv4_drop``，不会串到 v1。
        """
        if len(payload) <= 9 or not verify_checksum(payload[:payload[6]]):
            return False  # 坏包：交回 v1 路径，它会在同一处校验后静默丢弃
        data = ColorData(payload)
        if data.Flags.B or data.Flags.r:
            return False  # B=1 是本端发出的 ACK；r=1 是 RM 的服务摘要应答
        sid = sid_hex_from_packet(bytes(data.NSID), bytes(data.LSID))
        if self.content is not None and self.content.claims(sid):
            return self._on_content_reply(data, sid)
        if self.tunnels.get(sid) is None and not self.tunnels.is_pending(sid):
            return False

        load = bytes(data.payload)
        if load and load[0] & WEB_MSG_TYPE_MASK == WebMsgType.TUNNEL:
            return self._on_tunnel(data, sid)
        return self._on_downstream(data, sid, load)

    # --------------------------------------------------- 隧道 DATA（§5 ②）

    def handle_tunnel(self, payload: bytes) -> bool:
        """收到 ``load[0]=0x10`` 的隧道 DATA：存隧道并冲刷首包队列。

        返回 False 表示这个 SID 不在 L3 待建表里（调用方应交给 v1 路径）。
        """
        data = ColorData(payload)
        sid = sid_hex_from_packet(bytes(data.NSID), bytes(data.LSID))
        if self.content is not None and self.content.claims(sid):
            return self._on_content_reply(data, sid)
        if not self.tunnels.is_pending(sid):
            return False
        return self._on_tunnel(data, sid)

    def _on_content_reply(self, data: ColorData, sid: str) -> bool:
        """URL SID 的隧道 DATA（D20）：RM 放行了这个 URL，交给准入门放包。

        回复里的 PID/下一跳不用存：数据走的是服务级隧道，URL SID 只用来过 ACL。
        """
        self.counters.bump("colr_rx")
        load = bytes(data.payload)
        if load and load[0] & WEB_MSG_TYPE_MASK == WebMsgType.TUNNEL:
            assert self.content is not None
            self.content.on_admission_reply(sid)
        else:
            self.counters.bump("load0_mismatch")
        return True

    def _on_tunnel(self, data: ColorData, sid: str) -> bool:
        if not self.tunnels.is_pending(sid):
            # 隧道已建好后又收到一份隧道 DATA：提供端对重发的 GET 是幂等回应的，
            # 这属于正常重复，不是错误，照常忽略即可。
            logger.debug("隧道 DATA 重复到达（隧道已建立），忽略：SID=%s…", sid[:16])
            return True
        self.counters.bump("colr_rx")

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
        # 重探或新连接准入：旧隧道原子换成新的（§8.4 / D19）
        was_up = self.tunnels.get(sid) is not None
        tunnel, queued = self.tunnels.establish(
            sid, reverse_path_for_ack(recv_pids),
            int.from_bytes(bytes(data.NSID), "big"), next_hop, seg_id,
        )
        self.udp_flows.admit_sid(sid)
        if not was_up:
            self.counters.bump("tunnel_up")
            logger.info("L3 隧道已建立：SID=%s… 下一跳=%s，冲刷首包 %d 个",
                        sid[:16], next_hop, len(queued))
        elif queued:
            logger.debug("新连接准入通过：SID=%s… 下一跳=%s，冲刷 %d 个包",
                         sid[:16], next_hop, len(queued))
        else:
            logger.info("L3 隧道已刷新（重探成功）：SID=%s… 下一跳=%s", sid[:16], next_hop)
        for packet in queued:
            self._send_upstream(sid, tunnel.rev_pids, tunnel.seg_id, tunnel.next_hop_ip, packet)
        if queued:
            self.tunnels.mark_upstream(sid)
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
        return self._on_downstream(data, sid, bytes(data.payload))

    def _on_downstream(self, data: ColorData, sid: str, load: bytes) -> bool:
        self.counters.bump("colr_rx")
        self.tunnels.mark_downstream(sid)

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

        不实现这一条的话，握手失败后首包会永久滞留在队列里。由
        ``l3/service.py`` 的 ticker 周期调用——不是给调用方选做的。
        """
        for sid, dropped, was_redetect in self.tunnels.expire_handshakes():
            self.udp_flows.forget_pending(sid)
            if dropped:
                self.counters.bump("firstpkt_dropped", dropped)
            if was_redetect and dropped:
                # 隧道还在、却有包在等：是新连接的准入 GET 没回（D19）
                self.counters.bump("admit_timeout")
                logger.warning(
                    "新连接准入超时(%.1fs)：SID=%s… 提供端没回隧道 DATA（RM 的 ACL 拒绝了"
                    "本消费端，或 GET 丢失），丢弃新连接的包 %d 个；已有连接继续用旧隧道",
                    self.config.tunnel_timeout_sec, sid[:16], dropped,
                )
                continue
            if was_redetect:
                logger.warning(
                    "L3 隧道重探超时(%.1fs)：SID=%s… 提供端没回隧道 DATA，"
                    "继续用旧路径（§8.4）", self.config.tunnel_timeout_sec, sid[:16],
                )
                continue
            logger.warning(
                "L3 隧道握手超时(%.1fs)：SID=%s… 丢弃首包 %d 个，该 SID 退回未建立状态，"
                "下一个包会重新发 GET",
                self.config.tunnel_timeout_sec, sid[:16], dropped,
            )

    def redetect_silent_tunnels(self) -> None:
        """上行活跃但下行静默超过 ``tunnel_redetect_sec`` 的隧道，重发 GET（§8.4）。

        D1 不做刷新与回收，代价是"提供端重启、BR 侧 PID 表老化都会让隧道静默失效，
        且没有任何恢复路径"。本兜底默认关闭（``tunnel_redetect_sec=0``），联调不顺
        时打开。重探期间**旧隧道继续可用**，新的隧道 DATA 到达时原子替换。
        """
        silence = self.config.tunnel_redetect_sec
        if silence <= 0:
            return
        for sid in self.tunnels.silent_tunnels(silence):
            if not self.tunnels.begin_refresh(sid):
                continue
            self._send_get(sid)
            logger.warning(
                "L3 隧道下行静默 %.1fs（上行仍活跃），重发 GET 探测：SID=%s…（§8.4）",
                silence, sid[:16],
            )

    def prune_udp_flows(self) -> None:
        """清掉空闲超时的 UDP 流（D19），由 ``l3/service.py`` 的 ticker 周期调用。"""
        self.udp_flows.prune()

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
