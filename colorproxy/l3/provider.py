"""提供端 L3 数据面：注入方向与回送方向（docs/design-l3-v2.md §7.2 / §7.3）。

两个方向都**不写任何表**：``L3Tunnel`` 由握手写入，``peers`` 由配置写入。rev.2 的
``PeerTun`` 数据面学习已删除（D14），回程 SID 改由内层**源**三元组反推，与上行严格
对称；消费端身份由内层**目的**地址查静态 ``peers[]``。

注：报文解析仍用 scapy 的 ``ColorData``，逐包开销偏大。§10.3 第 1 条要求 M5 把数据面
彻底去 scapy（预生成头模板 + struct 回填），此处先求正确。
"""
from __future__ import annotations

import logging

from ..messages import build_data_packet
from ..protocol.constants import LoadFlag, WEB_MSG_TYPE_MASK, WebMsgType
from ..protocol.packets import ColorData, ColorGet
from ..protocol.sid import sid_hex_from_packet
from ..protocol.utils import verify_checksum
from ..state import ProviderState
from ..transport.sender import ColorSender
from ..tun import ipv4, mss
from ..tun.device import TunDevice
from .counters import Counters
from .tables import L3Tunnel, L3TunnelTable

logger = logging.getLogger(__name__)


class L3Provider:
    """提供端的 L3 隧道数据面。

    三个入口：``handle_get``（握手）、``handle_upstream``（收到上行 DATA）、
    ``on_tun_packet``（从 tun 读到回程包）。调用方负责按 SID 分派到这里（D13）。
    """

    def __init__(
        self,
        state: ProviderState,
        tun: TunDevice,
        sender: ColorSender,
        counters: Counters | None = None,
        mss_clamp: int | None = None,
    ) -> None:
        self.state = state
        self.tun = tun
        self.sender = sender
        self.counters = counters if counters is not None else Counters()
        self.tunnels = L3TunnelTable()
        self.mss_clamp = mss_clamp if mss_clamp is not None else state.config.l3.mss_clamp

    # ------------------------------------------------------------ 握手（§5 ①②）

    def handle_get(self, payload: bytes) -> bool:
        """收到 GET：校验 SID ∈ 已发布的 L3 服务 → 定回址 → 记隧道 → 回隧道 DATA。

        返回 False 表示这个 GET 不属于 L3（调用方应交给 v1 路径或丢弃）。
        """
        if not verify_checksum(payload):
            return False
        get = ColorGet(payload)
        sid = sid_hex_from_packet(bytes(get.NSID), bytes(get.LSID))
        service = self.state.get_l3_service(sid)
        if service is None:
            return False  # 不是 L3 的 SID，交回调用方分派

        consumer_nid = int.from_bytes(bytes(get.NID), "big")
        pids = list(get.PID_List)
        seg_id = int(get.Segment_ID) if get.Flags.S else 0
        random_num = bytes(get.Random_Num) if get.Flags.R else None

        # 来源校验也在握手期做一次：peers[] 里没有这个 NID，后续每个包都会被
        # src_bind_drop 丢掉，不如在这里就把原因说清楚（§7.3）
        if self.state.peer_tun_ip(consumer_nid) is None:
            logger.warning(
                "拒绝 L3 握手：消费端 NID=%032x 未登记在 l3.peers[]，"
                "建了隧道也过不了来源校验（服务 %s）",
                consumer_nid, service.canonical,
            )
            return True

        return_ip = self.state.resolve_return_ip(consumer_nid, pids)
        if return_ip is None:
            logger.warning("无法确定回送地址（域内/跨域均未命中），忽略 L3 GET：%s",
                           service.canonical)
            return True

        is_new = self.tunnels.put(L3Tunnel(
            sid=sid, consumer_nid=consumer_nid, return_ip=return_ip,
            pids=pids, seg_id=seg_id, random_num=random_num,
        ))
        if is_new:
            self.counters.bump("tunnel_up")

        tunnel_load = bytes([WebMsgType.TUNNEL | LoadFlag.LAST])
        self.sender.send(return_ip, build_data_packet(
            self.state.nid, sid, consumer_nid, pids, seg_id, tunnel_load,
            hmac_seed=random_num,
        ))
        self.counters.bump("colr_tx")
        logger.info("L3 隧道%s：服务=%s 消费端=%032x 回址=%s",
                    "已建立" if is_new else "已刷新", service.canonical, consumer_nid, return_ip)
        return True

    # ------------------------------------------------------ 注入方向（§7.2 注入）

    def handle_upstream(self, payload: bytes) -> bool:
        """收到上行 ``DATA(B=1)``：逐包准入校验后 ``write(tun)`` 交本机协议栈。

        返回 False 表示这个 DATA 不属于 L3（调用方应交给 v1 路径）。
        """
        header_length = payload[6]
        if not verify_checksum(payload[:header_length]):
            logger.warning("上行 DATA 包头校验和不通过，丢弃")
            return True
        data = ColorData(payload)
        sid = sid_hex_from_packet(bytes(data.NSID), bytes(data.LSID))
        service = self.state.get_l3_service(sid)
        if service is None:
            return False  # 交回调用方：可能是 v1 的 HTTP 请求

        self.counters.bump("colr_rx")
        consumer_nid = int.from_bytes(bytes(data.Source_NID), "big")
        load = bytes(data.payload)
        if not load:
            logger.warning("上行 DATA 负载为空，丢弃：%s", service.canonical)
            return True

        # load[0] 只作宽松校验：不符照常处理，只计数（D13）
        if load[0] & WEB_MSG_TYPE_MASK != WebMsgType.IP_UPSTREAM:
            self.counters.bump("load0_mismatch")
            logger.debug("上行 load[0]=0x%02x 与 IP_UPSTREAM 不符，仍按 L3 处理", load[0])

        tunnel = self.tunnels.get(sid, consumer_nid)
        if tunnel is None:
            self.counters.bump("no_tunnel_drop")
            logger.warning("上行包无匹配隧道，丢弃：%s 消费端=%032x",
                           service.canonical, consumer_nid)
            return True

        inner = load[1:]
        header = ipv4.parse_header(inner)
        if header is None:
            self.counters.bump("nonipv4_drop")
            return True
        if not header.is_tunnelable:
            self.counters.bump("proto_drop")
            return True
        if header.is_fragment:
            self.counters.bump("frag_drop")
            logger.warning("上行内层包是分片（MF=%s off=%d），丢弃：内层 UDP 数据报须 ≤ 1252 字节",
                           header.more_fragments, header.frag_offset)
            return True

        if not self._admit(inner, header, service, consumer_nid):
            return True

        self.tun.write(self._clamped(inner, header))
        self.counters.bump("tun_tx")
        return True

    def _admit(self, inner: bytes, header: ipv4.Ipv4Header, service, consumer_nid: int) -> bool:
        """§7.3 的双向准入校验。两条都过才放行。

        这是整个方案最重要的安全点：不逐包校验的话，任何持有一条 SID 的消费端都能
        借这条隧道把流量打到提供端可达的任意地址和端口——D9 开了弱主机模型之后，
        投递范围更是扩大到本机全部网卡地址。
        """
        endpoint = ipv4.endpoint(inner, header, source=False)
        if endpoint is None or not service.admits(*endpoint):
            self.counters.bump("admit_drop")
            logger.warning(
                "准入校验失败(目的)：内层目的 %s 不在 SID 绑定的服务 %s 范围内，丢弃",
                endpoint, service.canonical,
            )
            return False

        expected_src = self.state.peer_tun_ip(consumer_nid)
        actual_src = ipv4.format_ipv4(header.src)
        if expected_src != actual_src:
            self.counters.bump("src_bind_drop")
            logger.warning(
                "准入校验失败(来源)：消费端 %032x 的内层源应为 %s，实为 %s，丢弃"
                "（伪造源地址会劫持他人回程，见 §7.3）",
                consumer_nid, expected_src, actual_src,
            )
            return False
        return True

    # ------------------------------------------------------ 回送方向（§7.2 回送）

    def on_tun_packet(self, inner: bytes) -> bool:
        """从 tun 读到一个回程包：反推 SID 与消费端 → 封 DATA 发回。

        返回 False 表示该包被丢弃（原因已计数）。
        """
        self.counters.bump("tun_rx")
        header = ipv4.parse_header(inner)
        if header is None:
            self.counters.bump("nonipv4_drop")
            return False
        if not header.is_tunnelable:
            self.counters.bump("proto_drop")
            return False
        if header.is_fragment:
            self.counters.bump("frag_drop")
            return False

        # 由内层**源**三元组反推 SID：这就是消费端当初拿来作目的的那个服务串（D14）
        source_endpoint = ipv4.endpoint(inner, header, source=True)
        if source_endpoint is None:
            self.counters.bump("proto_drop")
            return False
        found = self.state.find_l3_service_for_endpoint(*source_endpoint)
        if found is None:
            self.counters.bump("sid_miss")
            logger.warning("回程包的源端点 %s 不是本机发布的 L3 服务，丢弃", source_endpoint)
            return False
        sid, _service = found
        self.counters.bump("sid_hit")

        # 由内层**目的**地址定消费端（静态 peers[]，不做数据面学习）
        dst_ip = ipv4.format_ipv4(header.dst)
        consumer_nid = self.state.peer_nid_by_tun_ip(dst_ip)
        if consumer_nid is None:
            self.counters.bump("no_peer_drop")
            logger.warning("回程包目的 %s 未登记在 l3.peers[]，丢弃", dst_ip)
            return False

        tunnel = self.tunnels.get(sid, consumer_nid)
        if tunnel is None:
            self.counters.bump("no_tunnel_drop")
            logger.warning("回程包查不到隧道，丢弃：源端点=%s 消费端=%032x",
                           source_endpoint, consumer_nid)
            return False

        payload = self._clamped(inner, header)  # SYN-ACK 的 MSS 兜底
        load = bytes([WebMsgType.IP_DOWNSTREAM | LoadFlag.LAST]) + payload
        self.sender.send(tunnel.return_ip, build_data_packet(
            self.state.nid, sid, consumer_nid, tunnel.pids, tunnel.seg_id, load,
            hmac_seed=tunnel.random_num,
        ))
        self.counters.bump("colr_tx")
        return True

    # ---------------------------------------------------------------- 公共

    def _clamped(self, inner: bytes, header: ipv4.Ipv4Header) -> bytes:
        """需要时改写 MSS（§6.2）。非握手包原样返回，不做无谓的复制。"""
        if not mss.is_syn(inner, header):
            return inner
        mutable = bytearray(inner)
        old = mss.clamp_syn_mss(mutable, header, self.mss_clamp)
        if old is None:
            return inner
        self.counters.bump("mss_clamped")
        logger.debug("MSS clamp：%d → %d", old, self.mss_clamp)
        return bytes(mutable)
