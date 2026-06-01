"""处理收到的 GET 与 ACK 报文（握手的服务端两步）。"""
from __future__ import annotations

import logging

from .messages import build_data_packet
from .origin import OriginWorker
from .protocol.constants import LoadFlag, WEB_MSG_TYPE_MASK, WebMsgType
from .protocol.packets import ColorData, ColorGet
from .protocol.sid import sid_hex_from_packet
from .protocol.utils import verify_checksum
from .state import PendingTx, ProviderState
from .transport.sender import ColorSender

logger = logging.getLogger(__name__)


def handle_get(state: ProviderState, sender: ColorSender, payload: bytes) -> None:
    """state A：收到 GET → 校验 → 定回址 → 记未决事务 → 回隧道 DATA。"""
    if not verify_checksum(payload):
        return
    get = ColorGet(payload)
    sid = sid_hex_from_packet(bytes(get.NSID), bytes(get.LSID))
    if state.get_service(sid) is None:
        logger.warning("收到未发布 SID 的 GET，忽略：%s…", sid[:16])
        return

    consumer_nid = int.from_bytes(bytes(get.NID), "big")
    pids = list(get.PID_List)
    seg_id = int(get.Segment_ID) if get.Flags.S else 0

    return_ip = state.resolve_return_ip(consumer_nid, pids)
    if return_ip is None:
        logger.warning("无法确定回送地址（域内/跨域均未命中），忽略 GET")
        return

    state.put_pending(sid, consumer_nid, PendingTx(return_ip, pids, seg_id, bool(pids)))

    tunnel_load = bytes([WebMsgType.TUNNEL | LoadFlag.LAST])
    tunnel = build_data_packet(state.nid, sid, consumer_nid, pids, seg_id, tunnel_load)
    sender.send(return_ip, tunnel)
    logger.info("已回送隧道 DATA：SID=%s… 回址=%s", sid[:16], return_ip)


def handle_ack(state: ProviderState, sender: ColorSender, payload: bytes) -> None:
    """state B：收到携带 HTTP 请求的 ACK(B=1) → 取出请求 → 起回源 worker。"""
    header_length = payload[6]
    if not verify_checksum(payload[:header_length]):
        return
    ack = ColorData(payload)
    sid = sid_hex_from_packet(bytes(ack.NSID), bytes(ack.LSID))
    consumer_nid = int.from_bytes(bytes(ack.Source_NID), "big")  # B=1：第二个 NID 为消费端

    load = bytes(ack.payload)
    if not load or (load[0] & WEB_MSG_TYPE_MASK) != WebMsgType.HTTP_REQUEST:
        return
    http_request = load[1:]

    tx = state.pop_pending(sid, consumer_nid)
    if tx is None:
        logger.warning("收到 ACK 但无匹配未决事务，忽略：SID=%s…", sid[:16])
        return
    service = state.get_service(sid)
    if service is None:
        return

    OriginWorker(state, sender, sid, consumer_nid, tx, service, http_request).start()
