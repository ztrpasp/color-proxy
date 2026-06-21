"""处理收到的 GET 与 ACK 报文（握手的服务端两步）。"""
from __future__ import annotations

import logging

from .messages import build_data_packet
from .origin import OriginWorker
from .protocol.constants import LoadFlag, WebMsgType
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
    # RM/BR 转发 GET 时置 R=1 并加 4 字节 Random_Num（一次性 nonce），作回送 DATA 的 HMAC 种子。
    random_num = bytes(get.Random_Num) if get.Flags.R else None
    logger.info("GET 携带 Random_Num=%s", random_num.hex() if random_num else "无")

    return_ip = state.resolve_return_ip(consumer_nid, pids)
    if return_ip is None:
        logger.warning("无法确定回送地址（域内/跨域均未命中），忽略 GET")
        return

    state.put_pending(sid, consumer_nid, PendingTx(return_ip, pids, seg_id, bool(pids), random_num))

    tunnel_load = bytes([WebMsgType.TUNNEL | LoadFlag.LAST])
    tunnel = build_data_packet(state.nid, sid, consumer_nid, pids, seg_id, tunnel_load, hmac_seed=random_num)
    sender.send(return_ip, tunnel)
    logger.info("已回送隧道 DATA：SID=%s… 回址=%s", sid[:16], return_ip)


def handle_ack(state: ProviderState, sender: ColorSender, payload: bytes) -> None:
    """state B：收到携带 HTTP 请求的 ACK(B=1) → 取出请求 → 起回源 worker。

    负载放行从宽：**不再校验 ``load[0]`` 的 WebMsgType 位**，默认整条 ACK 即承载
    HTTP 请求（``http_request = load[1:]``）；``load[0]`` 仅用于读取 LAST 标志做日志/
    分片提示。v1 假设请求单包装下，故非末片(LAST=0)也照常放行，仅告警。
    """
    header_length = payload[6]
    logger.info("收到 ACK(B=1)：共 %d 字节，包头 %d 字节", len(payload), header_length)
    if not verify_checksum(payload[:header_length]):
        logger.warning("ACK 包头校验和不通过，丢弃")
        return
    ack = ColorData(payload)
    sid = sid_hex_from_packet(bytes(ack.NSID), bytes(ack.LSID))
    consumer_nid = int.from_bytes(bytes(ack.Source_NID), "big")  # B=1：第二个 NID 为消费端

    load = bytes(ack.payload)
    if not load:
        logger.warning("ACK 负载为空，丢弃：SID=%s…", sid[:16])
        return
    is_last = bool(load[0] & LoadFlag.LAST)
    http_request = load[1:]  # 默认即 HTTP 请求，不再按 load[0] 的类型位判别
    logger.info(
        "ACK 解析：SID=%s… 消费端=%032x load[0]=0x%02x 末片=%s HTTP请求=%d字节",
        sid[:16], consumer_nid, load[0], is_last, len(http_request),
    )
    if not is_last:
        logger.warning("ACK 非末片(LAST=0)，v1 按单包处理仍放行：SID=%s…", sid[:16])

    tx = state.pop_pending(sid, consumer_nid)
    if tx is None:
        logger.warning("收到 ACK 但无匹配未决事务，忽略：SID=%s…", sid[:16])
        return
    service = state.get_service(sid)
    if service is None:
        logger.warning("收到 ACK 但 SID 未发布服务，忽略：SID=%s…", sid[:16])
        return

    OriginWorker(state, sender, sid, consumer_nid, tx, service, http_request).start()
    logger.info("已起回源 worker 处理请求：SID=%s…", sid[:16])
