"""把配置中的 Web 服务发布为 SID（向 RM 发送 ANN 通告）。"""
from __future__ import annotations

import logging

from .protocol.packets import AnnounceUnit, ColorAnnounce
from .protocol.sid import lsid_from_url, nid_to_bytes, sid_hex_from_url
from .state import ProviderState
from .transport.sender import ColorSender

logger = logging.getLogger(__name__)

# 通告动作类型：注册
_ANNOUNCE_ACTION_REGISTER = 1


def publish_services(state: ProviderState, sender: ColorSender) -> None:
    """为每个配置的服务计算 SID、发送 ANN，并登记到本机 Web 服务表。"""
    for service in state.config.services:
        sid = sid_hex_from_url(state.nid, service.url)
        announce = _build_announce(state.nid, service.url)
        sender.send(state.rm_ipv4, announce)
        state.add_service(sid, service)
        logger.info("已发布 Web 服务 %s -> %s (SID=%s…)", service.url,
                    f"{service.origin_host}:{service.origin_port}", sid[:16])


def _build_announce(provider_nid: int, url: str) -> ColorAnnounce:
    """构造仅含一个通告单元的 ANN 报文（N_sid=本机 NID，L_sid=SHA1(去 query 后 url)）。"""
    nsid = nid_to_bytes(provider_nid)
    unit = AnnounceUnit(
        N=1, L=1, I=1, AM=_ANNOUNCE_ACTION_REGISTER,
        NSID=nsid, LSID=lsid_from_url(url), NID=nsid,
    )
    return ColorAnnounce(Announce_Unit_List=[unit])
