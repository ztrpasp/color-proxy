"""把配置中的服务发布为 SID（向 RM 发送 ANN 通告）。

两种粒度共用同一套 ANN 报文与登记流程，只有 L_sid 的算法不同（§0.2）：

- 内容级（v1）：``services[]`` 的 URL → ``lsid_from_url``，登记进 ``_web_services``；
- 服务级（v2）：``l3.services[]`` 的三元组 → ``lsid_from_service``，登记进 ``_l3_services``。

两张表并列，后续按"SID 落在哪张表里"分派模式（docs/design-l3-v2.md §4.1，D13）。
"""
from __future__ import annotations

import logging

from .protocol.packets import AnnounceUnit, ColorAnnounce
from .protocol.sid import (
    lsid_from_service,
    lsid_from_url,
    nid_to_bytes,
    sid_hex,
    sid_hex_from_url,
)
from .state import ProviderState
from .transport.sender import ColorSender

logger = logging.getLogger(__name__)

# 通告动作类型：注册
_ANNOUNCE_ACTION_REGISTER = 1


def publish_services(state: ProviderState, sender: ColorSender) -> None:
    """发布全部服务：先 v1 内容级，再 v2 服务级（L3 未启用则跳过）。"""
    _publish_web_services(state, sender)
    _publish_l3_services(state, sender)


def _publish_web_services(state: ProviderState, sender: ColorSender) -> None:
    """为每个配置的 Web 服务计算 SID、发送 ANN，并登记到本机 Web 服务表。"""
    for service in state.config.services:
        sid = sid_hex_from_url(state.nid, service.url)
        sender.send(state.rm_ipv4, _build_announce(state.nid, lsid_from_url(service.url)))
        state.add_service(sid, service)
        logger.info("已发布 Web 服务 %s -> %s (SID=%s…)", service.url,
                    f"{service.origin_host}:{service.origin_port}", sid[:16])


def _publish_l3_services(state: ProviderState, sender: ColorSender) -> None:
    """为每个配置的 L3 端点计算 SID、发送 ANN，并登记到本机 L3 服务表。"""
    l3 = state.config.l3
    if not l3.enabled:
        return
    for service in l3.services:
        lsid = lsid_from_service(service.proto, service.ip, service.port)
        sid = sid_hex(nid_to_bytes(state.nid), lsid)
        sender.send(state.rm_ipv4, _build_announce(state.nid, lsid))
        state.add_l3_service(sid, service)
        logger.info(
            "已发布 L3 服务 %s%s (SID=%s…)",
            service.canonical,
            f" [{service.desc}]" if service.desc else "",
            sid[:16],
        )
    logger.info("L3 服务发布完毕：共 %d 条，已知消费端 %d 个",
                state.l3_service_count(), len(l3.peers))


def _build_announce(provider_nid: int, lsid: bytes) -> ColorAnnounce:
    """构造仅含一个通告单元的 ANN 报文（N_sid=本机 NID，L_sid 由调用方算好）。"""
    nsid = nid_to_bytes(provider_nid)
    unit = AnnounceUnit(
        N=1, L=1, I=1, AM=_ANNOUNCE_ACTION_REGISTER,
        NSID=nsid, LSID=lsid, NID=nsid,
    )
    return ColorAnnounce(Announce_Unit_List=[unit])
