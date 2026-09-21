"""把配置中的服务发布为 SID（向 RM 发送 ANN 通告）。

两种粒度共用同一套 ANN 报文与登记流程，只有 L_sid 的算法不同（§0.2）：

- 内容级（v1）：``services[]`` 的 URL → ``lsid_from_url``，登记进 ``_web_services``；
- 服务级（v2）：``l3.services[]`` 的三元组 → ``lsid_from_service``，登记进 ``_l3_services``。

两张表并列，后续按"SID 落在哪张表里"分派模式（docs/design-l3-v2.md §4.1，D13）。

**同一条 SID 只发一次 AM=1（2026-09-21 真机修正）**：此前认为"ANN 以 AM=1 重复发送、
RM 侧覆盖同一条 SID"，真机上不成立——RM 对已存在的 SID 会报
``unable to insert into sid_table``。故本模块按 ``ProviderState`` 里的已通告表去重，
刷新用 AM=2（更新）、退出用 AM=3（注销），三者分别对应技术文档里 ANN 的三种动作。
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

# 通告单元的动作类型（AM，见技术要点 §5.1）
ANNOUNCE_ACTION_REGISTER = 1  # 注册：SID 在 RM 侧不存在时才合法，重复发会被 RM 拒绝
ANNOUNCE_ACTION_UPDATE = 2    # 更新：SID 已在 RM 侧存在时用它刷新
ANNOUNCE_ACTION_WITHDRAW = 3  # 注销：退出时撤回，使下次启动能干净地再注册


def publish_services(state: ProviderState, sender: ColorSender) -> None:
    """发布全部服务：先 v1 内容级，再 v2 服务级（L3 未启用则跳过）。

    **可重复调用但不会重复发包**：已通告过的 SID 只登记本地服务表、不再发 ANN。
    """
    _publish_web_services(state, sender)
    _publish_l3_services(state, sender)


def refresh_services(state: ProviderState, sender: ColorSender) -> int:
    """对已通告的每条 SID 发一次 AM=2（更新），返回发出的条数。

    只在开启了周期性重注册（``registration.REGISTER_REFRESH_SEC > 0``）时才会被调到。
    用 AM=2 而不是 AM=1：后者在 RM 侧走的是"插入"路径，同一条 SID 第二次就会报
    ``unable to insert into sid_table``（2026-09-21 真机）。
    """
    return _announce_all(state, sender, ANNOUNCE_ACTION_UPDATE, "刷新")


def withdraw_services(state: ProviderState, sender: ColorSender) -> int:
    """退出前对已通告的每条 SID 发一次 AM=3（注销），返回发出的条数。

    不注销的后果不是"这次不干净"，而是**下次启动必然撞车**：RM 里留着上一轮的 SID，
    新一轮的 AM=1 插不进去。注销失败只记日志——退出路径上没有什么可补救的。
    """
    count = _announce_all(state, sender, ANNOUNCE_ACTION_WITHDRAW, "注销")
    state.clear_announced()
    return count


def _announce_all(state: ProviderState, sender: ColorSender, action: int, label: str) -> int:
    count = 0
    for sid, lsid in state.announced_services():
        try:
            sender.send(state.rm_ipv4, _build_announce(state.nid, lsid, action))
        except Exception:  # noqa: BLE001 单条失败不应影响其余条目
            logger.exception("%s服务 SID=%s… 失败（已忽略）", label, sid[:16])
            continue
        count += 1
    if count:
        logger.info("已向 RM(%s) %s %d 条服务（AM=%d）", state.rm_ipv4, label, count, action)
    return count


def _publish_web_services(state: ProviderState, sender: ColorSender) -> None:
    """为每个配置的 Web 服务计算 SID、发送 ANN，并登记到本机 Web 服务表。"""
    for service in state.config.services:
        lsid = lsid_from_url(service.url)
        sid = sid_hex_from_url(state.nid, service.url)
        state.add_service(sid, service)
        if not state.mark_announced(sid, lsid):
            continue  # 本进程内已通告过，重复发 AM=1 会被 RM 拒绝
        sender.send(state.rm_ipv4, _build_announce(state.nid, lsid))
        logger.info("已发布 Web 服务 %s -> %s (SID=%s…)", service.url,
                    f"{service.origin_host}:{service.origin_port}", sid[:16])


def _publish_l3_services(state: ProviderState, sender: ColorSender) -> None:
    """为每个配置的 L3 端点计算 SID、发送 ANN，并登记到本机 L3 服务表。"""
    l3 = state.config.l3
    if not l3.enabled:
        return
    published = 0
    for service in l3.services:
        lsid = lsid_from_service(service.proto, service.ip, service.port)
        sid = sid_hex(nid_to_bytes(state.nid), lsid)
        state.add_l3_service(sid, service)
        if not state.mark_announced(sid, lsid):
            continue
        sender.send(state.rm_ipv4, _build_announce(state.nid, lsid))
        published += 1
        logger.info(
            "已发布 L3 服务 %s%s (SID=%s…)",
            service.canonical,
            f" [{service.desc}]" if service.desc else "",
            sid[:16],
        )
    if published:
        logger.info("L3 服务发布完毕：共 %d 条，已知消费端 %d 个",
                    state.l3_service_count(), len(l3.peers))


def _build_announce(
    provider_nid: int, lsid: bytes, action: int = ANNOUNCE_ACTION_REGISTER
) -> ColorAnnounce:
    """构造仅含一个通告单元的 ANN 报文（N_sid=本机 NID，L_sid 由调用方算好）。"""
    nsid = nid_to_bytes(provider_nid)
    unit = AnnounceUnit(
        N=1, L=1, I=1, AM=action,
        NSID=nsid, LSID=lsid, NID=nsid,
    )
    return ColorAnnounce(Announce_Unit_List=[unit])
