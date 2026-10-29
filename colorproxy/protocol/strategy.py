"""ANN 通告单元里随 SID 一起发给 RM 的名称与描述（策略单元 tag 13 / 14）。

契约见 docs/design-ann-sid-desc.md：

- SID_NAME（13）：算 L_sid 时被哈希的那串字节，RM 校验 ``SHA1(名称) == L_sid``；
- SID_DESC（14）：配置里的 ``desc``，只写协议/服务名，只用于展示；
- 两者合计（含每个 2 字节头）不超过 ``ANN_STRATEGY_BUDGET``。超了先保 NAME：NAME 要么完整、
  要么不发（截断后校验必失败），DESC 按 UTF-8 字符边界截断；
- 不发空 value（老 RM 会把整个 ANN 当内存不足丢掉，方案 §2.4）。

裁剪在发布时做一次，结果存进已通告表，刷新（AM=2）和注销（AM=3）原样复用，
保证同一条 SID 的三种通告带完全相同的 TLV（方案 §6）。
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass

from .constants import ANN_STRATEGY_BUDGET, STRATEGY_SID_DESC, STRATEGY_SID_NAME
from .packets import StrategyUnit

logger = logging.getLogger(__name__)

#: 每个策略单元的 tag + len 两个字节
TLV_HEAD_LEN = 2


@dataclass(frozen=True)
class SidLabel:
    """已按预算裁好的名称与描述（UTF-8 字节）。空串表示不发对应的 TLV。"""

    name: bytes = b""
    desc: bytes = b""

    @property
    def wire_len(self) -> int:
        """这两个策略单元在通告单元里一共占多少字节。"""
        return sum(TLV_HEAD_LEN + len(v) for v in (self.name, self.desc) if v)


def fit_sid_label(
    name: str, desc: str, lsid: bytes, budget: int = ANN_STRATEGY_BUDGET
) -> SidLabel:
    """把名称和描述裁进预算。裁掉或截断时打 warn，所以每条 SID 只该调一次。"""
    name_b = name.encode("utf-8")
    desc_b = desc.encode("utf-8")

    if name_b and hashlib.sha1(name_b).digest() != lsid:
        # 名称和 L_sid 必须出自同一个函数（sid.py），对不上是代码错误；
        # 发出去 RM 只会把它标成"未校验"，不如不发
        logger.error("SID 名称 %s 的 SHA1 与 L_sid 不一致，不随 ANN 发送名称", name)
        name_b = b""

    room = budget
    if name_b:
        if TLV_HEAD_LEN + len(name_b) > room:
            logger.warning(
                "SID 名称 %s 共 %d 字节，超出通告单元的策略预算 %d 字节，不随 ANN 发送名称"
                "（RM 上这条 SID 只显示哈希）", name, len(name_b), budget,
            )
            name_b = b""
        else:
            room -= TLV_HEAD_LEN + len(name_b)

    if desc_b and TLV_HEAD_LEN + len(desc_b) > room:
        cut = _utf8_prefix(desc_b, room - TLV_HEAD_LEN)
        logger.warning(
            "SID %s 的 desc %r 放不进通告单元（剩 %d 字节），%s", name or "(无名称)", desc, room,
            f"截断为 {cut.decode('utf-8')!r} 发送" if cut else "不随 ANN 发送描述",
        )
        desc_b = cut
    return SidLabel(name=name_b, desc=desc_b)


def sid_label_units(label: SidLabel) -> list[StrategyUnit]:
    """生成通告单元的策略单元列表：先 NAME 后 DESC，空的不发。"""
    units = []
    if label.name:
        units.append(StrategyUnit(Type=STRATEGY_SID_NAME, Value=label.name))
    if label.desc:
        units.append(StrategyUnit(Type=STRATEGY_SID_DESC, Value=label.desc))
    return units


def _utf8_prefix(data: bytes, limit: int) -> bytes:
    """``data`` 不超过 ``limit`` 字节的最长前缀，不切断多字节字符。"""
    if limit <= 0:
        return b""
    return data[:limit].decode("utf-8", errors="ignore").encode("utf-8")
