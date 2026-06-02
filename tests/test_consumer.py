"""消费端单元测试（报文构造 / 反向路径 / SID 表登记）。

可用 ``python -m pytest tests/test_consumer.py`` 运行，
也可直接 ``python tests/test_consumer.py`` 运行（无需 pytest）。
无需管理员权限 / Npcap。
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from colorproxy.consumer import sid_table
from colorproxy.consumer.config import ConsumerConfig
from colorproxy.consumer.messages import (
    build_ack,
    build_get,
    build_sid_list_request,
    reverse_path_for_ack,
)
from colorproxy.consumer.state import ConsumerState
from colorproxy.protocol import control
from colorproxy.protocol.constants import (
    CONTROL_FIRST_BYTE,
    ControlSubtype,
    LoadFlag,
    WEB_MSG_TYPE_MASK,
    WebMsgType,
)
from colorproxy.protocol.packets import ColorData, ColorGet
from colorproxy.protocol.sid import lsid_from_url, nid_to_bytes, sid_hex_from_url
from colorproxy.protocol.utils import (
    calculate_checksum,
    int_to_bytes_be,
    int_to_bytes_le,
    verify_checksum,
)

PROVIDER_NID = 0xA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1
CONSUMER_NID = 0xB2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2
URL = "http://prov.local/hello.html"
SID = sid_hex_from_url(PROVIDER_NID, URL)


def _consumer_state() -> ConsumerState:
    return ConsumerState(ConsumerConfig(nid=CONSUMER_NID, ipv4="10.0.1.5", rm_ipv4="10.0.0.1"))


def test_build_get_layout_and_roundtrip():
    raw = bytes(build_get(SID, CONSUMER_NID, 0xABCD))
    assert raw[0] == 0x72
    assert verify_checksum(raw)
    parsed = ColorGet(raw)
    assert bytes(parsed.NSID) == nid_to_bytes(PROVIDER_NID)
    assert bytes(parsed.LSID) == lsid_from_url(URL)
    assert bytes(parsed.NID) == nid_to_bytes(CONSUMER_NID)
    assert parsed.Flags.S == 1 and parsed.Flags.A == 1
    assert parsed.Segment_ID == 0xABCD
    assert list(parsed.PID_List) == []


def test_build_sid_list_request_is_zero_sid():
    raw = bytes(build_sid_list_request(CONSUMER_NID))
    assert verify_checksum(raw)
    parsed = ColorGet(raw)
    assert bytes(parsed.NSID) == b"\x00" * 16
    assert bytes(parsed.LSID) == b"\x00" * 20
    assert bytes(parsed.NID) == nid_to_bytes(CONSUMER_NID)
    # 与参考实现哨兵 GET 对齐：A=1、S=0（不含 SegID）、r=0
    assert parsed.Flags.A == 1 and parsed.Flags.S == 0 and parsed.Flags.r == 0


def test_build_ack_carries_two_nids_and_request():
    http = b"GET http://prov.local/hello.html HTTP/1.1\r\nHost: prov.local\r\n\r\n"
    parsed = ColorData(bytes(build_ack(SID, CONSUMER_NID, [], 7, http)))
    assert parsed.Flags.B == 1 and parsed.Flags.S == 1
    assert parsed.Flags.R == 0   # 域内 ACK 不置 R（守护 scapy Flags 共享状态回归）
    assert bytes(parsed.Destination_NID) == nid_to_bytes(PROVIDER_NID)   # nid_pro
    assert bytes(parsed.Source_NID) == nid_to_bytes(CONSUMER_NID)        # nid_cus
    assert parsed.Segment_ID == 7
    load = bytes(parsed.payload)
    assert (load[0] & WEB_MSG_TYPE_MASK) == WebMsgType.HTTP_REQUEST
    assert load[0] & LoadFlag.LAST
    assert load[1:] == http


def test_reverse_path_for_ack():
    assert reverse_path_for_ack([]) == []                       # 域内
    assert reverse_path_for_ack([0x11, 0x22, 0]) == [0x22, 0x11]  # 去尾部保留位后反向
    assert reverse_path_for_ack([0x11, 0x22]) == [0x22, 0x11]


def _build_sid_list_control(sids: list[str]) -> bytes:
    """构造一个 RM 下发的 CONTROL(Subtype=40) 报文：负载 = 各 SID(36B) 拼接。

    布局对齐 control.build_register / ColorMonitor.py:480-494。
    """
    data = b"".join(bytes.fromhex(s) for s in sids)
    head = bytes([CONTROL_FIRST_BYTE, 64])
    after = (
        bytes([control.CONTROL_HEADER_LENGTH, ControlSubtype.SID_LIST_UPDATE])
        + int_to_bytes_le(len(data), 2)
        + data
    )
    checksum = calculate_checksum(head + b"\x00\x00" + after)
    return head + int_to_bytes_be(checksum, 2) + after


def test_sid_list_control_populates_table_and_skips_sentinel():
    state = _consumer_state()
    assert state.lookup_by_url(URL) is None
    other_url = "http://prov.local/world.html"
    other_sid = sid_hex_from_url(PROVIDER_NID, other_url)

    pkt = _build_sid_list_control(["0" * 72, SID, other_sid])  # 含全零哨兵
    assert control.is_sid_list(pkt) and verify_checksum(pkt)
    assert control.parse_sid_list(pkt) == ["0" * 72, SID, other_sid]

    sid_table.register_sid_list_control(state, pkt)
    assert state.lookup_by_url(URL) == SID
    assert state.lookup_by_url(other_url) == other_sid
    assert state.sid_count() == 2  # 全零哨兵被跳过


def test_register_reply_is_not_treated_as_sid_list():
    # 注册同步(Subtype=6) 不应被 SID 列表登记误吃
    reply_subtype_pkt = _build_sid_list_control([SID])
    assert control.is_sid_list(reply_subtype_pkt)
    not_sid_list = bytearray(reply_subtype_pkt)
    not_sid_list[5] = ControlSubtype.PROXY_REGISTER_REPLY  # 改成 Subtype=6
    assert not control.is_sid_list(bytes(not_sid_list))


def _run_all() -> int:
    funcs = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in funcs:
        try:
            fn()
            print(f"  PASS {fn.__name__}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"  FAIL {fn.__name__}: {exc!r}")
    print(f"\n{len(funcs) - failed}/{len(funcs)} passed")
    return failed


if __name__ == "__main__":
    raise SystemExit(_run_all())
