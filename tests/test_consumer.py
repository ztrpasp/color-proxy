"""消费端单元测试（报文构造 / 反向路径 / SID 表登记）。

可用 ``python -m pytest tests/test_consumer.py`` 运行，
也可直接 ``python tests/test_consumer.py`` 运行（无需 pytest）。
无需管理员权限 / Npcap。
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from colorproxy.consumer import handlers
from colorproxy.consumer.config import ConsumerConfig
from colorproxy.consumer.messages import (
    build_ack,
    build_get,
    build_sid_list_request,
    reverse_path_for_ack,
)
from colorproxy.consumer.state import ConsumerState
from colorproxy.protocol.constants import LoadFlag, WEB_MSG_TYPE_MASK, WebMsgType
from colorproxy.protocol.packets import ColorData, ColorGet
from colorproxy.protocol.sid import (
    lsid_from_url,
    nid_to_bytes,
    sid_hex_from_url,
    split_sid_hex,
)
from colorproxy.protocol.utils import verify_checksum

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
    parsed = ColorGet(bytes(build_sid_list_request(CONSUMER_NID, 0)))
    assert bytes(parsed.NSID) == b"\x00" * 16
    assert bytes(parsed.LSID) == b"\x00" * 20
    assert bytes(parsed.NID) == nid_to_bytes(CONSUMER_NID)


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


def test_sid_list_entry_populates_table():
    state = _consumer_state()
    assert state.lookup_by_url(URL) is None
    nsid, lsid = split_sid_hex(SID)
    entry = ColorData(Flags=0x01, NSID=nsid, LSID=lsid)  # r=1：RM 回送的 SID 列表条目
    handlers.handle_data(state, bytes(entry))
    assert state.lookup_by_url(URL) == SID
    assert state.sid_count() == 1


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
