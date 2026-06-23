"""协议层单元测试。

可用 ``python -m pytest tests/test_protocol.py`` 运行，
也可直接 ``python tests/test_protocol.py`` 运行（无需 pytest）。
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.packet import Raw

from colorproxy.protocol import control, sid
from colorproxy.protocol.constants import LoadFlag, WebMsgType
from colorproxy.protocol.packets import (
    AnnounceUnit,
    ColorAnnounce,
    ColorData,
    ColorGet,
)
from colorproxy.protocol.utils import (
    calculate_checksum,
    int_to_bytes_be,
    int_to_bytes_le,
    ipv4_to_le_bytes,
    le_bytes_to_ipv4,
    verify_checksum,
)

_NSID, _LSID = sid.split_sid_hex("aa" * 16 + "bb" * 20)

# DATA Flags 位（名称序 "rSCQMRBF"）：S=bit1, R=bit5, B=bit6
_DATA_S, _DATA_R, _DATA_B = 0x02, 0x20, 0x40
# GET Flags 位（名称序 "rCRASQKF"）：A=bit3, S=bit4
_GET_A, _GET_S = 0x08, 0x10


def test_checksum_self_consistency():
    payload = bytes(range(40))
    cs = calculate_checksum(payload + b"\x00\x00")
    assert verify_checksum(payload + int_to_bytes_be(cs, 2))


def test_ipv4_le_roundtrip():
    assert le_bytes_to_ipv4(ipv4_to_le_bytes("10.0.1.6")) == "10.0.1.6"
    assert ipv4_to_le_bytes("1.2.3.4") == bytes([4, 3, 2, 1])


def test_sid_from_url_is_72_hex():
    s = sid.sid_hex_from_url(0xABCD, "http://prov.local/hello.html")
    assert len(s) == 72
    nsid, lsid = sid.split_sid_hex(s)
    assert len(nsid) == 16 and len(lsid) == 20
    assert lsid == sid.lsid_from_url("http://prov.local/hello.html")


def test_lsid_ignores_query_but_distinguishes_path():
    """计算 SID 时去 query/fragment：同 path 不同查询参数命中同一 L_sid。"""
    base = sid.lsid_from_url("http://prov.local/api/items")
    assert sid.lsid_from_url("http://prov.local/api/items?id=1") == base
    assert sid.lsid_from_url("http://prov.local/api/items?id=2&x=y") == base
    assert sid.lsid_from_url("http://prov.local/api/items#frag") == base
    assert sid.lsid_from_url("http://prov.local/api/other") != base  # path 仍区分


def _build_data_b0_r1(load: bytes, pids):
    cd = ColorData(
        Flags=_DATA_R | _DATA_S,
        NSID=_NSID, LSID=_LSID, Destination_NID=b"\xcc" * 16,
        Source_NID=b"\xdd" * 16, Segment_ID=0x12345678,
        PID_List=list(pids) + [0],
    )
    return bytes(cd / Raw(load))


def test_data_b0_r1_layout_and_roundtrip():
    pids = [0x00010002, 0x00030004]
    load = bytes([WebMsgType.TUNNEL | LoadFlag.LAST])
    raw = _build_data_b0_r1(load, pids)

    header_length = raw[6]
    assert raw[7] == len(pids)          # PID_Pointer = 有效 PID 数
    assert raw[8] == len(pids)          # PID_Num（不含保留 PID）
    assert verify_checksum(raw[:header_length])  # DATA 校验和仅覆盖包头

    parsed = ColorData(raw)
    assert parsed.Flags.B == 0 and parsed.Flags.R == 1
    assert parsed.PID_List == pids + [0]            # 末尾保留 PID
    assert parsed.Segment_ID == 0x12345678
    assert parsed.Destination_NID == b"\xcc" * 16
    assert parsed.Source_NID == b"\xdd" * 16
    assert bytes(parsed.payload) == load


def test_data_b1_ack_carries_two_nids_and_payload():
    http = b"GET /hello.html HTTP/1.1\r\nHost: prov.local\r\n\r\n"
    load = bytes([WebMsgType.HTTP_REQUEST | LoadFlag.LAST]) + http
    ack = ColorData(
        Flags=_DATA_B | _DATA_S,
        NSID=_NSID, LSID=_LSID, Destination_NID=b"\x11" * 16,
        Source_NID=b"\x22" * 16, Segment_ID=7, PID_List=[0x99],
    )
    raw = bytes(ack / Raw(load))

    parsed = ColorData(raw)
    assert parsed.Flags.B == 1
    assert parsed.Flags.R == 0   # ACK 不置 R（守护 scapy Flags 共享状态回归）
    assert parsed.Destination_NID == b"\x11" * 16   # nid_pro
    assert parsed.Source_NID == b"\x22" * 16        # nid_cus（第二个 NID）
    assert parsed.load[0] == (WebMsgType.HTTP_REQUEST | LoadFlag.LAST)
    assert bytes(parsed.payload)[1:] == http


def test_get_parse_roundtrip():
    g = ColorGet(Flags=_GET_A | _GET_S, NSID=_NSID, LSID=_LSID, NID=b"\x33" * 16,
                 Segment_ID=0xABCD, PID_List=[0x00050006])
    raw = bytes(g)
    assert verify_checksum(raw)
    parsed = ColorGet(raw)
    assert parsed.NSID == _NSID and parsed.LSID == _LSID
    assert parsed.PID_List == [0x00050006]
    assert parsed.Segment_ID == 0xABCD


def test_announce_build_and_parse():
    unit = AnnounceUnit(AM=1, NSID=_NSID, LSID=_LSID, NID=b"\x44" * 16)
    ann = ColorAnnounce(Announce_Unit_List=[unit])
    raw = bytes(ann)
    assert raw[0] == 0x71
    assert raw[7] == 0x10  # Unit_Num=1, PX_Num=0
    assert verify_checksum(raw)
    parsed = ColorAnnounce(raw)
    assert parsed.Unit_Num == 1
    assert parsed.Announce_Unit_List[0].NSID == _NSID


def test_control_register_build():
    reg = control.build_register(nid=0xABCDEF, ipv4="10.0.1.6")
    assert reg[0] == 0x74
    assert reg[5] == int(control.ControlSubtype.PROXY_REGISTER)
    assert (reg[6] | (reg[7] << 8)) == 20  # data length
    assert verify_checksum(reg)


def test_control_reply_parse():
    body = (
        bytes([1])
        + int_to_bytes_be(0x1234, 16) + ipv4_to_le_bytes("10.0.1.7")  # 1 proxy
        + bytes([1])
        + int_to_bytes_le(0x55, 2) + ipv4_to_le_bytes("10.0.0.9")     # 1 BR
    )
    head = bytes([0x74, 64]) + b"\x00\x00" + bytes([8, 6]) + int_to_bytes_le(len(body), 2) + body
    checksum = calculate_checksum(head)
    reply = head[:2] + int_to_bytes_be(checksum, 2) + head[4:]

    assert control.is_register_reply(reply)
    proxies, brs = control.parse_register_reply(reply)
    assert proxies == [(0x1234, "10.0.1.7")]
    assert brs == [(0x55, "10.0.0.9")]


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
