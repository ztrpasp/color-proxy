"""DATA 报文 HMAC 计算的字节级回归测试。

锚定参考实现 color-agent-plus 的 wireshark 抓包常量（src/Test/test_CoLoRpacket.py:11-14,37-44），
确保本实现与真实边界路由器 (BR) 的 HMAC 校验字节级一致。

可用 ``python -m pytest tests/test_hmac.py`` 运行，
也可直接 ``python tests/test_hmac.py`` 运行（无需 pytest）。
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.packet import Raw

from colorproxy.messages import build_data_packet
from colorproxy.protocol import sid
from colorproxy.protocol.constants import LoadFlag, WebMsgType
from colorproxy.protocol.packets import ColorData
from colorproxy.protocol.utils import calc_hmac, verify_checksum

# 参考实现抓包常量（src/Test/test_CoLoRpacket.py）
_RN = bytes.fromhex("12345678")  # GET 携带、作 HMAC 种子的 4 字节 Random_Num
#: HMAC 计算输入（去掉首 10 字节包头、HMAC 位清零的 DATA 包头 + PID 列表），不含末尾种子
_DATPKT_HMAC_BYTES = bytes.fromhex(
    "ffffffffffffffffffffffffffffffff"        # NSID(16)
    "0101010101010101010101010101010101010101"  # LSID(20)
    "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"        # Destination_NID(16)
    "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"        # Source_NID(16)
    "00000000"                                # HMAC 位清零(4)
    "000000009876543201234567"                # PID_List(3*4)
)
#: post_build 完成后的完整 DATA(B=0,R=1,C=1,S=0)：HMAC 字段为 98eec036
_DATPKT_POSTBUILD_BYTES = bytes.fromhex(
    "73405e0038385e000224"                    # 包头前 10 字节（含 Flags=0x24）
    "ffffffffffffffffffffffffffffffff"
    "0101010101010101010101010101010101010101"
    "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"
    "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
    "98eec036"                                # HMAC（MD5 末 4 字节）
    "000000009876543201234567"
)
_EXPECTED_HMAC = bytes.fromhex("98eec036")


def test_calc_hmac_vector():
    """MD5 取末 4 字节，与参考实现 CalcHMAC 的抓包向量一致。"""
    assert calc_hmac(_DATPKT_HMAC_BYTES + _RN)[-4:] == _EXPECTED_HMAC


def test_colordata_postbuild_matches_reference():
    """解析黄金 DATA → 把 HMAC 还原为种子 → 重建须重算出同一字节串。

    复刻参考实现的 test_CalcHMAC：验证 ColorData.post_build 的 HMAC 计算字节级吻合。
    """
    cd = ColorData(_DATPKT_POSTBUILD_BYTES)
    assert cd.Flags.C == 1 and cd.Flags.R == 1 and cd.Flags.B == 0
    cd.HMAC = _RN  # 还原为种子，重建时 post_build 应重算回 98eec036
    assert bytes(cd) == _DATPKT_POSTBUILD_BYTES


def test_build_data_packet_with_seed_sets_c_and_valid_hmac():
    """build_data_packet 传入种子：置 C=1、HMAC 字段 4 字节，且独立重算一致。"""
    nsid, lsid = sid.split_sid_hex("aa" * 16 + "bb" * 20)
    pids = [0x00010002, 0x00030004]
    load = bytes([WebMsgType.TUNNEL | LoadFlag.LAST])
    raw = bytes(build_data_packet(
        provider_nid=0xDD, sid="aa" * 16 + "bb" * 20, consumer_nid=0xCC,
        pids=pids, seg_id=0x12345678, load=load, hmac_seed=_RN,
    ))

    parsed = ColorData(raw)
    assert parsed.Flags.C == 1
    assert len(bytes(parsed.HMAC)) == 4
    header_length = raw[6]
    assert verify_checksum(raw[:header_length])  # 校验和覆盖最终 HMAC

    # 独立重算：跨域 R=1/B=0 → hmac_offset=78；种子接在末尾
    header, payload = raw[:header_length], raw[header_length:]
    seed = header[10:78] + b"\x00\x00\x00\x00" + header[82:] + payload + _RN
    assert bytes(parsed.HMAC) == calc_hmac(seed)[-4:]


def test_build_data_packet_without_seed_is_backward_compatible():
    """不传种子：不置 C、不含 HMAC 字段，比带种子版本短 4 字节。"""
    s = "aa" * 16 + "bb" * 20
    pids = [0x00010002]
    load = bytes([WebMsgType.TUNNEL | LoadFlag.LAST])
    no_hmac = bytes(build_data_packet(0xDD, s, 0xCC, pids, 7, load))
    with_hmac = bytes(build_data_packet(0xDD, s, 0xCC, pids, 7, load, hmac_seed=_RN))

    assert ColorData(no_hmac).Flags.C == 0
    assert len(no_hmac) + 4 == len(with_hmac)


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
