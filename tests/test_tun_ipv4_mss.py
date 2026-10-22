"""内层包解析与 MSS clamp 测试（docs/design-l3-v2.md §11 M1a）。

报文样本用 scapy 构造（scapy 只出现在测试里，数据面不依赖它，见 §10.3 第 1 条），
再用本项目的解析器交叉验证——自己造样本、自己解析容易两边一起错。

可用 ``python -m pytest tests/test_tun_ipv4_mss.py`` 运行，
也可直接 ``python tests/test_tun_ipv4_mss.py`` 运行（无需 pytest）。
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.inet import ICMP, IP, IPOption_Router_Alert, TCP, UDP
from scapy.packet import Raw

from colorproxy.tun import ipv4, mss

CONSUMER_TUN = "10.99.1.1"
SERVICE_IP = "172.10.0.2"
CLAMP = 1240


def _raw(packet) -> bytes:
    """序列化并回填校验和（scapy 在 build 时自动算）。"""
    return bytes(IP(bytes(packet)))


def _syn(mss_value: int | None = 1460, flags: str = "S", **tcp_kwargs) -> bytes:
    options = [("MSS", mss_value)] if mss_value is not None else []
    return _raw(
        IP(src=CONSUMER_TUN, dst=SERVICE_IP)
        / TCP(sport=51000, dport=8000, flags=flags, options=options, **tcp_kwargs)
    )


def _carried_checksum(packet: bytes, header: ipv4.Ipv4Header) -> int:
    return struct.unpack_from("!H", packet, header.ihl + 16)[0]


# ---------------------------------------------------------------- 解析

def test_parse_tcp_matches_scapy() -> None:
    packet = _syn()
    reference = IP(packet)
    header = ipv4.parse_header(packet)
    assert header is not None
    assert header.ihl == reference.ihl * 4
    assert header.total_length == reference.len
    assert header.proto == ipv4.PROTO_TCP == reference.proto
    assert ipv4.format_ipv4(header.src) == CONSUMER_TUN
    assert ipv4.format_ipv4(header.dst) == SERVICE_IP
    assert ipv4.parse_ports(packet, header) == (51000, 8000)
    assert header.proto_name == "tcp"
    assert header.is_tunnelable and not header.is_fragment


def test_parse_udp_and_options_bearing_header() -> None:
    packet = _raw(IP(src=CONSUMER_TUN, dst=SERVICE_IP) / UDP(sport=40000, dport=5004) / Raw(b"rtp"))
    header = ipv4.parse_header(packet)
    assert header is not None and header.proto_name == "udp"
    assert ipv4.parse_ports(packet, header) == (40000, 5004)

    # 带 IP 选项时 ihl > 20，端口必须按 ihl 偏移取，不能写死 20
    with_options = _raw(
        IP(src=CONSUMER_TUN, dst=SERVICE_IP, options=[IPOption_Router_Alert()])
        / UDP(sport=40000, dport=5004)
    )
    padded = ipv4.parse_header(with_options)
    assert padded is not None
    assert padded.ihl > ipv4.IPV4_MIN_HEADER, "样本本身没带上 IP 选项，这条就没测到东西"
    assert ipv4.parse_ports(with_options, padded) == (40000, 5004)


def test_parse_rejects_malformed_packets() -> None:
    packet = _syn()
    assert ipv4.parse_header(b"") is None
    assert ipv4.parse_header(packet[:19]) is None, "短于 20 字节"
    assert ipv4.parse_header(b"\x60" + packet[1:]) is None, "版本号不是 4"
    assert ipv4.parse_header(b"\x44" + packet[1:]) is None, "IHL < 5"
    # Total Length 超过实际字节数
    bogus = bytearray(packet)
    struct.pack_into("!H", bogus, 2, len(packet) + 10)
    assert ipv4.parse_header(bytes(bogus)) is None


def test_fragment_detection_covers_first_and_later_pieces() -> None:
    """D15：首片(MF=1) 与非首片(offset>0) 都必须被识别为分片。"""
    first = ipv4.parse_header(
        _raw(IP(src=CONSUMER_TUN, dst=SERVICE_IP, flags="MF") / UDP(sport=1, dport=5004) / Raw(b"x" * 8))
    )
    assert first is not None and first.more_fragments and first.frag_offset == 0
    assert first.is_fragment, "首片也算分片：后续片会被丢，只发首片是浪费"

    later = ipv4.parse_header(
        _raw(IP(src=CONSUMER_TUN, dst=SERVICE_IP, frag=1, proto=17) / Raw(b"y" * 8))
    )
    assert later is not None and later.frag_offset == 1 and later.is_fragment

    whole = ipv4.parse_header(_syn())
    assert not whole.is_fragment


def test_df_flag_is_reported() -> None:
    header = ipv4.parse_header(_raw(IP(src=CONSUMER_TUN, dst=SERVICE_IP, flags="DF") / TCP()))
    assert header is not None and header.dont_fragment
    plain = ipv4.parse_header(_syn())
    assert plain is not None and not plain.dont_fragment


def test_endpoint_extracts_service_tuples_in_both_directions() -> None:
    """上行取目的端、回程取源端——两者都是规范服务串的三个组成部分（§7.2，D14）。"""
    upstream = _syn()
    header = ipv4.parse_header(upstream)
    assert ipv4.endpoint(upstream, header, source=False) == ("tcp", SERVICE_IP, 8000)
    assert ipv4.endpoint(upstream, header, source=True) == ("tcp", CONSUMER_TUN, 51000)

    # 回程包：源是服务、目的是消费端 tun 地址
    downstream = _raw(
        IP(src=SERVICE_IP, dst=CONSUMER_TUN) / TCP(sport=8000, dport=51000, flags="SA")
    )
    back = ipv4.parse_header(downstream)
    assert ipv4.endpoint(downstream, back, source=True) == ("tcp", SERVICE_IP, 8000)


def test_endpoint_refuses_icmp_and_fragments() -> None:
    icmp = _raw(IP(src=CONSUMER_TUN, dst=SERVICE_IP) / ICMP())
    header = ipv4.parse_header(icmp)
    assert header is not None and not header.is_tunnelable
    assert ipv4.endpoint(icmp, header, source=False) is None, "D11：ICMP 不进隧道"
    assert header.proto_name == ""

    fragment = _raw(IP(src=CONSUMER_TUN, dst=SERVICE_IP, frag=2, proto=6) / Raw(b"z" * 8))
    frag_header = ipv4.parse_header(fragment)
    assert ipv4.endpoint(fragment, frag_header, source=False) is None, (
        "非首片没有 TCP 头，取端口会读到载荷字节"
    )


# ---------------------------------------------------------------- MSS clamp

def test_clamp_reduces_mss_and_keeps_checksum_valid() -> None:
    packet = bytearray(_syn(1460))
    header = ipv4.parse_header(packet)
    assert mss.is_syn(packet, header)

    old = mss.clamp_syn_mss(packet, header, CLAMP)
    assert old == 1460

    # 用 scapy 重新解析，确认 MSS 真的改了
    reparsed = IP(bytes(packet))
    assert dict(reparsed[TCP].options)["MSS"] == CLAMP
    # 增量更新后的校验和必须与整包重算一致
    assert mss.tcp_checksum(bytes(packet), header) == _carried_checksum(packet, header)
    # 也让 scapy 自己验一遍（删掉校验和重算，应回到同一个值）
    original = reparsed[TCP].chksum
    del reparsed[TCP].chksum
    assert IP(bytes(reparsed))[TCP].chksum == original


def test_clamp_only_decreases() -> None:
    """只减不增：对端已在更小的路径上时不得把它改大（§6.2）。"""
    packet = bytearray(_syn(1200))
    header = ipv4.parse_header(packet)
    before = bytes(packet)
    assert mss.clamp_syn_mss(packet, header, CLAMP) is None
    assert bytes(packet) == before
    assert dict(IP(bytes(packet))[TCP].options)["MSS"] == 1200


def test_clamp_applies_to_syn_ack_too() -> None:
    """提供端侧改的是服务端发出的 SYN-ACK；只做一侧会形成黑洞（§6.2）。"""
    packet = bytearray(
        _raw(IP(src=SERVICE_IP, dst=CONSUMER_TUN)
             / TCP(sport=8000, dport=51000, flags="SA", options=[("MSS", 1460)]))
    )
    header = ipv4.parse_header(packet)
    assert mss.clamp_syn_mss(packet, header, CLAMP) == 1460
    assert dict(IP(bytes(packet))[TCP].options)["MSS"] == CLAMP
    assert mss.tcp_checksum(bytes(packet), header) == _carried_checksum(packet, header)


def test_clamp_skips_non_syn_and_missing_option() -> None:
    # 非 SYN（普通 ACK）不动
    ack = bytearray(_syn(mss_value=None, flags="A"))
    header = ipv4.parse_header(ack)
    assert not mss.is_syn(ack, header)
    assert mss.clamp_syn_mss(ack, header, CLAMP) is None

    # SYN 但没有 MSS 选项：不处理，对端会退到 536 默认值（§6.2）
    bare_syn = bytearray(_syn(mss_value=None))
    bare_header = ipv4.parse_header(bare_syn)
    assert mss.is_syn(bare_syn, bare_header)
    assert mss.clamp_syn_mss(bare_syn, bare_header, CLAMP) is None

    # 非 TCP 不动
    udp = bytearray(_raw(IP(src=CONSUMER_TUN, dst=SERVICE_IP) / UDP(dport=5004)))
    udp_header = ipv4.parse_header(udp)
    assert mss.clamp_syn_mss(udp, udp_header, CLAMP) is None
    assert mss.tcp_flags(udp, udp_header) == 0


def test_initial_syn_excludes_syn_ack_and_data() -> None:
    """D19 只对发起新连接的 SYN 发 GET：SYN-ACK、普通 ACK、UDP 都不算。"""
    for flags, expected in (("S", True), ("SA", False), ("A", False), ("PA", False),
                            ("R", False), ("SE", True)):
        packet = _syn(mss_value=None, flags=flags)
        assert mss.is_initial_syn(packet, ipv4.parse_header(packet)) is expected, flags
    udp = _raw(IP(src=CONSUMER_TUN, dst=SERVICE_IP) / UDP(dport=5004))
    assert not mss.is_initial_syn(udp, ipv4.parse_header(udp))


def test_clamp_survives_malformed_options() -> None:
    """选项区来自对端，可能畸形：不得越界读、不得死循环。"""
    packet = bytearray(_syn(1460))
    header = ipv4.parse_header(packet)
    tcp_start = header.ihl
    options_at = tcp_start + 20

    # 长度字段为 0 的选项（若按 length 前进就是死循环）
    broken = bytearray(packet)
    broken[options_at] = 8      # 未知 kind
    broken[options_at + 1] = 0  # 非法长度
    assert mss.clamp_syn_mss(broken, header, CLAMP) is None

    # 声称的长度越出选项区
    overrun = bytearray(packet)
    overrun[options_at] = 8
    overrun[options_at + 1] = 200
    assert mss.clamp_syn_mss(overrun, header, CLAMP) is None

    # EOL 之后不再解析
    ended = bytearray(packet)
    ended[options_at] = 0
    assert mss.clamp_syn_mss(ended, header, CLAMP) is None


def test_clamp_finds_mss_after_nop_padding() -> None:
    """MSS 不一定是第一个选项：NOP 填充后仍要找到（真实栈常见 NOP/SACK/TS 组合）。"""
    packet = bytearray(
        _raw(IP(src=CONSUMER_TUN, dst=SERVICE_IP)
             / TCP(sport=51000, dport=8000, flags="S",
                   options=[("NOP", None), ("NOP", None), ("SAckOK", b""), ("MSS", 1460)]))
    )
    header = ipv4.parse_header(packet)
    assert mss.clamp_syn_mss(packet, header, CLAMP) == 1460
    assert dict(IP(bytes(packet))[TCP].options)["MSS"] == CLAMP
    assert mss.tcp_checksum(bytes(packet), header) == _carried_checksum(packet, header)


def test_incremental_update_matches_full_recompute_over_many_values() -> None:
    """增量更新与整包重算在各种取值上都必须一致（含需要回卷进位的情形）。"""
    for old_mss in (536, 1400, 1460, 8960, 65535):
        for target in (1240, 1200, 576):
            if old_mss <= target:
                continue
            packet = bytearray(_syn(old_mss))
            header = ipv4.parse_header(packet)
            assert mss.clamp_syn_mss(packet, header, target) == old_mss
            assert mss.tcp_checksum(bytes(packet), header) == _carried_checksum(packet, header), (
                f"old={old_mss} target={target} 校验和不一致"
            )


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
