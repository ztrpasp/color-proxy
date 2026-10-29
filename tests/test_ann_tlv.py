"""ANN 携带 SID 名称/描述（策略单元 tag 13/14）的测试，对照 docs/design-ann-sid-desc.md。

可用 ``python -m pytest tests/test_ann_tlv.py`` 运行，
也可直接 ``python tests/test_ann_tlv.py`` 运行（无需 pytest）。
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from colorproxy import publish
from colorproxy.config import Config, ServiceConfig, load_config
from colorproxy.protocol.constants import (
    ANN_STRATEGY_BUDGET,
    STRATEGY_SID_DESC,
    STRATEGY_SID_NAME,
)
from colorproxy.protocol.packets import ColorAnnounce
from colorproxy.protocol.sid import (
    content_url,
    lsid_from_service,
    lsid_from_url,
    service_canonical,
    sid_name_from_url,
)
from colorproxy.protocol.strategy import fit_sid_label, sid_label_units
from colorproxy.state import ProviderState

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROTOTYPE_PROVIDER = os.path.join(ROOT, "deploy", "prototype", "config-svr1-1-provider.json")

#: 通告单元固定部分：flag + unit_len + strategy_num + N_SID + L_SID + NID
UNIT_FIXED_LEN = 3 + 16 + 20 + 16

#: 方案 §2.6 的 92 字节 ANN：NID a1×16，tcp://10.10.9.2:3306，DESC mysql，AM=1
DOC_VECTOR_HEX = (
    "71405c0092910010e85402a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1d992c50089cf6b0490bcff0dbf65bdede57e4e64"
    "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a10d147463703a2f2f31302e31302e392e323a333330360e056d7973716c"
)


class _CollectSender:
    """把发出的报文序列化后收起来，不碰网络。"""

    def __init__(self) -> None:
        self.sent: list[bytes] = []

    def send(self, dst_ip: str, packet) -> None:  # noqa: ANN001, ARG002
        self.sent.append(bytes(packet))


class _Capture(logging.Handler):
    """临时截住某个 logger 的 warning 及以上，不让它们打到控制台。"""

    def __init__(self, name: str) -> None:
        super().__init__(logging.WARNING)
        self.records: list[logging.LogRecord] = []
        self._logger = logging.getLogger(name)

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    def __enter__(self) -> "_Capture":
        self._propagate = self._logger.propagate
        self._logger.propagate = False
        self._logger.addHandler(self)
        return self

    def __exit__(self, *exc) -> None:  # noqa: ANN002
        self._logger.removeHandler(self)
        self._logger.propagate = self._propagate


def _fit(name: str, desc: str, budget: int = ANN_STRATEGY_BUDGET):
    """按名称自己的 SHA1 当 L_sid 裁剪（测预算用，与真实 SID 无关）。"""
    return fit_sid_label(name, desc, hashlib.sha1(name.encode("utf-8")).digest(), budget)


def _name_of_len(size: int) -> str:
    base = "http://10.10.9.2:8000/"
    return base + "a" * (size - len(base))


def _unit(raw: bytes):
    ann = ColorAnnounce(raw)
    assert ann.Unit_Num == 1, "每个 ANN 只带一个通告单元"
    return ann.Announce_Unit_List[0]


def _tlvs(raw: bytes) -> list[tuple[int, bytes]]:
    return [(s.Type, bytes(s.Value)) for s in _unit(raw).Strategy_Unit_List]


# ---------------------------------------------------------------- 报文字节

def test_matches_design_doc_vector() -> None:
    """与方案 §2.6 的 92 字节 ANN 逐字节一致（RM 侧单元测试用的也是它）。"""
    lsid = lsid_from_service("tcp", "10.10.9.2", 3306)
    label = fit_sid_label(service_canonical("tcp", "10.10.9.2", 3306), "mysql", lsid)
    raw = bytes(publish._build_announce(int("a1" * 16, 16), lsid, label=label))
    assert raw.hex() == DOC_VECTOR_HEX


def test_unit_length_and_strategy_num() -> None:
    lsid = lsid_from_service("udp", "10.10.9.2", 5004)
    label = fit_sid_label("udp://10.10.9.2:5004", "rtp", lsid)
    unit = _unit(bytes(publish._build_announce(0xA1, lsid, label=label)))
    assert unit.Strategy_Num == 2
    assert unit.Unit_Length == UNIT_FIXED_LEN + label.wire_len
    assert _tlvs(bytes(publish._build_announce(0xA1, lsid, label=label))) == [
        (STRATEGY_SID_NAME, b"udp://10.10.9.2:5004"), (STRATEGY_SID_DESC, b"rtp"),
    ]


def test_budget_constant_fits_unit_len() -> None:
    """预算再大也不能让 unit_len（1 字节）溢出；200 时单元正好 255 字节。"""
    assert UNIT_FIXED_LEN + ANN_STRATEGY_BUDGET <= 255
    with _Capture("colorproxy.protocol.strategy"):
        label = _fit(_name_of_len(194), "http", budget=200)  # 名称占 196，DESC 只剩 4 → "ht"
    assert label.wire_len == 200 and label.desc == b"ht"
    unit = _unit(bytes(publish._build_announce(0xA1, b"\x00" * 20, label=label)))
    assert unit.Unit_Length == 255


def test_no_tlv_without_label() -> None:
    """不传 label 时与改动前一样：没有策略单元。"""
    unit = _unit(bytes(publish._build_announce(0xA1, b"\x11" * 20)))
    assert unit.Strategy_Num == 0 and unit.Unit_Length == UNIT_FIXED_LEN


# ---------------------------------------------------------------- 名称

def test_name_is_the_hashed_string() -> None:
    """三种粒度的名称都正好是 L_sid 的哈希原文。"""
    url = "http://10.10.9.2:8000/api/items?x=1#frag"
    assert sid_name_from_url(url) == "http://10.10.9.2:8000/api/items"
    assert hashlib.sha1(sid_name_from_url(url).encode()).digest() == lsid_from_url(url)

    name = service_canonical("tcp", "10.10.9.2", 21)
    assert hashlib.sha1(name.encode()).digest() == lsid_from_service("tcp", "10.10.9.2", 21)

    content = content_url("10.10.9.2", 8000, "/api/model/medical/stream?q=1")
    assert hashlib.sha1(sid_name_from_url(content).encode()).digest() == lsid_from_url(content)


def test_name_not_matching_lsid_is_dropped() -> None:
    with _Capture("colorproxy.protocol.strategy") as cap:
        label = fit_sid_label("tcp://10.10.9.2:3306", "mysql", b"\x00" * 20)
    assert label.name == b"" and label.desc == b"mysql"
    assert any(r.levelno == logging.ERROR for r in cap.records)


# ---------------------------------------------------------------- 预算

def test_budget_exact_fit_and_one_byte_over() -> None:
    """正好 73 字节全部保留；名称多 1 字节时，DESC 截掉 1 字节，名称不动。"""
    label = _fit(_name_of_len(65), "abcd")          # (2+65) + (2+4) = 73
    assert label.wire_len == 73 and label.desc == b"abcd"

    with _Capture("colorproxy.protocol.strategy") as cap:
        label = _fit(_name_of_len(66), "abcd")      # 名称占 68，DESC 只剩 3
    assert len(label.name) == 66 and label.desc == b"abc"
    assert label.wire_len == 73
    assert cap.records, "截断要打 warn"


def test_name_over_budget_is_dropped_whole() -> None:
    """名称放不下就整个不发（截断的名称校验必失败），DESC 照发。"""
    with _Capture("colorproxy.protocol.strategy") as cap:
        label = _fit(_name_of_len(72), "http")      # 2+72 = 74 > 73
    assert label.name == b"" and label.desc == b"http"
    assert cap.records


def test_desc_truncation_keeps_utf8_boundary() -> None:
    with _Capture("colorproxy.protocol.strategy"):
        label = _fit(_name_of_len(65), "视频流")     # 剩 6 字节，DESC 最多 4 字节
    assert label.desc == "视".encode("utf-8")       # 3 字节，不是半个"频"
    label.desc.decode("utf-8")


def test_never_sends_empty_value() -> None:
    """空 desc、或截断后为空的 desc，都不发 TLV（老 RM 会把整个 ANN 丢掉）。"""
    assert [u.Type for u in sid_label_units(_fit(_name_of_len(30), ""))] == [STRATEGY_SID_NAME]
    with _Capture("colorproxy.protocol.strategy"):
        no_room = _fit(_name_of_len(69), "http")   # 名称占 71，只剩 2，放不下任何 value
        one_byte = _fit(_name_of_len(68), "视")     # 剩 1 字节，放不下 3 字节的字符
    for label in (no_room, one_byte):
        assert label.desc == b""
        assert all(len(bytes(u.Value)) > 0 for u in sid_label_units(label))


# ---------------------------------------------------------------- 发布流程

def _v1_state() -> ProviderState:
    services = [
        ServiceConfig(url="http://172.10.0.2:8000/hello.html", origin_host="172.10.0.2",
                      origin_port=8000, desc="http"),
        ServiceConfig(url="http://172.10.0.2:8000/items.html?page=2", origin_host="172.10.0.2",
                      origin_port=8000),
    ]
    return ProviderState(Config(nid=0xA1A1, ipv4="172.10.0.2", rm_ipv4="172.10.0.5",
                                services=services))


def test_three_actions_carry_identical_tlvs() -> None:
    """同一条 SID 的 AM=1/2/3 带完全相同的 TLV（方案 §6）。"""
    state = _v1_state()
    sender = _CollectSender()
    publish.publish_services(state, sender)
    publish.refresh_services(state, sender)
    publish.withdraw_services(state, sender)
    assert len(sender.sent) == 6

    by_lsid: dict[bytes, list[tuple[int, list]]] = {}
    for raw in sender.sent:
        unit = _unit(raw)
        by_lsid.setdefault(bytes(unit.LSID), []).append((unit.AM, _tlvs(raw)))
    assert len(by_lsid) == 2
    for history in by_lsid.values():
        assert [am for am, _ in history] == [1, 2, 3]
        assert history[0][1] == history[1][1] == history[2][1]
        assert history[0][1][0] == (STRATEGY_SID_NAME, history[0][1][0][1])

    tlvs = {bytes(_unit(raw).LSID): _tlvs(raw) for raw in sender.sent[:2]}
    assert tlvs[lsid_from_url("http://172.10.0.2:8000/hello.html")] == [
        (STRATEGY_SID_NAME, b"http://172.10.0.2:8000/hello.html"), (STRATEGY_SID_DESC, b"http"),
    ]
    # 没配 desc 的只带名称；名称不含 query
    assert tlvs[lsid_from_url("http://172.10.0.2:8000/items.html")] == [
        (STRATEGY_SID_NAME, b"http://172.10.0.2:8000/items.html"),
    ]


def test_republish_does_not_refit() -> None:
    """已通告过的 SID 再次 publish 时不重新裁剪，超预算的 warn 不会重复打。"""
    long_url = "http://172.10.0.2:8000/" + "p" * 80
    state = ProviderState(Config(nid=0xA1A1, ipv4="172.10.0.2", rm_ipv4="172.10.0.5", services=[
        ServiceConfig(url=long_url, origin_host="172.10.0.2", origin_port=8000, desc="http"),
    ]))
    sender = _CollectSender()
    with _Capture("colorproxy.protocol.strategy") as cap:
        publish.publish_services(state, sender)
        publish.publish_services(state, sender)
    assert len(sender.sent) == 1 and len(cap.records) == 1
    assert _tlvs(sender.sent[0]) == [(STRATEGY_SID_DESC, b"http")]


def test_prototype_provider_announces_names_and_descs() -> None:
    """原型提供端的全部 34 条 SID：名称可校验、DESC 正确、都在预算内。"""
    state = ProviderState(load_config(PROTOTYPE_PROVIDER))
    sender = _CollectSender()
    with _Capture("colorproxy.protocol.strategy") as cap:
        publish.publish_services(state, sender)
    assert not cap.records, [r.getMessage() for r in cap.records]
    assert len(sender.sent) == 4 + 4 + 26  # v1 + L3 服务级 + L3 内容级

    service_desc = {
        "tcp://10.10.9.2:8000": b"http", "tcp://10.10.9.2:21": b"ftp",
        "tcp://10.10.9.2:3306": b"mysql", "udp://10.10.9.2:5004": b"rtp",
    }
    seen_services = set()
    for raw in sender.sent:
        unit = _unit(raw)
        tlvs = dict(_tlvs(raw))
        name = tlvs[STRATEGY_SID_NAME]
        assert hashlib.sha1(name).digest() == bytes(unit.LSID), name
        assert unit.Unit_Length == UNIT_FIXED_LEN + sum(2 + len(v) for v in tlvs.values())
        assert unit.Unit_Length <= UNIT_FIXED_LEN + ANN_STRATEGY_BUDGET
        text = name.decode()
        if text in service_desc:
            assert tlvs[STRATEGY_SID_DESC] == service_desc[text]
            seen_services.add(text)
        elif text.startswith("http://10.10.9.2:8000/"):
            assert tlvs[STRATEGY_SID_DESC] == b"http", "URL SID 沿用端点的 desc"
        else:
            assert text.startswith("http://10.10.0.2:8000/"), text  # v1，配置里没写 desc
            assert STRATEGY_SID_DESC not in tlvs
    assert seen_services == set(service_desc)


def test_long_desc_warns_at_config_load() -> None:
    config = {
        "nid": "a1" * 16, "ipv4": "10.10.0.2", "rm_ipv4": "10.10.0.5",
        "services": [{"url": "http://10.10.0.2:8000/x", "desc": "REST/SSE 演示源站（很长的备注）"}],
    }
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "config.json")
        with open(path, "w", encoding="utf-8") as fp:
            json.dump(config, fp, ensure_ascii=False)
        with _Capture("colorproxy.config") as cap:
            loaded = load_config(path)
    assert loaded.services[0].desc == "REST/SSE 演示源站（很长的备注）", "只提醒，不改值"
    assert len(cap.records) == 1 and "services[0].desc" in cap.records[0].getMessage()


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
