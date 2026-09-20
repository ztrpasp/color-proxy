"""控制面测试：常驻注册线程与新代理通知（docs/design-l3-v2.md §9.3 第 3、4 条）。

可用 ``python -m pytest tests/test_registration.py`` 运行，
也可直接 ``python tests/test_registration.py`` 运行（无需 pytest）。
"""
from __future__ import annotations

import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from colorproxy import registration
from colorproxy.protocol import control
from colorproxy.protocol.constants import CONTROL_FIRST_BYTE, ControlSubtype
from colorproxy.protocol.utils import (
    calculate_checksum,
    int_to_bytes_be,
    int_to_bytes_le,
    ipv4_to_le_bytes,
)

PROXY_NID = 0x1234
PROXY_IP = "10.0.1.7"
BR_PX = 0x55
BR_IP = "10.0.0.9"


def _build_control(subtype: int, body: bytes) -> bytes:
    """按 8 字节固定头拼一个 CONTROL 报文并回填校验和。"""
    head = (
        bytes([CONTROL_FIRST_BYTE, 64]) + b"\x00\x00"
        + bytes([control.CONTROL_HEADER_LENGTH, subtype])
        + int_to_bytes_le(len(body), 2) + body
    )
    checksum = calculate_checksum(head)
    return head[:2] + int_to_bytes_be(checksum, 2) + head[4:]


def _proxy_table_body(extra: bytes = b"") -> bytes:
    """一个代理 + 一个 BR 的表布局（与 tag=6 相同）；``extra`` 用于制造多余字节。"""
    return (
        bytes([1]) + int_to_bytes_be(PROXY_NID, 16) + ipv4_to_le_bytes(PROXY_IP)
        + bytes([1]) + int_to_bytes_le(BR_PX, 2) + ipv4_to_le_bytes(BR_IP)
        + extra
    )


class _StateStub:
    """满足 registration 所需最小接口的 State（对照 _RegistrableState）。"""

    def __init__(self) -> None:
        self.nid = 0xABCD
        self.ipv4 = "10.0.1.6"
        self.rm_ipv4 = "10.0.0.1"
        self.registered = threading.Event()
        self.domain_calls: list[tuple[list, list]] = []

    def set_domain_info(self, proxies: list, brs: list) -> None:
        self.domain_calls.append((proxies, brs))


class _SenderStub:
    """记录发出的报文；``auto_reply`` 时模拟 RM 立刻回应（置 registered）。"""

    def __init__(self, state: _StateStub | None = None) -> None:
        self.sent: list[tuple[str, bytes]] = []
        self._state = state
        self._lock = threading.Lock()

    def send(self, dst_ip: str, payload: bytes) -> None:
        with self._lock:
            self.sent.append((dst_ip, bytes(payload)))
        if self._state is not None:
            self._state.registered.set()

    def count(self) -> int:
        with self._lock:
            return len(self.sent)


# ---------------------------------------------------------------- §9.3 第 4 条：tag=8

def test_is_proxy_notify_discriminates_subtype_and_checksum() -> None:
    notify = _build_control(ControlSubtype.PROXY_NOTIFY, _proxy_table_body())
    assert control.is_proxy_notify(notify)
    # tag=6 不应被当成 tag=8，反之亦然
    assert not control.is_register_reply(notify)
    reply = _build_control(ControlSubtype.PROXY_REGISTER_REPLY, _proxy_table_body())
    assert not control.is_proxy_notify(reply)
    # 校验和被破坏后拒收
    assert not control.is_proxy_notify(notify[:-1] + bytes([notify[-1] ^ 0xFF]))


def test_parse_proxy_table_strict_accepts_wellformed_layout() -> None:
    notify = _build_control(ControlSubtype.PROXY_NOTIFY, _proxy_table_body())
    proxies, brs = control.parse_proxy_table_strict(notify)
    assert proxies == [(PROXY_NID, PROXY_IP)]
    assert brs == [(BR_PX, BR_IP)]


def test_parse_proxy_table_strict_rejects_unconsumed_bytes() -> None:
    """布局不匹配必须抛错，绝不能把乱码当 NID→IP 写进表（回址会错得很难查）。"""
    notify = _build_control(ControlSubtype.PROXY_NOTIFY, _proxy_table_body(b"\xff\xff"))
    try:
        control.parse_proxy_table_strict(notify)
    except ValueError:
        return
    raise AssertionError("多余字节未被拒绝")


def test_handle_control_learns_from_proxy_notify() -> None:
    state = _StateStub()
    registration.handle_control(
        state, _build_control(ControlSubtype.PROXY_NOTIFY, _proxy_table_body())
    )
    assert state.domain_calls == [([(PROXY_NID, PROXY_IP)], [(BR_PX, BR_IP)])]
    # tag=8 不是注册应答，不应把 registered 置上
    assert not state.registered.is_set()


def test_handle_control_ignores_unparsable_proxy_notify() -> None:
    """布局与 tag=6 不符时只记日志、不改表（载荷布局未经证实，宁可学不到）。"""
    state = _StateStub()
    registration.handle_control(
        state, _build_control(ControlSubtype.PROXY_NOTIFY, _proxy_table_body(b"\xff\xff"))
    )
    assert state.domain_calls == []


def test_handle_control_still_handles_register_reply() -> None:
    state = _StateStub()
    registration.handle_control(
        state, _build_control(ControlSubtype.PROXY_REGISTER_REPLY, _proxy_table_body())
    )
    assert state.domain_calls == [([(PROXY_NID, PROXY_IP)], [(BR_PX, BR_IP)])]
    assert state.registered.is_set()


# ---------------------------------------------------------------- §9.3 第 3 条：常驻注册

def test_keeper_registers_once_then_refreshes_periodically() -> None:
    """常驻线程：首次注册成功后仍周期性重注册并重发布（RM 重启可自动恢复）。"""
    state = _StateStub()
    sender = _SenderStub(state)
    republish_count = [0]
    keeper = registration.RegistrationKeeper(
        state, sender, on_registered=lambda: republish_count.__setitem__(0, republish_count[0] + 1),
        refresh_sec=0.05,
    )
    keeper.start()
    try:
        assert keeper.wait_first(timeout=2.0), "首次注册应当成功"
        assert republish_count[0] >= 1, "首次注册后应重发布一次"
        first_round = sender.count()
        time.sleep(0.3)
        assert sender.count() > first_round, "应当周期性重注册（v1 只注册一次）"
        assert republish_count[0] > 1, "每轮重注册后应重发 ANN"
    finally:
        keeper.stop()
        keeper.join(timeout=2.0)

    # 发出的确实是注册报文（Subtype=5），且发往 RM
    dst, payload = sender.sent[0]
    assert dst == state.rm_ipv4
    assert payload[0] == CONTROL_FIRST_BYTE and payload[5] == ControlSubtype.PROXY_REGISTER


def test_keeper_wait_first_times_out_when_rm_silent() -> None:
    """RM 不回应时 wait_first 返回 False（调用方据此拒绝启动），线程仍在后台重试。"""
    state = _StateStub()
    sender = _SenderStub(state=None)  # 不模拟回应
    keeper = registration.RegistrationKeeper(
        state, sender, refresh_sec=0.05, retry_sec=0.05
    )
    keeper.start()
    try:
        assert keeper.wait_first(timeout=0.5) is False
        attempts = sender.count()
        assert attempts >= 1
        time.sleep(0.3)
        assert sender.count() > attempts, "未注册成功应持续重试，不能放弃"
    finally:
        keeper.stop()
        keeper.join(timeout=2.0)


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
