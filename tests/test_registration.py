"""控制面测试：注册线程、ANN 去重与新代理通知（docs/design-l3-v2.md §9.3 第 3、4 条）。

2026-09-21 真机修正后的语义：**注册报文与 AM=1 的 ANN 各只发一次**，重复发会被
RM 拒（unable to insert into sid_table）；开启 REGISTER_REFRESH_SEC 时走 AM=2。

可用 ``python -m pytest tests/test_registration.py`` 运行，
也可直接 ``python tests/test_registration.py`` 运行（无需 pytest）。
"""
from __future__ import annotations

import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from colorproxy import publish, registration
from colorproxy.config import Config, ServiceConfig
from colorproxy.protocol import control
from colorproxy.protocol.packets import ColorAnnounce
from colorproxy.state import ProviderState
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


# ------------------------------------------------- 注册次数（2026-09-21 真机修正）

def test_keeper_registers_once_and_stops_by_default() -> None:
    """默认 refresh_sec=0：注册成功后线程结束，不再发第二个注册报文。

    上一轮的常驻线程每 30 s 重注册并重发一遍 AM=1 的 ANN，真机 RM 每轮都报
    unable to insert into sid_table。
    """
    state = _StateStub()
    sender = _SenderStub(state)
    published: list[int] = []
    keeper = registration.RegistrationKeeper(
        state, sender, on_registered=lambda: published.append(1)
    )
    keeper.start()
    try:
        assert keeper.wait_first(timeout=2.0), "首次注册应当成功"
        keeper.join(timeout=2.0)
        assert not keeper.is_alive(), "默认配置下注册成功即应结束线程"
        assert sender.count() == 1, f"只应发一个注册报文，实发 {sender.count()} 个"
        assert published == [1], "发布回调只应被调一次"
    finally:
        keeper.stop()

    # 发出的确实是注册报文（Subtype=5），且发往 RM
    dst, payload = sender.sent[0]
    assert dst == state.rm_ipv4
    assert payload[0] == CONTROL_FIRST_BYTE and payload[5] == ControlSubtype.PROXY_REGISTER


def test_keeper_refresh_round_uses_update_callback() -> None:
    """显式开启刷新时才重注册，且走 on_refresh（AM=2），on_registered 仍只调一次。"""
    state = _StateStub()
    sender = _SenderStub(state)
    first: list[int] = []
    refreshed: list[int] = []
    keeper = registration.RegistrationKeeper(
        state, sender,
        on_registered=lambda: first.append(1),
        on_refresh=lambda: refreshed.append(1),
        refresh_sec=0.05,
    )
    keeper.start()
    try:
        assert keeper.wait_first(timeout=2.0), "首次注册应当成功"
        time.sleep(0.3)
        assert sender.count() > 1, "开启刷新时应当周期性重注册"
        assert len(refreshed) >= 1, "重注册轮应调 on_refresh（AM=2 更新）"
        assert first == [1], "首次注册回调不得被重复调用（那正是重复 AM=1 的来源）"
    finally:
        keeper.stop()
        keeper.join(timeout=2.0)


def test_keeper_sends_max_retries_before_wait_first_gives_up() -> None:
    """RM 不回应时 wait_first 返回 False，但要等发满 3 个注册报文（对齐 v1 的 3 次重传）。"""
    state = _StateStub()
    sender = _SenderStub(state=None)  # 不模拟回应
    keeper = registration.RegistrationKeeper(state, sender, retry_sec=0.05)
    keeper.start()
    try:
        assert keeper.wait_first(timeout=2.0) is False
        assert keeper.attempts >= registration.REGISTER_MAX_RETRIES
        attempts = sender.count()
        time.sleep(0.3)
        assert sender.count() > attempts, "未注册成功应持续重试，不能放弃"
    finally:
        keeper.stop()
        keeper.join(timeout=2.0)


def test_failure_message_names_the_addresses_to_check() -> None:
    """注册失败的报错必须带上两个地址：真机上消费端就是 rm_ipv4 写错了一位。"""
    state = _StateStub()
    keeper = registration.RegistrationKeeper(state, _SenderStub(state=None))
    keeper.attempts = 3
    message = registration.failure_message("消费端", state, keeper)
    assert state.rm_ipv4 in message, "要指出发给了哪个 RM 地址"
    assert state.ipv4 in message, "要指出本机绑的是哪个地址"
    assert "3" in message, "要说明发了几个注册报文"


def test_register_reply_survives_ethernet_padding() -> None:
    """尾部填充不得让注册回复被判成校验和错误。

    一个代理、零个 BR 的 tag=6 只有 30 字节，整帧不足 60 字节时网卡会补零，
    scapy 把补的零一并算进 payload。按自述长度截齐后校验和才对得上。
    """
    reply = _build_control(ControlSubtype.PROXY_REGISTER_REPLY, _proxy_table_body())
    assert control.is_register_reply(reply + bytes(10))
    state = _StateStub()
    registration.handle_control(state, reply + bytes(10))
    assert state.registered.is_set()
    # 真被截断（自述长度大于实收字节）时仍应拒收，不能连这个也放过去
    assert not control.is_register_reply(reply[:-3])


# ---------------------------------------------------------------- ANN 去重与注销

def _provider_state() -> ProviderState:
    services = [
        ServiceConfig(url="http://172.10.0.2:8000/hello.html",
                      origin_host="172.10.0.2", origin_port=8000),
        ServiceConfig(url="http://172.10.0.2:8000/items.html",
                      origin_host="172.10.0.2", origin_port=8000),
    ]
    return ProviderState(Config(nid=0xA1A1, ipv4="172.10.0.2", rm_ipv4="172.10.0.5",
                                services=services))


def _ann_actions(sender: _SenderStub) -> list[int]:
    """把发出的每个 ANN 解析回来，取其通告单元的动作类型 AM。"""
    actions = []
    for _, payload in sender.sent:
        unit = ColorAnnounce(payload).Announce_Unit_List[0]
        actions.append(unit.AM)
    return actions


def test_publish_services_announces_each_sid_once() -> None:
    """publish_services 可重复调用，但同一条 SID 只发一次 AM=1。"""
    state = _provider_state()
    sender = _SenderStub(state=None)
    publish.publish_services(state, sender)
    assert sender.count() == 2, "两条服务应各发一个 ANN"
    publish.publish_services(state, sender)
    assert sender.count() == 2, "重复调用不得再发 AM=1（RM 会拒绝重复插入）"
    assert _ann_actions(sender) == [publish.ANNOUNCE_ACTION_REGISTER] * 2
    assert len(state.announced_services()) == 2
    # 本地服务表仍然登记齐全（去重只管发包，不影响查表）
    assert state.get_service(next(iter(sid for sid, _ in state.announced_services())))


def test_refresh_and_withdraw_use_their_own_actions() -> None:
    """刷新用 AM=2、注销用 AM=3；注销后能干净地重新注册（下次启动的路径）。"""
    state = _provider_state()
    sender = _SenderStub(state=None)
    publish.publish_services(state, sender)

    assert publish.refresh_services(state, sender) == 2
    assert _ann_actions(sender)[2:] == [publish.ANNOUNCE_ACTION_UPDATE] * 2

    assert publish.withdraw_services(state, sender) == 2
    assert _ann_actions(sender)[4:] == [publish.ANNOUNCE_ACTION_WITHDRAW] * 2
    assert state.announced_services() == [], "注销后应清空已通告表"

    publish.publish_services(state, sender)
    assert _ann_actions(sender)[6:] == [publish.ANNOUNCE_ACTION_REGISTER] * 2


def test_provider_stop_withdraws_published_services() -> None:
    """提供端正常退出时把已发布的 SID 注销掉（否则下次启动必然撞 RM 的重复插入）。

    只替换发送器：``Provider`` 构造时不碰网络（收包套接字要到 start() 才开），
    所以这条能在离线环境里覆盖真实的装配与退出路径。
    """
    from colorproxy.provider import Provider

    state_holder = _provider_state()
    provider = Provider(state_holder.config)
    sender = _SenderStub(state=None)
    provider.sender = sender
    publish.publish_services(provider.state, sender)
    provider.state.registered.set()
    published = sender.count()
    assert published == 2

    provider.stop()
    assert _ann_actions(sender)[published:] == [publish.ANNOUNCE_ACTION_WITHDRAW] * 2
    assert provider.state.announced_services() == []


def test_provider_stop_skips_withdraw_when_never_registered() -> None:
    """没注册成功过就别对 RM 说话：启动失败的退出路径上不应再发任何 ANN。"""
    from colorproxy.provider import Provider

    provider = Provider(_provider_state().config)
    sender = _SenderStub(state=None)
    provider.sender = sender
    provider.stop()
    assert sender.count() == 0


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
