"""服务端单元测试（ACK 解析 / HTTP 请求还原）。

重点覆盖**跨域 ACK（非空 PID_List）**：消费端构造的 B=1 ACK 经 BR 到达服务端后，
服务端须能正确越过 PID 列定位负载、还原出完整 HTTP 请求——这是域内闭环测试
（tests/stub_consumer.py，PID 为空）未触及的路径。

可用 ``python -m pytest tests/test_provider.py`` 运行，
也可直接 ``python tests/test_provider.py`` 运行（无需 pytest）。
无需管理员权限 / Npcap。
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from colorproxy import handlers
from colorproxy.config import Config, ServiceConfig
from colorproxy.consumer.messages import build_ack
from colorproxy.messages import is_ack
from colorproxy.protocol.packets import ColorData
from colorproxy.protocol.sid import sid_hex_from_url
from colorproxy.state import PendingTx, ProviderState

PROVIDER_NID = 0xA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1
CONSUMER_NID = 0xB2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2
URL = "http://prov.local/hello.html"
SID = sid_hex_from_url(PROVIDER_NID, URL)


def _provider_state_with_service() -> ProviderState:
    svc = ServiceConfig(url=URL, origin_host="127.0.0.1", origin_port=8000)
    state = ProviderState(Config(PROVIDER_NID, "10.0.1.6", "10.0.0.1", [svc]))
    state.registered.set()
    state.add_service(SID, svc)
    return state


def _capture_handle_ack(state: ProviderState, ack_bytes: bytes) -> dict:
    """临时替换 OriginWorker，捕获 handle_ack 还原出的字段（避免真实回源 I/O）。"""
    captured: dict = {}

    class _StubWorker:
        def __init__(self, state, sender, sid, cus, tx, service, http_request):
            captured.update(sid=sid, cus=cus, tx=tx, service=service, req=http_request)

        def start(self):
            pass

    original = handlers.OriginWorker
    handlers.OriginWorker = _StubWorker
    try:
        handlers.handle_ack(state, None, ack_bytes)
    finally:
        handlers.OriginWorker = original
    return captured


def test_handle_ack_cross_domain_restores_http_request():
    state = _provider_state_with_service()
    pids = [0x00CD2222, 0x00AB1111]  # 反向路径（非空 => 跨域 ACK）
    state.put_pending(SID, CONSUMER_NID, PendingTx("10.0.0.9", pids, 7, True))

    http = (
        b"POST http://prov.local/hello.html HTTP/1.1\r\n"
        b"Host: prov.local\r\nContent-Length: 5\r\n\r\nhello"  # 含 body，验证完整还原
    )
    ack = bytes(build_ack(SID, CONSUMER_NID, pids, 7, http))

    # 收包分发判据：byte9 的 B 位，位置与 PID 数量无关
    assert is_ack(ack)
    parsed = ColorData(ack)
    assert int(parsed.PID_Num) == len(pids) and list(parsed.PID_List) == pids

    captured = _capture_handle_ack(state, ack)
    assert captured.get("sid") == SID
    assert captured.get("cus") == CONSUMER_NID
    assert captured.get("req") == http  # 越过 PID 列正确定位负载，body 完整还原
    assert state.pop_pending(SID, CONSUMER_NID) is None  # 已被 handle_ack 取走


def test_handle_ack_domain_internal_restores_http_request():
    state = _provider_state_with_service()
    state.put_pending(SID, CONSUMER_NID, PendingTx("10.0.1.5", [], 7, False))

    http = b"GET http://prov.local/hello.html HTTP/1.1\r\nHost: prov.local\r\n\r\n"
    ack = bytes(build_ack(SID, CONSUMER_NID, [], 7, http))

    captured = _capture_handle_ack(state, ack)
    assert captured.get("req") == http


def test_handle_ack_without_pending_is_ignored():
    state = _provider_state_with_service()  # 有服务但无未决事务
    http = b"GET http://prov.local/hello.html HTTP/1.1\r\n\r\n"
    ack = bytes(build_ack(SID, CONSUMER_NID, [], 7, http))

    captured = _capture_handle_ack(state, ack)
    assert captured == {}  # 无匹配 pending => 不应起回源 worker


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
