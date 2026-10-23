"""REST/SSE 演示源站在 L3 下的适配测试（tools/origin_server.py）。

覆盖迁到 L3 后才需要的几件事：
- 请求者身份只按 TCP 对端地址查 ``l3.peers[]``，浏览器伪造的 ``X-CoLoR-Requester-NID`` 无效；
- 源站的路由与 ``config.json`` 8000 条目的 ``paths`` 一一对应（D20 下没发布的 path 会被 RST）；
- SSE 是逐事件到达的流，结束时源站主动关连接，客户端断开时源站能察觉并停下。

不需要 MySQL / DeepSeek（模型服务换成假的）、scapy、tun 或管理员权限。
可用 ``python -m pytest tests/test_restful_origin.py`` 运行，
也可直接 ``python tests/test_restful_origin.py`` 运行（无需 pytest）。
"""
from __future__ import annotations

import http.client
import json
import os
import sys
import threading
import time
from contextlib import contextmanager

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import tools.origin_server as origin  # noqa: E402
from colorproxy.config import load_config  # noqa: E402
from colorproxy.consumer.config import load_consumer_config  # noqa: E402
from colorproxy.protocol.sid import content_url  # noqa: E402
from tools.demo_data import MODEL_API_KEY, MONITOR_API_KEY  # noqa: E402

B2 = "b2" * 16
D4 = "d4" * 16


class FakeRAG:
    """记录模型服务收到的 requester_nid。"""

    def __init__(self) -> None:
        self.seen: list[str | None] = []

    def complete(self, model, question, *, requester_nid=None):
        self.seen.append(requester_nid)
        return {"answer": "fake", "model": model, "requester": requester_nid}

    def stream(self, model, question, *, requester_nid=None):
        self.seen.append(requester_nid)
        yield "meta", {"model": model}
        yield "token", {"index": 0, "delta": "你"}
        yield "token", {"index": 1, "delta": "好"}
        yield "done", {"finish_reason": "stop"}


@contextmanager
def _origin(peer_nids=None):
    """起一个演示源站并把模型服务换成 FakeRAG。"""
    fake = FakeRAG()
    saved = origin.get_rag_service
    origin.get_rag_service = lambda: fake
    server = origin.DemoOriginServer(("127.0.0.1", 0), peer_nids=peer_nids)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], fake
    finally:
        server.shutdown()
        server.server_close()
        origin.get_rag_service = saved


def _request(port, method, path, *, body=None, headers=None, timeout=5.0):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    data = json.dumps(body).encode("utf-8") if body is not None else None
    hdrs = dict(headers or {})
    if data is not None:
        hdrs["Content-Type"] = "application/json"
    conn.request(method, path, body=data, headers=hdrs)
    return conn, conn.getresponse()


def _read_event(resp) -> dict:
    """读一个 SSE 事件（到空行为止），返回 {字段: 值}。"""
    fields: dict[str, str] = {}
    while True:
        line = resp.readline()
        if not line:
            raise EOFError("SSE 流提前结束")
        text = line.decode("utf-8").rstrip("\r\n")
        if not text:
            if fields:
                return fields
            continue
        key, _, value = text.partition(":")
        fields[key] = value.lstrip(" ")


# ---------------------------------------------------------------- 身份


def test_requester_comes_from_peer_address_not_header() -> None:
    """浏览器伪造 d4 的头，模型服务看到的仍是 peers[] 里这个地址绑的 b2。"""
    with _origin({"127.0.0.1": B2}) as (port, fake):
        conn, resp = _request(port, "POST", "/api/model/medical", body={"question": "hi"},
                              headers={"X-API-Key": MODEL_API_KEY, "X-CoLoR-Requester-NID": D4})
        assert resp.status == 200, resp.status
        assert json.loads(resp.read())["requester"] == B2
        conn.close()
    assert fake.seen == [B2], fake.seen


def test_unknown_peer_is_default_even_with_header() -> None:
    """对端地址不在 peers[] 里：不管带什么头都按 default（None）处理。"""
    with _origin({"10.99.1.1": B2}) as (port, fake):
        conn, resp = _request(port, "POST", "/api/model/education", body={"question": "hi"},
                              headers={"X-API-Key": MODEL_API_KEY, "X-CoLoR-Requester-NID": D4})
        assert resp.status == 200, resp.status
        resp.read()
        conn.close()
    assert fake.seen == [None], fake.seen


def test_plain_threading_server_falls_back_to_default() -> None:
    """现有测试直接用 ThreadingHTTPServer 起 _OriginHandler，没有 peer_nids 也不能出错。"""
    from http.server import ThreadingHTTPServer

    fake = FakeRAG()
    saved = origin.get_rag_service
    origin.get_rag_service = lambda: fake
    server = ThreadingHTTPServer(("127.0.0.1", 0), origin._OriginHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        conn, resp = _request(server.server_address[1], "POST", "/api/model/medical",
                              body={"question": "hi"}, headers={"X-API-Key": MODEL_API_KEY})
        assert resp.status == 200, resp.status
        resp.read()
        conn.close()
    finally:
        server.shutdown()
        server.server_close()
        origin.get_rag_service = saved
    assert fake.seen == [None], fake.seen


def test_load_peer_nids_from_shipped_config() -> None:
    consumer = load_consumer_config(os.path.join(ROOT, "config-consumer.json"))
    peers = origin.load_peer_nids(os.path.join(ROOT, "config.json"))
    assert peers.get(consumer.l3.tun_ip) == f"{consumer.nid:032x}", peers
    assert origin.load_peer_nids(os.path.join(ROOT, "no-such-config.json")) == {}


# ---------------------------------------------------------------- 发布路径


def _http_service(config):
    for svc in config.l3.services:
        if svc.app == "http" and svc.port == 8000:
            return svc
    raise AssertionError("config.json 里没有 8000 的 app=http 条目")


def test_published_paths_match_config() -> None:
    """源站路由 == config.json 8000 条目的 paths；消费端预载了每一条（无 RM 时的降级路径）。"""
    provider = load_config(os.path.join(ROOT, "config.json"))
    svc = _http_service(provider)
    assert len(set(origin.PUBLISHED_PATHS)) == len(origin.PUBLISHED_PATHS), "PUBLISHED_PATHS 有重复"
    missing = set(origin.PUBLISHED_PATHS) - set(svc.paths)
    extra = set(svc.paths) - set(origin.PUBLISHED_PATHS)
    assert not missing, f"源站有这些路由但 config.json 没发布（浏览器访问会被 RST）：{sorted(missing)}"
    assert not extra, f"config.json 发布了源站没有的路由：{sorted(extra)}"

    consumer = load_consumer_config(os.path.join(ROOT, "config-consumer.json"))
    preloaded = {entry.url for entry in consumer.sids}
    wanted = {content_url(svc.ip, svc.port, path) for path in svc.paths}
    assert wanted <= preloaded, f"config-consumer.json 的 sids[] 缺：{sorted(wanted - preloaded)}"


def test_every_published_path_is_served() -> None:
    """每条已发布的路由按它的用法请求一次，都不是 404。"""
    post_only = {f"/api/model/{m}" for m in origin.MODELS}
    with _origin() as (port, _fake):
        for path in origin.PUBLISHED_PATHS:
            key = MODEL_API_KEY if path.startswith("/api/model") else MONITOR_API_KEY
            if path in post_only:
                conn, resp = _request(port, "POST", path, body={"question": "hi"},
                                      headers={"X-API-Key": key})
            else:
                conn, resp = _request(port, "GET", path + ("?q=hi" if path.endswith("/stream") else ""),
                                      headers={"X-API-Key": key})
            assert resp.status != 404, f"{path} → 404"
            assert resp.status < 500, f"{path} → {resp.status}"
            conn.close()  # SSE 不读完，直接断开


def test_favicon_is_204_without_body() -> None:
    with _origin() as (port, _fake):
        conn, resp = _request(port, "GET", "/favicon.ico")
        assert resp.status == 204, resp.status
        assert resp.getheader("Content-Length") is None
        assert resp.read() == b""
        conn.close()


def test_api_key_required() -> None:
    with _origin() as (port, _fake):
        conn, resp = _request(port, "GET", "/api/monitor/location-a/recent")
        assert resp.status == 401, resp.status
        resp.read()
        conn.close()
        conn, resp = _request(port, "GET", "/api/monitor/location-a/recent",
                              headers={"X-API-Key": MONITOR_API_KEY})
        assert resp.status == 200, resp.status
        assert json.loads(resp.read())["location"] == "A"
        conn.close()


# ---------------------------------------------------------------- 流式


def test_monitor_sse_is_incremental_and_stops_on_disconnect() -> None:
    """事件逐个到达（约 1 s 一个、没有 Content-Length）；客户端断开后源站察觉并停下。"""
    stopped = threading.Event()
    saved = origin._OriginHandler._log_disconnect
    origin._OriginHandler._log_disconnect = lambda self, what: stopped.set()
    try:
        with _origin() as (port, _fake):
            conn, resp = _request(port, "GET",
                                  f"/api/monitor/location-b/stream?api_key={MONITOR_API_KEY}")
            assert resp.status == 200, resp.status
            assert resp.getheader("Content-Type", "").startswith("text/event-stream")
            assert resp.getheader("Content-Length") is None
            started = time.monotonic()
            first = _read_event(resp)
            first_at = time.monotonic() - started
            second = _read_event(resp)
            gap = time.monotonic() - started - first_at
            assert first["event"] == "monitor" and first["id"] == "1", first
            assert json.loads(second["data"])["seq"] == 2, second
            assert first_at < 1.0, f"首个事件 {first_at:.2f}s 才到，像是被攒批了"
            assert 0.5 < gap < 2.0, f"两个事件间隔 {gap:.2f}s，应约 1 s"
            resp.close()  # Connection: close 的响应持有底层 socket，关它才是真断开
            conn.close()
            assert stopped.wait(5.0), "客户端断开 5 s 后源站仍在写这条 SSE"
    finally:
        origin._OriginHandler._log_disconnect = saved


def test_model_sse_ends_with_connection_close() -> None:
    """模型流写完 done 后源站关连接：L3 下浏览器发的是 keep-alive，没有这一步流就不结束。"""
    with _origin({"127.0.0.1": B2}) as (port, fake):
        conn, resp = _request(port, "GET",
                              f"/api/model/medical/stream?q=hi&api_key={MODEL_API_KEY}",
                              headers={"Connection": "keep-alive", "X-CoLoR-Requester-NID": D4})
        assert resp.status == 200, resp.status
        assert resp.getheader("Connection", "").lower() == "close"
        body = resp.read().decode("utf-8")  # 不关连接的话这里会读到超时
        conn.close()
    events = [line[len("event: "):] for line in body.splitlines() if line.startswith("event: ")]
    assert events == ["meta", "token", "token", "done"], events
    assert fake.seen == [B2], fake.seen


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
