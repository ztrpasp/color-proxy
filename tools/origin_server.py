"""演示源站：REST / SSE 页面与接口（L3 隧道下由消费端直连访问）。

提供端 ``config.json`` 的 ``l3.services[]`` 把本服务以 ``tcp://172.10.9.2:8000`` 发布，并按
``paths`` 为每个路由另发一条内容级 SID（D20）。消费端浏览器**不设代理**，直接打开
``http://172.10.9.2:8000/showcase.html``；TCP 端到端穿过隧道，所以 SSE 流式与完整回答都按
原样工作，浏览器关闭连接时 FIN 直接到达这里，不需要 v1 的 ``STREAM_CANCEL``。

**本文件的每个路由都必须列在** ``PUBLISHED_PATHS`` **里，并同步写进** ``config.json``
**8000 条目的** ``paths``：消费端遇到没发布的 path 会立即 RST（D20）。
``tests/test_restful_origin.py`` 会核对两者一致。

页面：
- ``/``、``/hello.html``  最简冒烟页
- ``/showcase.html``      总览与导航
- ``/items.html``         ``/api/items`` 的 CRUD 控制台
- ``/monitor.html``       流量监控 REST
- ``/realtimemonitor.html``  流量监控 SSE，可主动停止
- ``/model.html``         医院 / 学校 RAG 大模型服务（MySQL 检索 + DeepSeek；完整 / SSE）

接口：
- ``/api/items``  内存 CRUD（id 走 query ``?id=N``，四种方法共用一条 SID）
- ``/api/monitor/location-a|location-b/recent|snapshot|stream``（A/B 用不同 path → 不同 SID，
  可分别设 ACL）；``/api/monitor/recent|snapshot|stream?location=`` 是别名
- ``/api/models``、``/api/model/questions``、``/api/model/{medical,education}``（POST 完整回答）、
  ``/api/model/{medical,education}/stream``（GET，SSE）
- ``/ping``、``/slow``（分段涓流，验证流式）

**请求者身份**（模型服务的 P2/P3 策略用）：不看任何请求头。L3 下提供端不改写 HTTP，浏览器
自带的 ``X-CoLoR-Requester-NID`` 可以随便写；这里按 TCP 对端地址（消费端 tun 地址）查
``config.json`` 的 ``l3.peers[]`` 得到 NID。提供端已按 D14 校验过内层源地址，所以这个地址可信。
查不到（如本机直连）按 default 策略处理。

用法::

    python tools/origin_server.py --host 0.0.0.0 --port 8000              # L3 必须听 0.0.0.0
    python tools/origin_server.py --host 0.0.0.0 --config config.json     # 指定身份映射来源
"""
from __future__ import annotations

import argparse
import contextlib
import datetime
import ipaddress
import json
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

_TOOLS_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _TOOLS_DIR.parent
# 直接 ``python tools/origin_server.py`` 时 sys.path[0] 是 tools/；读 config.json 要用 colorproxy
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

try:  # python tools/origin_server.py
    from demo_data import (
        MODEL_API_KEY,
        MODELS,
        MONITOR_API_KEY,
        model_questions,
        monitor_point,
        monitor_recent,
    )
    from rag_service import RAGPolicyBlocked, RAGServiceError, get_rag_service
except ImportError:  # 测试从仓库根 import tools.origin_server
    from tools.demo_data import (  # type: ignore
        MODEL_API_KEY,
        MODELS,
        MONITOR_API_KEY,
        model_questions,
        monitor_point,
        monitor_recent,
    )
    from tools.rag_service import RAGPolicyBlocked, RAGServiceError, get_rag_service  # type: ignore

_HELLO_HTML = (
    "<!doctype html><html><head><meta charset='utf-8'><title>color-proxy origin</title></head>"
    "<body><h1>color-proxy origin OK</h1>"
    "<p>这条页面经共生网络（CoLoR）跨域取回，说明 消费端→隧道→源站→响应 链路打通。</p>"
    "</body></html>"
).encode("utf-8")

_STATIC_DIR = _TOOLS_DIR / "static"


def _load_static(name: str) -> bytes:
    """读取 tools/static/ 下的静态文件；缺失时返回占位页（不致联调直接报错）。"""
    try:
        return (_STATIC_DIR / name).read_bytes()
    except OSError:
        return (f"<!doctype html><meta charset='utf-8'>"
                f"<p>缺少静态文件 static/{name}</p>").encode("utf-8")


#: 启动即缓存（测试会直接 import _OriginHandler，不走 main，故在模块层加载）
_SHOWCASE_HTML = _load_static("showcase.html")
_STATIC_PAGES = {
    "/showcase.html": _SHOWCASE_HTML,
    "/items.html": _load_static("items.html"),
    "/monitor.html": _load_static("monitor.html"),
    "/realtimemonitor.html": _load_static("realtimemonitor.html"),
    "/model.html": _load_static("model.html"),
}

_MONITOR_ACTIONS = ("recent", "snapshot", "stream")
_MONITOR_PREFIXES = (("A", "/api/monitor/location-a/"), ("B", "/api/monitor/location-b/"))

#: 对外发布的全部路由（D20：config.json 8000 条目的 ``paths`` 必须与它逐条一致）
PUBLISHED_PATHS: tuple[str, ...] = (
    "/", "/hello.html", "/favicon.ico",
    *_STATIC_PAGES,
    "/ping", "/slow",
    "/api/items",
    *(f"/api/monitor/{action}" for action in _MONITOR_ACTIONS),
    *(prefix + action for _loc, prefix in _MONITOR_PREFIXES for action in _MONITOR_ACTIONS),
    "/api/models", "/api/model/questions",
    *(path for model in MODELS for path in (f"/api/model/{model}", f"/api/model/{model}/stream")),
)

# -- /api/items 的内存存储（ThreadingHTTPServer 下需加锁） -----------------------
_store_lock = threading.Lock()
_items: dict[int, dict] = {}
_next_id = 1


def _create_item(fields: dict) -> dict:
    global _next_id
    with _store_lock:
        item_id = _next_id
        _next_id += 1
        item = {"id": item_id, **{k: v for k, v in fields.items() if k != "id"}}
        _items[item_id] = item
        return dict(item)


#: /slow 涓流端点的默认参数（可经 query 覆盖）：段数、每段字节、段间延时（秒）
_SLOW_SEGMENTS = 20
_SLOW_SEG_SIZE = 4096
_SLOW_DELAY = 0.05


def slow_body(segments: int, seg_size: int) -> bytes:
    """``/slow`` 的确定性响应体：第 i 段是 ``seg_size`` 个字母（A,B,C… 循环）。

    供源站与测试共同引用，用于逐字节校验流式重组结果。
    """
    return b"".join(bytes([65 + (i % 26)]) * seg_size for i in range(segments))


def load_peer_nids(config_path: str | os.PathLike | None) -> dict[str, str]:
    """从提供端配置的 ``l3.peers[]`` 建 ``{tun_ip: nid(32 位十六进制)}``。

    文件不存在返回空表（所有请求按 default 策略）；文件存在但非法则抛错，不静默降级。
    """
    if config_path is None or not Path(config_path).is_file():
        return {}
    from colorproxy.config import load_config  # 只解析 JSON，不依赖 scapy

    config = load_config(str(config_path))
    return {str(ipaddress.IPv4Address(peer.tun_ip)): f"{peer.nid:032x}"
            for peer in config.l3.peers}


def _stamp() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S")


class _OriginHandler(BaseHTTPRequestHandler):
    server_version = "color-proxy-origin/2.0"
    protocol_version = "HTTP/1.1"
    #: SSE 每个事件、模型每个 token 都是小写入；关掉 Nagle，免得在隧道往返上被攒批
    disable_nagle_algorithm = True

    # -- GET ---------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        path, query = self._split()
        if path == "/api/items":
            return self._items_get(query)
        if path in _STATIC_PAGES:
            return self._respond(200, _STATIC_PAGES[path], "text/html; charset=utf-8")
        if path in ("/", "/hello.html"):
            return self._respond(200, _HELLO_HTML, "text/html; charset=utf-8")
        if path == "/favicon.ico":
            # 浏览器会自动请求它；已发布，回 204 免得每次打开页面都多一条 RST / 404
            return self._respond(204, b"", "image/x-icon")
        if path == "/ping":
            return self._respond(200, b"pong\n", "text/plain; charset=utf-8")
        if path == "/slow":
            return self._slow(query)

        # 监控 REST + SSE。A/B 用不同 path，故是不同 SID，RM 可分别设 ACL
        monitor_route = self._monitor_route(path, query)
        if monitor_route is not None:
            action, location = monitor_route
            if not self._require_api_key(MONITOR_API_KEY, query):
                return
            if action == "recent":
                try:
                    limit = int(parse_qs(query).get("limit", ["16"])[0])
                except ValueError:
                    limit = 16
                return self._respond_json(200, {
                    "service": "network-flow-monitor",
                    "location": location,
                    "items": monitor_recent(location, limit),
                })
            if action == "snapshot":
                return self._respond_json(200, {
                    "service": "network-flow-monitor",
                    "item": monitor_point(location),
                })
            return self._monitor_stream(location)

        # 模型目录 / 建议问题
        if path == "/api/models":
            if not self._require_api_key(MODEL_API_KEY, query):
                return
            return self._respond_json(200, {
                "models": [spec.__dict__ for spec in MODELS.values()]
            })
        if path == "/api/model/questions":
            if not self._require_api_key(MODEL_API_KEY, query):
                return
            model = parse_qs(query).get("model", ["medical"])[0]
            if model not in MODELS:
                return self._respond_json(404, {"error": "unknown model"})
            return self._respond_json(200, {"model": model, "items": model_questions(model)})

        model, streaming = self._model_route(path)
        if model and streaming:
            if not self._require_api_key(MODEL_API_KEY, query):
                return
            question = parse_qs(query).get("q", [""])[0]
            return self._model_stream(model, question)

        self._not_found(path)

    def do_HEAD(self) -> None:  # noqa: N802
        self._respond(200, _HELLO_HTML, "text/html; charset=utf-8", write_body=False)

    # -- POST --------------------------------------------------------------
    def do_POST(self) -> None:  # noqa: N802
        path, query = self._split()
        if path == "/api/items":
            body = self._read_json()
            if body is None:
                return
            if not isinstance(body, dict):
                return self._respond_json(400, {"error": "body must be a JSON object"})
            return self._respond_json(201, _create_item(body))

        model, streaming = self._model_route(path)
        if model and not streaming:
            if not self._require_api_key(MODEL_API_KEY, query):
                return
            body = self._read_json()
            if body is None:
                return
            question = str(body.get("question", "")) if isinstance(body, dict) else ""
            try:
                result = get_rag_service().complete(
                    model, question, requester_nid=self._requester_nid()
                )
            except RAGPolicyBlocked as exc:
                return self._respond_json(403, exc.payload)
            except RAGServiceError as exc:
                return self._respond_json(503, {
                    "error": "rag_backend_unavailable",
                    "message": str(exc),
                })
            return self._respond_json(200, result)

        self._not_found(path)

    # -- PUT / DELETE（仅 /api/items） --------------------------------------
    def do_PUT(self) -> None:  # noqa: N802
        path, query = self._split()
        if path != "/api/items":
            return self._not_found(path)
        item_id = self._query_id(query)
        if item_id is None:
            return self._respond_json(400, {"error": "missing or invalid ?id="})
        body = self._read_json()
        if body is None:
            return
        if not isinstance(body, dict):
            return self._respond_json(400, {"error": "body must be a JSON object"})
        with _store_lock:
            if item_id not in _items:
                return self._respond_json(404, {"error": "not found", "id": item_id})
            item = {"id": item_id, **{k: v for k, v in body.items() if k != "id"}}
            _items[item_id] = item
        self._respond_json(200, dict(item))

    def do_DELETE(self) -> None:  # noqa: N802
        path, query = self._split()
        if path != "/api/items":
            return self._not_found(path)
        item_id = self._query_id(query)
        if item_id is None:
            return self._respond_json(400, {"error": "missing or invalid ?id="})
        with _store_lock:
            if _items.pop(item_id, None) is None:
                return self._respond_json(404, {"error": "not found", "id": item_id})
        self._respond_json(200, {"deleted": item_id})

    # -- 监控 ----------------------------------------------------------------
    @staticmethod
    def _monitor_route(path: str, query: str) -> tuple[str, str] | None:
        if path.startswith("/api/monitor/") and path.count("/") == 3:
            action = path.rsplit("/", 1)[1]
            if action in _MONITOR_ACTIONS:
                location = parse_qs(query).get("location", ["A"])[0].upper()
                return action, "B" if location == "B" else "A"
        for loc, prefix in _MONITOR_PREFIXES:
            if path.startswith(prefix) and path[len(prefix):] in _MONITOR_ACTIONS:
                return path[len(prefix):], loc
        return None

    def _sse_headers(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Accel-Buffering", "no")
        # 无 Content-Length 的长响应：读到连接关闭为止
        self.send_header("Connection", "close")
        self.close_connection = True
        self.end_headers()
        self.wfile.flush()

    def _monitor_stream(self, location: str) -> None:
        self._sse_headers()
        seq = 0
        try:
            while True:
                seq += 1
                payload = json.dumps({"seq": seq, **monitor_point(location)},
                                     ensure_ascii=False, separators=(",", ":"))
                self.wfile.write(f"id: {seq}\nevent: monitor\ndata: {payload}\n\n".encode("utf-8"))
                self.wfile.flush()
                time.sleep(1.0)
        except OSError:  # BrokenPipe / ConnectionReset / ConnectionAborted 都是它的子类
            self._log_disconnect(f"监控 SSE location-{location.lower()}，已发 {seq} 个事件")

    # -- 模型 ----------------------------------------------------------------
    @staticmethod
    def _model_route(path: str) -> tuple[str | None, bool]:
        for model in MODELS:
            if path == f"/api/model/{model}":
                return model, False
            if path == f"/api/model/{model}/stream":
                return model, True
        return None, False

    def _model_stream(self, model: str, question: str) -> None:
        self._sse_headers()

        def emit(event: str, obj: dict) -> None:
            payload = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
            self.wfile.write(f"event: {event}\ndata: {payload}\n\n".encode("utf-8"))
            self.wfile.flush()

        events = 0
        try:
            # closing：浏览器一断开就关掉生成器，连带关掉到 DeepSeek 的上游连接
            with contextlib.closing(get_rag_service().stream(
                model, question, requester_nid=self._requester_nid()
            )) as stream:
                for event, payload in stream:
                    emit(event, payload)
                    events += 1
        except RAGServiceError as exc:
            try:
                emit("error", {"error": "rag_backend_unavailable", "message": str(exc)})
                emit("done", {"finish_reason": "error"})
            except OSError:
                pass
        except OSError:
            self._log_disconnect(f"模型 SSE {model}，已发 {events} 个事件，已停止生成")

    # -- /api/items ----------------------------------------------------------
    def _items_get(self, query: str) -> None:
        item_id = self._query_id(query)
        with _store_lock:
            if item_id is None:
                return self._respond_json(200, {"items": list(_items.values())})
            item = _items.get(item_id)
        if item is None:
            return self._respond_json(404, {"error": "not found", "id": item_id})
        self._respond_json(200, dict(item))

    # -- /slow 慢速涓流（验证流式：分段到达而非整段返回） ----------------------
    def _slow(self, query: str) -> None:
        params = parse_qs(query)
        try:
            segments = int(params.get("segs", [str(_SLOW_SEGMENTS)])[0])
            seg_size = int(params.get("size", [str(_SLOW_SEG_SIZE)])[0])
            delay = float(params.get("delay", [str(_SLOW_DELAY)])[0])
        except ValueError:
            return self._respond_json(400, {"error": "segs/size/delay must be numbers"})
        body = slow_body(segments, seg_size)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        for i in range(segments):
            self.wfile.write(body[i * seg_size:(i + 1) * seg_size])
            self.wfile.flush()
            if i < segments - 1:
                time.sleep(delay)

    # -- 工具 --------------------------------------------------------------
    def _requester_nid(self) -> str | None:
        """按 TCP 对端地址查 ``l3.peers[]`` 得到的消费端 NID；查不到为 None（default 策略）。

        刻意不读任何请求头：L3 下没人替我们删掉浏览器伪造的 ``X-CoLoR-Requester-NID``。
        """
        peers = getattr(self.server, "peer_nids", None) or {}
        return peers.get(self.client_address[0])

    def _split(self) -> tuple[str, str]:
        """拆出 (path, query)。query 不参与 SID，但源站要真正读它。"""
        parts = urlsplit(self.path)
        return parts.path, parts.query

    @staticmethod
    def _query_id(query: str) -> int | None:
        raw = parse_qs(query).get("id", [None])[0]
        if raw is None:
            return None
        try:
            return int(raw)
        except ValueError:
            return None

    def _require_api_key(self, expected: str, query: str) -> bool:
        """REST 用 ``X-API-Key`` 头；EventSource 不能自定义头，SSE 走 ``?api_key=``。"""
        supplied = self.headers.get("X-API-Key") or parse_qs(query).get("api_key", [""])[0]
        if supplied == expected:
            return True
        self._respond_json(401, {
            "error": "invalid_api_key",
            "message": "A valid demo API key is required.",
        })
        return False

    def _read_json(self):
        """按 Content-Length 读 body 并解析 JSON；解析失败回 400 并返回 None。"""
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._respond_json(400, {"error": "invalid JSON body"})
            return None

    def _respond_json(self, code: int, obj) -> None:
        body = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._respond(code, body, "application/json; charset=utf-8",
                      extra_headers={"Cache-Control": "no-store"})

    def _not_found(self, path: str) -> None:
        self._respond(404, f"404 Not Found: {path}\n".encode("utf-8"), "text/plain; charset=utf-8")

    def _respond(self, code: int, body: bytes, content_type: str, write_body: bool = True,
                 extra_headers: dict[str, str] | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        if code != 204:  # 204 不得带 Content-Length（RFC 9110 §8.6）
            self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if write_body and body:
            self.wfile.write(body)

    def _log_disconnect(self, what: str) -> None:
        print(f"[{_stamp()}] {self.client_address[0]} 客户端断开：{what}")

    def log_message(self, fmt: str, *args) -> None:  # 带时间戳的简洁日志
        print(f"[{_stamp()}] {self.client_address[0]} {fmt % args}")


class DemoOriginServer(ThreadingHTTPServer):
    """演示源站。``peer_nids`` 是 ``{tun_ip: nid}``，供模型服务判定请求者身份。"""

    daemon_threads = True
    # Windows 的 SO_REUSEADDR 允许两个进程绑同一端口、之后谁收连接未定义（HANDOVER-l3 记过
    # 「答话的是另一个 http.server」）。Windows 上改用独占绑定，端口被占就直接报错。
    allow_reuse_address = sys.platform != "win32"

    def __init__(self, address, handler=_OriginHandler, *, peer_nids: dict[str, str] | None = None):
        self.peer_nids = dict(peer_nids or {})
        super().__init__(address, handler)

    def server_bind(self) -> None:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def handle_error(self, request, client_address) -> None:
        """对端复位/中止只打一行，其余异常照常打回溯。

        L3 下这很常见：浏览器直接中止 keep-alive 连接，或消费端 D20 准入拒绝时给源站也发一个
        RST。标准库默认对每次都打一整段回溯。
        """
        exc = sys.exc_info()[1]
        if isinstance(exc, ConnectionError):
            print(f"[{_stamp()}] {client_address[0]} 连接被对端复位/中止"
                  f"（{type(exc).__name__}；客户端关闭或 D20 准入拒绝）")
            return
        super().handle_error(request, client_address)


def main() -> None:
    # 中文 Windows 控制台是 GBK；重定向到文件/管道时也要逐行落盘，否则日志攒着不出来
    sys.stdout.reconfigure(errors="replace", line_buffering=True)
    parser = argparse.ArgumentParser(description="color-proxy REST/SSE 演示源站")
    parser.add_argument("--host", default="127.0.0.1",
                        help="监听地址（默认 127.0.0.1；L3 访问必须 0.0.0.0）")
    parser.add_argument("--port", type=int, default=8000, help="监听端口（默认 8000）")
    parser.add_argument("--config", default=str(_REPO_ROOT / "config.json"),
                        help="提供端配置，从 l3.peers[] 读 tun 地址 → NID（默认仓库根 config.json）")
    args = parser.parse_args()

    peer_nids = load_peer_nids(args.config)
    try:
        server = DemoOriginServer((args.host, args.port), peer_nids=peer_nids)
    except OSError as exc:
        raise SystemExit(f"监听 {args.host}:{args.port} 失败：{exc}\n"
                         f"  端口多半已被占用，先查：netstat -ano | findstr :{args.port}")
    print(f"演示源站已启动：http://{args.host}:{args.port}")
    if args.host in ("127.0.0.1", "localhost", "::1"):
        # 只听回环时，L3（服务级）那条路一定哑火：内层包的目的是 color0 的地址
        # 172.10.9.2，协议栈收下后找不到监听者，客户端看到的是超时或拒绝连接。
        print("  [!] 仅监听回环：经 L3 访问（http://172.10.9.2:8000/...）收不到包，"
              "要测 L3 请加 --host 0.0.0.0")
    print("  页面： /showcase.html /items.html /monitor.html /realtimemonitor.html /model.html")
    print("  监控： REST recent/snapshot + SSE stream；位置 A/B 是不同 path、不同 SID")
    print("  模型： HospitalMed-RAG / CampusEdu-RAG；MySQL RAG + DeepSeek；完整 / SSE 两种返回")
    print(f"  Demo keys: monitor={MONITOR_API_KEY} model={MODEL_API_KEY}")
    if peer_nids:
        print(f"  请求者身份（{args.config} 的 l3.peers[]，按 TCP 对端地址判定，不看请求头）：")
        for tun_ip, nid in peer_nids.items():
            print(f"    {tun_ip} → {nid}")
    else:
        print(f"  [!] 没有读到 l3.peers[]（{args.config}）：所有请求按 default 策略（只有 P0）")
    print(f"  已发布路由 {len(PUBLISHED_PATHS)} 条；新增路由要同步写进 config.json 8000 条目的 paths")
    print("按 Ctrl+C 退出")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n源站退出")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
