"""测试用源站 HTTP 服务器（端到端联调的真实后端 origin）。

提供端 ``config.json`` 里 ``services[].origin_host/origin_port`` 指向本服务；
提供端收到 HTTP 请求后会向它发起形如 ``GET /hello.html`` 的回源请求。本服务对
每个请求打印日志，方便联调时确认"提供端的回源是否打到了后端"。

注意：用 HTTP/1.0（默认），响应后即关闭连接 → 提供端"读到 EOF"能拿到完整响应。

提供的样例端点：

- ``GET  /`` / ``GET /hello.html``  小页面（单包即可传完，最简冒烟）
- ``GET  /showcase.html``           较大的自包含页面（跨多个 DATA 分片，验证分片重组）
- ``GET  /items.html``              ``/api/items`` 的交互控制台（内联 CSS/JS，自包含；表单增删改查）
- ``GET  /ping``                    ``pong``
- ``GET  /slow``                    分段涓流大响应（段间延时，验证流式 cut-through 的 TTFB）
- ``/api/items`` 内存 CRUD（条目 id 走 query ``?id=N``，故四种方法共用同一 SID）::

      GET    /api/items          列出全部
      GET    /api/items?id=N     取单条 / 404
      POST   /api/items          读 JSON body 创建，返回 {id, ...}（201）
      PUT    /api/items?id=N     覆盖更新 / 404
      DELETE /api/items?id=N     删除 / 404

  之所以把 id 放在 query 而非路径 ``/api/items/N``：SID 由 ``L_sid = SHA1(去 query 后 URL)``
  派生且是整路径精确匹配，路径式每个 id 都会是不同 SID；放 query 则增删改查共用
  ``/api/items`` 这一条 SID，同时端到端验证了"query 不入 SID、但原样透传到源站"。

用法::

    python tools/origin_server.py                 # 监听 127.0.0.1:8000
    python tools/origin_server.py --port 8000 --host 0.0.0.0
"""
from __future__ import annotations

import argparse
import datetime
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

_HELLO_HTML = (
    "<!doctype html><html><head><meta charset='utf-8'><title>color-proxy origin</title></head>"
    "<body><h1>color-proxy origin OK</h1>"
    "<p>这条页面经共生网络（CoLoR）跨域取回，说明 提供端→回源→响应 链路打通。</p>"
    "</body></html>"
).encode("utf-8")

_STATIC_DIR = Path(__file__).resolve().parent / "static"


def _load_static(name: str) -> bytes:
    """读取 tools/static/ 下的静态文件；缺失时返回占位页（不致联调直接报错）。"""
    try:
        return (_STATIC_DIR / name).read_bytes()
    except OSError:
        return (f"<!doctype html><meta charset='utf-8'>"
                f"<p>缺少静态文件 static/{name}</p>").encode("utf-8")


#: 启动即缓存（测试会直接 import _OriginHandler，不走 main，故在模块层加载）
_SHOWCASE_HTML = _load_static("showcase.html")
_ITEMS_HTML = _load_static("items.html")
#: 路径 -> 静态页字节。items.html 是 /api/items 的交互控制台（内联 CSS/JS，自包含）
_STATIC_PAGES = {
    "/showcase.html": _SHOWCASE_HTML,
    "/items.html": _ITEMS_HTML,
}

# -- /api/items 的内存存储（ThreadingHTTPServer 下需加锁） -----------------------
_store_lock = threading.Lock()
_items: dict[int, dict] = {}
_next_id = 1


#: /slow 涓流端点的默认参数（可经 query 覆盖）：段数、每段字节、段间延时（秒）
_SLOW_SEGMENTS = 20
_SLOW_SEG_SIZE = 4096
_SLOW_DELAY = 0.05


def slow_body(segments: int, seg_size: int) -> bytes:
    """``/slow`` 的确定性响应体：第 i 段是 ``seg_size`` 个字母（A,B,C… 循环）。

    供源站与测试共同引用，用于逐字节校验流式重组结果。
    """
    return b"".join(bytes([65 + (i % 26)]) * seg_size for i in range(segments))


def _create_item(fields: dict) -> dict:
    global _next_id
    with _store_lock:
        item_id = _next_id
        _next_id += 1
        item = {"id": item_id, **{k: v for k, v in fields.items() if k != "id"}}
        _items[item_id] = item
        return dict(item)


class _OriginHandler(BaseHTTPRequestHandler):
    server_version = "color-proxy-origin/1.0"

    # -- GET ---------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        path, query = self._split()
        if path == "/api/items":
            self._items_get(query)
        elif path in _STATIC_PAGES:
            self._respond(200, _STATIC_PAGES[path], "text/html; charset=utf-8")
        elif path in ("/", "/hello.html"):
            self._respond(200, _HELLO_HTML, "text/html; charset=utf-8")
        elif path == "/ping":
            self._respond(200, b"pong\n", "text/plain; charset=utf-8")
        elif path == "/slow":
            self._slow(query)
        else:
            self._not_found(path)

    # -- /slow 慢速涓流（验证流式 cut-through 的 TTFB 收益） ----------------
    def _slow(self, query: str) -> None:
        """分多段、段间延时地写 body，模拟"源站产字节慢"。

        query 可覆盖 ``segs`` / ``size`` / ``delay``。总量跨多个 DATA 分片。
        用 HTTP/1.0（默认）读到 EOF；每段 flush 以确保逐段真正上线。
        """
        params = parse_qs(query)
        segments = int(params.get("segs", [str(_SLOW_SEGMENTS)])[0])
        seg_size = int(params.get("size", [str(_SLOW_SEG_SIZE)])[0])
        delay = float(params.get("delay", [str(_SLOW_DELAY)])[0])
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

    def do_HEAD(self) -> None:  # noqa: N802
        self._respond(200, _HELLO_HTML, "text/html; charset=utf-8", write_body=False)

    # -- POST / PUT / DELETE（仅 /api/items） ------------------------------
    def do_POST(self) -> None:  # noqa: N802
        path, _ = self._split()
        if path != "/api/items":
            return self._not_found(path)
        body = self._read_json()
        if body is None:
            return
        if not isinstance(body, dict):
            return self._respond_json(400, {"error": "body must be a JSON object"})
        self._respond_json(201, _create_item(body))

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

    # -- /api/items 的 GET 分支 -------------------------------------------
    def _items_get(self, query: str) -> None:
        item_id = self._query_id(query)
        with _store_lock:
            if item_id is None:
                return self._respond_json(200, {"items": list(_items.values())})
            item = _items.get(item_id)
        if item is None:
            return self._respond_json(404, {"error": "not found", "id": item_id})
        self._respond_json(200, dict(item))

    # -- 工具 --------------------------------------------------------------
    def _split(self) -> tuple[str, str]:
        """拆出 (path, query)。query 不参与 SID，但源站这里要真正读它（验证透传）。"""
        parts = urlsplit(self.path)
        return parts.path, parts.query

    @staticmethod
    def _query_id(query: str) -> int | None:
        """从 query 解析 ``id``（透传验证点）；缺失/非整数返回 None。"""
        raw = parse_qs(query).get("id", [None])[0]
        if raw is None:
            return None
        try:
            return int(raw)
        except ValueError:
            return None

    def _read_json(self):
        """按 Content-Length 读 body 并解析 JSON；解析失败回 400 并返回 None。"""
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._respond_json(400, {"error": "invalid JSON body"})
            return None

    def _respond_json(self, code: int, obj) -> None:
        self._respond(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                      "application/json; charset=utf-8")

    def _not_found(self, path: str) -> None:
        self._respond(404, f"404 Not Found: {path}\n".encode("utf-8"),
                      "text/plain; charset=utf-8")

    def _respond(self, code: int, body: bytes, content_type: str, write_body: bool = True) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if write_body:
            self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:  # 带时间戳的简洁日志
        stamp = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"[{stamp}] {self.client_address[0]} {fmt % args}")


def main() -> None:
    parser = argparse.ArgumentParser(description="color-proxy 测试用源站 HTTP 服务器")
    parser.add_argument("--host", default="127.0.0.1", help="监听地址（默认 127.0.0.1）")
    parser.add_argument("--port", type=int, default=8000, help="监听端口（默认 8000）")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), _OriginHandler)
    print(f"源站已启动：http://{args.host}:{args.port}")
    if args.host in ("127.0.0.1", "localhost", "::1"):
        # 只听回环时，L3（服务级）那条路一定哑火：内层包的目的是 color0 的地址
        # 172.10.9.2，协议栈收下后找不到监听者，客户端看到的是超时或拒绝连接。
        # v1（内容级）不受影响——回源是本机发起的普通 TCP，把 origin_host 写成
        # 127.0.0.1 就能连上，这也是两条路径表现不一致的原因。
        print("  [!] 仅监听回环：经 L3 服务级访问（如 tcp://172.10.9.2:8000）收不到包，"
              "要测 L3 请加 --host 0.0.0.0")
    print("  页面： /hello.html  /showcase.html  /items.html（CRUD 交互控制台）")
    print("  接口： /ping  /api/items（GET/POST/PUT/DELETE，id 走 ?id=N）")
    print("按 Ctrl+C 退出")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n源站退出")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
