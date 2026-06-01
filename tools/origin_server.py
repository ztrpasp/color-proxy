"""测试用源站 HTTP 服务器（端到端联调的真实后端 origin）。

提供端 ``config.json`` 里 ``services[].origin_host/origin_port`` 指向本服务；
提供端收到 HTTP 请求后会向它发起形如 ``GET /hello.html`` 的回源请求。本服务对
每个请求打印日志，方便联调时确认"提供端的回源是否打到了后端"。

注意：用 HTTP/1.0（默认），响应后即关闭连接 → 提供端"读到 EOF"能拿到完整响应。

用法::

    python tools/origin_server.py                 # 监听 127.0.0.1:8000
    python tools/origin_server.py --port 8000 --host 0.0.0.0
"""
from __future__ import annotations

import argparse
import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_HELLO_HTML = (
    "<!doctype html><html><head><meta charset='utf-8'><title>color-proxy origin</title></head>"
    "<body><h1>color-proxy origin OK</h1>"
    "<p>这条页面经共生网络（CoLoR）跨域取回，说明 提供端→回源→响应 链路打通。</p>"
    "</body></html>"
).encode("utf-8")


class _OriginHandler(BaseHTTPRequestHandler):
    server_version = "color-proxy-origin/1.0"

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/", "/hello.html"):
            self._respond(200, _HELLO_HTML, "text/html; charset=utf-8")
        elif self.path == "/ping":
            self._respond(200, b"pong\n", "text/plain; charset=utf-8")
        else:
            self._respond(404, f"404 Not Found: {self.path}\n".encode("utf-8"),
                          "text/plain; charset=utf-8")

    def do_HEAD(self) -> None:  # noqa: N802
        self._respond(200, _HELLO_HTML, "text/html; charset=utf-8", write_body=False)

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
    print(f"源站已启动：http://{args.host}:{args.port}  （路径 /hello.html、/、/ping）")
    print("按 Ctrl+C 退出")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n源站退出")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
