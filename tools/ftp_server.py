"""M4 用例一的 FTP 源站：**被动模式** FTP server，在提供端机器 P 上跑。

用法::

    python tools/ftp_server.py                       # 0.0.0.0:21，被动端口 50000-50010
    python tools/ftp_server.py --make-testfile 10    # 顺手造一个 10 MB 下载用测试文件
    python tools/ftp_server.py --print-services      # 只打印要粘进 config.json 的那几行

依赖 ``pyftpdlib``（``pip install pyftpdlib``）。不需要管理员权限：Windows 对
1024 以下的端口没有特权限制。

与 L3 隧道有关的三条，写死在脚本里或由它提醒（详见 docs/M4-acceptance.md §2）：

1. **必须 bind 0.0.0.0**。只听 127.0.0.1 时内层包注进协议栈没人收，症状与丢包一样。
2. **客户端必须用被动模式（PASV）**。主动模式要服务端反向发起连接，CoLoR 是拉驱动，
   提供端建不了隧道（§8.1，结构性限制，不是 bug）。
3. **被动端口段里每个端口都是另一条 SID、另一条隧道**（§3.3）。要么把端口段逐条写进
   ``config.json`` 的 ``l3.services[]``，要么发布通配 ``"port": 0``。``--print-services``
   把两种写法都打出来，直接粘。
"""
from __future__ import annotations

import argparse
import json
import os
import sys

DEFAULT_PASSIVE_PORTS = "50000-50010"
#: 服务地址：D18 虚服务地址方案下就是提供端 color0 自己的地址（config.json 的 l3.tun_ip）
DEFAULT_SERVICE_IP = "172.10.9.2"


def _parse_port_range(text: str) -> range:
    """``"50000-50010"`` → ``range(50000, 50011)``；单个端口也接受。"""
    text = text.strip()
    if "-" not in text:
        port = int(text)
        return range(port, port + 1)
    low, high = (int(part) for part in text.split("-", 1))
    if not (0 < low <= high < 65536):
        raise ValueError(f"被动端口段不合法：{text}")
    return range(low, high + 1)


def _service_entries(service_ip: str, control_port: int, passive: range) -> list[dict]:
    """按端口段逐条列出要发布的 l3.services[] 条目。"""
    entries = [{"proto": "tcp", "ip": service_ip, "port": control_port, "desc": "FTP 控制"}]
    entries += [
        {"proto": "tcp", "ip": service_ip, "port": port, "desc": f"FTP 被动数据 {port}"}
        for port in passive
    ]
    return entries


def _print_services(service_ip: str, control_port: int, passive: range) -> None:
    print("把下面这些粘进提供端 config.json 的 l3.services[]（逐条发布，推荐）：\n")
    for entry in _service_entries(service_ip, control_port, passive):
        print("  " + json.dumps(entry, ensure_ascii=False) + ",")
    print(f"\n或者只发两条、用通配覆盖整段（配置短，但目的粒度退化到主机级，见 §8.3）：\n")
    for entry in (
        {"proto": "tcp", "ip": service_ip, "port": control_port, "desc": "FTP 控制"},
        {"proto": "tcp", "ip": service_ip, "port": 0, "desc": "FTP 被动数据（通配）"},
    ):
        print("  " + json.dumps(entry, ensure_ascii=False) + ",")
    print("\n改完 config.json 要重启提供端代理，新 SID 才会发 ANN 给 RM。")


def _make_testfile(root: str, size_mb: int) -> str:
    """造一个指定大小的测试文件（内容可压缩性低，避免被任何一层悄悄压掉）。"""
    path = os.path.join(root, f"test-{size_mb}mb.bin")
    if os.path.exists(path) and os.path.getsize(path) == size_mb * 1024 * 1024:
        return path
    block = os.urandom(1024 * 1024)
    with open(path, "wb") as handle:
        for _ in range(size_mb):
            handle.write(block)
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description="M4 用例一：被动模式 FTP 源站")
    parser.add_argument("--host", default="0.0.0.0", help="监听地址（默认 0.0.0.0，别改）")
    parser.add_argument("--port", type=int, default=21, help="控制端口（默认 21）")
    parser.add_argument("--root", default="ftproot", help="FTP 根目录（默认 ./ftproot）")
    parser.add_argument("--user", default="color", help="用户名（默认 color）")
    parser.add_argument("--password", default="color", help="口令（默认 color）")
    parser.add_argument("--anonymous", action="store_true", help="额外允许匿名只读登录")
    parser.add_argument("--passive-ports", default=DEFAULT_PASSIVE_PORTS,
                        help=f"被动数据端口段（默认 {DEFAULT_PASSIVE_PORTS}）")
    parser.add_argument("--service-ip", default=DEFAULT_SERVICE_IP,
                        help=f"发布用的服务地址，只影响打印（默认 {DEFAULT_SERVICE_IP}）")
    parser.add_argument("--masquerade", default="",
                        help="PASV 回复里强制通告的 IP。默认不设：pyftpdlib 用控制连接"
                             "的本地地址，经隧道进来时正好是服务地址。只有客户端报"
                             "「PASV 给的地址连不上」时才需要设成 --service-ip 的值")
    parser.add_argument("--make-testfile", type=int, metavar="MB", default=0,
                        help="在根目录造一个 MB 大小的测试文件（下载用例用）")
    parser.add_argument("--print-services", action="store_true",
                        help="只打印要发布的 l3.services[] 条目，不起服务")
    args = parser.parse_args()

    passive = _parse_port_range(args.passive_ports)
    if args.print_services:
        _print_services(args.service_ip, args.port, passive)
        return

    try:
        from pyftpdlib.authorizers import DummyAuthorizer
        from pyftpdlib.handlers import FTPHandler
        from pyftpdlib.servers import FTPServer
    except ImportError:
        print("缺少 pyftpdlib，请先装：pip install pyftpdlib", file=sys.stderr)
        raise SystemExit(2)

    root = os.path.abspath(args.root)
    os.makedirs(root, exist_ok=True)
    if args.make_testfile:
        path = _make_testfile(root, args.make_testfile)
        print(f"测试文件已就绪：{path}（{os.path.getsize(path) / 1024 / 1024:.0f} MB）")

    authorizer = DummyAuthorizer()
    # elradfmwMT = 读 + 写 + 删 + 改名 + 建目录 + 改时间，上传下载两个方向都要
    authorizer.add_user(args.user, args.password, root, perm="elradfmwMT")
    if args.anonymous:
        authorizer.add_anonymous(root, perm="elr")

    handler = FTPHandler
    handler.authorizer = authorizer
    handler.passive_ports = list(passive)
    if args.masquerade:
        handler.masquerade_address = args.masquerade
    handler.banner = "color-proxy M4 FTP 源站（仅被动模式可用）"

    server = FTPServer((args.host, args.port), handler)
    print(f"FTP 源站已启动：ftp://{args.host}:{args.port}  根目录 {root}")
    print(f"  账号：{args.user} / {args.password}" + ("（另允许匿名只读）" if args.anonymous else ""))
    print(f"  被动端口段：{passive.start}-{passive.stop - 1}"
          f"（共 {len(passive)} 个，每个都是一条独立隧道）")
    if args.host not in ("0.0.0.0", "::"):
        print("  [!] 没有绑 0.0.0.0：经 L3 访问 "
              f"{args.service_ip}:{args.port} 会收不到包")
    print("  消费端这样连（必须被动模式）：")
    print(f"    ftp> open {args.service_ip} {args.port}   然后 passive / quote PASV")
    print(f"    或 curl --ftp-pasv -u {args.user}:{args.password} "
          f"ftp://{args.service_ip}:{args.port}/test-10mb.bin -o test-10mb.bin")
    print("  用 --print-services 打印要粘进 config.json 的发布条目。按 Ctrl+C 退出")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nFTP 源站退出")
    finally:
        server.close_all()


if __name__ == "__main__":
    main()
