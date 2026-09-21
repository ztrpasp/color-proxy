"""M4 用例二的视频流：**请求驱动**的 RTP over UDP 收发一对（服务端在 P、客户端在 C）。

用法::

    # 提供端机器 P（服务地址那一侧）
    python tools/rtp_video.py --role server                    # 0.0.0.0:5004，500 pps × 1200 B ≈ 4.8 Mbps

    # 消费端机器 C
    python tools/rtp_video.py --role client --server 172.10.9.2 --seconds 300

**为什么不是直接用 VLC/ffmpeg 推流**：CoLoR 是"先拉后推"，隧道只能由消费端的第一个
上行包触发（`l3/consumer.py` 读到 tun 包 → 算 SID → 发 GET → 建隧道）。提供端**无法
主动**向消费端开一条流。所以这里把 RTP 发送端做成请求驱动：客户端先发一个订阅报文，
服务端才开始朝它发流——发出去的包源端口正是 5004，回程按内层**源**三元组反推 SID
（§7.2），与上行严格对称。

真播放器要测的话有两条路，都写在 docs/M4-acceptance.md §3 里：本脚本（判据精确，
能给出丢包率/最长中断）；或者 RTSP over TCP（`-rtsp_transport tcp`，真解码画面，
全程一条 TCP 隧道）。**不能用裸 RTP 推流**，那是服务端主动发起，建不了隧道。

判据由客户端自己打印：连续接收秒数、pps、码率、丢包率、最长中断、乱序/重复。
"""
from __future__ import annotations

import argparse
import logging
import socket
import struct
import sys
import threading
import time

# 控制台编码兜底（中文 Windows 控制台默认 GBK，输出重定向到管道时尤其容易撞上）
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(errors="replace")
    except (AttributeError, OSError):
        pass

logger = logging.getLogger("rtp")

#: 内层 UDP 净载荷上限：1280(tun MTU) − 20(IP) − 8(UDP)。超了内核会分片，
#: 而分片按 D15 一律丢弃、不重组（症状：小包通、大 UDP 静默丢 + frag_drop）
UDP_PAYLOAD_LIMIT = 1252
#: RTP 固定头 12 字节，含在 --payload 里
RTP_HEADER_LEN = 12
#: 订阅/保活报文。服务端见到它就（重新）把流指向发送方
KICK = b"COLOR-RTP-KICK"
DEFAULT_PORT = 5004
DEFAULT_PPS = 500
DEFAULT_PAYLOAD = 1200


# ----------------------------------------------------------------- 服务端（P）

# Windows 的 UDP 坑：对端不在时，之前发出去的包引来的 ICMP 端口不可达会让**下一次
# recvfrom 抛 ConnectionResetError**，不处理就整个进程退出（Unix 上没有这回事）。
# 正规解法是 WSAIoctl(SIO_UDP_CONNRESET, false)，但 Python 的 socket.ioctl 只认
# SIO_RCVALL 等几个码，走不通；所以两个收包循环各自 catch 一下就够了。


class _Sender(threading.Thread):
    """朝一个订阅者按固定 pps 发 RTP 包，直到被换目标或停掉。"""

    def __init__(self, sock: socket.socket, target: tuple[str, int],
                 pps: int, payload_len: int, seconds: float) -> None:
        super().__init__(name=f"rtp-send-{target[0]}:{target[1]}", daemon=True)
        self._sock = sock
        self._target = target
        self._interval = 1.0 / pps
        self._media = bytes(range(256)) * ((payload_len - RTP_HEADER_LEN) // 256 + 1)
        self._media = self._media[: payload_len - RTP_HEADER_LEN]
        self._seconds = seconds
        self._stop = threading.Event()
        self.sent = 0

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        seq = 0
        ssrc = 0x0C01C0DE  # 固定 SSRC，抓包时一眼认出是本脚本的流
        started = time.monotonic()
        next_at = started
        while not self._stop.is_set():
            if self._seconds and time.monotonic() - started >= self._seconds:
                break
            # RTP 头：V=2 P=0 X=0 CC=0 | M=0 PT=96(动态) | seq | timestamp | ssrc
            timestamp = int((time.monotonic() - started) * 90000) & 0xFFFFFFFF
            header = struct.pack("!BBHII", 0x80, 96, seq & 0xFFFF, timestamp, ssrc)
            try:
                self._sock.sendto(header + self._media, self._target)
            except OSError as exc:
                logger.warning("发送失败（%s），停止本次发流", exc)
                break
            self.sent += 1
            seq += 1
            next_at += self._interval
            delay = next_at - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            else:
                next_at = time.monotonic()  # 追不上就重新对表，不要越积越多
        logger.info("停止发流：%s:%d，共发出 %d 个包", *self._target, self.sent)


def run_server(args: argparse.Namespace) -> None:
    payload_len = args.payload
    if payload_len > UDP_PAYLOAD_LIMIT:
        raise SystemExit(
            f"--payload {payload_len} 超过内层 UDP 净载荷上限 {UDP_PAYLOAD_LIMIT}："
            "内核会分片，而分片按 D15 一律丢弃（计 frag_drop）。请 ≤ 1252，建议 1200"
        )
    if payload_len <= RTP_HEADER_LEN:
        raise SystemExit(f"--payload 至少要大于 RTP 头 {RTP_HEADER_LEN} 字节")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.host, args.port))
    bitrate = args.pps * payload_len * 8 / 1e6
    print(f"RTP 视频源已启动：udp://{args.host}:{args.port}")
    print(f"  参数：{args.pps} pps × {payload_len} B 净载荷 ≈ {bitrate:.1f} Mbps"
          f"（内层 UDP 上限 {UDP_PAYLOAD_LIMIT} B）")
    if args.host not in ("0.0.0.0", "::"):
        print("  [!] 没有绑 0.0.0.0：经 L3 访问收不到订阅包")
    print("  等待消费端订阅（客户端会先发一个 KICK 报文）。Ctrl+C 退出", flush=True)

    sender: _Sender | None = None
    current: tuple[str, int] | None = None
    try:
        while True:
            try:
                data, addr = sock.recvfrom(2048)
            except ConnectionResetError:
                # 订阅者退出后，之前发出去的包会引来 ICMP 端口不可达，Windows 把它
                # 变成下一次 recvfrom 的异常。与本服务无关，继续等下一个订阅者。
                continue
            if not data.startswith(KICK):
                continue
            if addr == current and sender is not None and sender.is_alive():
                continue  # 同一个订阅者的保活，不打断当前流
            if sender is not None:
                sender.stop()
            current = addr
            sender = _Sender(sock, addr, args.pps, payload_len, args.seconds)
            sender.start()
            print(f"  收到订阅：{addr[0]}:{addr[1]} —— 开始发流"
                  f"（源端口固定 {args.port}，回程按源三元组反推 SID）", flush=True)
    except KeyboardInterrupt:
        print("\nRTP 视频源退出")
    finally:
        if sender is not None:
            sender.stop()
        sock.close()


# ----------------------------------------------------------------- 客户端（C）

class _Stats:
    """按 RTP 序号统计丢包/乱序/重复，以及最长中断。

    序号是 16 位、会回绕，所以按"与上一个序号的有符号距离"判断：正的一大截 = 中间
    丢了，负的 = 乱序或重复。判据要的是"5 分钟连续无中断"，因此最长包间隔单列。
    """

    def __init__(self) -> None:
        self.received = 0
        self.bytes = 0
        self.lost = 0
        self.reordered = 0
        self.max_gap_ms = 0.0
        self.first_at: float | None = None
        self.last_at: float | None = None
        self._last_seq: int | None = None

    def add(self, seq: int, size: int, now: float) -> None:
        self.received += 1
        self.bytes += size
        if self.first_at is None:
            self.first_at = now
        else:
            gap_ms = (now - (self.last_at or now)) * 1000
            self.max_gap_ms = max(self.max_gap_ms, gap_ms)
        self.last_at = now
        if self._last_seq is not None:
            delta = (seq - self._last_seq) & 0xFFFF
            if delta == 0 or delta > 0x8000:
                self.reordered += 1
            elif delta > 1:
                self.lost += delta - 1
        self._last_seq = seq

    @property
    def elapsed(self) -> float:
        if self.first_at is None or self.last_at is None:
            return 0.0
        return self.last_at - self.first_at

    def line(self) -> str:
        expected = self.received + self.lost
        loss = (self.lost / expected * 100) if expected else 0.0
        pps = self.received / self.elapsed if self.elapsed else 0.0
        mbps = self.bytes * 8 / self.elapsed / 1e6 if self.elapsed else 0.0
        return (f"已收 {self.received} 包 / {self.bytes / 1e6:.1f} MB，"
                f"{pps:.0f} pps，{mbps:.2f} Mbps，丢 {self.lost}（{loss:.2f}%），"
                f"乱序/重复 {self.reordered}，最长中断 {self.max_gap_ms:.0f} ms")


def run_client(args: argparse.Namespace) -> None:
    if not args.server:
        raise SystemExit("客户端必须用 --server 指定服务地址（如 --server 172.10.9.2）")
    target = (args.server, args.port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", args.local_port))
    sock.settimeout(1.0)
    local_port = sock.getsockname()[1]
    print(f"订阅 udp://{args.server}:{args.port}（本地端口 {local_port}），"
          f"计划接收 {args.seconds} 秒")
    print("  第一个 KICK 会触发建隧道：消费端发 GET、等隧道 DATA，期间首包在队列里等"
          "（§5.2），所以前一两秒没有数据是正常的")

    out = open(args.out, "wb") if args.out else None
    stats = _Stats()
    deadline = time.monotonic() + args.seconds if args.seconds else float("inf")
    next_kick = 0.0
    next_report = time.monotonic() + args.report_sec
    refused_reported = False
    try:
        while time.monotonic() < deadline:
            now = time.monotonic()
            # 收到第一个包之前每秒催一次；之后按 --keepalive-sec 保活（默认 10 s）
            if now >= next_kick:
                sock.sendto(KICK, target)
                next_kick = now + (args.keepalive_sec if stats.received else 1.0)
            try:
                data, _ = sock.recvfrom(4096)
            except ConnectionResetError:
                # 本机直连时：服务端没在听，ICMP 端口不可达被 Windows 抛成异常。
                # 经隧道时看不到这条（ICMP 不进隧道，D11），表现为纯超时。
                if not refused_reported:
                    refused_reported = True
                    print(f"  收到 ICMP 端口不可达：{args.server}:{args.port} 上没人听。"
                          "先确认提供端已经 --role server 起来了")
                continue
            except socket.timeout:
                if not stats.received and now - (next_report - args.report_sec) > 10:
                    print("  10 秒还没收到数据：看消费端计数器 sid_miss/firstpkt_dropped，"
                          "以及提供端 tun_tx 是否在涨")
                continue
            if data.startswith(KICK):
                continue  # 自己发的保活被回环回来（不应发生，保险起见）
            if len(data) < RTP_HEADER_LEN:
                continue
            seq = struct.unpack("!H", data[2:4])[0]
            stats.add(seq, len(data), time.monotonic())
            if out is not None:
                out.write(data[RTP_HEADER_LEN:])
            if time.monotonic() >= next_report:
                next_report = time.monotonic() + args.report_sec
                print("  " + stats.line())
    except KeyboardInterrupt:
        print()
    finally:
        sock.close()
        if out is not None:
            out.close()

    print("\n==== 结果 ====")
    if not stats.received:
        print("一个包都没收到。按 docs/M4-acceptance.md §6 分流：消费端 tun_rx / sid_miss，"
              "提供端 colr_rx / tun_tx")
        raise SystemExit(1)
    print(stats.line())
    print(f"连续接收 {stats.elapsed:.0f} 秒")
    expected = stats.received + stats.lost
    loss = stats.lost / expected * 100 if expected else 0.0
    verdict = []
    verdict.append(("接收时长 ≥ 计划的 95%", stats.elapsed >= args.seconds * 0.95 if args.seconds else True))
    verdict.append(("丢包率 < 1%", loss < 1.0))
    verdict.append(("最长中断 < 1000 ms", stats.max_gap_ms < 1000))
    for label, ok in verdict:
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    print("另外去两端看：frag_drop 必须为 0，tunnel_up 全程为 1（D1：隧道不刷新、不回收）")
    raise SystemExit(0 if all(ok for _, ok in verdict) else 1)


def main() -> None:
    parser = argparse.ArgumentParser(description="M4 用例二：请求驱动的 RTP 视频流收发")
    parser.add_argument("--role", choices=("server", "client"), required=True,
                        help="server 跑在提供端 P，client 跑在消费端 C")
    parser.add_argument("--host", default="0.0.0.0", help="服务端监听地址（默认 0.0.0.0）")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"服务端口（默认 {DEFAULT_PORT}，要与 l3.services[] 一致）")
    parser.add_argument("--server", default="", help="客户端用：服务地址，如 172.10.9.2")
    parser.add_argument("--local-port", type=int, default=0,
                        help="客户端本地端口（默认随机；固定下来便于抓包）")
    parser.add_argument("--pps", type=int, default=DEFAULT_PPS,
                        help=f"服务端发包速率（默认 {DEFAULT_PPS}/s）")
    parser.add_argument("--payload", type=int, default=DEFAULT_PAYLOAD,
                        help=f"UDP 净载荷字节数，含 12 B RTP 头（默认 {DEFAULT_PAYLOAD}，"
                             f"上限 {UDP_PAYLOAD_LIMIT}）")
    parser.add_argument("--seconds", type=float, default=300,
                        help="客户端接收时长 / 服务端单次发流时长（默认 300=5 分钟，0=不限）")
    parser.add_argument("--report-sec", type=float, default=5.0, help="统计行打印间隔")
    parser.add_argument("--keepalive-sec", type=float, default=10.0,
                        help="收到流之后的保活间隔（默认 10 s）")
    parser.add_argument("--out", default="", help="客户端把收到的媒体净载荷写进这个文件")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")

    if args.role == "server":
        run_server(args)
    else:
        run_client(args)


if __name__ == "__main__":
    main()
