"""从提供端 / 消费端配置生成 RM 的 ACL 命令清单（Markdown）。

RM 不能从文件加载 ACL，规则只能在它的命令行里逐条 ``acl add``。本脚本把提供端发布的每条
服务级 SID 和 D20 的每条 URL SID 都算出来，按消费端分组，写成可以直接粘贴的命令。SID 是
从配置现算的，NID、地址或 paths 改了就重跑一次，不要手改生成的文件。

用法::

    python tools/gen_acl_rules.py deploy/prototype/config-svr1-1-provider.json \\
        deploy/prototype/config-svr1-3-consumer.json=2 \\
        deploy/prototype/config-svr2-3-consumer.json=4 \\
        -o deploy/prototype/acl-rules.md

``=N`` 是该消费端所在的 AS 号，也就是 RM 从 GET 的 PID 回溯出的源 AS，写进规则的 ``asid``。
规则 id 默认按 AS 号分段：AS N 的服务级规则从 ``N01`` 起，URL 规则从 ``N11`` 起。同一个 AS
里有两个消费端时，用 ``=N:基数`` 给第二个指定别的段，例如 ``=2:500``。
"""
from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from colorproxy.config import Config, load_config  # noqa: E402
from colorproxy.consumer.config import load_consumer_config  # noqa: E402
from colorproxy.protocol.sid import sid_hex_from_service, sid_hex_from_url  # noqa: E402

#: 服务级规则在段内的起点与上限（段长 100：01–09 给服务，11–99 给 URL）
SERVICE_OFFSET, URL_OFFSET, BLOCK = 1, 11, 100


@dataclass(frozen=True)
class Consumer:
    path: Path
    nid: str
    ipv4: str
    tun_ip: str
    asid: int
    base: int
    label: str


def parse_consumer(arg: str, provider: Config) -> Consumer:
    path_text, sep, spec = arg.rpartition("=")
    if not sep:
        raise SystemExit(f"消费端参数要写成 <配置路径>=<AS 号>：{arg}")
    asid_text, _, base_text = spec.partition(":")
    asid = int(asid_text, 0)
    base = int(base_text, 0) if base_text else asid * BLOCK
    path = Path(path_text)
    config = load_consumer_config(path)
    nid = f"{config.nid:032x}"

    peer = next((p for p in provider.l3.peers if p.nid == config.nid), None)
    if peer is None:
        raise SystemExit(f"{path}：NID {nid} 不在提供端的 l3.peers[] 里，提供端会丢掉它的每个包")
    if peer.tun_ip != config.l3.tun_ip:
        raise SystemExit(
            f"{path}：l3.tun_ip={config.l3.tun_ip}，提供端 peers[] 登记的是 {peer.tun_ip}，两边必须一致"
        )
    label = peer.desc.split("（", 1)[0].strip() or path.stem
    return Consumer(path, nid, config.ipv4, config.l3.tun_ip, asid, base, label)


def rule(rule_id: int, sid: str, consumer: Consumer) -> str:
    return f"acl add id {rule_id} action deny sid {sid} asid 0x{consumer.asid:08x} nid {consumer.nid}"


def render(provider_path: Path, provider: Config, consumers: list[Consumer]) -> str:
    nid = provider.nid
    services = provider.l3.services
    urls = [url for service in services for url in service.content_urls]
    if len(services) > URL_OFFSET - SERVICE_OFFSET:
        raise SystemExit(f"服务级条目 {len(services)} 条，超出每段 {URL_OFFSET - SERVICE_OFFSET} 条的位置")
    if len(urls) > BLOCK - URL_OFFSET:
        raise SystemExit(f"URL {len(urls)} 条，超出每段 {BLOCK - URL_OFFSET} 条的位置")
    bases = [c.base for c in consumers]
    if len(set(bases)) != len(bases):
        raise SystemExit("有两个消费端落在同一个 id 段（同一个 AS？），用 =N:基数 给其中一个换段")

    sources = " ".join(f"`{p.as_posix()}`" for p in [provider_path, *(c.path for c in consumers)])
    out = [
        "# ACL 规则",
        "",
        f"> 由 `tools/gen_acl_rules.py` 从 {sources} 生成。配置改了就重跑，不要手改本文件。",
        "",
        f"- **在哪执行**：提供端所在域的 RM（`{provider.rm_ipv4}`）的命令行，一条一行粘进去。"
        "RM 必须是带 ACL 的版本（`the-rm-server`）。",
        f"- 提供端 NID `{nid:032x}`；服务地址 "
        + "、".join(sorted({f"`{s.ip}`" for s in services})) + "（L3 虚服务地址，D18）。",
        "- `asid` 是消费端所在的 AS 号。RM 从 GET 携带的 PID 倒推出源 AS，再与规则比对，"
        "所以 RM 的拓扑图（`global_as_config`）必须包含 GET 路径上的每条链路；"
        "回溯失败时 RM 会直接拒绝（`GET denied by ACL: unable to identify source AS`），与有没有规则无关。",
        "- 这里只生成 `deny`。RM 按 id 从小到大找第一条命中的规则，都没命中就放行；"
        "id 不能重复（重复会报 `maybe duplicated id`）。",
        "- 想对该 AS 里的任意消费端生效，把 `nid` 写成 `00000000000000000000000000000000`（全 0 是通配）。",
        "- 加完用 `display acl` 核对，删除用 `acl delete id <id>`；拒绝时 RM 打印 `GET denied by ACL rule <id>`。",
        "- 服务级 SID 只拦**新连接**：消费端每条新 TCP 连接、每个新 UDP 流先发一次 GET（D19），"
        "已经建好的连接不受影响。",
        "- URL SID 是逐请求的（D20）：拦了某个 URL，只有那个请求被 RST，同站其它页面照常；URL 的 query 不参与 SID。",
        "",
        "| 消费端 | NID | 物理地址 | tun 地址 | asid | 规则 id |",
        "|---|---|---|---|---|---|",
    ]
    for c in consumers:
        last = c.base + URL_OFFSET + len(urls) - 1
        out.append(
            f"| {c.label} | `{c.nid}` | `{c.ipv4}` | `{c.tun_ip}` | `0x{c.asid:08x}` "
            f"| {c.base + SERVICE_OFFSET}–{last} |"
        )

    for c in consumers:
        service_ids = [c.base + SERVICE_OFFSET + i for i in range(len(services))]
        url_ids = [c.base + URL_OFFSET + i for i in range(len(urls))]
        out += ["", f"## {c.label}", "",
                f"NID `{c.nid}`，asid `0x{c.asid:08x}`（AS{c.asid}）。", "",
                f"### 服务级（id {service_ids[0]}–{service_ids[-1]}）", "",
                "| id | 服务 | 说明 |", "|---|---|---|"]
        for rule_id, service in zip(service_ids, services):
            out.append(f"| {rule_id} | `{service.canonical}` | {service.desc.split('（', 1)[0]} |")
        out += ["", "```"]
        out += [rule(rule_id, sid_hex_from_service(nid, s.proto, s.ip, s.port), c)
                for rule_id, s in zip(service_ids, services)]
        out += ["```"]
        if urls:
            out += ["", f"### 内容级：{len(urls)} 个 URL（id {url_ids[0]}–{url_ids[-1]}）", "",
                    "| id | URL |", "|---|---|"]
            out += [f"| {rule_id} | `{url}` |" for rule_id, url in zip(url_ids, urls)]
            out += ["", "```"]
            out += [rule(rule_id, sid_hex_from_url(nid, url), c) for rule_id, url in zip(url_ids, urls)]
            out += ["```"]
        out += ["", "### 删除本节全部规则", "", "```"]
        out += [f"acl delete id {rule_id}" for rule_id in service_ids + url_ids]
        out += ["```"]
    return "\n".join(out) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="从配置生成 RM 的 ACL 命令清单（Markdown）")
    parser.add_argument("provider", help="提供端配置（config.json 格式）")
    parser.add_argument("consumers", nargs="+", metavar="CONSUMER=AS[:BASE]",
                        help="消费端配置路径=所在 AS 号，可选 :规则 id 基数")
    parser.add_argument("-o", "--output", help="输出文件（缺省打印到标准输出）")
    args = parser.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    provider_path = Path(args.provider)
    provider = load_config(provider_path)
    if not provider.l3.services:
        raise SystemExit(f"{provider_path} 没有 l3.services[]，没有可写规则的 SID")
    consumers = [parse_consumer(arg, provider) for arg in args.consumers]
    text = render(provider_path, provider, consumers)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8", newline="\n")
        print(f"已写入 {args.output}")
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
