"""一次性把配置里的全部服务向 RM 注销（ANN AM=3）。

什么时候用：RM 里留着上一轮进程的 SID，导致新一轮启动时逐条报
``unable to insert into sid_table``。正常退出（Ctrl-C）时提供端自己会注销，
这个脚本是给**没能正常退出**（进程被杀、蓝屏、改代码前的旧版本）留下的残留用的。

用法::

    python tools/rm_withdraw.py [config.json]

需管理员权限（发包走 scapy 二层）。它只发 AM=3，不注册、不监听回复——RM 收没收到
要看 RM 那边的日志。注销报文带着与发布时相同的名称/描述 TLV（docs/design-ann-sid-desc.md §6）：
RM 不看 AM，不带 TLV 的注销会被当成"策略变了"，把这条 SID 的策略整个清空。
"""
from __future__ import annotations

import argparse
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from colorproxy import publish
from colorproxy.config import load_config
from colorproxy.state import ProviderState
from colorproxy.transport.sender import ColorSender


class _NullSender:
    """只登记不发包：``publish_services`` 顺带算好每条服务的 SID 并登记进
    ``ProviderState`` 的已通告表，本脚本要的正是那张表，而不是再发一遍 ANN。"""

    def send(self, dst_ip: str, packet) -> None:  # noqa: ANN001, ARG002
        return None


def main() -> None:
    parser = argparse.ArgumentParser(description="向 RM 注销本配置发布的全部服务（AM=3）")
    parser.add_argument("config", nargs="?", default="config.json", help="提供端配置文件")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    state = ProviderState(load_config(args.config))
    publish.publish_services(state, _NullSender())  # 只算 SID、不发包
    services = state.announced_services()
    if not services:
        print("配置里没有任何服务，无事可做")
        return
    for sid, _ in services:
        print(f"  注销 SID={sid}")
    count = publish.withdraw_services(state, ColorSender())
    print(f"已向 RM({state.rm_ipv4}) 发出 {count} 条注销(AM=3)。"
          "请到 RM 侧确认 sid_table 已清空，再启动提供端")


if __name__ == "__main__":
    main()
