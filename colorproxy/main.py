"""服务端入口。

用法::

    python -m colorproxy.main [config.json]

需以管理员权限运行（原始套接字 + Npcap）。
"""
from __future__ import annotations

import argparse
import logging
import time

from .config import load_config
from .provider import Provider

DEFAULT_CONFIG_PATH = "config.json"


def main() -> None:
    parser = argparse.ArgumentParser(description="共生网络 Web 代理服务端（提供端）")
    parser.add_argument("config", nargs="?", default=DEFAULT_CONFIG_PATH,
                        help="配置文件路径（默认 config.json）")
    parser.add_argument("-v", "--verbose", action="store_true", help="输出调试日志")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    config = load_config(args.config)
    print(config.nid, config.ipv4, config.rm_ipv4, config.services)
    provider = Provider(config)
    provider.start()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        logging.getLogger(__name__).info("收到中断，正在退出")
    finally:
        provider.stop()


if __name__ == "__main__":
    main()
