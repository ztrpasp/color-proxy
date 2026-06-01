"""消费端入口。

用法::

    python -m colorproxy.consumer.main [config-consumer.json]

需以管理员权限运行（原始套接字 + Npcap）。浏览器/系统把 HTTP 代理指向
本机的 ``proxy_port``（默认 8910）即可无感知访问已发布到共生网络的 URL。
"""
from __future__ import annotations

import argparse
import logging

from .config import load_consumer_config
from .consumer import Consumer

DEFAULT_CONFIG_PATH = "config-consumer.json"


def main() -> None:
    parser = argparse.ArgumentParser(description="共生网络 Web 代理消费端（请求端）")
    parser.add_argument("config", nargs="?", default=DEFAULT_CONFIG_PATH,
                        help="配置文件路径（默认 config-consumer.json）")
    parser.add_argument("-v", "--verbose", action="store_true", help="输出调试日志")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    config = load_consumer_config(args.config)
    consumer = Consumer(config)
    consumer.start()
    try:
        consumer.serve_forever()
    except KeyboardInterrupt:
        logging.getLogger(__name__).info("收到中断，正在退出")
    finally:
        consumer.stop()


if __name__ == "__main__":
    main()
