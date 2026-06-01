"""服务端配置的读取与校验。"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


@dataclass(frozen=True)
class ServiceConfig:
    """一个对外发布的 Web 服务。"""

    url: str
    origin_host: str
    origin_port: int


@dataclass(frozen=True)
class Config:
    """服务端运行配置。"""

    nid: int
    ipv4: str
    rm_ipv4: str
    services: list[ServiceConfig]


def load_config(path: str | Path) -> Config:
    """从 JSON 文件读取并校验配置。

    JSON 形如::

        {
          "nid": "00112233445566778899aabbccddeeff",
          "ipv4": "10.0.1.6",
          "rm_ipv4": "10.0.0.1",
          "services": [
            {"url": "http://prov.local/hello.html",
             "origin_host": "127.0.0.1", "origin_port": 8000}
          ]
        }

    ``origin_host`` / ``origin_port`` 可省略，缺省取 URL 中的主机与端口。
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))

    nid = int(str(data["nid"]), 16)
    ipv4 = str(data["ipv4"])
    rm_ipv4 = str(data["rm_ipv4"])

    services: list[ServiceConfig] = []
    for entry in data.get("services", []):
        url = entry["url"]
        default_host, default_port = _default_origin(url)
        services.append(
            ServiceConfig(
                url=url,
                origin_host=entry.get("origin_host", default_host),
                origin_port=int(entry.get("origin_port", default_port)),
            )
        )
    if not services:
        raise ValueError("配置中至少需要一个 services 条目")

    return Config(nid=nid, ipv4=ipv4, rm_ipv4=rm_ipv4, services=services)


def _default_origin(url: str) -> tuple[str, int]:
    parsed = urlparse(url)
    if not parsed.hostname:
        raise ValueError(f"无法从 URL 解析主机：{url}")
    return parsed.hostname, parsed.port or 80
