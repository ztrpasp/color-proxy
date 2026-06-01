"""消费端配置的读取与校验。

与服务端 ``colorproxy.config`` 风格一致，但消费端不发布服务（无 ``services``），
SID 表在运行期从 RM 拉取（见 ``sid_table``），故配置只含身份与监听端口。
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

#: HTTP 正向代理默认监听端口（用户在浏览器/系统里把 HTTP 代理指向它）
DEFAULT_PROXY_PORT = 8910


@dataclass(frozen=True)
class StaticSid:
    """预置的 URL→提供方 NID 映射（联调/测试用，见 ConsumerConfig.sids）。"""

    url: str
    provider_nid: int


@dataclass(frozen=True)
class ConsumerConfig:
    """消费端运行配置。"""

    nid: int
    ipv4: str
    rm_ipv4: str
    proxy_port: int = DEFAULT_PROXY_PORT
    #: 可选静态 SID 预载：联调时绕开"从 RM 拉取 SID 表"这一未决环节，单独验证
    #: 数据面握手（GET→隧道→ACK→响应）。为空则完全依赖 RM 下发的 SID 表。
    sids: tuple[StaticSid, ...] = ()


def load_consumer_config(path: str | Path) -> ConsumerConfig:
    """从 JSON 文件读取并校验消费端配置。

    JSON 形如::

        {
          "nid": "00112233445566778899aabbccddeeff",
          "ipv4": "10.0.1.5",
          "rm_ipv4": "10.0.0.1",
          "proxy_port": 8910,
          "sids": [
            {"url": "http://prov.local/hello.html",
             "provider_nid": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"}
          ]
        }

    ``proxy_port`` 可省略（缺省 8910）；``sids`` 可省略（缺省空，仅用 RM 下发的表）。
    ``sids[].provider_nid`` 即该 URL 提供方的 NID（=对方 config 的 ``nid``）。
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    sids = tuple(
        StaticSid(url=str(entry["url"]), provider_nid=int(str(entry["provider_nid"]), 16))
        for entry in data.get("sids", [])
    )
    return ConsumerConfig(
        nid=int(str(data["nid"]), 16),
        ipv4=str(data["ipv4"]),
        rm_ipv4=str(data["rm_ipv4"]),
        proxy_port=int(data.get("proxy_port", DEFAULT_PROXY_PORT)),
        sids=sids,
    )
