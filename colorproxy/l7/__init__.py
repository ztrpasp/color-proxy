"""应用层解析（docs/design-l3-v2.md §8.7，D20）。

与 ``l3/`` 并列：``l3/`` 负责把 IP 包装进 CoLoR 隧道，本包负责从字节流里读出应用层的
含义。这里的模块都是**纯逻辑**——不认识 CoLoR、SID、tun，也不碰 TCP 序号，调用方按
到达顺序喂字节即可，所以能离线单测，也能给别的地方复用。

- ``http``：HTTP/1.x 请求流的增量解析（D20 内容级准入用）。

以后的 FTP（被动模式要从 227/229 回复里读数据端口）放 ``ftp.py``，并把名字加进
``SUPPORTED_APPS``。配置里 ``app`` 字段的合法取值以这里为准。
"""

#: 配置项 ``app`` 的合法取值（``l3.services[].app`` / ``l3.app_services[].app``）
SUPPORTED_APPS = ("http",)
