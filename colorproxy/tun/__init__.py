"""tun 设备与内层 IPv4 包处理（L3 隧道模式，docs/design-l3-v2.md §10.1）。

- ``ipv4``：内层包解析（version/ihl/proto/地址/端口/DF/MF/分片偏移）
- ``mss``：MSS clamp 与 TCP 校验和
- ``tcp``：TCP 段解析、序号运算与 RST 构造（D20）
- ``device_win`` / ``device_linux``：tun 设备读写（Wintun / ``/dev/net/tun``），由 ``factory`` 按平台选用

本包只处理**内层**报文（路径二），不涉及外层 CoLoR 报文（路径一，见 §1.1）。
纯逻辑、无平台依赖，Windows 与 Linux 共用。
"""
