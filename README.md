# color-proxy —— 共生网络 Web 代理终端

基于共生网络（CoLoR）实现无感知跨域 Web 获取的代理终端，**消费端（请求端）与服务端
（提供端）两端均已实现**：

- **服务端（提供端）**：把后端真实 Web 服务的 URL 发布为 SID，接收消费端经共生网络发来的
  HTTP 请求，回源取响应后经共生网络发回。设计见 `docs/design-server-v1.md`。
- **消费端（请求端）**：浏览器侧 HTTP 正向代理，截取浏览器请求 → 查本域 SID 表 → 经"先拉后推"
  握手取回响应写回浏览器。设计见 `docs/design-client-v1.md`。

总体需求/分析见 `docs/PRD-v1.md`。

> 本轮实现的是 **v1 最小功能**：不含 ESS 加密/HMAC、可靠传输（滑动窗口/重传）、
> 并发（同 `(SID, 消费端NID)` 串行）、HTTPS、请求分片。

## 交互流程（先拉后推）

```
消费端                                         本服务端
  │  GET(SID, 无 payload, SegID=事务) ───────────▶│ 校验 SID → 记未决事务
  │ ◀── 隧道 DATA(B=0, 空载, 携带 PID 序列) ───────│ 让消费端取得跨域 PID 隧道
  │  ACK(B=1, payload = 完整 HTTP 请求) ──────────▶│ 取出请求 → 新建 TCP 回源
  │ ◀── 响应 DATA(B=0, payload = HTTP 响应) × N ──│ best-effort，可多片
```

`load[0]` 高 2 位标识用途：`0x10` 隧道 / `0x20` HTTP 请求 / `0x30` HTTP 响应；
低位 `0x01` 为最后分片（LAST）。详见 `docs/design-server-v1.md` §1。

## 安装

```
python -m pip install -r requirements.txt
```

Windows 需另装 [Npcap](https://npcap.com/)（scapy 收发链路层报文所需）。Python 3.8+。

## 运行

**服务端（提供端）**：

```
# 1) 准备配置
copy config.example.json config.json   # 按需修改 nid / ipv4 / rm_ipv4 / services

# 2) 以管理员权限启动（原始套接字 + Npcap）
python -m colorproxy.main config.json
```

`config.json` 字段：

| 字段 | 说明 |
|---|---|
| `nid` | 本机节点标识，32 位十六进制（128 bit） |
| `ipv4` | 本机 IPv4（绑定原始套接字、注册给 RM） |
| `rm_ipv4` | 资源管理器 IP |
| `services[].url` | 对外发布的 URL；`L_sid = SHA1(去 query 后的 URL)`，故同 path、不同 `?query` 命中同一 SID |
| `services[].origin_host/port` | 该 URL 对应的真实后端地址，省略则取 URL 自身的主机端口 |

**消费端（请求端）**：

```
# 1) 准备配置
copy config-consumer.example.json config-consumer.json   # 按需修改 nid / ipv4 / rm_ipv4 / proxy_port

# 2) 以管理员权限启动（原始套接字 + Npcap）
python -m colorproxy.consumer.main config-consumer.json

# 3) 把浏览器/系统的 HTTP 代理指向本机 proxy_port（默认 8910）
```

`config-consumer.json` 字段：`nid` / `ipv4` / `rm_ipv4` 同上；`proxy_port` 为 HTTP 正向代理
监听端口（默认 8910）。消费端启动时向 RM 注册并拉取本域 SID 表；访问未发布到共生网络的
URL 会收到 502。

## 测试

无需管理员权限 / Npcap，可在普通环境运行：

```
python tests/test_protocol.py     # 协议编解码单元测试（含 SID 去 query，10/10）
python tests/stub_consumer.py     # 桩消费端 + 本地源站，验证服务端业务闭环
python tests/test_consumer.py     # 消费端单元测试（GET/ACK 布局、反向路径、SID 表/去 query，8/8）
python tests/stub_provider.py     # 桩提供端 + 桩 RM，验证消费端业务闭环（浏览器→GET→隧道→ACK→响应→写回）
python tests/test_e2e_inproc.py   # 进程内贯通两端 + 真实源站（hello / showcase 分片 / CRUD 多方法 + query 透传）
```

> Windows 控制台若显示中文乱码，加 `PYTHONUTF8=1` 前缀（仅影响日志显示，不影响断言）。

### 测试源站与样例端点

端到端联调用的测试源站：`python tools/origin_server.py --port 8000`，提供：

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/hello.html`、`/` | 小页面，单包即传完（最简冒烟） |
| `GET` | `/showcase.html` | 较大的**自包含**页面（内联 CSS/SVG，约 7 KB / 6 个分片），验证分片重组 |
| `GET` | `/items.html` | `/api/items` 的**交互控制台**：表单增删改查，页面实时更新（内联 CSS/JS，自包含） |
| `GET` | `/ping` | `pong` |
| `GET` | `/api/items` | 列出全部条目；`?id=N` 取单条 / 404 |
| `POST` | `/api/items` | 读 JSON body 创建，返回 `{id, ...}`（201） |
| `PUT` | `/api/items?id=N` | 覆盖更新 / 404 |
| `DELETE` | `/api/items?id=N` | 删除 / 404 |

浏览器（或经代理）打开 `/items.html` 即可填表单创建、保存、删除条目——每个动作都是一次真实的
`fetch('/api/items')`（用**相对 URL**，故直连与经代理两种方式都成立），页面随响应即时刷新并打印请求日志。

条目 id 走 query（`?id=N`）而非路径：因 `L_sid = SHA1(去 query 后 URL)` 是整路径精确匹配，
放 query 可让增删改查共用 `/api/items` 一条 SID，并端到端验证 **query 不入 SID、却原样透传到源站**。
直连源站快速试：

```
curl http://127.0.0.1:8000/showcase.html
curl -X POST -d '{"name":"a"}' http://127.0.0.1:8000/api/items
curl -X PUT  -d '{"name":"b"}' "http://127.0.0.1:8000/api/items?id=1"
curl -X DELETE              "http://127.0.0.1:8000/api/items?id=1"
```

> 经代理访问需先把这些 URL 发布为服务（已在 `config.json` / `config-consumer.json` 预置
> `showcase.html` 与 `/api/items`）。**自包含约束**：经代理取回的页面不能引用任何外链资源
> （`<link>`/`<img src>`/`<script src>`/外部字体）——代理只取所请求的这一个 URL，子资源会是
> 各自独立、未发布的请求。

## 模块结构

```
colorproxy/
  protocol/        CoLoR 报文编解码（scapy 声明式 + 手工 CONTROL）
    constants.py   常量、报文类型、load[0] 标志
    utils.py       校验和、字节序转换
    sid.py         SID = N_sid(NID) ‖ L_sid(SHA1(url))
    packets.py     ColorGet / ColorData / ColorAnnounce（含两处 ColorData 修正）
    control.py     注册请求构造 / 同步回复解析
  transport/
    receiver.py    原始套接字接收（proto 150 + SIO_RCVALL）
    sender.py      scapy sendp 发送（Ether/IP/CoLoR）
  config.py        配置读取
  state.py         运行期状态（域内表、Web 服务表、未决事务表）
  registration.py  向 RM 注册 + 处理同步回复
  publish.py       发布 Web 服务（ANN）
  handlers.py      GET（隧道 DATA）/ ACK（取请求）处理
  origin.py        回源（新建 TCP、规整请求、读到 EOF）+ 发响应 DATA
  messages.py      构造发往消费端的 DATA 报文
  provider.py      装配与收包分发（提供端）
  main.py          提供端入口
  consumer/        消费端（请求端）—— 附加式复用 protocol/transport/registration
    config.py      消费端配置（nid/ipv4/rm_ipv4/proxy_port）
    state.py       消费端状态（域内表、本域 SID 表、未决请求表）
    messages.py    构造 GET / B=1 ACK / 哨兵 SID 列表请求
    sid_table.py   向 RM 拉取并登记本域 SID 表
    handlers.py    收 DATA：SID 列表条目 / 隧道(置事件) / 响应(拼接写回)
    proxy.py       HTTP 正向代理 + 单请求握手编排
    consumer.py    装配（收包分发 + 注册 + 拉表 + 起代理）
    main.py        消费端入口
```

## 已知限制（v1）

- CoLoR 段 **best-effort**，无重传；大响应或丢包时页面可能不完整。
- 假设单个 HTTP 请求可装入一个 IP 包（不支持大 body 的请求分片）。
- 不实现 ESS/HMAC；若部署的边界路由器强制校验 HMAC，需后续补充。
- 仅服务已发布到共生网络的 URL；同 `(SID, 消费端NID)` 并发请求按 last-wins 串行。
