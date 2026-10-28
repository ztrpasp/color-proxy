# 交接文档 —— 共生网络 Web 代理终端（color-proxy）

> 目的：让新的开发会话（或新成员）能**快速接手并继续**本项目，不必重新摸索背景。
> 建议新会话开场先读：本文件 → `docs/软件说明书.md` → `docs/design-server-v1.md`。
>
> ⚠ **本文覆盖的是 v1 内容级 HTTP 模式，部分内容已过时**（如 §9 把「消费端开发」列为下一步，但消费端 v1 已完成；§10 写的 `test_protocol.py` 期望 9/9 现为 10/10）。
> 当前在 `dev_tun` 分支上进行的是 **L3 隧道模式**：交接见 **`docs/HANDOVER-l3.md`**，契约见 `docs/design-l3-v2.md`。

---

## 1. 一句话现状

基于共生网络（CoLoR）实现"无感知跨域 Web 获取"的新终端。**服务端（提供端）与消费端（请求端）v1 最小功能均已实现并通过本地测试**；
与真实 RM/BR 的端到端联调（S4）待在部署环境完成。

---

## 2. 文档索引（都在本仓库）

| 文档 | 位置 | 内容 |
|---|---|---|
| 需求原文 | `需求.md` | 用户最初的终端开发需求 |
| 共生网络技术要点 | `技术文档/共生网络技术要点（终端开发相关）.md` | CoLoR 概念/报文/机制（开发相关提炼） |
| 原始技术资料 | `技术文档/*.docx`、`技术文档/示意图.png` | 共生网络与包格式权威定义、握手示意图 |
| PRD | `docs/PRD-v1.md` | 需求分析、范围、已知风险、验收 |
| 服务端设计 | `docs/design-server-v1.md` | 服务端详细设计（本轮实现依据） |
| 请求端设计 | `docs/design-client-v1.md` | 消费端契约级设计（定义对端） |
| 软件说明书 | `docs/软件说明书.md` | 架构/实现/运行/测试/限制 |
| README | `README.md` | 快速上手 |

参考实现（**只读对照**，字段定义/功能正确但风格差）：`C:\Users\ZWD15\Desktop\color-agent-plus`。

---

## 3. 已完成 / 未完成

**已完成（服务端 v1，里程碑 S1–S3）**
- 协议层编解码：GET/DATA/ANN（scapy 声明式）+ CONTROL（手工）；9/9 单元测试通过。
- 传输层：原始套接字接收（proto 150 + `SIO_RCVALL`）+ scapy `sendp` 发送。
- 业务：向 RM 注册并处理同步、发布 Web 服务（ANN）、`handle_get`（隧道 DATA）、`handle_ack`（取 HTTP 请求）、`OriginWorker`（回源 + 响应 DATA）。
- **HMAC 生成**：对发出的 DATA（隧道/响应）填充报文头 HMAC（`Flags.C`，无密钥 MD5 末 4 字节，种子取 GET 的 `Random_Num`），以通过 BR 校验；`tests/test_hmac.py` 4/4 通过。仅生成/填充，不校验入站。
- **多方法 HTTP + query 透传**：GET/POST/PUT/DELETE/HEAD 均可端到端（`CONNECT`/HTTPS 回 501）；`L_sid = SHA1(去 query 后 URL)`，query 不入 SID 但透传到源站（`tests/test_e2e_inproc.py` 覆盖 CRUD 多方法 + query 透传）。
- 业务闭环测试 `tests/stub_consumer.py` 通过（绕过原始套接字，用本地源站）。

**已完成（消费端 v1，里程碑 M3）**
- 新增 `colorproxy/consumer/` 子包（附加式，复用 `protocol`/`transport`/`registration`，未改服务端文件）：
  HTTP 正向代理（默认 8910）→ 查本域 SID 表 → GET → 收隧道 DATA → 发 B=1 ACK(载 HTTP 请求) → 拼接响应 DATA 写回浏览器。
- **SID 表来源：从 RM 拉取**（哨兵零 SID GET；只取回送 DATA 包头里的 SID，不耦合 RM 负载格式）。
- 测试通过：`tests/test_consumer.py`（5/5：GET/ACK/哨兵 GET 字节布局、反向路径、SID 表登记）、
  `tests/stub_provider.py`（域内闭环：浏览器→GET→隧道→ACK→响应→写回，`stub_consumer.py` 的镜像）。

**未完成 / 待做**
- **S4 端到端**：真实 RM + 跨域 BR + 管理员 + Npcap + 浏览器下的联调与抓包验证。
  - 重点验证两项消费端 S4 假设：① 哨兵零 SID GET 能否触发 RM 回送本域 SID 列表（回送格式已查明并实现，见下方控制面缺口②；仅"RM 是否对该哨兵 GET 响应"待真机确认）；
    ② ~~跨域 PID 反向布局待校准~~ **【已修正】**：S4 联调中 ACK 被 BR 以 `verify_pid_inbound failed`
    丢弃，对照参考实现 `ColorMonitor.py:224,248,290-296` 定位为消费端反向 PID 取法错误。修正：DATA 经真实
    BR 反向路由后，消费端收到的 PID 列**首位**是 BR 入域校验用的保留/返回 PID，故下一跳 PX 取 `recv_pids[1]>>16`、
    ACK 反向路径取 `recv_pids[1:][::-1]`（原实现误按"尾部保留位"剥离且用了 `recv_pids[0]`）。改在
    `consumer/handlers.py:_handle_tunnel` 与 `consumer/messages.py:reverse_path_for_ack`，回归见
    `tests/test_consumer.py:test_tunnel_cross_domain_sets_return_ip_and_reverse_pids`。服务端尾部追加保留位
    （`messages.py build_data_packet`）与参考 DataPkt(B=0/R=1) 一致，无需改。
  - **两个控制面缺口（真实 RM 下可能踩，对照 color-agent-plus/ColorMonitor.py:447-491）**：
    ① ~~CONTROL tag=8（新代理通知）未处理~~ **【2026-10-28 已实现】**：`control.parse_proxy_notify`，布局见下 §6 第 2 条。以下为原记录：
    **CONTROL tag=8（新代理通知）未处理**（提供端+消费端共用的 `registration.handle_control` 只认 tag=6）。
       若 RM 仅在注册时同步域内代理表、对后加入者用 tag=8 增量通知，则先注册的一方学不到后注册方的
       NID→IP。症状：提供端日志「无法确定回送地址」、消费端 504。**应急**：两端都起好后重启"先启动的那个"。
    ② ~~本域 SID 表的真实下发可能是 CONTROL tag=40 而非 DATA(r=1)~~ **【已修正】**：经对照参考实现
       （`ColorMonitor.py:480-494`）确认 RM 确实用 **CONTROL(Subtype=40)** 一次性下发本域 SID 列表，
       负载为裸的每 36 字节一个 SID 拼接。已实现：`protocol/control.py:is_sid_list/parse_sid_list`、
       `consumer/sid_table.py:register_sid_list_control`，并在 `consumer.py:_on_payload` 的 CONTROL 分支登记；
       原 DATA(r=1) 取 SID 的路已废（DATA r=1 实为"服务摘要"应答，需先发摘要 GET 才有，本端不取）。
       `config-consumer.json` 的静态 SID 预载（`sids`）仍保留作离线/兜底。
- 端到端联调脚手架：`tools/origin_server.py`（测试源站）、`tests/test_e2e_inproc.py`（进程内贯通两端，
  真 RM 前的最强离线保障）。运行方式见 README「运行」。
- v2 演进：CoLoR 段可靠传输、HTTPS、请求分片、并发去复用、ESS 端到端加密、入站 HMAC 校验 / 消费端 HMAC。（**出站 HMAC 生成已实现**。）

---

## 4. 锁定的关键决策（不要轻易推翻；如要改先与用户确认）

| 决策 | 取值 |
|---|---|
| 范围 | 消费端 + 提供端两端都做；**两端 v1 均已实现并通过本地测试** |
| 接入形态 | 消费端为 HTTP 正向代理；服务端为纯后台服务（无 GUI/托盘） |
| 服务范围 | 仅服务已发布到共生网络的 URL；仅 HTTP（无 HTTPS） |
| 可靠传输 | CoLoR 段 **best-effort**，v1 不做（v2 复用 `slideWindow`） |
| 加密 | **不实现 ESS 端到端加密**；**HMAC 已实现**（出站 DATA 生成/填充以通过 BR 校验，不校验入站） |
| ACK 携带请求 | **复用 B=1 ACK 通道扩展 payload** 承载 HTTP 请求 |
| 回源 | **每请求新建到 origin 的 TCP**，强制 `Connection: close` 读到 EOF |
| 并发 | 不支持，按 `(SID, 消费端NID)` 串行（last-wins）；不引入事务 ID |
| 平台/技术栈 | 仅 Windows；Python 3.8+ + scapy（移植参考实现的协议定义） |

---

## 5. 代码地图

模块职责见 `docs/软件说明书.md` §2.2。一句话索引：
`protocol/`（编解码）→ `transport/`（收发）→ `state`/`config` → `registration`/`publish`/`handlers`/`origin`（业务）→ `provider`（装配）→ `main`（入口）。

---

## 6. 重要技术约束与"坑"（务必先读，避免重复踩坑）

1. **scapy `Flags` 共享状态坑**：`pkt.Flags.X = True` 会**跨实例共享同一可变标志对象**，
   造成标志位互相污染。**必须构造时整体赋整数** `ColorData(Flags=0x22, ...)`。
   DATA 位：`S=0x02 R=0x20 B=0x40`。（`tests/test_protocol.py` 有回归断言守护。）
2. **CONTROL 同步表字段次序**：Subtype=6 的 Proxy 条目是 **IP 在前、NID 在后**，与注册请求(Subtype=5)相同；
   Subtype=8 是新代理的注册载荷原样转发（IP+NID 共 20 字节，没有条目数）。依据是三份 RM 源码的 `src/packets/ctrl.c`
   （注释写着 `[NID IP]`，与代码相反）。**2026-10-28 勘误**：此处原写「NID 在前」，是照抄 color-agent-plus
   `ProxyLib.ControlPkt` 的错误，导致同域回址在两端都查不到；它自己的 scapy 定义 `IP_NID` 反而是对的。
   解析见 `protocol/control.py`。
3. **DATA 校验和只覆盖包头** `data[0:Header_Length]`；GET/ANN/CONTROL 覆盖整包。
4. **`ColorData` 两处修正**（已做，勿回退）：B=1 时 `Source_NID`（第二个 NID）出现；`post_build` 回填 `PID_Pointer`。
5. **字节序**：长度/SegID/PID/MTU/控制长度/控制 IP 为小端；校验和大端；NID/SID 字节数组。
6. **运行环境**：需管理员权限 + Npcap；Python 3.13 + scapy 2.7.0 已验证可用。
7. **回送路径**：跨域 `R=1` + `PID_List = GET 的 PID + 保留 0`；域内 `R=0` + 直接查域内代理表。
   这是与 BR 正确反向路由的关键，对照 `color-agent-plus/src/Frontend/ColorMonitor.py:541-556,653-665`。

---

## 7. 与消费端的接口契约（两端必须一致）

详见 `docs/design-client-v1.md` §1。要点：
- `SID = N_sid(提供方NID) ‖ L_sid(SHA1(去 query 后的 url))`，消费端按同法在本域 SID 表匹配得 N_sid（query 不入 SID，但透传到源站）。
- 握手：GET → 隧道 DATA(B=0, `load[0]=0x10`) → ACK(B=1, `load=[0x20]+HTTP请求`) → 响应 DATA(B=0, `load=[0x30(|0x01末片)]+分片`)。
- 消费端 GET 须置 S 标志并在 `Segment_ID` 放事务标识（服务端原样回带）。
- ACK(B=1)：`Destination_NID=提供方NID`、`Source_NID(第二个NID)=消费端NID`、`PID_List=` 从隧道 DATA 提取并按现有 ACK 约定反向。
- **HMAC**：提供端发出的隧道/响应 DATA 均置 `Flags.C` 并填 4 字节 HMAC（无密钥 MD5 末 4 字节，种子=GET 的 `Random_Num`）；消费端 GET/ACK **当前不带 HMAC**。

---

## 8. 参考实现移植依据（行号，便于继续对照）

`C:\Users\ZWD15\Desktop\color-agent-plus`：
- `src/CoLoRProtocol/CoLoRpacket.py` —— 报文声明式定义（本项目协议层移植来源）。
- `src/Frontend/ProxyLib.py`：`DataPkt`(567-797)、`ControlPkt`(306-490)、`SidAnn`(183-246)、`SendIpv4`(1003-1014)、全局状态(15-38)。
- `src/Frontend/ColorMonitor.py`：收包主循环(951-981)、分发与 DATA/ACK 处理(134-440)、`SendingThread`(497-708)、回址判定(541-556)、`DataFlag`(76-78)。

---

## 9. 如何继续（建议下一步）

1. **S4 端到端联调**（最高优先）：
   - 准备拓扑：本机跑服务端（发布 `http://prov.local/x` → 本地 `python -m http.server 8000`），真实 RM（+跨域 BR）。
   - 以管理员启动 `python -m colorproxy.main config.json -v`，确认日志出现"代理注册完成""已发布 Web 服务"。
   - 用桩或消费端发 GET，抓包（Wireshark 过滤 `ip.proto==150`）确认 GET→隧道DATA→ACK→响应DATA 链路与 `load[0]` 类型。
   - 易错点：注册同步表解析、回址(PX/域内)、Flags 设置、HMAC 能否通过 BR 校验（出站生成已实现，需真机确认 BR 放行）。
2. **消费端开发**：按 `docs/design-client-v1.md`，HTTP 正向代理监听端口 → 解析 URL → 查 SID 表 → 跑握手 → 写回浏览器。可复用本仓库 `colorproxy/protocol`。
3. **可靠传输（v2）**：把响应流接入参考实现的滑动窗口（`slideWindow.py`）思路。

---

## 10. 在新会话快速上手

1. 读 `docs/HANDOVER.md`（本文）→ `docs/软件说明书.md` → `docs/design-server-v1.md`。
2. 复现环境：`python -m pip install -r requirements.txt`（Windows 另装 Npcap）。
3. 跑测试确认基线：
   ```
   python tests/test_protocol.py      # 期望 9/9 passed
   python tests/stub_consumer.py      # 期望 业务闭环验证通过
   ```
4. 需要改协议/报文时，先看 `protocol/packets.py` 的注释与 §6 的坑，再改并补 `tests/test_protocol.py`。
