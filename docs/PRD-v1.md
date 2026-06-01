# 共生网络 Web 代理终端 PRD 需求文档 v1（color-proxy）

> 状态：v1 草案（需求分析阶段产物）。本阶段只做需求分析，不含实现代码。
> 配套参考：`需求.md`、`技术文档/共生网络技术文档.docx`、`技术文档/共生网络包格式.docx`、`技术文档/示意图.png`；参考实现 `C:\Users\ZWD15\Desktop\color-agent-plus`。

---

## 0. Context（背景与目标）

现有共生网络（CoLoR）终端 `color-agent-plus` 是一款基于 PyQt 的客户端，实现域内/跨域**文件传输**。它存在两个使用门槛：

1. **必须下载重客户端**：新用户使用成本高。
2. **只能文件传输**：传统 Web 服务（访问一个 URL 的资源）无法借助共生网络的先进性（内生安全、防跨域攻击、防数据泄露等）。

**目标**：开发新终端 `color-proxy`，**基于共生网络实现"无感知"的跨域 Web 获取服务**——用户在浏览器里正常访问 URL，跨域流量被自动封装为共生网络协议传输，无需为每次访问感知底层。

**关键设计难点**：CoLoR 是"先拉后推"的**单向拉取**模型（GET 不带 payload，由提供方推送 DATA）；而 HTTP 是**双向**的，请求端需要把 HTTP 头+body 主动推给服务端。本 PRD 的核心是用"GET → 提供端回 PID 隧道 → 请求端用携带 payload 的 DATA/ACK 推送 HTTP 请求"的握手解决该矛盾（见 §6 核心流程）。

---

## 1. 术语与技术基础（来自技术文档 + color-agent-plus 实现）

| 标识 | 长度 | 含义 |
|---|---|---|
| **NID** 节点标识 | 128 bit / 16 B | 节点唯一标识 = 节点公钥哈希，用于节点认证 |
| **SID** 服务标识 | 288 bit / 36 B | `N_SID(128b) ‖ L_SID(160b)`。N_SID=提供方 NID（用于路由+提供方认证）；L_SID=内容哈希（用于真实性校验） |
| **PID** 路径标识 | 32 bit / 4 B（每跳一个） | 由 RM/BR 在转发时累积，记录最短转发路径，供数据反向沿原路返回与校验。即"跨域通信隧道" |

**报文类型**（IP 协议号 **150**，Version=**7**）：

| Type | 名称 | 关键点 |
|---|---|---|
| 1 | **ANN** 通告报文 | 提供方→RM 发布服务（SID）。携带通告单元(AU)、可选公钥/AS Path |
| 2 | **GET** 请求报文 | 请求端发出，**不带 payload**。携带 NSID+LSID+请求者 NID；末尾累积 PID 序列 |
| 3 | **DATA** 数据报文 | 提供方→请求端推送数据。含 `B` 标志（**B=1 即 ACK 确认报文**）、`R` 标志（跨域/反向路径）、PID 指针、PID 序列、Destination_NID、Source_NID、SegID（滑动窗口序号） |
| 4 | **CONTROL** 控制报文 | 终端↔RM/BR 注册与信息同步（子类型：代理注册=5、注册应答=6、新代理通知=8 等） |

> 注：技术文档定义"确认报文(B=1 ACK)不含负载部分"。本项目对 ACK/DATA 做**协议适配**——允许携带 PID 序列的 DATA 型报文承载 HTTP 请求 payload（见 §7）。

**现有 `color-agent-plus` 可复用资产**（路径见 §10）：完整 CoLoR 协议栈（`CoLoRProtocol/CoLoRpacket.py`）、收发包（raw socket 收协议 150 + scapy 发，`Frontend/ColorMonitor.py`、`Frontend/ProxyLib.py`）、RM 注册/获取域内 SID 表/ANN 通告/GET（`ProxyLib.py`）、滑动窗口（`Frontend/slideWindow.py`，v1 不启用，留作 v2）。**缺失**：HTTP 解析、端口监听、应用层代理转发——这是本项目新增重点。

---

## 2. 产品概述与角色

`color-proxy` 是一个**对称**的共生网络 Web 代理终端，同一份软件可同时扮演两种角色：

- **消费端（Consumer / 浏览器侧正向代理，NID_C）**：在固定端口运行 HTTP 正向代理，截取浏览器 HTTP 请求 → 转为 CoLoR 流量 → 取回响应交还浏览器。
- **提供端（Provider / Web 服务侧反向代理，NID_P）**：把本地/后端真实 Web 服务的 URL 发布为 SID（ANN）→ 接收 CoLoR 请求 → 转发给真实 Web 服务器 → 把响应经 CoLoR 发回。

**RM（资源管理器）/ BR（边界路由器）需求保持不变**：RM 处理通告/请求/终端注册/下发本域可访问 SID 表；BR 转发跨域 CoLoR 包、拦截非法入域/出域包。本项目不改动 RM/BR。

---

## 3. v1 范围

### 3.1 In Scope
- 消费端 HTTP 正向代理（固定端口）+ 提供端反向代理，**两端均实现**，可端到端联调。
- **仅 HTTP**（明文，代理可取到完整 URL）。
- URL ↔ SID 映射的生成与维护；本域可访问 SID 表的获取（复用现有 CONTROL 注册/同步）。
- 监听 IP 协议号 150 的 CoLoR 包并按本项目流程处理。
- "先拉后推"握手（GET → 隧道 DATA → 携带 HTTP 请求的 DATA/ACK → 响应 DATA）。
- Windows 后台服务 + 系统托盘（状态/启停/配置）。
- **仅服务已发布到共生网络的 URL**：URL 不在本域 SID 表中时，向浏览器返回错误（如 502/404），不直连回落。

### 3.2 Out of Scope（v1 不做，列入 v2 演进）
- **HTTPS / TLS**（加密导致代理拿不到明文 URL）。
- **CoLoR 段可靠传输**（v1 完全尽力而为，见 §8）。
- **HTTP 请求分片**（v1 假设单个请求可装入一个 IP 包，见 §8）。
- 透明流量劫持（WFP/路由重定向）；非 CoLoR URL 的直连回落。
- 跨平台（v1 仅 Windows）。
- 端到端加密 / 完整 PyQt 可视化界面。

---

## 4. 功能需求

### FR-1 消费端 HTTP 正向代理
- FR-1.1 在可配置端口（默认如 `8910`）监听，接受浏览器/系统代理设置的 HTTP 连接。
- FR-1.2 解析 HTTP 请求，提取**完整 URL**（含 scheme+host+path+query）与完整请求字节（头+body）。
- FR-1.3 计算 `L_SID = SHA1(完整 URL)`；在本域可访问 SID 表中按 L_SID 匹配，得到完整 SID（含 N_SID=提供方 NID）。
- FR-1.4 命中：发起 §6 的 CoLoR 握手流程取回响应，原样写回浏览器 TCP 连接。
- FR-1.5 未命中（非 CoLoR 服务）：向浏览器返回明确错误响应（502/404），并记录日志。
- FR-1.6 维护**未决请求表**：`(SID, 事务标识) → 浏览器 TCP socket`，用于把异步到达的响应路由回正确连接（并发去复用，见 §9 开放项）。

### FR-2 提供端反向代理
- FR-2.1 配置后端真实 Web 服务（URL 列表或 origin host:port）。
- FR-2.2 为每个对外 URL 生成 SID（`N_SID=本机 NID`，`L_SID=SHA1(URL)`），通过 ANN 向 RM 发布；可携带访问策略（密级/白名单，复用现有 `SidUnit.Strategy_units`）。
- FR-2.3 标记该 SID 为"**Web 类型**"，使收到 GET 时走握手流程（先回隧道 DATA），而非直接推内容。
- FR-2.4 收到 GET（Web 类型 SID）：校验 SID 已发布 → 回一个**隧道建立 DATA**（B=0，**空/占位 payload**），把累积的 PID 序列带回请求端。
- FR-2.5 收到携带 HTTP 请求 payload 的 DATA/ACK：提取 HTTP 请求字节 → 转发给真实 Web 服务器（建立到 origin 的 TCP）→ 取回 HTTP 响应。
- FR-2.6 把 HTTP 响应（头+body）作为 payload 封装为 DATA（B=0），沿 PID 序列发回请求端（best-effort，可多包）。

### FR-3 SID 生成与映射
- FR-3.1 `L_SID = SHA1(完整 URL)`（160 bit，与现有文件哈希同算法）。
- FR-3.2 `N_SID = 提供方 NID`（128 bit）。`SID = N_SID ‖ L_SID`（288 bit / 72 hex）。
- FR-3.3 消费端**按 L_SID 匹配**本域 SID 表即可解析出 N_SID/提供方，无需在表中存明文 URL（隐私友好）。
- FR-3.4 提供端维护 `SID → 后端 URL/origin` 反向映射，用于收到请求后定位真实服务。

### FR-4 本域可访问 SID 表
- FR-4.1 复用现有 CONTROL 注册流程（向 RM 注册代理，子类型 5/6）。
- FR-4.2 接收 RM 下发的本域可访问 SID 表，至少包含每条 `{L_SID, N_SID(提供方), 可选策略}`；缓存于内存供 FR-1.3 查询。
- FR-4.3 接收域内 Peer 代理表（NID→IP）与 BR 表（PX→IP），用于域内/跨域回址（复用 `PeerProxys`/`PXs`）。

### FR-5 共生网络包监听与处理
- FR-5.1 raw socket 监听 IP 协议号 150（复用 `ColorMonitor` 的 Windows `SOCK_RAW`+`SIO_RCVALL`）。
- FR-5.2 按首字节类型分发：ANN/GET/DATA(含 ACK)/CONTROL，按角色（消费/提供）执行 §6 流程。
- FR-5.3 还原 Web 服务包：从 DATA payload 还原 HTTP 字节，写入对应 TCP 连接（消费端）或 origin（提供端）。
- FR-5.4 发包复用 scapy `Ether/IP(proto=150)/Raw` 封装（`ProxyLib.SendIpv4`）。

### FR-6 后台服务与系统托盘
- FR-6.1 以 Windows 后台服务/常驻进程运行（需管理员权限：raw socket + Npcap）。
- FR-6.2 系统托盘：显示运行状态、启停代理、打开配置、查看简要日志。
- FR-6.3 配置项：本机 NID、本机 IPv4、RM IP、代理监听端口、角色开关（消费/提供）、提供端后端 URL 表。复用现有 `data.json` 风格配置。

---

## 5. 本域可访问 SID 表（数据结构建议）

```
SIDEntry {
  l_sid:     hex(20B)      # SHA1(URL)，消费端用它匹配
  n_sid:     hex(16B)      # 提供方 NID（=路由目标/认证）
  type:      "web"         # 区分文件类/Web 类
  strategy:  {密级, 白名单} # 复用 SidUnit.Strategy_units（可选）
}
```
- 消费端：`SHA1(intercepted_url)` → 查 `l_sid` → 取 `n_sid` 组装 GET。
- 提供端额外本地保存：`sid → backend_url/origin`（不下发）。

---

## 6. 核心交互流程（"先拉后推"，对应 技术文档/示意图.png）

```
浏览器        消费端Agent-C(NID_C)         RM/BR(跨域)        提供端Agent-P(NID_P)        真实Web服务器
  │                  │                        │                      │                        │
  │ ①HTTP请求(TCP)   │                        │                      │                        │
  │─────────────────>│                        │                      │  ⓪ANN发布URL→SID       │
  │                  │ 解析URL,L_SID=SHA1(url)│                      │─────通告──────────────>│(RM)
  │                  │ 查表得SID(N_SID=NID_P) │                      │                        │
  │                  │ ②GET(SID,nid=NID_C,空PID,无payload)           │                        │
  │                  │───────────────────────>│──累积PID序列────────>│                        │
  │                  │                        │                      │ 校验SID(Web类型)        │
  │                  │ ③隧道DATA(B=0,空payload,携带PID序列)          │                        │
  │                  │<───────────────────────│<─────────────────────│                        │
  │                  │ 提取合法PID序列(隧道)   │                      │                        │
  │                  │ ④DATA/ACK(payload=完整HTTP请求,沿PID序列)     │                        │
  │                  │───────────────────────>│─────────────────────>│ 提取HTTP请求           │
  │                  │                        │                      │ ⑤转发───────────────>│
  │                  │                        │                      │ HTTP响应<──────────────│
  │                  │ ⑥DATA(B=0,payload=HTTP响应,沿PID序列,best-effort,可多包)              │
  │                  │<───────────────────────│<─────────────────────│                        │
  │ ⑦写回TCP         │ 还原HTTP响应            │                      │                        │
  │<─────────────────│                        │                      │                        │
```

**为什么需要 ③隧道 DATA**：GET 在转发途中由 RM/BR 累积 PID，但**消费端自己看不到这些累积的 PID**（是它发出之后才被加上的），只有提供端能看到完整 PID 序列。因此必须由提供端回送一个 DATA 把 PID 序列交给消费端，消费端才拿到合法跨域隧道，进而用 ④ 把 HTTP 请求推出去。

---

## 7. 协议适配要点

- **ACK/DATA 携带 payload**：技术文档中 B=1 的 ACK 不含负载。v1 需扩展：允许携带 PID 序列的 DATA 型报文（步骤④，方向为消费端→提供端）承载 HTTP 请求字节作为 payload。实现上可选 (a) 直接用 B=0 的 DATA 携带 payload + Destination_NID=NID_P + PID 序列；或 (b) 复用 B=1 ACK 通道并扩展其 payload 字段。**设计阶段二选一**（倾向 a，语义更清晰）。
- **隧道 DATA 的识别**：步骤③的隧道 DATA 用空/占位 payload + 约定标志位识别，消费端据此只提取 PID 序列、不交浏览器。
- **回址**：域内（PID 序列为空）走 `PeerProxys[NID]→IP`；跨域走 `PXs[PX]→IP`（PX = PID 高 16 位），复用现有逻辑。

---

## 8. 可靠传输与分片（v1 决策 + 直接回答需求文末三个疑问）

**v1 决策：CoLoR 层完全尽力而为，不做可靠传输。** 直接回答需求文末三问：

1. **"靠浏览器-代理的 TCP 保证端到端可靠"是否可行？** —— **对 CoLoR 跨域段不成立**。浏览器↔消费端代理的 TCP 只覆盖"浏览器到本地代理"这一跳；跨域共生网络段在两个代理之间，任一 TCP 连接都看不到它，**CoLoR 丢包不会被任何 TCP 重传**。
2. **建立隧道的 ACK（携带 HTTP 头+body）是否需要 CoLoR 层可靠传输？一个 IP 包能否传完？** —— v1 **不做**可靠传输；**假设单个 HTTP 请求可装入一个 IP 包**。MTU 预算：1500 − IP头20 − CoLoR DATA头(NSID16+LSID20+目的NID16+基础≈10) − PID序列(4×跳数) ≈ **可用 ~1.3–1.4 KB**。典型 GET 请求头远小于此，单包可行；**带大 body 的 POST 可能超限 → v1 不支持**（列入 §3.2）。
3. **服务端返回的数据是否需要可靠传输？** —— 同样**不做**。注意上面第 1 点：此处**不能**依赖已建立的 TCP（它不跨 CoLoR）。因此 v1 的响应为 best-effort、可多包但无重传。

**已知风险（必须明确）**：响应较大或网络丢包时，页面会损坏/不完整，浏览器可能卡住。**v1 仅适合小资源/受控演示**。
**可选的低成本鲁棒性缓解（设计阶段评估，不违背"尽力而为"主基调）**：对步骤②GET / ④请求做一次应用层超时重试，避免隧道建立丢包导致整笔事务静默失败。
**v2 演进**：直接复用现有 `slideWindow.py`（滑动窗口 + ACK + 超时重传）为响应流提供可靠传输与分片重组。

---

## 9. 非功能需求与开放设计项

**非功能需求**
- 平台：**仅 Windows**；复用 `color-agent-plus` 的 `CoLoRProtocol/ProxyLib/slideWindow`（slideWindow v1 不启用）。
- 运行环境：Python 3.8+、scapy、需管理员权限 + Npcap。
- 形态：后台服务 + 系统托盘（轻量，贴近"无感知"）。
- 性能：v1 以"功能跑通 + 小资源演示"为准，不设吞吐指标。

**开放设计项（设计阶段细化，本阶段不阻塞 PRD）**
1. **并发响应去复用**：同一 URL（同 SID）多个并发请求时，如何把响应路由回正确浏览器连接（事务 ID 放在哪个字段 / 是否串行化 / 用 SegID 空间）。
2. **§7 的 ACK 携带 payload 方案 (a) vs (b) 最终选型**。
3. **提供端取回响应的方式**：每请求新建到 origin 的 TCP，还是连接池/keep-alive。
4. **HTTP keep-alive / 多请求复用同一浏览器 TCP 连接**的处理。

---

## 10. 关键复用文件（color-agent-plus → color-proxy）

| 能力 | 源文件 |
|---|---|
| CoLoR 四类报文定义/解析 | `src/CoLoRProtocol/CoLoRpacket.py` |
| 收包(raw socket proto150)/分发/发送线程 | `src/Frontend/ColorMonitor.py` |
| SID 生成/ANN/GET/CONTROL注册/发包/全局状态 | `src/Frontend/ProxyLib.py` |
| 滑动窗口可靠传输（v2 启用） | `src/Frontend/slideWindow.py` |
| PID 序列解析工具 | `src/Tools/pid_transfer.py` |
| 配置(NID/IPv4/RM IP)采集与 data.json | `src/Frontend/logInWindow.py` |

**新增模块（color-proxy 新写）**：HTTP 正向代理监听+解析、提供端反向代理转发、URL↔SID 映射与本域表查询、Web 类型 SID 的握手编排、系统托盘/后台服务。

---

## 11. 验收 / 端到端验证方法

**演示拓扑**：两台（或两虚机/两域）各跑一份 `color-proxy`；一个 RM、（跨域时）两个 BR；提供端后端跑一个简单 HTTP 服务（如 `python -m http.server` 暴露一个小页面/小图片）。

**验收用例**
1. **服务发布**：提供端把后端 URL（如 `http://prov.local/hello.html`）发布为 SID（ANN），RM 收到并下发至消费端本域 SID 表。
2. **域内/跨域获取**：消费端浏览器设置 HTTP 代理指向消费端监听端口；访问该 URL → 页面正确显示。抓包确认链路：GET → 隧道 DATA(带 PID) → DATA/ACK(带 HTTP 请求) → DATA(带 HTTP 响应)，IP 协议号均为 150。
3. **未发布 URL**：访问一个未发布到共生网络的 URL → 浏览器收到 502/404，日志记录"非 CoLoR 服务"。
4. **小资源完整性**：小图片/小 HTML 在 best-effort 下完整返回（确认单包/少量包路径可用）。
5. **边界（记录而非通过）**：大响应/带大 body 的 POST 出现损坏/失败 → 验证与 §8 风险描述一致，作为 v2 改进依据。

**通过标准**：用例 1–4 全部通过；用例 5 行为符合 §8 预期（已知限制）。

---

## 12. 里程碑（建议，供后续排期）
- M1 协议栈移植 + 收发包打通（proto 150 收发、配置/注册/SID 表）。
- M2 提供端：ANN 发布 Web 类型 SID + GET→隧道 DATA + 接收 HTTP 请求→转发 origin→响应 DATA。
- M3 消费端：HTTP 正向代理监听/解析 + GET + 提取 PID + 推 HTTP 请求 + 还原响应回浏览器。
- M4 端到端联调（§11 用例）+ 系统托盘/后台服务封装。
