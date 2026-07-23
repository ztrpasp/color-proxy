# 共生网络 Web 代理终端 — 请求端（消费端）设计方案 v1（契约级）

> 状态：v1 设计（契约级）。基于已批准的 `docs/PRD-v1.md`。
> 适用对象：**请求端（消费端 Consumer）负责方**。本文自带 §1 共享接口契约（与服务端一致）。
> 配套：`docs/design-server-v1.md`（服务端详细设计）。
> 说明：本项目当前由服务端负责方主导，本文仅把请求端职责定义到"契约 + 状态机"层面，内部实现由请求端负责方细化。

---

## 0. Context（背景 + 已锁定决策）

PRD-v1 已批准。与请求端相关的锁定决策：
- 接入方式：**HTTP 正向代理**（固定端口，用户设系统/浏览器代理）。
- **仅服务已发布到共生网络的 URL**：URL 不在本域 SID 表中→回 502/404。
- CoLoR 段 **best-effort**，无可靠传输 / 无滑动窗口 / 无事务ID；并发同 SID 请求由消费端自行串行。
- HTTP 请求假设单包可装下；HTTP 响应可多包，best-effort。

---

## 1. 共享接口契约（两端必须一致）

### 1.1 基本约定
- IP 协议号 **150**；报文类型：GET(0x72)、DATA(0x73，B=1 即 ACK)、ANN(0x71)、CONTROL(0x74)。
- `SID = N_sid(提供方 NID,16B) ‖ L_sid(SHA1(去 query/fragment 后的 URL),20B)`（72 hex）。消费端按同法匹配本域 SID 表得到 N_sid；query 不入 SID，但随请求透传到源站。
- **v1 无可靠传输 / 无滑动窗口 / 无事务ID**；未决事务按 `(SID, 消费端NID)` 串行，后到覆盖。
- **假设单个 HTTP 请求可装入一个 IP 包**；HTTP 响应可多包，best-effort，无重传。

### 1.2 握手状态机（"先拉后推"，对应 技术文档/示意图.png）
```
消费端C(NID_C)                                   提供端P(NID_P)
  │ ① GET(NSID=NID_P, LSID=SHA1(url), nid=NID_C, S=1,SegID=tx, 无payload) ──────────────▶│  校验SID∈已发布&Web类型
  │                                                                                       │  记未决事务(SID,NID_C)
  │ ◀────────── ② 隧道DATA(B=0, nid_cus=NID_C, SegID=tx, PIDs=回址, load=[TUNNEL|LAST]) ──│  (空内容，只为给C送回PID序列)
  │ 从包头PID_List提取合法PID序列(隧道)                                                    │
  │ ③ ACK(B=1, nid_pro=NID_P, nid_cus=NID_C, SegID=tx, PIDs=反向路径, load=[REQUEST]+HTTP请求字节) ─▶│ 提取HTTP请求→回源
  │ ◀──── ④ 响应DATA(B=0, nid_cus=NID_C, SegID=tx, PIDs=回址, load=[RESPONSE|可选LAST]+分片) × N ─────│ best-effort,可多包
```
- **为何需要 ②**：GET 途中的 PID 是 RM/BR 在 C 发出之后累积的，**C 自己看不到**，只有 P 看得到完整序列；必须由 P 回送 DATA，C 才能拿到合法跨域隧道，进而用 ③ 把 HTTP 请求推出去。
- `SegID(tx)`：消费端为本次请求放入 GET 的 SegID，提供端在 ②④ 原样回带（v1 仅用于日志/对账）。

### 1.3 `load[0]` 前缀字节约定（扩展现有 `DataFlag`，`ColorMonitor.py:76-78`）
现有：`bit0 LAST=0x1`（最后分片）、`bit2 ESS=0x4`（加密，v1 恒 0）。**v1 新增高 2 位作 WebMsgType（bit4-5）**：

| WebMsgType (bit5,bit4) | 值 | 含义 | 方向 | 内容 load[1:] |
|---|---|---|---|---|
| 00 | 0x00 | 文件模式/保留 | — | （v1 web 不用） |
| 01 | 0x10 | **TUNNEL** 隧道建立 | P→C | 空 |
| 10 | 0x20 | **HTTP_REQUEST** | C→P | 完整 HTTP 请求字节 |
| 11 | 0x30 | **HTTP_RESPONSE** | P→C | HTTP 响应分片 |

- TUNNEL / REQUEST 单包，`LAST=1`。RESPONSE 多包时仅最后一片置 `LAST`。
- 消费端据 `load[0]` 区分"②隧道(空)"与"④响应(有内容)"，避免把空隧道包误当响应。
- 注意：`load[0]` 的 `bit2 ESS` 是应用层负载位（v1 恒 0，不加密），与报文头 `Flags.C`(HMAC) 不同。提供端发出的 DATA 已填 HMAC（见服务端设计 §2.5/§2.9）；消费端 GET/ACK **当前不带 HMAC**。

---

## 2. 请求端（消费端）设计 —— 契约级

### 2.1 进程形态
- 固定端口运行 HTTP 正向代理（默认 8910）；用户一次性设置系统/浏览器 HTTP 代理。
- 复用 `color-agent-plus` 的 CoLoR 网络栈（raw socket 收 proto 150 + `SendIpv4` 发）与配置（`Nid/IPv4/rmIPv4`）、RM 注册、本域 SID 表获取。

### 2.2 核心流程（每条浏览器 TCP 连接 / 每个请求）
1. 解析 HTTP 请求，取**完整 URL** 与完整请求字节；`L_SID=SHA1(去 query/fragment 后的 URL)`（query 不入 SID、但随请求透传），查本域 SID 表得 `SID`(含 N_sid)。命中→继续；未命中→回 502/404。
2. 发 **GET**：`NSID/LSID/nid=NID_C`，`S=1` 且 `SegID=本次tx`，发往 RM（`SendIpv4(GetRMip(), ...)`）。记 `pending[(SID,NID_C)]=浏览器socket`（与服务端键一致，串行）。
3. 收 **隧道DATA(B=0, load[0]=TUNNEL)**：从包头 `PID_List` 提取 PID 序列。
4. 发 **ACK(B=1)**：`nid_pro=该 SID 的提供方NID`、`nid_cus=NID_C`、`SegID=tx`、`PIDs=按现有 ACK 约定的反向路径`（参考现有 ACK 构造 `RecvDataPkt.PIDs[1:][::-1]`）、`load=bytes([0x20|0x01])+完整HTTP请求字节`（HTTP_REQUEST|LAST）。
5. 收 **响应DATA(B=0, load[0]=HTTP_RESPONSE)**：按到达顺序拼接 `load[1:]`，遇 `LAST` 结束，原样写回浏览器 TCP，关闭/复用连接。

### 2.3 超时与错误
- 步骤 3/5 等待超时 → 对浏览器返回 504（v1 不在 CoLoR 层重传）。
- 未命中 SID 表 → 502/404。

### 2.4 契约依赖（务必遵守）
- §1.2 状态机与 §1.3 `load[0]` 约定。
- GET 必须 `S=1` 并在 `SegID` 放置 tx，ACK 原样回带。
- 并发同 `(SID,NID_C)` 请求由消费端自行串行（实现用**每-SID 锁**把 GET→隧道→ACK→响应整个往返串起来，与服务端 last-wins 策略对齐；见 `consumer/proxy.py:orchestrate_request`、`consumer/state.py:sid_lock`）。
- 单个 HTTP 请求需可装入一个 IP 包（v1 不做请求分片）。

### 2.5 验证（请求端为主）
- 桩提供端：写测试脚本模拟服务端（收 GET→回隧道 DATA(带 PID)→收 B=1 ACK 解出 HTTP 请求→回响应 DATA），校验代理能把响应正确写回浏览器。
- 端到端：与真实服务端 + 浏览器联调（PRD §11 用例 1/2/4）。
