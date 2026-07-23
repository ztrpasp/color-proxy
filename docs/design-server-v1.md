# 共生网络 Web 代理终端 — 服务端（提供端）设计方案 v1

> 状态：v1 设计（设计阶段产物）。基于已批准的 `docs/PRD-v1.md`。
> 适用对象：**服务端（提供端 Provider）负责方**。本文自带 §1 共享接口契约（与请求端一致）。
> 配套：`docs/design-client-v1.md`（请求端契约级设计）。

---

## 0. Context（背景 + 已锁定决策）

PRD-v1 已批准，进入设计阶段。锁定决策：

- **复用 B=1 ACK 通道扩展 payload**：经字节级核实，`ProxyLib.DataPkt.packing()` 的 `load` 本就在 checksum 之后通用追加，`PktLength`/`Checksum` 会自动把 load 计入（`ProxyLib.py:746,792-794`）。**B=1 ACK 携带 payload 无需改动包序列化/解析**，只需构造时传 `load=` 并在接收端重定义 B=1 分支语义。
- **纯后台服务**（无系统托盘）：复用 `ColorMonitor.Monitor` 收包主循环 + `PktHandler` 线程池，去掉 PyQt，做成 Windows 控制台/后台进程。
- **每请求新建到 origin 的 TCP**：收到 HTTP 请求后，对每个请求新建一条到真实 Web 服务器的 TCP，强制 `Connection: close`，读到 EOF 即得完整响应。
- **并发：不支持，按 (SID, 消费端NID) 串行**（last-wins）：未决事务表以 `(SID, consumer_nid)` 为键，不引入事务ID。
- **HMAC 生成（实现补充）**：对发出的每个 DATA（隧道/响应）填充报文头 HMAC 字段（`Flags.C=0x04`，DATA 的 HMAC 4 字节），算法为无密钥 MD5 取末 4 字节，种子取 GET 的 `Random_Num`（R=1 时），以通过 BR 的 HMAC 校验；仅生成、不校验入站（详见 §2.5/§2.9 与 `protocol/packets.py:ColorData.post_build`）。

参考实现路径：`C:\Users\ZWD15\Desktop\color-agent-plus`（复用其 `src/CoLoRProtocol`、`src/Frontend/ProxyLib.py`、`src/Frontend/ColorMonitor.py`）。

---

## 1. 共享接口契约（两端必须一致 —— 服务端正确性的前提）

### 1.1 基本约定
- IP 协议号 **150**；报文类型沿用：GET(0x72)、DATA(0x73，B=1 即 ACK)、ANN(0x71)、CONTROL(0x74)。
- `SID = N_sid(提供方 NID,16B) ‖ L_sid(SHA1(去 query/fragment 后的 URL),20B)`（72 hex）。消费端按同法匹配本域 SID 表得到 N_sid；query 不入 SID，但随请求透传到源站。
- **v1 无可靠传输 / 无滑动窗口 / 无事务ID**；未决事务按 `(SID, 消费端NID)` 串行，后到覆盖。
- **假设单个 HTTP 请求可装入一个 IP 包**（GET 类请求头远小于 ~1.3KB 预算）；HTTP 响应可多包，best-effort，无重传。

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
- `SegID(tx)`：消费端为本次请求放入 GET 的 SegID，提供端在 ②④ 原样回带（v1 仅用于日志/对账，不作并发去复用键）。

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
- 注意：此处 `load[0]` 的 `bit2 ESS` 是**应用层负载首字节**的位（v1 恒 0，不加密），与**报文头 `Flags` 的 `C`(HMAC) 位**是两码事。报文头 HMAC（`C=0x04`）已实现并在提供端发出的 DATA 上填充（见 §2.5/§2.9）。

---

## 2. 服务端（提供端）详细设计

### 2.1 进程与线程结构（复用 + 去 UI）
复用 `ColorMonitor` 的网络栈，剥离 PyQt，落为后台进程：
- **Monitor 线程**：raw socket(`AF_INET,SOCK_RAW,150`)+`SIO_RCVALL`+`recvfrom(2048)`→均衡入 `msgQueue`（`ColorMonitor.py:951-981,922-938`）——**原样复用**。
- **PktHandler 线程池**：按首字节分发 0x71/0x72/0x73/0x74（`ColorMonitor.py:138-147`）——**复用，但替换 GET / B=1 分支为 web 逻辑**（§2.5/§2.6）。
- **OriginFetchWorker（新）**：每个 HTTP 请求一个短生命周期 worker（阻塞 I/O 回源 + 发响应），对应现有 `SendingThread` 的角色但走 web 流程。
- **启动**：纯函数式 `main()`：读配置 → 设 `PL.Nid/IPv4/rmIPv4` → 起 Monitor → 起注册线程 `ControlPktSender`（`ColorMonitor.py:745-754`）→ 发布服务（§2.4）→ 阻塞运行。

### 2.2 配置（沿用 data.json 风格，去 UI）
```
{ "nid": "<32hex>", "ipv4": "10.0.x.x", "rm_ipv4": "10.0.0.1",
  "services": [ {"url":"http://prov.local/hello.html", "origin_host":"127.0.0.1","origin_port":8000}, ... ] }
```
- `origin_host/port` 省略时默认取 url 的 host:port。

### 2.3 启动注册与域内同步（**原样复用**）
- `AnnProxy()`→`ControlPkt(1)`(tag=5)→`SendIpv4(GetRMip())`（`ProxyLib.py:63-67,443-455`）。
- 收 CONTROL tag=6：填 `PeerProxys[NID]→IP`、`PXs[PX]→IP`、置 `RegFlag=1`（`ColorMonitor.py:156-191`，`ProxyLib.py:351-380`）。

### 2.4 Web 服务发布（ANN，新增薄封装，复用现有机制）
新增 `AddWebSidUnit(url, origin)`，复用 `SidUnit`/缓存/`SidAnn`：
- `Hash_sid = SHA1(去 query/fragment 后的 url)`（`protocol/sid.py:lsid_from_url`，替代 `Sha1Hash(file)`；query 不入 SID）。
- `N_sid=Nid, L_sid=Hash_sid, nid=Nid` → `SidUnit` → 入 `CacheSidUnits` → `SidAnn()` 发往 RM（`ProxyLib.py:183-250`）。
- 发布后：`AnnSidUnits[SID]=SidUnit`（复用），并新增 `WebServices[SID]=(url, origin_host, origin_port)` 标记为 Web 类型。

### 2.5 收到 GET（state A，替换/扩展 0x72 分支）
入口：`PktHandler.run()` 的 `data[0]==0x72`（`ColorMonitor.py:197-206`），校验和后：
1. `get_pkt=GetPkt(0,Pkt=data)`；还原 `SID`，取 `nid=get_pkt.nid`、`pids=get_pkt.PIDs.copy()`、`tx=get_pkt.SegID`，并在 R=1 时取 4 字节 `Random_Num` 作 HMAC 种子（`ColorMonitor.py:510-536`）。
2. 校验 `SID∈AnnSidUnits` 且 `SID∈WebServices`（Web 类型）；否则丢弃+日志。
3. **回址判定（原样复用 `ColorMonitor.py:541-556`）**：`len(pids)==0`→域内 `PeerProxys[nid]`；否则跨域 `PX=pids[-1]>>16`→`PXs[PX]`。
4. 记未决事务：`PendingWebTx[(SID,nid)] = {return_ip, pids, tx, random_num, ts}`（同键已存在则覆盖，§2.7）。
5. **发隧道 DATA**（内容为空）：`DataPkt(1, B=0, R=(1 if 跨域 else 0), C=(1 if 有种子 else 0), SID, nid_cus=nid, SegID=tx, PIDs=pids, HMAC种子=random_num, load=bytes([0x10|0x01]))`（TUNNEL|LAST）→ `SendIpv4(return_ip, pkt.packing())`。
   - 说明：隧道 DATA 即"内容为空的普通 B=0 DATA"，PIDs/R/PID指针处理**完全沿用现有发送逻辑**（`ColorMonitor.py:653-665`），仅把"读文件内容"换成"空载 TUNNEL 标记"。

### 2.6 收到 ACK（B=1，state B，**重定义 0x73 的 B==1 分支**）
v1 无滑动窗口 → 原 B==1 的滑窗 ACK 语义在 web 模式下不存在，整段重定义（`ColorMonitor.py:408-434` 处替换）：
1. `RecvDataPkt=DataPkt(0,Pkt=data)`；还原 `SID`，`nid_cus=RecvDataPkt.nid_cus`（消费端 NID）。
2. 校验 `load[0]` 高 2 位为 `HTTP_REQUEST(0x20)`，`http_req=RecvDataPkt.load[1:]`。
3. 查 `tx=PendingWebTx.get((SID,nid_cus))`；缺失→丢弃+日志。
4. 提交 `OriginFetchWorker(tx, http_req)`（异步，避免阻塞 PktHandler）。

### 2.7 并发策略（按决策：串行 / last-wins）
- `PendingWebTx` 键 `(SID, consumer_nid)`。同键新 GET 到来→覆盖旧事务（last-wins）；ACK 命中当前事务即处理，处理完 `pop`。
- 不引入事务ID；`SegID` 仅回带不作键。（已知局限：同消费端对同 URL 的并发请求会相互覆盖，记入风险。）

### 2.8 回源（state C，每请求新建 TCP）
`OriginFetchWorker`：
1. `socket.create_connection((origin_host,origin_port), timeout=T)`。
2. **改写请求**：强制 `Connection: close`（必要时校正 `Host`），写入 `http_req`。
3. **读到 EOF**：循环 `recv` 直到对端关闭 → 完整 HTTP 响应字节 `resp`。
4. 关闭 socket。失败/超时 → 合成 `502 Bad Gateway` 文本作为 `resp`（让浏览器看到错误而非卡死）。

### 2.9 发送 HTTP 响应（state D，best-effort）
复用文件发送的报文构造，去掉滑动窗口/重传：
- 取 `tx=PendingWebTx[(SID,nid_cus)]` 的 `return_ip/pids/SegID/random_num`（HMAC 种子）。
- `resp` 按 `CHIP=1200B` 分片；对每片 `i`：
  `load = bytes([0x30 | (0x01 if 最后片 else 0)]) + chip`（HTTP_RESPONSE，末片置 LAST）
  `DataPkt(1, B=0, R=(1 if 跨域 else 0), C=(1 if 有种子 else 0), SID, nid_cus=nid_cus, SegID=tx, PIDs=pids, HMAC种子=random_num, load=load)` → `SendIpv4(return_ip, pkt.packing())`（或 `SendIpv4_batch`）。
- 顺序发送一次，无 ACK、无重传（v1）。发完 `PendingWebTx.pop((SID,nid_cus))`。
- 与现有 `send_block_packets` 的差异：内容源=HTTP 响应而非文件、无 `SendingWindow`、不注册 `update_timer` 重传。

### 2.10 复用 / 新增 一览
| 能力 | 处理 | 位置 |
|---|---|---|
| 收包主循环/分发/发包 | **原样复用** | `ColorMonitor.Monitor`、`PktHandler`、`ProxyLib.SendIpv4(_batch)` |
| RM 注册 / tag=6 同步 | **原样复用** | `ProxyLib.AnnProxy/ControlPkt`、`ColorMonitor:156-191` |
| DATA 序列化/解析(含 load) | **原样复用**（B=1 携带 payload 无需改） | `ProxyLib.DataPkt:567-797` |
| 回址判定(域内/跨域) | **原样复用** | `ColorMonitor:541-556` |
| GET 解析 | 复用 `GetPkt` | `ColorMonitor:510-536` |
| 0x72 GET 分支 | **替换为 web state A** | §2.5 |
| 0x73 B==1 分支 | **重定义为 HTTP 请求接收** | §2.6 |
| Web 发布 `AddWebSidUnit` | **新增**（薄封装 SidUnit/SidAnn，URL 哈希） | §2.4 |
| `WebServices` / `PendingWebTx` | **新增**全局表 | §2.7 |
| `OriginFetchWorker` | **新增**（回源+发响应，替代 SendingThread 角色） | §2.8/2.9 |
| 去 PyQt 后台 `main()` | **新增**入口 | §2.1 |

### 2.11 全局状态（复用 + 新增）
- 复用：`Nid/IPv4/rmIPv4/RegFlag/PeerProxys/PXs/AnnSidUnits`（`ProxyLib.py:15-38`）。
- 新增：`WebServices: {SID→(url,host,port)}`、`PendingWebTx: {(SID,consumer_nid)→{return_ip,pids,SegID,random_num,ts}}`（加锁）。

---

## 3. 边界与错误处理（服务端）
- GET 的 SID 未发布 / 非 Web 类型 → 丢弃 + 日志（消费端最终超时回 504）。
- ACK 无匹配未决事务 / `load[0]` 非 REQUEST → 丢弃 + 日志。
- 回源连接失败/超时 → 合成 `502` 作为响应发回（state D 正常路径）。
- HTTP 请求超过单包（v1 不支持）→ 按收到字节处理并日志告警。
- 响应过大/丢包 → best-effort，可能不完整（PRD §8 已知风险）。

## 4. 验证（服务端为主）
1. **单元**：`AddWebSidUnit` 的 `SID` 正确性；隧道 DATA / 响应 DATA 的字节布局（用 `CoLoRpacket.ColorData` 反解校验 `load[0]`、PIDs、Checksum）；B=1 带 payload 的 `DataPkt` 往返（packing→parse `load`）。
2. **桩消费端联调**：写测试脚本（参考 `src/Test/end-to-end-client.py`/`end-to-end-server.py`）：发 GET→收隧道 DATA→提 PID→发 B=1 ACK(载一条 `GET /hello.html HTTP/1.1` 原始请求)→收响应 DATA→拼接校验与后端一致。
3. **端到端**：后端 `python -m http.server 8000`；提供端发布 `http://prov.local/hello.html`→origin `127.0.0.1:8000`；配合真实消费端 + 浏览器（PRD §11 用例 1/2/4），抓包确认链路全程 proto=150 且 `load[0]` 类型正确。
4. **错误用例**：未发布 URL（消费端 504）、origin 关停（提供端回 502）。

## 5. 里程碑（服务端）
- S1：去 UI 后台骨架 + Monitor/PktHandler 复用 + 配置/注册/域内同步打通。
- S2：`AddWebSidUnit` 发布 + state A（GET→隧道 DATA）。
- S3：state B/C/D（B=1 接收→回源→响应 DATA），桩消费端联调（§4.2）。
- S4：端到端 + 错误用例（§4.3/4.4）。
