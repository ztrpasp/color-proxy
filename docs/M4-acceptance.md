# M4 真机验收手册（L3 隧道模式）

> 对应 `docs/design-l3-v2.md` §11 的 M4：**被动 FTP 上传下载 / 一条视频流连续 5 分钟 /
> MySQL 增删改查**。
> 前置：M2 的两端装配已完成（`colorproxy/l3/service.py`），M1c 两半已在真机通过。
> 截至 2026-09-21。

---

## 0. 为什么必须两台机器

**同一个内核上跑不了这三个用例**，而且失败方式是"看起来通过了"：

按 §2.5，服务地址 `172.10.9.2` 是提供端 color0 自己的地址；消费端 tun 地址
`10.99.1.1` 是消费端 color0 自己的地址。两端在同一台机器上时，**两个内层端点都是
本机地址**：

- 客户端 `connect("172.10.9.2", …)` 被内核直接投给本地协议栈，`172.10.9.2/32 → color0`
  那条捕获路由根本轮不上；
- 就算正向侥幸进了隧道，源站回程的目的 `10.99.1.1` 又是本机地址，同样环回。

结果是 **TCP 连接建得成功、应用跑得起来，但一个包都没经过隧道**。D9 的物理地址方案
一样（`172.10.0.2` 同样是本机地址）。

因此 M4 必须：**两台机器**，或两个 VM，或一台物理机 + 一个 VM。单机上能做的那部分
已经写成离线回归 `tests/test_l3_acceptance.py`（见 §5），跑真客户端之前先跑它。

---

## 1. 环境（§2.5 虚服务地址方案，两端各一次）

### 提供端机器 P

```powershell
# 1) 起代理（会自己创建 color0、配 172.10.9.2/24、MTU 1280、加 10.99.1.0/24 路由）
#    先把 config.json 的 l3.enabled 改成 true
python -m colorproxy.main config.json -v

# 2) 确认 color0 就绪（MTU 必须是 1280）
Get-NetIPInterface -AddressFamily IPv4 |
  Select-Object InterfaceAlias, WeakHostSend, WeakHostReceive, NlMtu

# 3) 防火墙：Wintun 是新网卡，NLA 大概率归"公用网络"，入站几乎全拦
Set-NetConnectionProfile -InterfaceAlias "color0" -NetworkCategory Private
New-NetFirewallRule -DisplayName "color-tun" -Direction Inbound -InterfaceAlias "color0" -Action Allow
```

> §2.5 下**不需要**任何弱主机模型开关（服务地址就在 color0 自己身上）。
> 代理启动时会打印一行"服务地址全部绑在 color0 自己身上……不需要弱主机模型开关"
> 来确认。若打印的是告警，说明 `l3.services[].ip` 配的不是 `l3.tun_ip`，回到 D9 方案
> 了，按 §2.3 开四个开关。

**三个服务端都必须 bind `0.0.0.0`**（§2.6 第 4 条）。只听 `127.0.0.1` 的话包到了也
没人收，症状与丢包完全一样：

```powershell
netstat -ano | findstr ":21 :3306 :5004"
```

### 消费端机器 C

```powershell
# config-consumer.json 的 l3.enabled 改成 true，capture_routes 已是 172.10.9.2/32
python -m colorproxy.consumer.main config-consumer.json -v
```

启动时若打印 **"拒绝启动 L3：以下外层目的地址落进了 l3.capture_routes"**，说明两端在
同一个 CoLoR 域（§2.4 第 3 条不成立），外层包会被自己的 tun 吞掉。必须换域部署。

### 两端必须逐字节对齐的三项

| 项 | 提供端 | 消费端 | 不一致的症状 |
|---|---|---|---|
| 消费端 tun 地址 | `l3.peers[0].tun_ip` | `l3.tun_ip` | 隧道建得起来，但每个上行包都被 `src_bind_drop` 拦掉（D14） |
| 服务地址 | `l3.services[].ip` | `capture_routes` 覆盖它 | 流量不进 tun，或进了算不出 SID（`sid_miss`） |
| MTU / MSS | 1280 / 1240 | 1280 / 1240 | 小请求正常、一传大数据就卡死（§6.2） |

### 最小连通性判据（做完再往下）

ICMP 不走隧道（D11），所以**不能用 ping**。用 TCP：

```powershell
Test-NetConnection 172.10.9.2 -Port 8000      # 只看三次握手
curl http://172.10.9.2:8000/hello.html
```

---

## 2. 用例一：被动 FTP 上传下载

### 发布

`config.json` 的 `l3.services[]` 需要**两条**：

```json
{ "proto": "tcp", "ip": "172.10.9.2", "port": 21, "desc": "FTP 控制" },
{ "proto": "tcp", "ip": "172.10.9.2", "port": 0,  "desc": "FTP 被动数据（通配）" }
```

数据连接用临时端口，逐个发布 SID 不现实，只能通配（§3.3）。**通配是另一条 SID、
另一条隧道**：控制连接与数据连接分别走两条，两端各持两条隧道记录。

> 若 FTP server 支持配置被动端口段（如 50000–50100），**优先按段逐条发布**，比通配
> 整机干净得多（§8.3）。代价是配置里多几十行。

### 步骤

1. P 上起 FTP server（`pyftpdlib` 或 FileZilla Server），`bind 0.0.0.0:21`，
   **被动模式**，被动端口段若可配则设 50000–50010 并逐条发布。
2. C 上用 FileZilla / `ftp` 客户端连 `172.10.9.2:21`，**必须选被动模式（PASV）**。
3. 下载一个 ≥ 10 MB 的文件，再上传一个 ≥ 10 MB 的文件，校验 MD5 一致。

### 判据

- 两端计数器里 `tunnel_up = 2`（控制 + 通配各一条）。
- `admit_drop = 0`、`src_bind_drop = 0`、`no_tunnel_drop = 0`。
- 上传下载的 MD5 与原文件一致。

### 已知不支持

**主动模式 FTP 一定不通**（§8.1）：主动模式要服务端反向发起连接，CoLoR 是拉驱动，
提供端无法主动建隧道。客户端必须显式选被动模式，这不是缺陷、是结构性限制。

---

## 3. 用例二：一条视频流连续 5 分钟

### 硬约束（先读这一条，否则一定踩）

> **内层 UDP 数据报净载荷必须 ≤ 1252 字节**（= 1280 − 20 IP − 8 UDP）。

超过就会被内核按 tun MTU 分片，而分片按 D15 **一律丢弃、不重组**。症状是
"小包通、大 UDP 静默丢"，而且在 `frag_drop` 之外没有任何迹象。

RTP/RTCP 默认远小于此值；编码器若可配 MTU，**配 1200 更稳**。

### 步骤

1. P 上发 RTP 流到 `172.10.9.2:5004`（VLC「串流」→ RTP/UDP，或 ffmpeg
   `-f rtp rtp://…:5004`），MTU 配 1200。
2. `config.json` 发布 `{ "proto": "udp", "ip": "172.10.9.2", "port": 5004 }`。
3. C 上用 VLC 打开 `rtp://@:5004`，**连续播放 5 分钟**，期间记录计数器。

### 判据

- 播放全程无中断、无明显花屏。
- `frag_drop = 0`（有值就说明净载荷超了 1252，回去调编码器 MTU）。
- `tunnel_up = 1` 且全程不变（D1：隧道长期有效，不刷新不回收）。
- `tun_rx` / `colr_tx` 持续增长且比值接近 1:1。

### 性能预期（重要）

数据面目前**每包一次 scapy 解析 + 构造**（`l3/provider.py`、`l3/consumer.py` 都用
`ColorData`），是已知的逐包开销。§10.3 估计约几千 pps 到顶：**5 Mbps 视频（约 500
pps）能扛，50 Mbps 不行**。M5「去 scapy 数据面」尚未做，本轮按用户决定推迟。

所以这条用例**请用低码率流**（≤ 5 Mbps）。卡顿先看是不是撞了 pps 上限，不要先怀疑
隧道——判据是 `tun_rx` 的增速停在某个数上不动了。

---

## 4. 用例三：MySQL 增删改查

### 步骤

1. P 上起 MySQL，`bind-address = 0.0.0.0`，发布
   `{ "proto": "tcp", "ip": "172.10.9.2", "port": 3306 }`。
2. C 上 `mysql -h 172.10.9.2 -P 3306 -u <user> -p`。
3. 建库建表 → `INSERT` / `SELECT` / `UPDATE` / `DELETE` 各若干条 →
   再跑一次 ≥ 10 万行的 `SELECT`（把大响应也覆盖到）。

### 判据

- 四类语句都正确返回。
- `tunnel_up = 1`：一条长连接、多次往返**共用同一条隧道**（§5.1，隧道以 SID 为单位
  而非以流为单位）。再开第二个 `mysql` 客户端，`tunnel_up` 仍应是 1。
- 大 `SELECT` 不卡死。**卡死在大响应上 = MSS clamp 只做了一侧**（§6.2）：查两端的
  `mss_clamped` 是否都 > 0，以及 `Get-NetIPInterface` 里两端 color0 的 MTU 是否都是
  1280。

---

## 5. 跑真客户端之前：先跑离线回归

`tests/test_l3_acceptance.py` 把三个用例**各自特有的危险点**在假链路上钉死了，
不需要管理员、不需要第二台机器：

```bash
PYTHONDONTWRITEBYTECODE=1 python tests/test_l3_acceptance.py   # 8/8
```

它覆盖的（也就是不必在真机上重新摸索的）：

| 用例 | 钉住的东西 |
|---|---|
| 被动 FTP | 控制 + 通配是**两条独立隧道**、回程按内层源端口各自反推 SID、端口不串台（rev.2 的单键 `PeerTun` 正是死在这里，D14） |
| 被动 FTP | 通配只放宽**目的**粒度到主机级；换 IP 仍拦、伪造内层源仍拦（§8.3 末段） |
| 视频流 | 600 包持续流只握手一次、无 per-packet 状态；净载荷正好 1252 必过；超限与分片分别计 `mtu_drop` / `frag_drop`，不静默 |
| MySQL | 200 次小往返共用一条隧道；第二条连接不再发 GET；未发布端口即使持有合法 SID 也打不进去 |

它**不覆盖**的（只有真机能验）：真 tun 读写、内核注入与路由选择、真实客户端的协议
行为（FTP 的 PASV 协商、MySQL 的握手包、RTP 的时序）、以及吞吐与时延。

---

## 6. 出问题时看哪个计数器

两端每 5 s 打一行快照（内容没变就不打）。按现象对号入座：

| 现象 | 先看 | 最可能的原因 |
|---|---|---|
| 完全不通，`tun_rx = 0` | 消费端 `tun_rx` | 路由没生效，流量没进 tun。`route print` 看 `172.10.9.2` 的下一跳 |
| `tun_rx` 涨但 `sid_miss` 同步涨 | `sid_miss` | 算出的 SID 不在表中：服务没发布，或两端服务串不一致（IP/端口/协议任一不同即完全不同的哈希） |
| 隧道建起来了但一个包不过 | 提供端 `src_bind_drop` | 消费端 `l3.tun_ip` 与提供端 `l3.peers[].tun_ip` 不一致（D14） |
| 能连上但访问别的端口也通 | 提供端 `admit_drop` | 发布了通配 `:0`，目的粒度退化到主机级（§8.3，预期行为） |
| 小请求正常、大数据卡死 | 两端 `mss_clamped` | MSS clamp 只做了一侧，或某端 MTU 不是 1280（§6.2） |
| 小包通、大 UDP 静默丢 | `frag_drop` | 内层 UDP 净载荷超过 1252（D15） |
| 跑着跑着断了、重启消费端才好 | `no_tunnel_drop` | D1 的已知风险：提供端重启 / BR PID 表老化会让隧道静默失效。把消费端 `l3.tunnel_redetect_sec` 设成 30 打开重探兜底（§8.4） |
| 回程查不到隧道 | `no_peer_drop` | 内层目的地址没登记在 `l3.peers[]` |

`load0_mismatch` **不影响转发**，只作诊断（D13）：对端实现的 `load[0]` 与本文不一致
时会涨，包照常处理。

---

## 7. 做完 M4 要回填的事

1. 把三个用例的实测结果（通过 / 不通过、卡在哪一步、计数器快照）补进
   `docs/HANDOVER-l3.md` 的里程碑表。
2. 视频流若撞到 pps 上限，把实测的 pps 数字记下来——那是 M5「去 scapy」的立项依据。
   **性能数字与压测脚本按既定规矩只进 `perf/bench` 分支，不进 `dev_tun`。**
3. §8.5 的四个问题（上行是否需要 HMAC、`Random_Num` 长期复用、BR 的 PID 是否会老化、
   单 SID 有无速率限制）在真机上会给出答案，答案直接决定 D1 能否成立，务必记录。
