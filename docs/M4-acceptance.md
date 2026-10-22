# M4 真机验收手册（L3 隧道模式）

> 对应 `docs/design-l3-v2.md` §11 的 M4：**被动 FTP 上传下载 / 一条视频流连续 5 分钟 /
> MySQL 增删改查**。
> 前置：M2 的两端装配已完成（`colorproxy/l3/service.py`），M1c 两半**已在真机通过**
> （2026-09-21）。
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
# 0) 先起源站，且必须 bind 0.0.0.0 —— 只听 127.0.0.1 的话 L3 这条路一定哑火（见下）
python tools/origin_server.py --host 0.0.0.0 --port 8000

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

> **弱主机开关（按 §2.3 的 rev.4 勘误）**：§2.5 省掉的是**服务网卡上那两个**，
> **color0 自己的两个仍要开**——M1b 唯一成功的那组实验里它们是开着的，从未被隔离
> 验证过能关，而不开时的症状是"包写进 tun 了、`tun_tx` 也涨，协议栈连 RST 都不回"。
> 代理只检查告警、不改系统配置（§9.1），所以要手工执行一次：
>
> ```powershell
> netsh interface ipv4 set interface "color0" weakhostsend=enabled
> netsh interface ipv4 set interface "color0" weakhostreceive=enabled
> ```
>
> 若启动日志里的告警提到了**第二张网卡**，说明 `l3.services[].ip` 配的不是
> `l3.tun_ip`，那是回到 D9 方案了，按 §2.3 四个全开。

**全部服务端都必须 bind `0.0.0.0`**（§2.6 第 4 条）。只听 `127.0.0.1` 的话包到了也
没人收，症状与丢包完全一样——这是整条链路**最常见的哑火点**，而且计数器上看不出来：
隧道建得起来、`tun_tx` 照涨，客户端只看到超时（防火墙吃掉 RST 时）或拒绝连接。

```powershell
netstat -ano | findstr ":8000 :21 :3306 :5004 :8554"   # 左列必须是 0.0.0.0:xxxx，不能是 127.0.0.1:xxxx
```

> **两条路径为什么表现不一样**：v1 内容级的回源是提供端本机发起的普通 TCP 连接，
> `services[].origin_host` 写成 `127.0.0.1` 就能连上（写 `172.10.0.2` 而源站只听回环
> 时报「目标计算机积极拒绝连接」）；L3 服务级则是把内层包直接注入协议栈，目的地址
> 恒为 `l3.services[].ip`（=`172.10.9.2`），源站不在那个地址上听就没人收。**所以
> v1 通不代表 L3 通。** 代理启动时会对每条 TCP 服务探一次，没人监听会打一行告警。

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

### 最小连通性判据：用 HTTP 测 L3（做完再往下）

HTTP 比 FTP / 视频 / 数据库都好测，而且**它本来就能当端点级服务发**——`config.json`
里那条 `{ "proto": "tcp", "ip": "172.10.9.2", "port": 8000 }` 就是。L3 这一侧根本不看
HTTP：它从内层 IP 头读 `(proto, dst_ip, dst_port)` 就去算哈希了，载荷是 HTTP 还是
MySQL 协议它不关心。

ICMP 不走隧道（D11），所以**不能用 ping**。用 TCP：

```powershell
Test-NetConnection 172.10.9.2 -Port 8000      # 只看三次握手
curl http://172.10.9.2:8000/hello.html
```

> ⚠ **curl / 浏览器绝对不能配 `:8910` 代理。** 配了就走 v1 内容级那条路了，测的是
> 另一套机制。消费端分辨两种粒度**不靠 URL，靠流量从哪个入口进来**：
>
> | | 内容级（v1） | 服务级（L3） |
> |---|---|---|
> | 入口 | HTTP 正向代理 `:8910` | tun 设备 + 主机路由 |
> | 查表键 | `SHA1(去 query 的 URL)` | `SHA1("tcp://ip:port")` |
> | 代码 | `consumer/proxy.py` → `lookup_by_url()` | `l3/consumer.py` → `lookup_by_service()` |
>
> 两者查同一张 `_sid_table`，不冲突是因为哈希域按 scheme 天然隔离（内容级恒为
> `http`/`https`，服务级恒为 `tcp`/`udp`，§3.1/D12）。所以**同一个源站可以两种粒度
> 同时发布**，互不干扰——这正好是一组 A/B 对照。

**没有 RM 时**消费端拿不到服务级 SID（每个包都 `sid_miss`）。用 §9.2 的降级路径，在
`config-consumer.json` 的 `l3` 段预置：

```json
"static_services": [
  { "proto": "tcp", "ip": "172.10.9.2", "port": 8000,
    "provider_nid": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1" }
]
```

注意这只解决"SID 表"这一个环节。**握手仍要发 GET 给 RM**，所以完整链路依旧需要
RM/BR；不接 CoLoR 而只想验内层链路的话，跑 `tools/l3_m1c_loopback.py`（它已经做了
一次完整的 HTTP 请求-响应穿过真 tun）。

---

## 2. 用例一：被动 FTP 上传下载

### 2.1 起 FTP 源站（P 上）

```powershell
pip install pyftpdlib
python tools/ftp_server.py --make-testfile 10
```

默认：`0.0.0.0:21`、账号 `color/color`、根目录 `./ftproot`、被动端口段 `50000-50010`，
并顺手造一个 10 MB 的 `test-10mb.bin` 供下载用例。**不需要管理员**——Windows 对
1024 以下的端口没有特权限制。常用开关：

| 开关 | 用途 |
|---|---|
| `--passive-ports 50000-50004` | 改被动端口段（段越小，要发布的 SID 越少） |
| `--print-services` | 只打印要粘进 `config.json` 的 `l3.services[]`，不起服务 |
| `--make-testfile 100` | 造更大的测试文件 |
| `--anonymous` | 额外允许匿名只读登录 |
| `--masquerade 172.10.9.2` | PASV 回复里强制通告这个地址（默认不用，见 2.5） |

起好后确认监听地址是 `0.0.0.0`：

```powershell
netstat -ano | findstr ":21 "
```

### 2.2 发布（改 `config.json` 的 `l3.services[]`）

被动数据连接用的是端口段里的端口，**每个端口都是另一条 SID、另一条隧道**（§3.3）。
两种写法，脚本把两份都打出来：

```powershell
python tools/ftp_server.py --print-services --passive-ports 50000-50010
```

- **逐条发布**（推荐）：控制口 21 + 段里每个端口各一条。目的粒度精确到端口，
  `admit_drop` 才有意义。代价是配置里多十几行。
- **通配**：只发 `21` 和 `{"port": 0}` 两条。配置短，但目的粒度退化到主机级——
  持有这条 SID 的消费端能打到 `172.10.9.2` 的**任意 TCP 端口**（§8.3，预期行为）。

改完 `config.json` **要重启提供端代理**（新 SID 在启动时发 ANN）。消费端也要重启：
本域 SID 表是启动时从 RM 拉一次的。没有 RM 时在消费端 `l3.static_services[]` 里
预置同样的三元组（§9.2）。

### 2.3 客户端（C 上，**必须被动模式**）

```powershell
# 下载
curl --ftp-pasv -u color:color ftp://172.10.9.2/test-10mb.bin -o test-10mb.bin
# 上传
curl --ftp-pasv -u color:color -T .\upload.bin ftp://172.10.9.2/
# 校验（和 P 上 ftproot\ 里的对比）
Get-FileHash .\test-10mb.bin -Algorithm MD5
```

FileZilla：站点管理器 → 传输设置 → **被动**。Windows 自带的 `ftp.exe` **只有主动
模式，不能用**（见 2.5）。

### 2.4 判据

- 提供端 `tunnel_up`：逐条发布时 = 1（控制）+ 实际用到的被动端口数；通配发布时 = 2。
- `admit_drop = 0`、`src_bind_drop = 0`、`no_tunnel_drop = 0`、`sid_miss = 0`、`frag_drop = 0`。
- 上传、下载两个方向的 MD5 都与原文件一致。
- 10 MB 能传完。**卡在几十 KB = MSS clamp 只做了一侧**（§6.2）：查两端 color0 的
  MTU 是否都是 1280、`mss_clamped` 是否都 > 0。

### 2.5 已知不支持与常见坑

- **主动模式一定不通**（§8.1）。主动模式要服务端反向 connect 客户端，CoLoR 是拉驱动，
  提供端建不了隧道。这是结构性限制，不是缺陷。
- **登录成功、`ls` 就卡住** = 数据连接那条 SID 没发布。`LIST` 也走数据连接，所以
  "能登录"只证明控制口那条隧道通。看消费端 `sid_miss` 是不是在涨。
- **PASV 回复的地址**：pyftpdlib 用控制连接的本地地址回复，经隧道进来时正好是
  `172.10.9.2`，一般不用管。客户端若报"PASV 给的地址连不上"，加
  `--masquerade 172.10.9.2`。
- **防火墙**：§1 第 3 步那条 color0 入站放行规则要在，否则数据连接的 SYN 进去了
  没人应答，表现与丢包一样。

---

## 3. 用例二：一条视频流连续 5 分钟

### 3.0 先读这条：**不能用推流**

CoLoR 是"先拉后推"，**隧道只能由消费端的第一个上行包触发**（消费端从 tun 读到包 →
算 SID → 发 GET → 建隧道）。提供端**无法主动**朝消费端开一条流。

所以 `VLC 串流 → RTP/UDP` 直接往消费端推是**建不了隧道**的（rev.5 勘误：本节旧版
写的就是这种推流，不成立）。能跑的只有两类：

| | 方案 A：请求驱动的 RTP/UDP | 方案 B：RTSP over **TCP** |
|---|---|---|
| 测到的 | UDP 路径、1252 净载荷硬约束、长时间单隧道 | 真播放器、真解码、TCP 长连接 |
| 画面 | 无（合成码流，判据靠统计） | 有 |
| 工具 | `tools/rtp_video.py`（本仓库） | MediaMTX / ffmpeg + ffplay / VLC |

两个都跑最好：A 给精确判据，B 证明真播放器能用。

### 3.1 硬约束：内层 UDP 净载荷 ≤ 1252 字节

> `1280（tun MTU） − 20（IP） − 8（UDP） = 1252`

超过就会被内核按 tun MTU 分片，而分片按 D15 **一律丢弃、不重组**。症状是"小包通、
大 UDP 静默丢"，除了 `frag_drop` 没有任何别的迹象。RTP/RTCP 默认远小于此值；
编码器若可配 MTU，**配 1200 更稳**（`tools/rtp_video.py` 默认就是 1200，超限会直接
拒绝启动而不是让你去猜）。

### 3.2 方案 A：请求驱动的 RTP（`tools/rtp_video.py`）

客户端先发一个订阅报文（KICK）把隧道拉起来，服务端再朝它发流——发出去的包源端口
就是 5004，回程按内层**源**三元组反推 SID（§7.2），与上行严格对称。

```powershell
# P 上：0.0.0.0:5004，500 pps × 1200 B ≈ 4.8 Mbps，一直发到 Ctrl+C
python tools/rtp_video.py --role server --seconds 0

# C 上：订阅并连续收 5 分钟，每 5 秒打一行统计
python tools/rtp_video.py --role client --server 172.10.9.2 --seconds 300
```

`config.json` 发布：`{ "proto": "udp", "ip": "172.10.9.2", "port": 5004 }`（已预置）。

客户端每 5 秒打印一行：`已收 N 包 / X MB，pps，Mbps，丢 n（x%），乱序/重复 m，
最长中断 t ms`，结束时给三条 PASS/FAIL。调码率用 `--pps`（服务端），调包大小用
`--payload`（含 12 字节 RTP 头，上限 1252）。

想灌真实媒体数据而不是合成码流：让 ffmpeg 把 RTP 打到**本机** 5004 端口之前那一段
不成立（同样是推流），改用方案 B。

### 3.3 方案 B：RTSP over TCP（真播放器）

关键是 **`-rtsp_transport tcp`**：RTSP 的控制与数据都走那一条 TCP 连接（interleaved），
全程由客户端发起 → 一条隧道、一条 SID。默认的 UDP 传输模式**不行**：那是服务端
主动朝客户端的 RTP 端口发包，没有对应隧道，表现为 `no_tunnel_drop` / `sid_miss`。

```powershell
# P 上：用 MediaMTX（单个 exe，https://github.com/bluenviron/mediamtx/releases）
.\mediamtx.exe                       # 默认 RTSP 监听 :8554
# 另开一个窗口，把一个文件循环推进去（也可以接真摄像头 -f dshow -i video=...）
ffmpeg -re -stream_loop -1 -i sample.mp4 -c copy -f rtsp rtsp://127.0.0.1:8554/live

# config.json 发布：{ "proto": "tcp", "ip": "172.10.9.2", "port": 8554 }，重启代理

# C 上
ffplay -rtsp_transport tcp rtsp://172.10.9.2:8554/live
# VLC：打开网络串流 → 输入 rtsp://172.10.9.2:8554/live，
#      并在 输入/编解码器 里勾选「RTP over RTSP (TCP)」
```

MediaMTX 默认监听 `0.0.0.0`，确认一下：`netstat -ano | findstr ":8554"`。

### 3.4 判据

方案 A（客户端自己打印，三条都要 PASS）：

- 连续接收 ≥ 285 秒（计划 300 秒的 95%）；
- 丢包率 < 1%；
- 最长中断 < 1000 ms。

两端计数器还要满足：

- `frag_drop = 0`（有值就是净载荷超了 1252，回去调 `--payload` 或编码器 MTU）；
- `tunnel_up = 1` 且**全程不变**（D1：隧道长期有效，不刷新、不回收）；
- `tun_rx` / `colr_tx` 持续增长且比值接近 1:1；
- `no_tunnel_drop = 0`（中途变非零 = 隧道静默失效了，把消费端
  `l3.tunnel_redetect_sec` 设成 30 打开重探兜底，§8.4）。

方案 B：播放 5 分钟不中断、不花屏；`tunnel_up = 1`；`frag_drop` 恒为 0（TCP 路径不
会碰到 UDP 分片）。

### 3.5 性能预期（重要，先看这条再判断卡顿）

数据面目前**每包一次 scapy 解析 + 构造**（`l3/provider.py`、`l3/consumer.py` 都用
`ColorData`），是已知的逐包开销。§10.3 估计约几千 pps 到顶：**5 Mbps 视频（约 500
pps）能扛，50 Mbps 不行**。M5「去 scapy 数据面」尚未做（本轮按用户决定推迟）。

所以这条用例**请用低码率流**（≤ 5 Mbps）。卡顿先看是不是撞了 pps 上限，不要先怀疑
隧道——判据是 `tun_rx` 的增速停在某个数上不动了，而客户端统计里的 pps 明显低于
服务端设定的 `--pps`。把那个数记下来，它就是 M5 的立项依据（数字只进 `perf/bench`）。

---

## 4. 用例三：MySQL 增删改查

### 4.1 起 MySQL（P 上）

装 MySQL 8 Community（或 MariaDB），装完确认两件事：

```powershell
# 1) 监听地址必须是 0.0.0.0（MySQL 8 默认如此；被安装向导改成 127.0.0.1 的话要改回来）
netstat -ano | findstr ":3306"
# 若是 127.0.0.1：改 my.ini 的 [mysqld] bind-address=0.0.0.0 后重启服务
Restart-Service MySQL80
```

```sql
-- 2) 建一个从隧道那边能登录的账号。
--    关键：提供端看到的客户端地址是**消费端的 tun 地址 10.99.1.1**，不是它的真实 IP，
--    因为进到协议栈的是内层包。所以账号的 host 要写 '%' 或 '10.99.1.1'。
CREATE USER 'm4'@'%' IDENTIFIED BY 'M4-test-pass';
CREATE DATABASE m4;
GRANT ALL PRIVILEGES ON m4.* TO 'm4'@'%';
FLUSH PRIVILEGES;
```

### 4.2 发布

`config.json` 的 `l3.services[]`（已预置）：

```json
{ "proto": "tcp", "ip": "172.10.9.2", "port": 3306, "desc": "MySQL" }
```

改完重启提供端代理与消费端。

### 4.3 连接（C 上）

```powershell
mysql -h 172.10.9.2 -P 3306 -u m4 -p m4
```

没装 MySQL 客户端就用 Python：

```powershell
pip install pymysql
python -c "import pymysql; c=pymysql.connect(host='172.10.9.2',port=3306,user='m4',password='M4-test-pass',database='m4'); print(c.get_server_info())"
```

### 4.4 跑一遍增删改查 + 一次大响应

```sql
CREATE TABLE items (id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(64), payload VARCHAR(200));

INSERT INTO items (name, payload) VALUES ('a', 'hello'), ('b', 'world');
SELECT * FROM items;
UPDATE items SET payload = 'updated' WHERE name = 'a';
DELETE FROM items WHERE name = 'b';
SELECT * FROM items;

-- 大响应：造 10 万行（约 12 MB 的结果集），专门压 MSS clamp 与分片这条路径
SET SESSION cte_max_recursion_depth = 200000;
INSERT INTO items (name, payload)
WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < 100000)
SELECT CONCAT('row-', n), REPEAT('x', 100) FROM seq;

SELECT COUNT(*) FROM items;
SELECT * FROM items;              -- 10 万行一次吐回来，看会不会卡死
```

再开**第二个** `mysql` 客户端连同一个库，用来验"多条连接共用一条隧道"。

### 4.5 判据

- 四类语句都正确返回，10 万行的 `SELECT` 能跑完、不卡死。
- `tunnel_up = 1`：一条长连接、多次往返共用同一条隧道（§5.1，隧道以 **SID** 为单位
  而非以流为单位）。**开第二个客户端后 `tunnel_up` 仍应是 1**；rev.6 起它会为准入再发
  一次 GET（消费端 `admit_get` +1，D19），但那只是刷新同一条隧道。
- `admit_drop = 0`、`src_bind_drop = 0`、`sid_miss = 0`。
- 大 `SELECT` 卡死 = MSS clamp 只做了一侧（§6.2）：查两端 `mss_clamped` 是否都 > 0、
  两端 color0 的 MTU 是否都是 1280。

### 4.6 常见坑

- **`Host '10.99.1.1' is not allowed to connect`**：账号 host 没开（见 4.1 第 2 步）。
  这条错误本身是好消息——说明隧道通了、TCP 也通了，是 MySQL 在做权限判断。
- **`Authentication plugin 'caching_sha2_password' ...`**：MySQL 8 的默认认证插件对
  非本机连接要走 RSA 换钥。`mysql` 客户端加 `--get-server-public-key`，或建账号时
  指定 `IDENTIFIED WITH mysql_native_password BY '...'`。
- **连上就卡在握手**：MySQL 的握手包不大，卡这里通常不是 MSS 问题，先看提供端
  `tun_tx` 有没有涨（没涨 = 上行没到，按 §6 的表分流）。
- **`max_allowed_packet`**：默认 64 MB，本用例够用；真要传大 BLOB 时两端都要调。

---

## 4b. 用例四：RM 的 ACL 按连接生效（rev.6，D19）

需要**带 ACL 功能的 RM**。目的是确认三件事：RM 改了 ACL 后新连接立刻被拦；已经在跑的连接
不受影响；其他 SID 不受影响。消费端 `l3.get_per_connection` 保持默认的 `true`。

### 4b.1 准备

- 提供端发布两条服务：SID1 = `tcp://172.10.9.2:8000`（用最小连通性判据那个 HTTP 源站），
  SID2 = 另一个端口（例如 MySQL 的 `3306`，或再起一个 `python -m http.server 8001 --bind 0.0.0.0`）。
- 消费端分别访问两条，确认都通：

```powershell
curl http://172.10.9.2:8000/hello.html
curl http://172.10.9.2:8001/
```

### 4b.2 步骤

1. 在 SID1 上开一条**长连接**并让它一直跑：`curl --limit-rate 50k -o NUL http://172.10.9.2:8000/<一个几十 MB 的文件>`，
   或者用 `tools/rtp_video.py` 跑一条视频流（视频要发布成 SID1，它每 10 s 发一次上行保活）。
2. 在**提供端的 RM** 上设 ACL：拒绝本消费端 NID 访问 SID1。
3. 新开一个窗口再 `curl` 一次 SID1，再 `curl` 一次 SID2。
4. 撤销 ACL，再 `curl` 一次 SID1。

### 4b.3 判据

- 第 3 步的 SID1：`curl` 连接超时（Windows 约 21 s）。消费端每 5 秒左右出现一行
  「新连接准入超时 … RM 的 ACL 拒绝了本消费端」，`admit_timeout` 随客户端重传 SYN 上涨；
  提供端**没有**新的「L3 隧道已刷新」日志（GET 被 RM 丢了，到不了提供端）。
- 第 1 步的长连接 / 视频流**不中断**（连接级粒度，§8.6）。
- 第 3 步的 SID2 照常返回。
- 第 4 步的 SID1 恢复正常。
- 顺带回答设计 §8.5 第 6 问：RM 的 `Random_Num` 是否仍是常量。L3 的握手不打印 rn，
  改走 v1 路径连发两次（`curl -x 127.0.0.1:8910 http://<一条 v1 发布的 URL>`），
  看提供端日志 `GET 携带 Random_Num=…` 两次的值是否相同。**不同**的话，再看第 1 步的
  长连接在别的客户端新建连接时有没有短暂卡顿（§8.6 最后一条代价）。

---

## 5. 跑真客户端之前：先跑离线回归

`tests/test_l3_acceptance.py` 把三个用例**各自特有的危险点**在假链路上钉死了，
不需要管理员、不需要第二台机器：

```bash
PYTHONDONTWRITEBYTECODE=1 python tests/test_l3_acceptance.py   # 8/8
```

> 真机跑之前还要确认一件事：**三个服务端口上不能有别的进程在听**。M1c 真机就撞过——
> 机器上另有一个 `python -m http.server` 占着 8000，链路其实是通的，判据却挂在最后
> 一步，看着像隧道不通。`netstat -ano | findstr ":21 :3306 :5004 :8000 :8554 :50000"` 先过一遍。

它覆盖的（也就是不必在真机上重新摸索的）：

| 用例 | 钉住的东西 |
|---|---|
| 被动 FTP | 控制 + 通配是**两条独立隧道**、回程按内层源端口各自反推 SID、端口不串台（rev.2 的单键 `PeerTun` 正是死在这里，D14） |
| 被动 FTP | 通配只放宽**目的**粒度到主机级；换 IP 仍拦、伪造内层源仍拦（§8.3 末段） |
| 视频流 | 600 包持续流只握手一次、无 per-packet 状态；净载荷正好 1252 必过；超限与分片分别计 `mtu_drop` / `frag_drop`，不静默 |
| MySQL | 200 次小往返共用一条隧道；第二条连接只为准入再发一次 GET、不新建隧道（D19）；未发布端口即使持有合法 SID 也打不进去 |
| RM 的 ACL | 在 `tests/test_l3_dataplane.py` 的假链路上模拟「RM 丢掉被拒的 GET」：新连接被拦、已有连接照常、撤销后恢复；并发新连接只发一个 GET；UDP 待准入期间的包不会从旧隧道抢跑 |

它**不覆盖**的（只有真机能验）：真 tun 读写、内核注入与路由选择、真实客户端的协议
行为（FTP 的 PASV 协商、MySQL 的握手包、RTP 的时序）、以及吞吐与时延。

---

## 6. 出问题时看哪个计数器

两端每 5 s 打一行快照（内容没变就不打）。按现象对号入座：

| 现象 | 先看 | 最可能的原因 |
|---|---|---|
| 完全不通，`tun_rx = 0` | 消费端 `tun_rx` | 路由没生效，流量没进 tun。`route print` 看 `172.10.9.2` 的下一跳 |
| `tun_rx` 涨但 `sid_miss` 同步涨 | `sid_miss` | 算出的 SID 不在表中：服务没发布，或两端服务串不一致（IP/端口/协议任一不同即完全不同的哈希） |
| `nonunicast_drop` 一直涨 | —— | **正常现象，不用管**：本机往 tun 上发的 mDNS/SSDP/NetBIOS/IGMP。新建的 tun 上每秒好几个 |
| 隧道建起来了但一个包不过 | 提供端 `src_bind_drop` | 消费端 `l3.tun_ip` 与提供端 `l3.peers[].tun_ip` 不一致（D14） |
| 隧道建起来了，`colr_rx` 也不涨 | 消费端 `colr_tx` / 提供端 `colr_rx` | 上行 ACK 没到提供端：跨域时 PID/BR 那一段（GET 是 RM 转发的，上行是终端按 PID 自己发的，两条路不同）|
| `tun_tx` 涨但 `tun_rx` 不涨 | 提供端启动日志 | 包注进去了、协议栈没回话：**源站只听 127.0.0.1**（最常见）、color0 的两个弱主机开关没开、或防火墙把 color0 的入站拦了。三者症状完全一样，逐个排 |
| 能连上但访问别的端口也通 | 提供端 `admit_drop` | 发布了通配 `:0`，目的粒度退化到主机级（§8.3，预期行为） |
| 小请求正常、大数据卡死 | 两端 `mss_clamped` | MSS clamp 只做了一侧，或某端 MTU 不是 1280（§6.2） |
| 小包通、大 UDP 静默丢 | `frag_drop` | 内层 UDP 净载荷超过 1252（D15） |
| 跑着跑着断了、重启消费端才好 | `no_tunnel_drop` | D1 的已知风险：提供端重启 / BR PID 表老化会让隧道静默失效。把消费端 `l3.tunnel_redetect_sec` 设成 30 打开重探兜底（§8.4） |
| 回程查不到隧道 | `no_peer_drop` | 内层目的地址没登记在 `l3.peers[]` |
| 已有连接正常，新连接全部超时 | 消费端 `admit_timeout` | 新连接准入的 GET 没有回复：RM 的 ACL 拒绝了本消费端（预期行为，§8.6）；没设 ACL 时则查 RM/提供端是否在线 |

`load0_mismatch` **不影响转发**，只作诊断（D13）：对端实现的 `load[0]` 与本文不一致
时会涨，包照常处理。

---

## 7. 做完 M4 要回填的事

1. 把三个用例的实测结果（通过 / 不通过、卡在哪一步、计数器快照）补进
   `docs/HANDOVER-l3.md` 的里程碑表。
2. 视频流若撞到 pps 上限，把实测的 pps 数字记下来——那是 M5「去 scapy」的立项依据。
   **性能数字与压测脚本按既定规矩只进 `perf/bench` 分支，不进 `dev_tun`。**
3. §8.5 的六个问题（上行是否需要 HMAC、`Random_Num` 长期复用、BR 的 PID 是否会老化、
   单 SID 有无速率限制、RM 的表会不会老化、新版 RM 的 `Random_Num` 是否仍是常量）在真机上
   会给出答案，其中前三个直接决定 D1 能否成立，第六个决定 D19 有无副作用，务必记录。
