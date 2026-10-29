# 交接文档 —— L3 隧道模式（分支 `dev_tun`）

> 目的：让新会话直接接着做，不必重建上下文。
> 开场读序：**本文 → `docs/design-l3-v2.md`（契约，rev.8）→ `docs/M4-acceptance.md`**。
> v1 的背景见 `docs/HANDOVER.md`。截至 2026-10-23。

---

## 1. 一句话现状

L3 隧道模式（把完整内层 IP 包作 CoLoR DATA 载荷透传，取代端点级 L4 中继）在 `dev_tun` 上
**代码全部写完、离线全绿**：契约 rev.5，M0–M4 的代码与离线回归都在。
**M1c 已在真机跑通**（2026-09-21，两半全部通过）。

**2026-09-21 晚：真 RM 环境到位（两台机器、两个 RM，跨域）**，M2 开跑并暴露了两个
控制面问题，均已修（详见 §4②、踩坑 13/14）：提供端每 30 s 的重注册让 RM 刷
`unable to insert into sid_table`；消费端连发 3 个注册包收不到回复，根因是
`config-consumer.json` 的 `rm_ipv4` 写成了 `10.10.0.1`（实为 `10.10.0.5`）。

| 里程碑 | 状态 | 说明 |
|---|---|---|
| M0 | ✅ | 类型位扩展、服务级 SID、两张服务表、配置校验、§9.3 四个 v1 遗留问题 |
| M1a | ✅ | `tun/ipv4.py`、`tun/mss.py`、`tun/device_win.py`(Wintun 绑定) |
| M1b | ✅ **真机** | `tools/l3_m1b_inject.py` 读回 SYN-ACK（2026-09-20） |
| M2 | ✅ 代码 / ◑ 真机 | 两端装配接入、按 SID 分派、tun 读线程、§2.4 第二道校验。控制面（注册/发布）已上真 RM |
| M3 | ✅ | 首包缓冲、握手超时回收、`mtu_drop`、计数器日志、§8.4 下行重探 |
| **M1c** | ✅ **真机** | 2026-09-21 第三跑**两半全部通过**。过程见 §4① |
| M4 | ◑ 离线完成 / ⬜ 真机 | 离线 8 项；真客户端验收**需要两台机器** |
| M5 | ⬜ 推迟 | 去 scapy 数据面，2026-09-21 用户决定本轮不做 |

M2 行的"真机"改为 ◑：两端都已接上真 RM，注册/发布这一段跑通了；GET→隧道→数据
那一段还没验（见 §4②）。

**2026-10-23：适配 RM 新增的 ACL（设计 rev.6，D19「新连接准入」）。** RM 只对 GET 做
ACL，而 L3 每条 SID 只发一次 GET，之后的连接都复用缓存的 PID，ACL 改了也管不到。
现在消费端对每条新连接（TCP `SYN` 无 `ACK`；UDP 按四元组 + 上行空闲 60 s）先为所属 SID
重发 GET，回了隧道 DATA 才放行；已有连接继续走旧隧道。**只改了消费端**（用户决定：信任
消费端软件，提供端不做校验），开关 `l3.get_per_connection`（默认开）。边界与代价在设计
§8.6，真机用例在 M4 手册 §4b（需要带 ACL 的 RM）。实现复用了 §8.4 重探的「保留旧隧道、
回包原子替换」：`ConsumerTunnelTable.begin_redetect` 已改名 `begin_refresh`，两处共用。

**2026-10-23（同日）：HTTP 在 L3 下找回内容级准入（设计 rev.7，D20）。** RM 的 ACL 原先在
L3 里只能管到 `tcp://172.10.9.2:8000` 整个端口。现在提供端在 `l3.services[]` 的 HTTP 条目上
加 `app: "http"` + `paths`，按 URL 另发 SID；消费端在 `l3.app_services[]` 声明这个端点是 HTTP，
每个请求先扣住，解析出请求行后为 `SHA1(http://172.10.9.2:8000/<path>)` 发 GET，回了才放行
（数据仍走服务级隧道，端到端 TCP 不断），URL 未发布立刻 RST、GET 超时（ACL 拒绝）5 s 后 RST。
用户当场定的两件事：**连接走端口级、请求走 URL 级**（不把数据改用 URL SID 承载，也不在消费端
终结 TCP 转给 v1）；**拒绝时两端各发 RST**（不注入 403 页面）。新模块：`l7/http.py`（纯解析，
以后的 FTP 也放 `l7/`）、`tun/tcp.py`、`l3/content.py`。**v1 一行没动。** 契约与边界在设计
§8.7，真机用例在 M4 手册 §4c。实现时有一处偏离计划：Upgrade/CONNECT **不**开透传，按普通
请求准入、升级后的字节被 RST——开透传的话带一个 `Upgrade` 头就能绕过后续请求的检查。

**2026-10-23（同日）：被动 FTP 不再需要通配（设计 rev.8，D21）。** 用户提的方案是「解析 229、把端口放进消费端的临时白名单、数据连接复用已有隧道」；评审后定下的做法是：**判定放在提供端**（只改消费端根本不通——提供端的目的准入会把端口 p 丢掉，回程也按源端口 p 查不到 SID），消费端只加一条路由回退。两端在控制端口 21 上标 `app: "ftp"`；提供端读控制连接上的 `PASV`/`EPSV` 与源站的 227/229，在回复下行**之前**登记一次性期望 `(NID, ip, p)`，数据连接**带着控制 SID** 走同一条隧道、不发 GET（继承控制连接的准入，ACL 对 FTP 因此按会话生效）。防绕过的几条：回复只按 CRLF 切行（裸 LF 回显能伪造 229）、按 RFC 959 多行分帧、只认紧跟 PASV/EPSV 的回复、不用 227 里的地址、拒绝 <1024 / 控制端口 / 同地址已发布的端口。`config.json` 的通配 `:0` 已删，`tools/ftp_server.py` 默认不再限被动端口段。新模块 `l7/ftp.py`、`l3/ftp.py`；契约在设计 §8.8，真机步骤在 M4 手册 §2（已重写）。顺带修掉一个隐患：以前控制与数据各走一条 SID，下载超过 800 s 时控制 SID 的 BR ODC 表项过期，最后的 `226` 会被丢。另：装了 Clash 的机器上 curl 会把 `ftp://` 交给 `all_proxy` 里的 HTTP 代理（502），手册里的命令已加 `--noproxy '*'`。

**2026-10-24：REST/SSE 演示服务迁入（只动源站与配置，数据面一行没改）。** 把 color-proxy-restful 的源站与 RAG 后端搬进 `tools/`、`data/`、`sql/`，经 L3 访问 `http://172.10.9.2:8000/...`。L3 下有三处不能照搬：
- **身份**：提供端不再注入 `X-CoLoR-Requester-NID`，浏览器反而能伪造它。现在源站按 TCP 对端地址（消费端 tun 地址，D14 已校验）查 `l3.peers[]`，请求头一律忽略。
- **D20**：源站全部 26 个路由（`PUBLISHED_PATHS`）都要写进 `config.json` 的 `paths`，包括 `/favicon.ico`。
- **SSE**：结束时源站要主动关连接，否则 keep-alive 下浏览器永远等不到流结束。

没有迁移的部分：`STREAM_CANCEL`（关连接即 FIN）、v1 的 HMAC 身份绑定和防重放、`/bulk/*`（留在 perf/bench）。部署与六类测试见 `docs/RESTFUL-L3.md`。

**2026-10-30：ANN 带上 SID 的名称和描述（`docs/design-ann-sid-desc.md`）。** 每个通告单元多两个策略单元：tag 13 是算 L_SID 时被哈希的那个串（RM 可以校验 `SHA1 == L_SID`），tag 14 是配置里的 `desc`（已精简为 `http`/`ftp`/`mysql`/`rtp`）。两者合计不超过 73 字节，部署里所有 RM 都完成方案 P0 之后才能放宽到 200。裁剪在首次发布时做，结果存进已通告表，AM=2/AM=3 原样复用。新模块 `protocol/strategy.py`，测试 `tests/test_ann_tlv.py`。

回归基线：**236 项断言 + 3 个脚本式 e2e，全绿**（D21 新增 33 项；演示源站新增 10 项 + P2/P3 的 4 项 unittest；tag=8 新代理通知 5 项；ANN 名称/描述 14 项）。

---

## 2. 本轮（2026-09-21）做了什么

按用户四个决策开工：**采用 §2.5 虚服务地址**、**只有这台开发机**、
**wintun 二进制进仓库**、**M5 推迟**。

```
colorproxy/
  l3/service.py        ★新增。两端的 L3 运行期：tun 读线程（§1.2/§1.3）、周期任务、
                       计数器日志。握手超时回收由它统一拉起——§5.2 点名"不调首包会
                       永久滞留"，不给调用方漏掉的机会
  tun/factory.py       ★新增。装配层不直接 import device_win，离线测试可注入 LoopbackTun，
                       Linux 移植只在这里加一个分支
  provider.py          接 L3：GET/ACK 先试 L3，SID 不属于 L3 再回落 v1（D13）
  consumer/consumer.py 接 L3：DATA(B=0) 同上；起 tun 前做 §2.4 的第二道路由隔离校验
  consumer/state.py    +capture_route_conflicts()（§2.4 第二道校验的判据）
  l3/consumer.py       +handle_data() 总入口、mtu_drop、redetect_silent_tunnels()
  l3/tables.py         +上下行时间戳、begin_redetect()、expire 区分握手/重探
  l3/provider.py       +回程方向的 mtu_drop
  tun/device_win.py    +check_local_address()（从 M1b 脚本挪过来，两处共用）
tools/
  l3_m1c_loopback.py   ★新增。M1c：真 tun + 真两端数据面，UDP 代替 CoLoR。
                       --dry-run 免管理员，已在本机跑通
tests/
  test_l3_assembly.py  ★新增 12 项。装配层：D13 分派、tun 读线程、超时确实被扫、
                       重探原子替换、mtu_drop、§2.4 校验
  test_l3_acceptance.py ★新增 8 项。M4 三个用例各自特有的危险点
docs/
  M4-acceptance.md     ★新增。真机验收手册（两端环境 + 三个用例 + 故障对照表）
  design-l3-v2.md      → rev.4：D18、M1c 改写、里程碑回填、两处勘误
```

**补齐了设计里写了但没实现的三处**（都是"漏了也不报错、只是某条路径永远不发生"）：

1. **§2.4 第二道路由隔离校验**。配置加载时只查得了 `rm_ipv4`；域内代理与 BR 的地址要
   到注册回复同步下来才知道。现在起 tun 前用实际同步下来的表再核对一遍，命中则拒绝
   启动。命中域内代理通常意味着两端在同一个 CoLoR 域，外层包会被自己的 tun 吞掉。
2. **`mtu_drop`**。此前这个计数器从未被递增过。
3. **§8.4 的下行静默重探**（`tunnel_redetect_sec`，默认关闭）。重探期间旧隧道继续
   可用，新隧道 DATA 到达时原子替换。

---

## 3. 两个必须知道的实情修正（**都不是 bug，别去"修"**）

### 3.1 单机跑不了完整一条流 —— 而且会"看起来通过"

设计 §11 原来写 M1c 是"一台机器两个进程两个 tun"。**不成立**：

- 服务地址 `172.10.9.2` 是提供端 color0 自己的地址 → 客户端 `connect` 被内核直接投给
  本地协议栈，捕获路由根本轮不上；
- 消费端 tun 地址 `10.99.1.1` 是消费端 color0 自己的地址 → 源站回程也走环回。

**两个内层端点都是本机地址，TCP 会建成功，但一个包都没经过隧道。** D9 的物理地址方案
一样。所以 M1c 拆成两半（每半只留一个真实端点），M4 的真客户端必须两台机器。
完整推理写在 `tools/l3_m1c_loopback.py` 的模块文档里。

### 3.2 MSS clamp 在 D3 拓扑下多半是空操作

客户端的 SYN 与源站的 SYN-ACK 都是内核按 tun MTU(1280) 发出的，内核自己就会填
`MSS=1240`；clamp 只减不增，于是什么也不改，`mss_clamped` 停在 0。**这不是故障。**
判据应当是"观察到的 MSS ≤ 1240"（证明 tun MTU 生效），不是"clamp 改写过字节"。
clamp 兜的是 MTU 没配对、内层包来自别的主机、对端按 1460 硬填这几种情形。

---

## 4. 下一步怎么做（按优先级）

### ① M1c 真机 —— ✅ 已完成（2026-09-21，跑了三次）

三次运行查出的东西（两半是**两个不同的病因**，别当成一个问题查）：

- **半 P，第一跑**：`tun_tx=1` 说明 SYN 写进了 tun，但回程侧一个 TCP 包都没有——
  协议栈连 RST 都不回。病因是 **color0 的两个弱主机开关没开**（见踩坑 1）。
  已修：脚本为自己创建的 tun 打开它们。
- **半 P，第二跑**：链路**通了**——真实 HTTP 200 穿过真 tun、真内核注入、真源站又
  回来了，SYN-ACK 的 MSS=1240 也对。判据却报失败，因为响应头写着
  `Server: SimpleHTTP/0.6`：答话的不是脚本起的那个源站，而是机器上另一个占着 8000 的
  `python -m http.server`（`allow_reuse_address=True` 让两个 socket 都绑上了同一端口，
  Windows 上谁收连接是未定义的）。已修：端口被占用时**不抢**、沿用现成的那个，
  判据也放宽到"拿到一个完整的 HTTP 响应"——这才是 M1c 要证明的事。
- **半 C，第二跑：通过。** 第一跑的 `src_bind_drop=4` 随弱主机开关一起消失了。
- **第三跑：两半全部通过。** 另外顺手修掉一件淹诊断的事：tun 上的广播/组播噪声
  （mDNS/SSDP/NetBIOS，每秒好几个）此前全计进 `sid_miss` 并逐包打 warning，
  现在单列 `nonunicast_drop` 且不打 warning（见踩坑 12）。

回归时重跑即可（脚本会先打一段预检，再跑流量）：

```powershell
# 管理员 PowerShell，本机即可，不需要 RM/BR、不需要第二台机器
python tools/l3_m1c_loopback.py            # 依次跑半 P 与半 C
python tools/l3_m1c_loopback.py --role provider -v   # 只跑半 P，出问题时
```

两半依次跑（同时起两个 tun 就回到 §3.1 的短路了）。判据脚本会自己打印。
失败时先看它打印的两端计数器，再对照 `docs/M4-acceptance.md` §6 的对照表。

空跑已在本机通过（`--dry-run`，免管理员），所以**脚本逻辑、UDP 链路、两端数据面、
MSS clamp 都是验证过的**，真机上新增的只有 Wintun 与内核路径。

### ② M2 真机 —— 控制面已通（2026-09-21 晚），数据面待跑

环境已经有了：两台机器、两个 RM（跨域）。**注册与发布这一段真机跑过了**，代价是两个
控制面 bug（都已修，见踩坑 13/14）：

- 提供端每 30 s 重注册并重发一遍 AM=1 的 ANN → RM 每轮报 `unable to insert into
  sid_table`。现在注册报文与每条 SID 的 AM=1 各只发一次，退出时发 AM=3 注销；
- 消费端连发 3 个注册包无回复 → `rm_ipv4` 配错。注册失败现在会打出 RM 地址、本机
  地址、出口网卡与下一跳 MAC，并列出逐条核对项。

**接着跑数据面**：把两份配置的 `l3.enabled` 改成 `true`，按 `docs/M4-acceptance.md` §1
配环境，然后 `Test-NetConnection 172.10.9.2 -Port 8000` →
`curl http://172.10.9.2:8000/hello.html`。跨域拓扑下先确认 RM 同步回来的 BR 表
（tag=6 的 `PXs`）非空，否则提供端回送时查不到下一跳。

**2026-09-21 晚第一次跑：隧道建得起来，TCP 握手超时。** 已确认的一个成因：源站只听
`127.0.0.1`（见踩坑 15），L3 的目的地址是 `172.10.9.2`，注进去没人收。源站改
`--host 0.0.0.0` 后重跑；若仍超时，按 `docs/M4-acceptance.md` §6 的两条新行分流——
先看提供端 `colr_rx` 涨不涨（不涨＝上行没到，查跨域 PID/BR），再看 `tun_tx` 与
`tun_rx`（`tun_tx` 涨而 `tun_rx` 不动＝协议栈没回话：监听地址 / 弱主机开关 / 防火墙）。

代码路径本身在 `tests/test_l3_assembly.py` 里跑通了（真的装配分派 + 真的 CoLoR 报文 +
真的读线程，只有链路是假的），真机上新增的是 raw socket 收发与 RM/BR 的实际行为。

> 升级到本轮代码后**第一次**启动提供端，RM 里可能还留着上一轮 30 s 刷进去的 SID，
> 仍会报一次 `unable to insert into sid_table`。先跑 `python tools/rm_withdraw.py`
> 把它们注销掉（或重启 RM）。

### ③ M4 真机 —— 需要第二台机器

步骤、判据、故障对照表全在 `docs/M4-acceptance.md`（§2/§3/§4 已按 2026-09-21 晚的实情
重写成可照抄的命令）。跑之前先跑 `python tests/test_l3_acceptance.py`（8/8），它已经把
三个用例各自特有的危险点钉死了。三个源站分别是：

| 用例 | 提供端起什么 | 消费端拿什么测 |
|---|---|---|
| 被动 FTP | `python tools/ftp_server.py --make-testfile 10`（需 `pip install pyftpdlib`；D21 起被动端口不限、不发布） | `curl --noproxy '*' --ftp-pasv`（EPSV）/ 加 `--disable-epsv`（PASV），**主动模式本轮不支持**（§8.8） |
| 视频流 | `python tools/rtp_video.py --role server --seconds 0` | `python tools/rtp_video.py --role client --server 172.10.9.2 --seconds 300`，自己打丢包率/最长中断 |
| MySQL | 本机 MySQL，`bind-address=0.0.0.0` + 账号 host 写 `%` | `mysql -h 172.10.9.2 -P 3306` |

> **视频流不能用推流**：CoLoR 是拉驱动，隧道只能由消费端的第一个上行包触发，提供端
> 无法主动开流。`tools/rtp_video.py` 因此做成请求驱动（客户端先发 KICK）；要真播放器
> 就走 RTSP **over TCP**（`-rtsp_transport tcp`，全程一条 TCP 隧道）。手册 §3 旧版写的
> 「P 上 VLC 串流 RTP 到消费端」不成立，已重写。

### ④ M5 —— 用户决定本轮不做

真机跑视频流撞到 pps 上限时再立项，那时把实测 pps 记下来作依据。
**压测脚本与实测数字只进 `perf/bench` 分支**；快路径、raw socket 发送器这类生产代码
优化可以留在本分支（规矩同 `dev_multi-protocol`）。

---

## 5. 踩过的坑（**务必先读**，每条都真实耗过时间）

1. **弱主机开关**。两条都要记：
   - D9 下**两张网卡都要开**。rev.2 写的「仅 color0」是错的（rev.3 已修）。
   - **D18（§2.5）下省掉的只是服务网卡那两个，color0 自己的两个仍要开。**
     2026-09-21 真机踩到：设计 §2.3 那句「四个开关一个都不需要」与它自己的对照表
     矛盾——第一行那次成功实验里 color0 的两个是**开着**的。四个全关时 M1c 半 P 的
     症状是 `tun_tx=1`（包确实写进 tun 了）但协议栈**连 RST 都不回**，回程侧一个
     TCP 包都没有。rev.4 已在 §2.3 加勘误框，代码与 M1c 脚本都已跟进。
2. **netsh 输出是本地化的**。中文 Windows 打印「弱主机发送 / 弱主机接收」，按
   `weakhostsend` 解析永远匹配不到。用 `Get-NetIPInterface`（属性名与 Enabled/Disabled
   枚举都与语言无关）。
3. **服务地址必须在本机**。不在本机时内层包递上来既非本机地址、又无转发目标，直接
   丢弃，症状与弱主机丢弃、防火墙拦截一模一样。`check_local_address` 已覆盖
   （并查 `AddressState` 必须为 Preferred）。
4. **`load[0]` 不能作模式分派判据**（D13）。提供端 ACK 路径的类型校验是 `cd9348b`
   刻意删掉的（"宽松放行"）。一律先按 SID 查服务表分派，`load[0]` 只作宽松校验 +
   `load0_mismatch` 计数。**不要好心把强校验加回去。**
5. **PowerShell 单引号串里反引号不转义**：`'{0}`t{1}'` 会原样输出 `` `t ``。
   用 `-join` 或双引号串。
6. **仓库跟踪了 `__pycache__/*.pyc`**：跑测试一律加 `PYTHONDONTWRITEBYTECODE=1`，
   否则弄脏工作区。**注意用 `python - <<EOF` 跑临时脚本时也要带上**，我这轮就漏过一次。
7. **提交消息里的 ASCII 直引号会破坏 shell 引号配对**：中文长消息用 `git commit -F <文件>`。
8. **控制台编码**：中文 Windows 控制台默认 GBK，输出重定向到管道时打印 `✅` 一类字符会
   抛 `UnicodeEncodeError` 把整个脚本带崩。两个工具脚本都加了 `reconfigure(errors=...)`
   兜底，新写脚本请照做，或直接用 `[PASS]`/`[FAIL]`。
9. **Wintun 细节**：非管理员 `WintunCreateAdapter` 返回 `ERROR_ACCESS_DENIED`（能走到
   驱动就说明签名/调用约定对）；`WintunSetLogger` 的回调对象必须保住引用
   （`_logger_callback_ref`），否则被 GC 后驱动回调会崩进程；`ring_capacity` 必须是
   2 的幂且在 [128 KiB, 64 MiB]。
10. **新 tun 上有大量 IPv6 RS/MLD 与 IGMP 噪声**，是正常现象；诊断时按 IP 版本分类
    计数，别笼统报成"坏包"。
11. **别和已经在听那个端口的服务抢**。Windows 上 `SO_REUSEADDR` 的语义与 Unix 不同：
    两个 socket 能绑同一个 addr:port，此后**哪个收到连接是未定义的**。M1c 半 P 第二跑
    就是这么报的假失败——链路全通，答话的却是机器上另一个 `python -m http.server`。
    跑真机前先 `netstat -ano | findstr ":8000"`。
12. **tun 上的广播/组播噪声会淹掉诊断**。新建的 tun 上本机持续发 mDNS(5353)、
    SSDP/WSD、NetBIOS(137)、IGMP，每秒好几个。rev.4 起它们单独计 `nonunicast_drop`
    并且**不打 warning**：此前它们全计进 `sid_miss`（一次 7 秒的运行 20 个），而
    §10.4 给 `sid_miss` 的含义是"路由把不该进的流量导进了 tun"——一个要改配置、
    一个什么都不用做，混在一起等于没有诊断。
13. **RM 不接受重复的 SID 注册**。ANN 的 `AM=1` 在 RM 侧走的是**插入**，不是"覆盖同
    一条 SID"；第二次就报 `unable to insert into sid_table`。所以：每条 SID 只发一次
    AM=1（`ProviderState` 里有已通告表去重），刷新用 AM=2，退出时发 AM=3 注销——
    **不注销的话下次启动必然撞上同一条错误**，残留用 `tools/rm_withdraw.py` 清。
    设计 §9.3 第 3 条那条"必须改成常驻注册线程"已在 rev.5 撤销。
14. **注册"没有回复"几乎总是地址配错**。真机上消费端连发 3 个注册包、RM 那边一行日志
    都没有，根因只是 `rm_ipv4` 写成了 `10.10.0.1`（实为 `10.10.0.5`）。这类错误在日志里
    与"二层不通""RM 没起""防火墙拦了"长得完全一样，所以现在：注册失败会打出 RM 地址、
    本机 `ipv4`、出口网卡与下一跳 MAC（解析不到 MAC 时额外警告——scapy 会静悄悄改用广播
    照发不误）；收到"协议号对、但目的地址不是本机绑定地址"的 CoLoR 包提示一次（那是
    `ipv4` 配到了另一张网卡的典型症状）；未实现的 CONTROL 子类型也各提示一次。
15. **源站只听 `127.0.0.1` 时，v1 通而 L3 纯超时**。内容级回源是提供端本机发起的普通
    TCP 连接（`origin_host` 写 `127.0.0.1` 就连得上），服务级是把内层包注入协议栈、
    目的地址恒为 `l3.services[].ip`（`172.10.9.2`），没人在那个地址上听就没人收。
    症状与"弱主机开关没开""防火墙拦 color0"一模一样：`tun_tx` 照涨、`tun_rx` 不动。
    源站一律 `--host 0.0.0.0` 起；设计 §2.6 第 4 条原来写的 `172.10.0.2` 是 D9 时代的
    地址，rev.5 已勘误。提供端启动时会探一次监听并告警，但装了 Proxifier/Clash 的机器
    上探不出来（连空端口也是超时而非拒绝），仍以 `netstat -ano | findstr :8000` 为准。
16. **`LoopbackTun.pop_written()` 是"取出并清空"**：一次可能带回好几个包（对端的 ACK
    紧跟着数据包），写测试/工具时不缓冲就会丢掉后面的。`MiniTcp` 里有 `_backlog`。

---

## 6. 怎么跑

```bash
# 离线回归（全绿基线：236 项断言 + 3 个脚本）
PYTHONDONTWRITEBYTECODE=1 python tests/test_l3_m0.py          # 15/15
PYTHONDONTWRITEBYTECODE=1 python tests/test_l3_dataplane.py   # 28/28  ← 含 D19 的 8 项
PYTHONDONTWRITEBYTECODE=1 python tests/test_l3_content.py     # 21/21  ← D20 内容级准入
PYTHONDONTWRITEBYTECODE=1 python tests/test_l7_http.py        # 15/15  ← HTTP 请求流解析
PYTHONDONTWRITEBYTECODE=1 python tests/test_l3_ftp.py         # 19/19  ← D21 被动 FTP
PYTHONDONTWRITEBYTECODE=1 python tests/test_l7_ftp.py         # 14/14  ← FTP 命令/回复解析
PYTHONDONTWRITEBYTECODE=1 python tests/test_tun_tcp.py        #  7/7   ← TCP 段 / RST
PYTHONDONTWRITEBYTECODE=1 python tests/test_l3_assembly.py    # 13/13  ← 装配层
PYTHONDONTWRITEBYTECODE=1 python tests/test_l3_acceptance.py  #  8/8   ← M4 离线
PYTHONDONTWRITEBYTECODE=1 python tests/test_tun_ipv4_mss.py   # 15/15
PYTHONDONTWRITEBYTECODE=1 python tests/test_tun_device.py     #  7/7
PYTHONDONTWRITEBYTECODE=1 python tests/test_registration.py   # 20/20
PYTHONDONTWRITEBYTECODE=1 python tests/test_ann_tlv.py        # 14/14  ← ANN 名称/描述（tag 13/14）
PYTHONDONTWRITEBYTECODE=1 python tests/test_protocol.py       # 10/10
PYTHONDONTWRITEBYTECODE=1 python tests/test_consumer.py       #  8/8
PYTHONDONTWRITEBYTECODE=1 python tests/test_provider.py       #  4/4
PYTHONDONTWRITEBYTECODE=1 python tests/test_hmac.py           #  4/4
PYTHONDONTWRITEBYTECODE=1 python tests/test_restful_origin.py # 10/10  ← 演示源站 L3 适配（docs/RESTFUL-L3.md）
PYTHONDONTWRITEBYTECODE=1 python tests/test_provider_p2p3.py  #  4 项 ← 模型服务 P2/P3（unittest）
PYTHONDONTWRITEBYTECODE=1 python tests/test_e2e_inproc.py     # 脚本式
PYTHONDONTWRITEBYTECODE=1 python tests/test_streaming_ttfb.py # 脚本式
PYTHONDONTWRITEBYTECODE=1 python tools/l3_m1c_loopback.py --dry-run   # 脚本式
```

真机（**管理员 PowerShell**）：

```powershell
python tools/l3_m1b_inject.py --configure   # M1b，已通过，回归用
python tools/l3_m1c_loopback.py             # M1c，下一步
```

---

## 7. 验证到什么程度（别高估）

| 已验证 | 方式 |
|---|---|
| §3.4 全部 SID 测试向量 | 单测 |
| MSS clamp + 校验和（多组取值） | 单测，与整包重算交叉验证 |
| 分片识别、ICMP 过滤、准入校验三种攻击 | 单测 |
| 两端数据面端到端（真 CoLoR 报文、假链路） | `test_l3_dataplane.py` |
| **两端装配的 D13 分派、读线程、超时回收、重探** | `test_l3_assembly.py` |
| **三个 M4 用例各自的协议级危险点** | `test_l3_acceptance.py` |
| **D20：扣留/放行、未发布与 ACL 拒绝的 RST、keep-alive 逐请求准入、重传、并发单飞** | `test_l3_content.py`（异步假链路）；测试另做过变异检查（把门改成从不扣留，4 项失败） |
| RST 的 IP/TCP 校验和 | `test_tun_tcp.py`，与 scapy 交叉核对 |
| **两端数据面 + 真 UDP 链路上的一次完整 HTTP 往返** | `l3_m1c_loopback.py --dry-run` |
| 注入 → 跨网卡投递 → 源站 → 回程 | **M1b 真机**（D9 拓扑下） |
| **`l3/` 跑在真 tun 上：真内核注入、真路由选择、真 MTU** | **M1c 真机两半全部通过** |
| **`WintunDevice` 的 configure/add_route/read/write 在持续流量下** | **M1c 真机** |
| Wintun 绑定的调用约定 | 非特权下 `CreateAdapter` 得到 `ACCESS_DENIED` |

| **未验证** | 备注 |
|---|---|
| CoLoR 链路（GET/隧道/上下行 DATA 经 RM/BR） | **完全没接**，需要 RM/BR 环境 |
| 跨域 PID 语义在 L3 下 | 复用 v1 的 `reverse_path_for_ack`，有 v1 单测，L3 下未实测 |
| 三个 M4 用例的真客户端 | 需要第二台机器 |
| D20 在真内核下的 RST（客户端是否立刻报 reset、源站半连接是否被清掉） | 需要第二台机器 + 带 ACL 的 RM，M4 手册 §4c |
| 吞吐 / pps / 时延 | M5 推迟；现状每包一次 scapy，估计几千 pps 到顶 |
| 上行是否需要 HMAC、`Random_Num` 长期复用 | 设计 §8.5，待与 RM/BR 团队确认 |

---

## 8. 仍然待决

1. **§8.5 的四个问题**（上行要不要 HMAC、`Random_Num` 能否长期复用、BR 的 PID 会不会
   老化、单 SID 有无速率限制）。第三个直接决定 D1 能否成立、§8.4 的兜底要不要默认
   打开。**要 RM/BR 团队的答复，或真机实测。** rev.6 又加了第 6 问：带 ACL 的新版 RM
   的 `Random_Num` 是否仍是常量（手头源码 `get.c` 写死 `0x20220220`）。是常量则 D19
   没有副作用；改成真随机的话，每条新连接的 GET 会让同 SID 其他连接的下行丢一小段。
2. **最小弱主机开关集合**。采用 D18 后这条不再挡路，D9 仍是备选，四个全开是安全超集。
3. **多提供端时的选源策略**。`consumer/state.py` 的 `_sid_table` 是单值的：两个提供端
   发布同一服务串会得到同一 L_sid、不同 N_sid，后入表者覆盖先入表者。原型单提供端
   无影响，多提供端时隧道对端可能在重启后静默切换。

---

## 9. 提交历史（`dev_tun`，从 `dev_consumer` 切出）

```
d7b4f1d [feat] L3 M4：三个验收用例的离线回归 + 真机验收手册
1cd4dc0 [feat] L3 M1c：真 tun 回环验证脚本（含空跑模式）
7b31eba [feat] L3 M2/M3：两端装配接入 L3，按 SID 分派并补齐运行期
bd5223c [doc] 新增 L3 交接文档，供新会话从 M1c 接手
a4b24e4 [fix] M1b 通过，按实测修正 §2.3 的弱主机开关要求
285c0e8 [feat] M1b 脚本：失败后自动做决定性判据与 A/B 定位
6ce2b22 [feat] M1b 脚本支持 --configure，可在开发机上自备环境
765c397 [feat] M1b 脚本增加目标地址归属检查
f56703a [feat] L3 M1a 收尾：Wintun 封装与 M1b 注入验证脚本
984cba3 [feat] L3 数据面：两端收发路径与双向准入校验
bd06c22 [feat] L3 M1a：内层 IPv4 解析与 MSS clamp
9835957 [feat] L3 M0：类型位扩展、服务级 SID、两张服务表与配置校验
b07da40 [doc] L3 隧道模式设计 rev.3
```
