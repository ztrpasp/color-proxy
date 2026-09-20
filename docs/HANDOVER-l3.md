# 交接文档 —— L3 隧道模式（分支 `dev_tun`）

> 目的：让新会话直接接着做，不必重建上下文。
> 开场读序：**本文 → `docs/design-l3-v2.md`（契约，rev.4）→ `docs/M4-acceptance.md`**。
> v1 的背景见 `docs/HANDOVER.md`。截至 2026-09-21。

---

## 1. 一句话现状

L3 隧道模式（把完整内层 IP 包作 CoLoR DATA 载荷透传，取代端点级 L4 中继）在 `dev_tun` 上
**代码全部写完、离线全绿**：契约 rev.4 已冻结，M0–M4 的代码与离线回归都在。
**卡在环境上**：真 RM/BR 没有，第二台机器没有，所以 M2 的 CoLoR 链路与 M4 的真客户端
跑不了。M1c 的真 tun 不需要这些，2026-09-21 跑了两次：**半 C 已通过**；半 P 的隧道
链路其实也打通了（真实 HTTP 200 穿过真 tun、真内核注入、真源站又回来了），只是判据
押在"答话的是我起的那个源站"上，撞了机器上另一个占着 8000 的 `http.server`，报了假
失败。两处都已修，待第三跑，见 §4①。

| 里程碑 | 状态 | 说明 |
|---|---|---|
| M0 | ✅ | 类型位扩展、服务级 SID、两张服务表、配置校验、§9.3 四个 v1 遗留问题 |
| M1a | ✅ | `tun/ipv4.py`、`tun/mss.py`、`tun/device_win.py`(Wintun 绑定) |
| M1b | ✅ **真机** | `tools/l3_m1b_inject.py` 读回 SYN-ACK（2026-09-20） |
| M2 | ✅ 代码 / ⬜ 真机 | 两端装配接入、按 SID 分派、tun 读线程、§2.4 第二道校验 |
| M3 | ✅ | 首包缓冲、握手超时回收、`mtu_drop`、计数器日志、§8.4 下行重探 |
| **M1c** | ◑ **真机** | 2026-09-21 第二跑：**半 C 通过**；半 P 的链路也已打通（真实 HTTP 200 穿过真 tun 回来了），只因撞上机器上另一个占着 8000 的源站而判据报假失败，已修，**待第三跑**（见 §4①） |
| M4 | ◑ 离线完成 / ⬜ 真机 | 离线 8 项；真客户端验收**需要两台机器** |
| M5 | ⬜ 推迟 | 去 scapy 数据面，2026-09-21 用户决定本轮不做 |

回归基线：**108 项断言 + 3 个脚本式 e2e，全绿**。

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

### ① M1c 真机 —— 2026-09-21 首次运行两半皆未通过，已补诊断待重跑

两次真机运行的结论（两半是**两个不同的病因**，别当成一个问题查）：

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

重跑即可（脚本现在会先打一段预检，再跑流量）：

```powershell
# 管理员 PowerShell，本机即可，不需要 RM/BR、不需要第二台机器
python tools/l3_m1c_loopback.py            # 依次跑半 P 与半 C
python tools/l3_m1c_loopback.py --role provider -v   # 只跑半 P，出问题时
```

两半依次跑（同时起两个 tun 就回到 §3.1 的短路了）。判据脚本会自己打印。
失败时先看它打印的两端计数器，再对照 `docs/M4-acceptance.md` §6 的对照表。

空跑已在本机通过（`--dry-run`，免管理员），所以**脚本逻辑、UDP 链路、两端数据面、
MSS clamp 都是验证过的**，真机上新增的只有 Wintun 与内核路径。

### ② M2 真机 —— 需要 RM/BR 环境

把两份配置的 `l3.enabled` 改成 `true`，按 `docs/M4-acceptance.md` §1 配环境，然后
`Test-NetConnection 172.10.9.2 -Port 8000` → `curl http://172.10.9.2:8000/hello.html`。

代码路径本身在 `tests/test_l3_assembly.py` 里跑通了（真的装配分派 + 真的 CoLoR 报文 +
真的读线程，只有链路是假的），真机上新增的是 raw socket 收发与 RM/BR 的实际行为。

### ③ M4 真机 —— 需要第二台机器

步骤、判据、故障对照表全在 `docs/M4-acceptance.md`。跑之前先跑
`python tests/test_l3_acceptance.py`（8/8），它已经把三个用例各自特有的危险点钉死了。

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
13. **`LoopbackTun.pop_written()` 是"取出并清空"**：一次可能带回好几个包（对端的 ACK
    紧跟着数据包），写测试/工具时不缓冲就会丢掉后面的。`MiniTcp` 里有 `_backlog`。

---

## 6. 怎么跑

```bash
# 离线回归（全绿基线：108 项断言 + 3 个脚本）
PYTHONDONTWRITEBYTECODE=1 python tests/test_l3_m0.py          # 13/13
PYTHONDONTWRITEBYTECODE=1 python tests/test_l3_dataplane.py   # 20/20
PYTHONDONTWRITEBYTECODE=1 python tests/test_l3_assembly.py    # 12/12  ← 装配层
PYTHONDONTWRITEBYTECODE=1 python tests/test_l3_acceptance.py  #  8/8   ← M4 离线
PYTHONDONTWRITEBYTECODE=1 python tests/test_tun_ipv4_mss.py   # 14/14
PYTHONDONTWRITEBYTECODE=1 python tests/test_tun_device.py     #  7/7
PYTHONDONTWRITEBYTECODE=1 python tests/test_registration.py   #  8/8
PYTHONDONTWRITEBYTECODE=1 python tests/test_protocol.py       # 10/10
PYTHONDONTWRITEBYTECODE=1 python tests/test_consumer.py       #  8/8
PYTHONDONTWRITEBYTECODE=1 python tests/test_provider.py       #  4/4
PYTHONDONTWRITEBYTECODE=1 python tests/test_hmac.py           #  4/4
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
| **两端数据面 + 真 UDP 链路上的一次完整 HTTP 往返** | `l3_m1c_loopback.py --dry-run` |
| 注入 → 跨网卡投递 → 源站 → 回程 | **M1b 真机**（D9 拓扑下） |
| Wintun 绑定的调用约定 | 非特权下 `CreateAdapter` 得到 `ACCESS_DENIED` |

| **未验证** | 备注 |
|---|---|
| `l3/` 跑在**真 tun** 上 | M1c 脚本已就绪，只差以管理员跑一次 |
| `WintunDevice.configure/add_route/read/write` | 只在 M1b 脚本里跑过，且是单次 SYN |
| CoLoR 链路（GET/隧道/上下行 DATA 经 RM/BR） | **完全没接**，需要 RM/BR 环境 |
| 跨域 PID 语义在 L3 下 | 复用 v1 的 `reverse_path_for_ack`，有 v1 单测，L3 下未实测 |
| 三个 M4 用例的真客户端 | 需要第二台机器 |
| 吞吐 / pps / 时延 | M5 推迟；现状每包一次 scapy，估计几千 pps 到顶 |
| 上行是否需要 HMAC、`Random_Num` 长期复用 | 设计 §8.5，待与 RM/BR 团队确认 |

---

## 8. 仍然待决

1. **§8.5 的四个问题**（上行要不要 HMAC、`Random_Num` 能否长期复用、BR 的 PID 会不会
   老化、单 SID 有无速率限制）。第三个直接决定 D1 能否成立、§8.4 的兜底要不要默认
   打开。**要 RM/BR 团队的答复，或真机实测。**
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
