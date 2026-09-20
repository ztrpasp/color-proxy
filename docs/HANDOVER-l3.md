# 交接文档 —— L3 隧道模式（分支 `dev_tun`）

> 目的：让新会话直接从 **M1c** 接着做，不必重建上下文。
> 开场读序：**本文 → `docs/design-l3-v2.md`（契约，rev.3）**。v1 的背景见 `docs/HANDOVER.md`。
> 截至 2026-09-20。

---

## 1. 一句话现状

L3 隧道模式（把完整内层 IP 包作 CoLoR DATA 载荷透传，取代端点级 L4 中继）在 `dev_tun` 分支上
**做到 M1b 真机通过**：契约 rev.3 已冻结，M0 / M1a / 数据面全部实现且离线全绿，
提供端的"注入 → 源站 → 回程"这一段已在真机验证。**尚未把 L3 接进两端装配，CoLoR 链路一行没接。**

| 里程碑 | 状态 | 说明 |
|---|---|---|
| M0 | ✅ | 类型位扩展、服务级 SID、两张服务表、配置校验、§9.3 四个 v1 遗留问题 |
| M1a | ✅ | `tun/ipv4.py`、`tun/mss.py`、`tun/device_win.py`(Wintun 绑定) |
| 数据面 | ✅ 离线 | `l3/`，§7.1 / §7.2 / §7.3 全部判据，18 项端到端断言 |
| **M1b** | ✅ **真机** | `tools/l3_m1b_inject.py` 读回 SYN-ACK |
| **M1c** | ⬜ **下一步** | 两个 tun + UDP 代替 CoLoR |
| M2 | ⬜ | 装配 + 接 CoLoR |
| M3 / M4 / M5 | ⬜ | 计数器日志与超时回收 / 三个验收用例 / 去 scapy |

回归基线：**86 项断言 + 2 个脚本式 e2e，全绿**。

---

## 2. 代码地图（本轮新增）

```
colorproxy/
  tun/
    ipv4.py         内层包解析。is_fragment 同时覆盖首片(MF=1)与非首片(off>0)，D15 两者都丢
    mss.py          MSS clamp（任何带 SYN 的包）+ RFC 1624 增量校验和；tcp_checksum 仅供自检
    device.py       TunDevice 协议 + LoopbackTun（读写方向分开，与真 tun 同语义）
    device_win.py   Wintun ctypes 绑定；interface_state/warn_if_weak_host_disabled
  l3/
    counters.py     §10.4 的 19 个计数器，每个丢包分支一个，不共用 drop
    tables.py       L3TunnelTable(提供端) / ConsumerTunnelTable(三态+首包队列+超时) / FlowCache
    provider.py     §7.2 握手/注入/回送 + §7.3 双向准入校验
    consumer.py     §7.1 上行/隧道/下行
  protocol/sid.py   service_canonical / lsid_from_service（规范串归一化集中在这里）
  config.py         l3 段 + §9.1 全部 fail-fast 校验
  consumer/config.py l3 段 + capture_routes 强制 /32 且不得覆盖本域 RM
  registration.py   RegistrationKeeper 常驻注册线程；tag=8 容错处理
tools/l3_m1b_inject.py   M1b 注入验证（需管理员）
tests/test_l3_m0.py / test_l3_dataplane.py / test_tun_ipv4_mss.py / test_tun_device.py / test_registration.py
```

---

## 3. 验证到什么程度（别高估）

| 已验证 | 方式 |
|---|---|
| §3.4 全部 SID 测试向量 | 单测 |
| MSS clamp + 校验和（多组取值） | 单测，与整包重算交叉验证 |
| 分片识别、ICMP 过滤、准入校验三种攻击 | 单测 |
| 两端数据面端到端（真 CoLoR 报文、假链路） | `test_l3_dataplane.py` |
| Wintun 绑定的调用约定 | 非特权下 `CreateAdapter` 得到 `ACCESS_DENIED`（走到驱动才有此错） |
| 注入 → 跨网卡投递 → 源站 → 回程 | **M1b 真机** |

| **未验证** | 备注 |
|---|---|
| `l3/` 数据面跑在**真 tun** 上 | 至今只在 `LoopbackTun` 下跑过 |
| `WintunDevice.configure/add_route/read/write` | 只在 M1b 脚本里跑过，且是单次 SYN |
| CoLoR 链路（GET/隧道/上下行 DATA 经 RM/BR） | **完全没接** |
| 跨域 PID 语义在 L3 下 | 复用 v1 的 `reverse_path_for_ack`，有 v1 单测，L3 下未实测 |
| 上行是否需要 HMAC、Random_Num 长期复用 | 见设计 §8.5，待与 RM/BR 团队确认 |

---

## 4. 三个待决问题（新会话开场先问用户）

1. **D9 还是 §2.5？** M1b 量化了 D9 的代价：**两张网卡上四个弱主机开关**，含在物理网卡上放宽主机模型（攻击面变大）。§2.5 的虚服务地址方案实测**四个开关一个都不需要**，契约完全相同，切换只改 `l3.services[].ip`。除非论述必须强调"发布真实物理地址"，否则 §2.5 更省事。
2. **`bin/` 与 `include/` 要不要进仓库？** 现为未跟踪。`wintun.h` 是 `GPL-2.0 OR MIT`，有 MIT 选项所以携带无许可问题；只是 427 KB 二进制进 git 历史拿不掉。备选：`.gitignore` + README 写下载步骤。
3. **最小弱主机开关集合要不要收窄？** 现在只知道"两边都开可行、只开 color0 不行"；服务网卡侧 send/receive 是一起开的，没隔离。四个全开是安全超集，文档已如实标注。

---

## 5. 踩过的坑（**务必先读**，每条都真实耗过时间）

1. **弱主机开关必须两端都开**（§2.3 rev.3 实测修正）。rev.2 写的"仅 color0"是错的：包写进了 tun、读写通路活着，但 TCP 协议栈根本不接受，**连 RST 都不回**，症状与防火墙拦截/源站只听回环完全一样。
2. **netsh 输出是本地化的**。中文 Windows 打印「弱主机发送 / 弱主机接收」，按 `weakhostsend` 解析永远匹配不到，症状是"开关明明开了还一直告警"。用 `Get-NetIPInterface`（属性名与 Enabled/Disabled 枚举都与语言无关）。
3. **服务地址必须在本机**——设计 §11 列的四种同症状故障之外的第五种。不在本机时内层包递上来既非本机地址、又无转发目标，直接丢弃，症状同上。`check_local_address` 已覆盖（并查 `AddressState` 必须为 Preferred）。
4. **`load[0]` 不能作模式分派判据**（D13）。提供端 ACK 路径的类型校验是 `cd9348b` 刻意删掉的（"宽松放行"），说明该字节在真机上曾对不上。一律先按 SID 查服务表分派，`load[0]` 只作宽松校验 + `load0_mismatch` 计数。**不要好心把强校验加回去。**
5. **PowerShell 单引号串里反引号不转义**：`'{0}`t{1}'` 会原样输出 `` `t ``。用 `-join` 或双引号串。
6. **仓库跟踪了 `__pycache__/*.pyc`**：跑测试一律加 `PYTHONDONTWRITEBYTECODE=1`，否则弄脏工作区。
7. **提交消息里的 ASCII 直引号会破坏 shell 引号配对**：中文长消息用 `git commit -F <文件>`。
8. **Wintun 细节**：非管理员 `WintunCreateAdapter` 返回 `ERROR_ACCESS_DENIED`（能走到驱动就说明签名/调用约定对）；`WintunSetLogger` 的回调对象必须保住引用（`_logger_callback_ref`），否则被 GC 后驱动回调会崩进程；`ring_capacity` 必须是 2 的幂且在 [128 KiB, 64 MiB]。
9. **新 tun 上有大量 IPv6 RS/MLD 与 IGMP 噪声**，是正常现象；诊断时按 IP 版本分类计数，别笼统报成"坏包"。

---

## 6. 怎么跑

```bash
# 离线回归（全绿基线：86 项断言 + 2 个脚本）
PYTHONDONTWRITEBYTECODE=1 python tests/test_l3_m0.py          # 13/13
PYTHONDONTWRITEBYTECODE=1 python tests/test_l3_dataplane.py   # 18/18
PYTHONDONTWRITEBYTECODE=1 python tests/test_tun_ipv4_mss.py   # 14/14
PYTHONDONTWRITEBYTECODE=1 python tests/test_tun_device.py     # 7/7
PYTHONDONTWRITEBYTECODE=1 python tests/test_registration.py   # 8/8
```

M1b（**管理员 PowerShell**，本机即可，提供端环境与本机类似）：

```powershell
# 一次性：把提供端的服务地址加到一张 host-only 网卡上（测完删）
netsh interface ipv4 add address "VMware Network Adapter VMnet1" 172.10.0.2 255.255.255.0
netsh interface ipv4 set interface "VMware Network Adapter VMnet1" weakhostreceive=enabled
netsh interface ipv4 set interface "VMware Network Adapter VMnet1" weakhostsend=enabled

python -m http.server 8000 --bind 0.0.0.0        # 另一个窗口，最小源站
python tools/l3_m1b_inject.py --configure        # 期望：✅ 读回 SYN-ACK
```

`--configure` 只替**脚本自己创建的 color0** 开弱主机开关与防火墙放行（退出即清理）；
服务地址所在网卡是长期存在的，属于改系统配置，按 §9.1 只告警不代劳。

三种结果的含义：**SYN-ACK** = 全链路成立；**RST** = 投递通、只是没人监听；
**超时** = 脚本会自动做半开连接检查与 A/B（改用 tun 自身地址）定位到具体哪一跳。

---

## 7. 下一步怎么做

### M1c —— 两个 tun + UDP 代替 CoLoR（下一步）

数据面的**逻辑**已由 `test_l3_dataplane.py` 端到端覆盖，所以 M1c 的增量价值只在
**真 tun + 真内核路径**：MTU 生效、真实 SYN/SYN-ACK 经过 clamp、内核路由选择。建议
写 `tools/l3_m1c_loopback.py`：起两个 Wintun 适配器（消费端侧 / 提供端侧），把
`L3Consumer` 与 `L3Provider` 的 `sender` 换成一对 UDP socket 直连，跑一次 `curl`。

注意：两个 tun 在**同一台机器**上，地址与路由要避免互相吞掉（§2.4 的规则同样适用），
两端 tun 不能都在 `10.99.1.0/24` 里用同机路由——M1c 需要单独规划一段，别照抄 §2.1。

### M2 —— 装配 + 接 CoLoR（最要紧的一块）

1. `provider.py`：`_on_payload` 的 GET/ACK 分支先试 `L3Provider.handle_get/handle_upstream`
   （它们在 SID 不属于 L3 时返回 `False`），再回落 v1 的 `handlers`；起 tun 读线程调
   `on_tun_packet`；启动时 `warn_if_weak_host_disabled(tun, 服务地址所在网卡)`。
2. `consumer/consumer.py`：DATA(B=0) 分支先试 `L3Consumer.handle_tunnel/handle_downstream`，
   再回落 v1；起 tun 读线程；起一个定时线程调 `expire_handshakes()`（**不调的话握手失败的
   首包会永久滞留**）。
3. 两端各起一个每 5 s 打 `counters.format_line()` 的线程（§10.4）。
4. 然后把 `l3.enabled` 改 `true`，按 §2.1 配地址，跑
   `Test-NetConnection 172.10.0.2 -Port 8000` → `curl http://172.10.0.2:8000/hello.html`。

### M3 / M4 / M5

- **M3**：数据面已实现首包缓冲与超时回收，缺的只是 M2 第 2、3 步的定时调用。
  ICMP 3/4 按 D16 已降级为可选，别花时间（D3 拓扑下近乎不触发）。
- **M4**：被动 FTP（需 `tcp://ip:0` 通配，注意 §8.3 目的粒度退化到主机级）、
  一条视频流连续 5 分钟（**内层 UDP 净载荷须 ≤ 1252 字节**，否则分片被 `frag_drop` 丢）、
  MySQL 增删改查。
- **M5**：数据面去 scapy（`l3/provider.py`、`l3/consumer.py` 现在都用 `ColorData`
  解析/构造，是已知的逐包开销）；预生成 CoLoR 头模板 + `struct` 回填，走 raw socket
  `sendto` 并**显式指定源地址/接口**（§2.4 第 2 条）。另需实测逐包 MD5 HMAC 的成本。

---

## 8. 提交历史（`dev_tun`，从 `dev_consumer` 切出）

```
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
