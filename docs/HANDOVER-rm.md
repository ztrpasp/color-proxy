# RM 工作区快速导览

给在 `共生网络终端开发方案/the-rm-server-web` 里新开的工作区看。读完应该能回答：共生网络是什么、RM/BR/终端各管什么、
RM 的代码在哪、现在要做什么、以后排着什么。

- 写于 2026-10-29，基于 RM 分支 `dev_zwd`（`c598cb8`）与 color-proxy 分支 `fix/tun`。
- 本轮任务的方案：`C:\Users\ZWD15\Desktop\color-proxy\docs\design-ann-sid-desc.md`（下称「方案」），**先读本文，再读方案**。
- 协议原文：`共生网络终端开发方案/参考资料/共生网络技术文档+报文转发（修正）.docx`（命名空间、报文格式、转发流程）。

---

## 1. 共生网络是什么（5 分钟版）

面向**跨域**数据安全流动的网络架构，以自治域（AS）为单元。每个 AS 里有三类组件：

| 组件 | 职责 | 代码 |
|---|---|---|
| **RM**（资源管理器） | 终端注册；处理通告（ANN），维护 SID 路由表；处理请求（GET），查表转发并追加 PID；ACL；向 BR 同步控制信息 | `the-rm-server-web`（本仓库，DPDK） |
| **BR**（边界路由器） | 跨域转发 ANN/GET/DATA；入域 PID 校验；出域数据管控（ODC）+ HMAC | `the-new-br-master`（DPDK + sqlite3 + openssl） |
| **终端代理** | 提供端发布 SID（ANN）、回数据（DATA）；消费端发请求（GET）、收数据 | `color-proxy`（Python，Windows） |

### 1.1 三个名字空间

- **NID**：128 bit，节点标识（规范上是公钥哈希，原型里是配置的 16 字节，例如 `a1a1…a1`）。
- **SID**：288 bit = `N_SID(16) ‖ L_SID(20)`。N_SID 是提供者的 NID，L_SID 是服务本身的哈希。
  color-proxy 的 L_SID = SHA1(规范串)：内容级是 `http://ip:port/path`，服务级是 `tcp://ip:port`（见方案 §2.2）。
- **PID**：4 字节，标识一段域间路径。高 16 位是 **PX**（相邻两个 AS 之间链路的前缀，只需局部唯一），
  低 16 位取自 MD5(消费端 NID ‖ SID ‖ 上一个 PID ‖ 本域密钥 sk ‖ PX)（`rte_CoLoR.c:233` 的 `GET_calculate_PID`）。
  RM 转发 GET 出域时追加一个 PID，BR 按 PID 前缀转发、入域时校验。

### 1.2 四类报文（CoLoR 跑在 IPv4 上，**IP 协议号 150**，CoLoR 头首字节 = 版本 7 << 4 | 类型）

| 类型 | 谁发给谁 | RM 处理 |
|---|---|---|
| ANN（1） | 提供端 → 本域 RM；RM → BR → 邻域 RM | `src/packets/ann.c` → `rm_ANN_parse_store` / `rm_ANN_forward_px_units` / `rm_ANN_construct_ann` |
| GET（2） | 消费端 → 本域 RM → BR → … → 提供端所在域 RM → 提供端 | `src/packets/get.c` → `rm_GET_process` |
| DATA（3） | 提供端 → BR → … → 消费端，**不经过 RM** | RM 直接丢弃（计入 unsupported） |
| CONTROL（4） | 注册、配置、同步、统计 | `src/packets/ctrl.c` → `rm_CONTROL_process` |

### 1.3 一次完整的流程

```
通告：提供端 P ──ANN──▶ RM_a ──(附 PX)──▶ BR_a ──▶ BR_b ──▶ RM_b ──▶ … 每个 RM 存表后按策略继续泛洪
请求：消费端 C ──GET──▶ RM_b ──(查表、追加 PID)──▶ BR_b ──▶ BR_a ──▶ RM_a ──▶ P
                        提供端所在域的 RM 另给 BR 发 CONTROL tag 16（SID、消费端 NID、PID 序列、随机数 rn）
数据：P ──DATA(PID 序列, 指针)──▶ BR_a（查 ODC 表 + 校验 HMAC）──▶ BR_b（校验 PID、指针减 1）──▶ C
```

### 1.4 注册（CONTROL）

1. 终端发 tag 5（REG_PROXY），载荷 `IP(4) + NID(16)`；
2. RM 回 tag 6（RET_PROXY）：`num + [IP(4, 小端) NID(16)]×num + num + [PX(2) IP(4)]×num`
   ——**IP 在前**，`ctrl.c` 里的注释写成 `[NID IP]`，是错的；
3. RM 向本域其他终端和全部 BR 发 tag 8（SYN_CONFIG_PROXY），载荷就是注册者的 20 字节 `IP + NID`，**没有条目数**；
4. 全 0 SID 的 GET 表示终端在要 SID 列表，RM 用 CONTROL tag 40 回复，每包最多 10 条，每条 36 字节。

---

## 2. 仓库地图（`C:\Users\ZWD15\Desktop\共生网络终端开发方案\`）

| 目录 | 是什么 |
|---|---|
| `the-rm-server-web` | **线上在用的 RM**。在 `the-rm-server` 基础上加了 Web 监控、结构化日志、计数器 |
| `the-rm-server` | 原版带 ACL 的 RM，对照用 |
| `the-new-rm-master` | 更老的一版 RM，对照用 |
| `the-new-br-master` | BR 源码 |
| `参考资料/` | 协议技术文档（两份 docx，「+报文转发（修正）」那份更新） |
| `corlor多协议代理/`、`应用层HTTP代理终端/`、`archive/`、`BF/` | 终端侧的汇报材料、需求分析、拓扑图（pptx/md） |
| `C:\Users\ZWD15\Desktop\color-proxy` | 终端代理（另一个仓库） |

### 2.1 RM 仓库的分支

- `dev_zwd`（当前）：在 main 之上多两个修复——`925eb57` 重算 IPv4 校验和前先清零（之前转发的 GET 校验和是错的，
  Windows 终端在 IP 层把包丢了），`c598cb8` 查不到 SID 的 GET 默认丢弃（「攻击者 AS」演示改为由环境变量开启）。
  **两个修复都还没上真机验证。**
- `main`：`c1a2b67` 是用户原有未提交改动（Web/日志/计数器）的快照。
- `origin/dev`：远端另有 4 个提交不在 main 里，与 `dev_zwd` 无关，别混用。

---

## 3. 原型部署（两节点四区）

| AS | 网段 | RM | BR | 终端 |
|---|---|---|---|---|
| AS1（节点 1 一级区） | `10.10.X.X` | `10.10.0.5` | `10.10.0.1` | SVR1-1 `10.10.0.2`，**提供端**，NID `a1…`，服务地址 `10.10.9.2` |
| AS2（节点 1 二级区） | `172.10.X.X` | `172.10.0.5` | `172.10.0.1` | SVR1-3 `172.10.0.2`，消费端，NID `b2…` |
| AS3（节点 2 一级区） | `10.20.X.X` | `10.20.0.5` | `10.20.0.1` | — |
| AS4（节点 2 二级区） | `172.20.X.X` | `172.20.0.5` | `172.20.0.1` | SVR2-3 `172.20.0.2`，消费端，NID `c3…` |

链路：AS1—AS2、AS3—AS4（节点内），AS1—AS3、AS2—AS4（广域网切片）。服务有 HTTP（8000，另有 26 个 URL 级 SID）、
FTP（21）、MySQL（3306）、RTP（udp 5004）。ACL 规则加在 RM 1-1（`10.10.0.5`），清单在
`color-proxy/deploy/prototype/acl-rules.md`（由脚本生成）。详见 `color-proxy/deploy/prototype/README.md`。

---

## 4. RM 代码导览

### 4.1 编译、运行

- 依赖 DPDK 23 LTS，只能在 Linux 上编译运行（README 以 Ubuntu 22.04 为例）。Windows 上只能改代码，编译和测试都要到 RM 机器上做。
  **改好的代码怎么同步到 RM 机器，先问用户。**
- 开机执行一次 `set-rm.sh`（大页内存 + 绑网卡），改了代码执行 `re-build-rm.sh`（meson），运行用 `run-rm.sh`。
- `run-rm.sh` 用 `-l 1,2`：**主 lcore 跑 CLI，另一个 lcore 跑全部收发包**（`worker_main`）。另外还有两个 pthread：
  Web（`rm_web.c:942`）和日志消费线程（`rm_log.c:403`）。所以数据面是单线程的，但 CLI、Web 会和数据面并发读写同一批表。
- 工作区 `core.autocrlf=true`，仓库里存的是 LF。如果绕过 git 直接把工作区文件拷到 Linux，`*.sh` 会带上 CRLF，跑不起来。
- 单元测试：`meson test -C build`（`tests/` 下 metrics、log、monitor 三个）；`bash tests/web_smoke.sh` 测 Web 接口；
  `pytest/` 里是 scapy 发包脚本（从另一台机器往 RM 网卡打 ANN/ARP/DATA，脚本里写死了网卡名和 MAC）。

### 4.2 收包到处理

`include/process/rm_main_function.h` 的 `rm_process_single_packet`：ARP → `arp.c`；非 IPv4、IP 协议号不是 150、CoLoR 版本不是 7
的直接丢；然后按类型分给 ann/get/ctrl，DATA 丢弃。

### 4.3 模块

| 路径 | 内容 |
|---|---|
| `src/app/main.c`、`init.c` | EAL/端口/内存池初始化，lcore 分配，启动时打开的全局策略开关，读 `global_as_config`、`ip_route_static` |
| `src/packets/` | 四类报文的入口（`ann.c`、`get.c`、`ctrl.c`、`arp.c`）；`rte_CoLoR.c` 是报文构造、校验和、打印（`CoLoR_show_pkg`）、md5 |
| `src/process/rm_pkt_process.c` | **核心逻辑**：ANN 解析/存表/转发决策/重组，GET 查表、ACL、策略过滤、追加 PID，CONTROL 解析 |
| `src/process/rm_send.c`、`include/process/rm_send.h` | 组 IP 头发包；ARP 未解析时缓存待发包 |
| `src/tables/rm_sid_table.c` | SID 表：cuckoo hash，按 L_SID（20 字节）优先，否则按 N_SID 作键，值是 `sid_info_t` 链表（同一 SID 的多个来源，按 AS 路径长度排序）。另有 `g_tsid_table`：N、L 都有的 SID 的平铺列表（上限 1024），给 Web/CLI/tag 40 用 |
| `src/tables/rm_proxy_table.c`、`rm_br_table.c` | 本域终端、BR（NID ↔ IP ↔ 端口） |
| `src/tables/rm_as_table.c`、`rm_as_graph.c` | 邻域 AS、BR 与 PX 的对应；全局拓扑图，`graph_trace` 从 GET 的 PID 倒推源 AS（ACL 用） |
| `src/tables/rm_acl_table.c` | ACL：`(SID, ASID, NID)` 精确匹配（NID 全 0 为通配），按 id 从小到大找第一条命中的规则，都不命中则放行 |
| `src/tables/rm_info.c` | `my_as_info`（本 AS 的 aid、端口 IP、密钥 sk、拓扑图）、全局策略表与快速开关位图 |
| `src/tables/rm_control.c` | 解析 `rm_config`（端口 IP）、`config_recieve_file`（CONFIG_RM 控制报文的二进制） |
| `src/tables/rm_routing_table.c`、`rm_ip_mac.c` | 静态路由（`ip_route_static`，最长前缀匹配）、ARP 表 |
| `src/telemetry/` | 结构化日志（`rm.log`，自动轮转）、计数器、Web（`rm_web.c` + `web/`）、监控快照 |
| `src/commandline/` | CLI：`display [config\|graph\|acl\|sid\|status]`、`acl add …`、`acl delete id N` |

### 4.4 配置文件

| 文件 | 作用 | 怎么生成 |
|---|---|---|
| `rm_config` | 端口 IP（`#端口号 IP`，`@`/`&` 包住） | 手写，或用 `gen-rm-config.py` |
| `config_recieve_file` | CONFIG_RM 控制报文：本域信息、邻域 AS、BR、PX | `as-config.py` |
| `global_as_config` | 全局拓扑：`$ <AS> <AS> 0x<px>` 一行一条有向边 | 手写。**ACL 依赖它**：GET 路径上每条链路都要有 |
| `ip_route_static` | 静态路由 | 手写 |

### 4.5 Web 与环境变量

默认监听 `127.0.0.1:8080`。接口有 `/api/v1/{health,metrics,logs,sids,acls}`、`POST/DELETE /api/v1/acls`、
`/metrics`（Prometheus 格式）。环境变量：`RM_WEB_*`、`RM_LOG_*`；`RM_DEMO_FORWARD_UNKNOWN_SID=1` 开启「攻击者 AS」演示，正式部署不要设。详见 README。

---

## 5. BR 速览（`the-new-br-master`）

- 收发分离的 pipeline（`br-pipeline0.c`：`br_rx_loop` / `br_worker_loop` / `br_tx_loop`）。
- 主要的表（`tables/`）：`nid_table`（终端 NID → 域内地址，来自 tag 8）、`px_table` / `peer_table`（PX → 对端 BR）、
  `odc_table`（出域数据管控，来自 RM 的 tag 16）、`arp_table`。
- CLI：`display arp|config|nid-table|odct|peer|px|stats|ports`，`debugging on|off`，`odc enable|disable`，`pid-verify enable|disable`。
- 已知行为：
  - **ODC 表项按 SID 空闲 800 s 过期**（`ODC_ENTRY_EXPIRE_SECONDS`），每个匹配的下行 DATA 会把计时器重置回 800 s。
    过期后，提供端发的下行 DATA 报 "No ODC entry" 并被丢弃；上行（B=1）不受影响。
  - 每个键 `(L_SID, 消费端 NID, hash(PIDs))` 只保留最新的 rn。
  - `odc_key` 把 uint32 的 hash 按 uint64 写进 4 字节的槽，越界写 4 字节。
  - BR 对每个 DATA 都打印 "received a color data packet"，但丢包日志要 `debugging on` 才出来。

---

## 6. 终端（color-proxy）怎么用 RM

- **提供端**：注册（tag 5）→ 每条 SID 发**一次** AM=1 的 ANN → 收 GET 回 DATA。退出时发 AM=3（但 RM 不看 AM，见 §7）。
  `REGISTER_REFRESH_SEC` 默认 0，即不做周期刷新；设成正数时刷新用 AM=2。
- **消费端**：注册 → 用全 0 SID 拉 SID 列表（tag 40）→ 发 GET（标志 0x18 = A|S，NID 后面跟 4 字节 Segment_ID，
  所以第一个 PID 在偏移 68 而不是 64）→ 收 DATA。
- **L3 隧道模式**（当前主线）：完整 IP 包作为 DATA 载荷透传。消费端对每条新 TCP 连接、每个新 UDP 流先发一次 GET（D19），
  HTTP 每个请求再按 URL SID 发一次 GET（D20），所以 **RM 的 ACL 能管到新连接和单个 URL**。
- 终端侧总体交接：`color-proxy/docs/HANDOVER-l3.md`；L3 契约：`color-proxy/docs/design-l3-v2.md`（§8.5 是待 RM/BR 团队回答的六个问题）。

---

## 7. 真机踩过的坑（排障先看这里）

| 现象 | 原因 | 怎么查 |
|---|---|---|
| Wireshark 抓得到 RM 转来的 GET，提供端一行日志都没有 | RM 算 IPv4 校验和前没清零旧值，Windows 在 IP 层丢包（已在 `925eb57` 修，待真机验证） | Wireshark 打开 IPv4 校验和验证；`netstat -s -p ip` 看「接收的标头错误」 |
| `GET denied by ACL: unable to identify source AS`（ACL 表为空也会这样） | `global_as_config` 缺 GET 路径上的链路，`graph_trace` 倒推失败，倒推失败一律拒绝 | CLI `display graph`；每台跑 ACL 版本的 RM（包括中转的）都要有完整拓扑 |
| 运行中重新配置 RM 后 ACL 全部拒绝 | 收到 CONFIG_RM 时 `global_set_as_info` 清空拓扑图，而且不重读 `global_as_config` | 重启 RM |
| 同一条 SID 重复通告报 `unable to insert SID entry` | RM 不看 AM，重复通告走插入路径，策略相同时返回 -2 | 无害，但会刷屏（方案 P1 第 9 条） |
| 屏幕上打印出来的 GET PID 不对 | `show_GET` 从固定偏移读 PID，没跳过 Segment_ID | 以 `rm_GET_pid_start`（从包尾倒推）为准 |
| `graph_trace` 调试行的 `npx` 不对 | 这行在 `npx` 赋值之前打印，显示的是上一次的值 | 别据此判断 PX 解析错 |
| 空闲十几分钟后下行全断，重启消费端才好 | BR 的 ODC 表项空闲 800 s 过期（§5） | BR `display odct`、`debugging on` |
| 注册发了 3 个包都没有回复 | 几乎总是终端的 `rm_ipv4` 配错了（RM 那边一行日志都没有） | 核对终端配置 |

---

## 8. 现在要做的：ANN 携带 SID 名称与描述

方案已定，见 `design-ann-sid-desc.md`。要点：

- 通告单元新增两个策略 TLV：**tag 13 = SID_NAME**（L_SID 的哈希原文，RM 校验 `SHA1(NAME) == L_SID`），
  **tag 14 = SID_DESC**（协议名，例如 `http`/`ftp`/`mysql`/`rtp`，只展示）；跨域原样转发。
- RM 侧分三档（方案 §4）：
  - **P0 必修**：`ubuf[128]` 和 256 字节转发缓冲；解析边界检查；转发循环读到未初始化的 `mark_array`；`check_same_strategy` 越界读与泄漏；
  - **P1**：TSID 表存名称/描述副本、内嵌 SHA1 校验、Web/CLI 展示、-2 的日志降级；
  - **P2（可选）**：按名称前缀写 ACL。
- 建议顺序：P0 → P1 → P2，每档单独提交。终端侧在 RM 完成 P0 之前按 73 字节预算发送，对现有 RM 是安全的。
- 自测可以直接用方案 §2.6 的 92 字节 ANN 和 SHA1 向量。

---

## 9. 以后要做的（backlog）

RM：

| 事项 | 说明 |
|---|---|
| ANN 的 AM 语义 | 实现注册/更新/注销；修 `GET_ANN_UNIT_FLAG_AM`（应为 `((flag >> 3) & 0x3)`）。现在 SID 无法注销，只能重启 RM |
| SID 表老化 / RM 重启恢复 | 表从不过期；RM 重启后终端不会自动重新通告 |
| ACL 表线程安全 | worker、CLI、Web 三个线程读写同一张 ACL 表，没有加锁 |
| Web 健壮性 | 启动失败会 `rte_exit` 拖垮整个 RM；`recv` 没有超时；400 错误的具体信息被丢掉了 |
| 终端重复注册 | 重复注册时 RM 不报任何东西 |
| GET 的 rn 写死 | `get.c` 里 `rn = 0x20220220`（todo）。改成真随机前要考虑 BR 每个键只保留最新 rn，以及终端每条新连接都发 GET（D19）带来的影响 |
| tag 40 带名称 | SID 列表回给终端时带上名称/描述，消费端就有服务目录（两端一起改） |
| 多单元 ANN 转发溢出 | 已包含在方案 P0 第 1 条 |

BR：`odc_key` 越界写；ODC 800 s 空闲过期是否合理。

待 RM/BR 团队确认（`design-l3-v2.md` §8.5）：上行 DATA 是否要 HMAC；同一个 rn 能否长期复用；BR 的 PID 会不会老化；单条 SID 有无速率限制。

---

## 10. 工作约定

- 用户用中文交流；回答先说结论，少用自造的术语。
- 可以按判断 commit（大任务分步提交）；**push、改写历史要先问**。
- 改 RM 时同步更新 README 里受影响的部分（CLI、接口、环境变量）。
- 跨仓库的契约（报文格式、tag 号）以 color-proxy 的 `docs/` 为准；两边对不上时，先停下来问用户。
