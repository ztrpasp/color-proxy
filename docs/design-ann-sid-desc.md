# ANN 通告单元携带 SID 名称与描述（策略 tag 13 / 14）

- 状态：方案已定（2026-10-29）。RM 侧 P0、P1 已实现（the-rm-server-web `dev_zwd`：P0 `87f48b3`、P1 `9350422`，
  2026-10-30）；终端侧已实现（color-proxy `fix/tun` 的 `6142756`，2026-10-30，预算 73 字节）。两者都**待真机验证**；
  RM 的 P2 未实现
- 2026-10-30 修订：RM 实现 P0 时对照代码 review，改了 6 处，都不涉及报文格式和 tag 号——
  终端预算改为 200 的前提（§2.5、§5、§7）、`len = 0` 的实际后果（§2.4、§3.1）、转发时 AM 位被清零（§3.2、§9）、
  P0 第 1、2 条的做法（§4）、无 TLV 的通告会连 tag 1/2 一起清掉（§6）
- 涉及：终端 color-proxy（本仓库）、RM `共生网络终端开发方案/the-rm-server-web`（分支 `dev_zwd`）
- BR 不用改：它只转发 ANN，不解析通告单元（技术文档 §5.1.3）

## 0. 要解决的问题

提供端发布 SID 时，ANN 里只有 `N_SID ‖ L_SID ‖ NID`。L_SID 是哈希值，RM 只看得到一串 72 位十六进制，
不知道它对应哪个服务。RM 做资源管理（SID 列表、统计）、配 ACL 时只能拿终端日志去对照。

做法：在通告单元的**策略单元**（Strategy Unit，TLV：1 字节 tag + 1 字节 length + value）里加两种新策略，
一种带 SID 的名称（L_SID 的哈希原文），一种带描述。

## 1. 已定的决策

| # | 决策 | 理由 |
|---|---|---|
| 1 | 用**两个** TLV：tag 13 = SID_NAME，tag 14 = SID_DESC | NAME 能被 RM 校验（`SHA1(NAME) == L_SID`），可以用于 ACL；DESC 是提供端自己说的、核实不了，只用于展示 |
| 2 | tag 号定为 **13 / 14** | RM 里 1–12 已占用（见 §3.1），13、14 是下一个空位 |
| 3 | 跨域转发时**原样带上** | RM 现在本来就把全部策略 TLV 原样转发；邻域 RM 也能展示和校验 |
| 4 | DESC **复用现有的 `desc` 配置**，内容精简为协议/服务名（`http`、`ftp`、`mysql`、`rtp`） | 不新增配置项。原来写在 desc 里的运维备注已移到 `deploy/prototype/README.md` |

## 2. 报文格式

### 2.1 在报文里的位置

```
ANN = ANN_front(8) + Announce_Unit × Unit_Num + PX × PX_Num

Announce_Unit:
  flag(1)          N|L|I|AM(2)|r(3)
  unit_len(1)      本单元总字节数，含全部策略单元
  strategy_num(1)  策略单元个数
  N_SID(16)        N=1 时有
  L_SID(20)        L=1 时有
  NID(16)          I=1 时有
  Strategy_Unit × strategy_num:
    tag(1) | len(1) | value(len)
```

color-proxy 发出的单元 N、L、I 恒为 1，所以固定部分是 3 + 16 + 20 + 16 = **55 字节**。

### 2.2 tag 13：SID_NAME

- value 是**计算 L_SID 时被哈希的那串字节**，原样放进来，不带 NUL 结尾：
  - 内容级（v1，或 L3 的 D20 URL SID）：去掉 query/fragment 的 URL，例如 `http://10.10.9.2:8000/api/items`；
  - 服务级（L3）：`<proto>://<ipv4>:<port>`，例如 `tcp://10.10.9.2:3306`。
- 因此任何一台 RM 都能校验 `SHA1(value) == L_SID`。L_SID 在转发途中不变，所以邻域 RM 也能独立校验。
- 校验不通过时：**不拒收这个通告**（保持兼容），RM 只记一条 warn，并把这个 SID 的名称标成"未校验"。
  未校验的名称只能展示（显示时要能看出没校验过），不能用于 ACL。

### 2.3 tag 14：SID_DESC

- value 是 UTF-8 文本，不带 NUL 结尾。约定只写协议/服务名，小写：`http`、`ftp`、`mysql`、`rtp`。
- 只用于展示，**不参与任何判定**。

### 2.4 共同规则

- 一个通告单元里每种 tag 最多出现一次。重复出现时 RM 取第一个，并记 warn。
- RM 不得依赖 13 和 14 的先后顺序。终端固定先 13 后 14。
- 不发空 value（`len = 0`）。P0 之前的 RM 存表时要 `rte_malloc(0)`，它返回 NULL，
  **整个 ANN 被当成内存不足丢弃**（日志 `unable to copy ANN strategy value`，计入 no_memory）。
  P0 之后改为存成 value = NULL；但转发时 `ANN_unit_append_strategy` 仍然跳过 `len = 0` 的策略单元
  （`strategy_num` 跟着少 1，不会错），所以邻域 RM 看不到它。
- 同一条 SID 的 AM=1 / AM=2 / AM=3 三种通告都带**相同的** TLV，理由见 §6。

### 2.5 长度预算

| 约束 | 来源 | 策略单元合计上限（含每个 2 字节头） |
|---|---|---|
| RM 转发时用 `uint8_t ubuf[128]` 拼单元（P0 之前） | `rm_pkt_process.c:448` | 128 − 55 = **73 字节**（超了 RM 栈溢出） |
| `unit_len` 只有 1 字节 | 报文格式 | 255 − 55 = **200 字节** |

- **终端按 73 字节执行，直到部署里所有 RM 都完成 §4 的 P0，才改为 200**。只升级提供端所在域的 RM 不够：
  ANN 会泛洪到每个域，每台 RM 转发前都要用自己的缓冲重新拼单元，任何一台没升级的 RM 都会被超长的单元写坏栈。
- 超出预算时的取舍：NAME 要么完整发、要么不发（截断后校验必定失败）；DESC 按 UTF-8 字符边界截断。
  无论是丢弃 NAME 还是截断 DESC，都要打 warn。
- 现有配置都在预算内：最长的 NAME 是 `http://10.10.9.2:8000/api/monitor/location-a/snapshot`（53 字节），
  加上 DESC `http`，合计 (2+53) + (2+4) = 61 字节。

### 2.6 测试向量

SHA1(NAME) = L_SID：

| NAME | 字节数 | SHA1 = L_SID |
|---|---|---|
| `tcp://10.10.9.2:3306` | 20 | `d992c50089cf6b0490bcff0dbf65bdede57e4e64` |
| `http://10.10.9.2:8000/api/items` | 31 | `b16b4f7c8a252c6c03ccb763d4f2c49ec8553d00` |
| `http://10.10.9.2:8000/api/monitor/location-a/snapshot` | 53 | `c318064243d0e4e453c9cc978f84046e9a79a494` |

一个完整的 ANN（92 字节）：提供端 NID `a1`×16，服务 `tcp://10.10.9.2:3306`，DESC `mysql`，AM=1。
它是用 color-proxy 现有的 `ColorAnnounce` / `AnnounceUnit` / `StrategyUnit` 生成的，可以直接用于 RM 侧的单元测试：

```
71405c0092910010e85402a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1d992c50089cf6b0490bcff0dbf65bdede57e4e64
a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a10d147463703a2f2f31302e31302e392e323a333330360e056d7973716c
```

拆开来看：`71` 版本 7 / 类型 ANN，`40` TTL，`5c00` 总长 92（小端），`9291` 校验和，`00` 标志，`10` = 1 个单元、0 个 PX；
单元 `e8` = N|L|I、AM=1，`54` unit_len = 84，`02` 两个策略单元；
`0d 14 "tcp://10.10.9.2:3306"`，`0e 05 "mysql"`。

### 2.7 发送与转发的粒度（2026-10-30 补）

**终端**：每条 SID 发一个 ANN，每个 ANN 只带一个通告单元，不攒批。注册成功后按顺序一次发完，中间不限速：
先 v1 `services[]`，再 L3 服务级，最后 L3 内容级（原型提供端共 4 + 4 + 26 = 34 个 ANN）。
每个 ANN 最长 8 + 55 + 73 = 136 字节（预算放宽到 200 后是 263 字节），远小于 MTU，不会被 IP 分片。
刷新（AM=2，默认关）和注销（AM=3，退出时）也是一条 SID 一个包。

**RM**：每收到一个 ANN 立即处理，不跨包合并，也不攒批：

1. 格式检查（`ANN_check_format`）→ 校验和 → 逐个单元存表；
2. 对每个邻域 AS（跳过通告来源的 AS，以及开启 AS 安全检查时安全等级不够的 AS），挑出可以发给它的单元。
   这几种单元不转发：存表时判为策略没变（-2）的、不是最短 AS 路径（0）的、被 tag 1/2 策略拦下的；
3. 每个邻域 AS 生成一个新的 ANN，装着挑出来的单元，PX 序列末尾追加去往该邻域的 PX，发给连着这个邻域的 BR。

所以 RM 只按邻域拆分：收到一个带 n 个单元的 ANN，最多转出「邻域数」个 ANN，每个不超过 n 个单元。
终端的每个 ANN 只有一个单元，RM 转出的也就各只有一个。`Unit_Num` 只有 4 位，一个 ANN 最多 15 个单元。

## 3. RM 现状（2026-10-29 审查 the-rm-server-web `dev_zwd`）

本节是 P0 之前的代码状态，行号对应 `c598cb8`；P0 改了什么见 §4。

### 3.1 通告单元怎么处理

| 环节 | 位置 | 行为 |
|---|---|---|
| 解析 | `src/process/rm_pkt_process.c:212` | 按 `strategy_num` 逐个读 TLV，存进 `mark_array[i].strategy_pt[]`（`mark_t` 定义在 `include/process/rm_pkt_process.h`） |
| 存储 | 同上 `:265` | 每个 TLV 的 value `rte_malloc` 一份，挂到 `sid_info_t.strategy_array`。**不认识的 tag 也照存** |
| 转发判定 | 同上 `:380` | 只认 tag 1（安全等级）、2（通告路径白名单），其余忽略 |
| 重组转发 | 同上 `:442`、`rte_CoLoR.c:140` | `ubuf[128]` 拼单元，全部 TLV 原样追加，不查越界；每个转出的 ANN 只分配 256 字节（`src/packets/ann.c:54`） |
| GET 过滤 | `rm_GET_check_filter`，`rm_pkt_process.c:558` | 只认 tag 1/2 |
| ACL | `src/tables/rm_acl_table.c:48` | 36 字节 SID + ASID + NID 精确匹配 |
| 展示 | `rm_web.c:495`（`/api/v1/sids`）、`cmd_parser.c:332`（`display sid`） | 读 `g_tsid_table`，每条只有 36 字节 SID（`include/tables/rm_sid_table.h:21`） |

结论：**协议上只要新增 tag，RM 不改也能收下、存下、转发出去**（前提是不超过 73 字节，否则写坏 RM 栈；
并且不发 `len = 0` 的策略单元，否则整个 ANN 被丢弃，见 §2.4）；
要展示、校验、拿来做 ACL，都要写新代码。

已占用的 tag（`include/packets/rte_CoLoR.h:176`）：1、2 随 ANN 携带；3–12 是 RM 的全局开关，和 ANN 的 tag 共用一套编号。
`global_quick_set_strategy`（`rm_info.c:186`）用 `0x1 << t` 置位，`t ≥ 31` 是未定义行为，以后新增的 tag 也不要超过 30。

### 3.2 RM 不看 AM 位

`GET_ANN_UNIT_FLAG_AM` 只有定义、没有任何地方调用（而且这个宏本身写错了，见 §9）。注册、更新、注销三种通告都走插入路径
（`rm_sid_table.c` 的 `sid_store_insert`）。同一 SID、同一节点再收到一次通告时：

- 策略与已存的相同：返回 -2，调用方把它当成错误，打 `unable to insert SID entry`；
- 策略不同：用新的策略数组整体替换旧的，并重新向邻域转发。

所以**改 DESC、重新通告一次就能生效**。注意：`g_tsid_table` 只在首次插入时写入（`rm_sid_table.c:160`），
替换策略的那条路径不会更新它。

另外，**RM 转发时会把 AM 位清零**：`ANN_unit_construct`（`rte_CoLoR.c`）重建单元时 flag 只置 N/L/I，
所以邻域 RM 收到的通告单元一律是 AM = 0，与提供端发的是哪种通告无关。RM 现在不看 AM，暂时没有影响。

## 4. RM 侧改动

### P0：必修（不修的话，终端一带 TLV，RM 就可能被写崩或误过滤）

已实现（`87f48b3`）：格式检查是 `rte_CoLoR.c` 的 `ANN_check_format`，单元测试在 `tests/test_ann_format.c`。
另外顺带修了 §2.4 的 `len = 0`：存成 value = NULL，转发判定和 GET 过滤读 tag 1（安全等级）之前先检查 len。

1. **重组缓冲**：`rm_pkt_process.c:448` 的 `ubuf[128]` 改成 256；`ANN_unit_append_strategy` 写之前先检查
   `unit_len + 2 + l ≤ 255`，放不下就不追加（并记 warn）。`ann.c:54` 每个转出 ANN 固定分配 256 字节，
   多单元 ANN 现在就会溢出：5 个不带策略的单元已经要 8 + 5×55 = 283 字节。改为按收到的报文分配 `pkg_len + 2`：
   转出的报文里，单元只会被过滤、字段只会被省略、放不下的策略只会被丢掉，只多出一个 PX，所以不会比收到的长。
   不要把报文里的 `unit_len` 加起来算——第 2 条说了它不可信。
2. **解析边界检查**（`rm_pkt_process.c:125` 起）：
   - 整包：`pkg_len` 不大于 mbuf 里 IP 头之后的实际长度；
   - 每个单元：固定部分和每个 TLV 的 `pt + 2 + len` 都不越过 `pkt + pkg_len − 2 × PX_Num`；
   - `unit_len` 与按 flag 和 TLV 实算出的长度不一致时：记 warn，以实算为准（别家终端不一定把 `unit_len` 填对）；
   - 越界即丢弃整个 ANN，计入 malformed；
   - 这些检查要在算校验和之前做（校验和按 `pkg_len` 读整包），也要在任何单元存表之前全部做完：
     原来是边解析边存表，后面的单元越界时，前面的单元已经存进表里了。
   - 什么情况下会越界（color-proxy 正常发的包都不会）：
     - **报文被截断**：`pkg_len` 比实际收到的长。比如 ANN 超过 MTU 被 IP 分片——RM 不做 IP 重组，只看得到第一片
       （只有多单元的 ANN 才可能这么大：15 个满长单元约 3.8 KB）。后面几片开头不是 CoLoR 头，多半在版本检查就被丢掉；
     - **发送方长度字段算错**：TLV 的 `len` 按字符数而不是 UTF-8 字节数填（中文 desc 会少算）；`strategy_num`、
       `Unit_Num` 比实际多；`PX_Num` 写大了（PX 区从 `pkg_len` 倒推，单元区被压短）；flag 置了 N/L/I 却没带对应字段；
     - **恶意构造**的报文。
   - 不算越界的：`pkg_len` 比实际收到的短（比如以太网补零，多出的尾巴不读）；`unit_len` 与实算不一致（只记 warn）。
3. **转发循环读到未初始化数据**：`rm_pkt_process.c:380` 靠「tag == 0 结束」最多扫 32 个槽，但 `mark_array`
   （`ann.c:28`）是没有初始化的栈数组，第 `strategy_num` 个槽以后都是残留数据；碰巧是 tag 1/2 时就会解引用野指针。
   改为 `s_i < unit_front->strategy_num`。
4. **`check_same_strategy`**（`rm_sid_table.c:86`）只按 a 的个数比较：旧条目 0 个策略、新条目 2 个时会读旧数组里未初始化的槽；
   反过来新条目 0 个时直接判"相同"。改为先比个数。同一函数的替换分支（`:220`）有两处泄漏：
   `rte_array_destroy` 没释放各个 value，被并入的新 `sid_info_t` 也没释放。

### P1：存储、校验与展示

已实现（`9350422`），和下面写的有 4 处不同：

- 名称、描述的缓冲是 256 字节（255 + NUL），不是 201：TLV 的 len 是 1 字节，单元不带 NID 时名称可以超过 200 字节；
- TSID 里存的是**清洗过的展示副本**：非法 UTF-8 和控制字符换成 `?`，防止往运维终端注入转义序列；SHA1 校验用原始字节；
- 名称、描述**以最近一次存进表的通告为准**：首次插入、同一来源换策略、同一 SID 的新来源都会更新；
- ACL 列表的名称在前端按 SID 关联，`/api/v1/acls` 不变；Web 响应缓冲调到 2 MB。

日志事件码：策略没变的重复通告 2006（debug），名称校验不通过 2007（warn）。
SHA-1 在 `src/vendor/sha1.c`，单元测试 `tests/test_sid_text.c`。

5. **TSID 表带上名称和描述**：`tsid_entry_t` 加 `name[201]`、`desc[201]`（末字节恒为 0）、`name_len`、`desc_len`、`name_verified`。
   首次插入和"策略不同、整体替换"两条路径都要写。
   - **存副本，不让 Web/CLI 去读 `strategy_array`**：Web 是独立 pthread，CLI 跑在主 lcore，数据面在 worker lcore 上；
     替换策略时数据面会释放旧数组，跨线程直接读就是 use-after-free。
   - 读的一方一律按 `*_len` 加 `strnlen(buf, 200)` 取值，写到一半被读到时最多读出半截字符串，不会越界。
6. **NAME 校验**：RM 现有 md5（`rte_CoLoR.h` 的 `md5()`），没有 SHA1。建议像 md5 一样内嵌一份公有领域的 SHA1（约 100 行），
   不要为此引入 libcrypto。用 §2.6 的向量写单元测试。
7. **Web**：
   - `/api/v1/sids` 改为返回 `{"count":N,"sids":[{"sid":"…","name":"…","name_verified":true,"desc":"…"}]}`，
     `web/app.js` 的 SID 表（约 `:458`）同步加「名称」「描述」两列，未校验的名称要标出来；
   - 名称和描述来自终端，属于不可信输入，C 侧必须做 JSON 转义。`rm_monitor.c:67` 已有 `json_append_string`，可以提出来共用。
     前端 `renderTable` 用的是 `textContent`，没有 XSS 问题；
   - `RM_WEB_RESPONSE_SIZE` 是 256 KB，1024 条 SID × (72 + 两段文本 + 转义) 在最坏情况下会超，要么调大要么分页；
   - ACL 列表按规则里的 SID 反查 TSID，显示名称和描述；添加 ACL 时点 SID 行可以自动填入 SID。
8. **CLI**：`display sid` 加名称、描述两列（未校验的标 `?`）；`CoLoR_show_pkg` 打印 ANN 时把 tag 13/14 按文本打印（`rte_CoLoR.c:544`）。
9. **日志降级**：-2（策略没变）从错误日志降为 debug。终端开启周期刷新（AM=2）时，现在每次都会刷出一条错误。

### P2：按名称写 ACL（可选，可以后做）

10. ACL 规则增加一种匹配方式：**NAME 前缀**。例如拒绝 ASID 2 访问 `http://10.10.9.2:8000/api/model/` 下的全部 URL。
    - 只对 `name_verified = 1` 的 SID 生效。未校验的 SID 不命中按名称写的规则，但精确 SID 规则照常生效；
    - `rm_GET_process`（`rm_pkt_process.c:708`）在 ACL 检查（`:829`）之前已经拿到 `search_node`，从它取名称即可，
      不用再查表。可以在 `sid_info_t` 上缓存「名称指针 + 已校验」，替换策略数组时一并更新；
    - CLI：`acl add id <n> action deny name-prefix <str> asid <hex> nid <hex>`；Web 的 POST 体加 `name_prefix`；
    - 匹配顺序不变：按 id 从小到大，第一条命中的规则生效。

## 5. 终端侧改动（color-proxy）

已实现（`fix/tun` 的 `6142756`，2026-10-30）。

1. **常量**（`colorproxy/protocol/constants.py`）：`STRATEGY_SID_NAME = 13`、`STRATEGY_SID_DESC = 14`、
   `ANN_STRATEGY_BUDGET = 73`（部署里所有 RM 都完成 P0 后改为 200，见 §2.5）、`ANN_DESC_WARN_BYTES = 32`。
2. **裁剪与 TLV**（新模块 `colorproxy/protocol/strategy.py`）：`fit_sid_label(name, desc, lsid)` 按 §2.5 的规则裁剪，
   返回 `SidLabel`（UTF-8 字节，空表示不发）；`sid_label_units` 生成 `StrategyUnit` 列表，先 13 后 14。
   另加一道自校验：名称的 SHA1 与 L_SID 对不上时记 error、不发名称——这只可能是代码错误，发出去 RM 也只会标成未校验。
3. **NAME 自动生成，不需要配置**：取自算 L_SID 的同一个函数。v1 和 L3 内容级用 `sid.py` 的 `sid_name_from_url`
   （原来的 `_canonical_for_sid`，改名公开），L3 服务级用 `service_canonical`。
4. **DESC 来源**：
   - L3 服务级：`l3.services[].desc`；
   - L3 内容级（D20 URL SID）：继承所属端点的 desc（8000 端点下的 26 个 URL 都是 `http`）；
   - v1 `services[]`：`ServiceConfig` 新增可选的 `desc`，不配就不发 DESC；
   - 配置加载时，desc 超过 32 字节（UTF-8）就打 warn（只提醒，不改值、不拒绝启动）。
5. **构造与发布**（`publish.py`）：`_build_announce` 增加 `label` 参数。每条 SID 首次发布时裁剪一次（`_announce_once`），
   结果连同 L_SID 存进已通告表（`state.py` 的 `AnnouncedSid`），AM=2 / AM=3 原样复用，三种通告的 TLV 完全相同（§6）。
   已通告过的 SID 再次发布时不重新裁剪，超预算的 warn 只打一次。`tools/rm_withdraw.py` 用的是同一张表，注销也带 TLV。
6. **已改的配置**（2026-10-29）：`config.json` 和 `deploy/prototype/config-svr1-1-provider.json` 的 `l3.services[].desc`
   已改为 `http` / `ftp` / `mysql` / `rtp`；`tools/ftp_server.py --print-services` 输出的 desc 改为 `ftp`；
   `deploy/prototype/acl-rules.md` 已重新生成（只有「说明」列变了，SID 不变）。
   消费端配置里的 desc 和 `l3.peers[].desc` 不会发给 RM，保持原样。
7. **测试**（`tests/test_ann_tlv.py`，14 项）：
   - TLV 字节布局与 §2.6 的 92 字节向量逐字节一致；
   - 预算边界（正好 73 字节 / 多 1 字节）；NAME 超预算时整个丢弃；DESC 截断不切断多字节字符；不发空 value；
   - `Unit_Length` 与实算一致，预算 200 时正好 255；
   - 三种 AM 带相同的 TLV；已通告的 SID 再发布不重新裁剪；
   - 用 `deploy/prototype/config-svr1-1-provider.json` 走一遍发布：34 条 SID 的名称全部满足 `SHA1 == L_SID`，
     DESC 分别是 `http`/`ftp`/`mysql`/`rtp`，URL SID 是 `http`，v1 的不带 DESC，都在 73 字节内。

## 6. 和 AM、刷新、注销的关系

RM 不看 AM（§3.2），收到任何一种通告都是"插入或替换"。如果注销（AM=3）不带 TLV，RM 做完 P0 第 4 条以后，
会把它看成"策略变了"，用空策略替换掉原来的策略，而 SID 本身仍留在表里（并且会再向邻域转发一次）。
被清掉的不只是名称和描述：替换是整个策略数组一起换，已存的 tag 1（安全等级）、tag 2（通告路径白名单）
也会被清掉，这条 SID 的 GET 过滤随之放宽。
所以终端规定：**同一条 SID 的三种通告带完全相同的 TLV**，只有 AM 位不同。

以后 RM 实现 AM 语义时（§8），注销路径直接忽略 TLV。

## 7. 实施顺序与兼容

| 阶段 | 终端 | RM | 效果 |
|---|---|---|---|
| ① 终端先上（已实现） | 按 73 字节预算发 TLV | 未改 | 安全。RM 当作未知策略存下、原样转发，只是看不到 |
| ② 所有 RM 做 P0（`87f48b3` 已实现，待部署到每台 RM） | 全部 RM 升级后，预算改 200（§2.5） | P0 | 不会再被超长 TLV 写崩；坏包会被丢弃 |
| ③ RM 做 P1 | — | P1 | Web/CLI 显示名称和描述，名称已校验 |
| ④ 可选 | — | P2 | 可以按名称前缀写 ACL |

兼容性：

- 老终端不带 TLV，新 RM 照常处理（名称、描述为空）；
- 新终端配老 RM，只要不超过 73 字节就没问题；
- 其他域的老 RM 收到带 TLV 的转发通告，也只是当作未知策略存下（前提同样是不超过 73 字节）。

## 8. 验收

1. 提供端起来后，RM CLI `display sid` 能看到每条 SID 的名称和描述，名称全部是已校验；
2. Web「资源管理」页同样能看到，邻域 RM（例如 AS2 的 RM）上也能看到同样的名称；
3. 手工发一个 NAME 故意写错的 ANN：RM 照常注册该 SID，打 warn，名称标为未校验；
4. 发一个 TLV 长度越界的 ANN：RM 丢弃该包、计入 malformed，进程不崩；
5. 改提供端某条的 desc 后重启提供端：RM 上的描述随之更新，日志里没有 `unable to insert SID entry`。

## 9. 不在本轮范围（记下来以后做）

- **AM 语义**：RM 实现注册 / 更新 / 注销。现在注销无效，SID 只能靠重启 RM 清掉；`GET_ANN_UNIT_FLAG_AM` 宏也写错了：
  `((flag)<<3)>>6` 在 int 提升后不截断，应为 `(((flag) >> 3) & 0x3)`。RM 转发时还会把 AM 位清零（§3.2），
  实现 AM 语义时，重建单元要保留原来的 AM。
- **给消费端的 SID 列表带上名称**：RM 回给终端的 SID 列表（CONTROL tag 40）现在只有 36 字节的 SID，
  每包 10 条。带上名称以后，消费端就能拿到一份服务目录。这需要改 tag 40 的载荷格式，两端要一起改。
- **SID 表老化**：RM 的 SID 表从不过期，RM 重启后全部丢失，终端默认不会重新通告（`REGISTER_REFRESH_SEC` 默认 0）。
