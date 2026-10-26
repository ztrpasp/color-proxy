# 原型系统部署：两节点四区

拓扑：节点 1 = AS1（一级区 `10.10.X.X`）+ AS2（二级区 `172.10.X.X`）；节点 2 = AS3（一级区 `10.20.X.X`）+
AS4（二级区 `172.20.X.X`）。链路 AS1—AS2、AS3—AS4（节点内），AS1—AS3、AS2—AS4（广域网切片）。

| 角色 | 机器 | 所在区 | 物理地址 | 本域 RM | NID | tun（color0） | 配置文件 |
|---|---|---|---|---|---|---|---|
| 提供端 | SVR1-1 | AS1 | `10.10.0.2` | `10.10.0.5` | `a1a1…a1` | `10.10.9.2/24`（服务就绑在它上面） | `config-svr1-1-provider.json` |
| 消费端 | SVR1-3 | AS2 | `172.10.0.2` | `172.10.0.5` | `b2b2…b2` | `10.99.1.1/24` | `config-svr1-3-consumer.json` |
| 消费端 | SVR2-3 | AS4 | `172.20.0.2` | `172.20.0.5` | `c3c3…c3` | `10.99.1.2/24` | `config-svr2-3-consumer.json` |

ACL 规则：`acl-rules.md`（在 RM 1-1 上执行，见下文第 2 步）。

## 地址怎么定的

- **服务地址 `10.10.9.2`** 是提供端 color0 的地址（D18 虚服务地址，原来 AS2 提供端用 `172.10.9.2`，这里照同一规则
  放进 AS1 的地址段）。两个消费端都只配一条主机路由 `10.10.9.2/32 → color0`，不会把任何 RM/BR 吞进 tun。
- **消费端 tun 地址** `10.99.1.1`、`10.99.1.2` 必须互不相同，且与提供端 `l3.peers[]` 里登记的逐字一致：
  提供端靠它定位消费端、校验来源，源站也靠它判断请求者身份。
- 三台都是 `l3.enabled: true`。`services[]`（v1 内容级）与 `sids[]` 只是保底，演示走 L3。

## 部署步骤

### 1. 三台机器都要做

- 管理员 PowerShell，`python -m pip install -r requirements.txt`，仓库自带 `bin/amd64/wintun.dll`。
- 起代理前确认 `ipv4` 对应的网卡就是连本域 RM/BR 的那张网卡。

### 2. RM 侧（ACL 生效的前提）

ACL 规则加在 **RM 1-1（`10.10.0.5`）**。它从 GET 带的 PID 倒推消费端所在的 AS，推不出来时**直接拒绝**，
与有没有规则无关（日志 `GET denied by ACL: unable to identify source AS`）。所以 RM 1-1 的
`global_as_config` 必须包含四条链路：AS2 的 GET 走 AS2→AS1，AS4 的 GET 走 AS4→AS2→AS1 或
AS4→AS3→AS1。GET 路径上其它跑 ACL 版本的 RM 也要配齐。

```
$ 1 2 0x<AS1—AS2 链路的 px>
$ 2 1 0x<同上>
$ 1 3 0x<AS1—AS3 链路的 px>
$ 3 1 0x<同上>
$ 2 4 0x<AS2—AS4 链路的 px>
$ 4 2 0x<同上>
$ 3 4 0x<AS3—AS4 链路的 px>
$ 4 3 0x<同上>
```

px 填 BR 的实际配置；同一条链路两个方向写同一个值，与现有 `global_as_config` 的写法一致。改完重启 RM，用
`display graph` 核对。RM 运行中再收到 CONFIG_RM 会清空拓扑图，而且不会重新读这个文件。

`asid` 按 AS 号 1–4 写，前提是四台 RM 配置里的 `as_id` 就是 1–4；如果不是，用实际值重新生成规则（见文末）。

### 3. 提供端 SVR1-1（AS1）

```powershell
# 源站必须听 0.0.0.0（只听 127.0.0.1 时 L3 包到了也没人收）；--config 让源站读到两个消费端的身份
python tools/origin_server.py --host 0.0.0.0 --port 8000 --config deploy/prototype/config-svr1-1-provider.json

# 另开管理员终端
python -m colorproxy.main deploy/prototype/config-svr1-1-provider.json -v

# color0 建好后放行入站（Wintun 网卡默认按公用网络处理，入站基本全拦）
Set-NetConnectionProfile -InterfaceAlias "color0" -NetworkCategory Private
New-NetFirewallRule -DisplayName "color-tun" -Direction Inbound -InterfaceAlias "color0" -Action Allow
```

源站启动时应打印 `10.99.1.1 → b2b2…` 和 `10.99.1.2 → c3c3…`。RAG 模型页还需要 MySQL 和 `rag.env`，
见 `docs/RESTFUL-L3.md`。

### 4. 消费端 SVR1-3（AS2）/ SVR2-3（AS4）

```powershell
python -m colorproxy.consumer.main deploy/prototype/config-svr1-3-consumer.json -v   # SVR1-3
python -m colorproxy.consumer.main deploy/prototype/config-svr2-3-consumer.json -v   # SVR2-3

curl --noproxy "*" http://10.10.9.2:8000/hello.html
```

浏览器直接打开 `http://10.10.9.2:8000/`，**不要**设置 `:8910` 代理（设了就走 v1 了）。

## 演示时两个消费端的区别

- **ACL**：两个消费端的规则 id 分开（AS2 用 2xx，AS4 用 4xx），可以对同一个页面只拦其中一个。
- **模型页权限**：源站按 `provider-policy.json` 区分，`b2`（SVR1-3）检索能用到 P2，`c3`（SVR2-3）能用到 P3、
  导出仍到 P2。想对调，就把两份消费端配置的 `nid` 和提供端 `peers[]` 里的 NID 一起对调，再重新生成 ACL。

## 改了 NID / AS 号 / paths 之后

规则里的 SID 和 NID 都来自配置，改完重新生成：

```powershell
python tools/gen_acl_rules.py deploy/prototype/config-svr1-1-provider.json `
    deploy/prototype/config-svr1-3-consumer.json=2 `
    deploy/prototype/config-svr2-3-consumer.json=4 `
    -o deploy/prototype/acl-rules.md
```

`=2`、`=4` 是消费端所在的 AS 号。加 8000 上的新路由时，`tools/origin_server.py` 的 `PUBLISHED_PATHS`、
提供端 `paths` 和两份消费端的 `sids[]` 要一起改。
