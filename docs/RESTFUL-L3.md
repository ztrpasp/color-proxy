# REST / SSE 演示服务（L3 版）

这套演示服务原本在 `color-proxy-restful/server`，跑在 v1 应用层代理上。本仓库把它迁到了
**L3 隧道**：消费端浏览器直接访问 `http://172.10.9.2:8000/...`，TCP 端到端穿过隧道。

页面与接口都没有改动，只改了说明文字。源站做了几处 L3 适配，见 §5。

| 页面 | 内容 |
|---|---|
| `/showcase.html` | 总览与导航 |
| `/items.html` | REST CRUD 控制台（`/api/items`） |
| `/monitor.html` | 流量监控，REST：打开即拉 `recent`，按钮拉 `snapshot` |
| `/realtimemonitor.html` | 流量监控，SSE：每秒一个事件，可主动停止 |
| `/model.html` | 医院 / 学校 RAG 大模型：MySQL 检索 + DeepSeek 生成，支持「完整回答」和「SSE 流式」两种模式 |

Demo key：监控用 `monitor-demo-key`，模型用 `model-demo-key`。key 明文写在前端，只用来演示鉴权字段的传递。

## 1. 文件在哪

| 路径 | 作用 |
|---|---|
| `tools/origin_server.py` | 源站，全部路由列在 `PUBLISHED_PATHS` |
| `tools/static/*.html` | 五个自包含页面 |
| `tools/demo_data.py` | 监控样本、模型清单、建议问题 |
| `tools/rag_service.py`、`mysql_rag.py`、`deepseek_client.py`、`rag_config.py`、`rag_documents.py` | RAG 后端 |
| `tools/provider_policy.py` + `provider-policy.json` | 模型服务的 P2/P3 策略（NID → 可检索 / 可导出的知识 SID） |
| `tools/rag_admin.py` | 建表、导入、查看状态、查策略 |
| `tools/generate_*_mock.py` | 重新生成合成隐私数据，一般不用跑 |
| `data/` | 随仓库携带的 10500 条 QA，说明见 `data/README.md` |
| `sql/` | 建库脚本、小内存 MySQL 参考配置 |
| `rag.env.example` | 复制成 `rag.env`（已加进 .gitignore）后填 MySQL 密码和 DeepSeek key |

RAG 的细节见 `docs/RAG-MYSQL-DEEPSEEK.md`、`docs/PRIVACY-MOCK-DATA.md` 和 `docs/PROVIDER-P2P3-0.3.1.md`。

## 2. 提供端怎么起

```powershell
# 0) 依赖（模型服务才需要 mysql-connector-python）
python -m pip install -r requirements.txt

# 1) 模型服务的一次性初始化（只用 items/monitor 的话可以跳过）
#    以 MySQL 管理员执行 sql/create-database.sql（先把里面的 change-me 改掉）
Copy-Item rag.env.example rag.env          # 填 MYSQL_PASSWORD、DEEPSEEK_API_KEY
python tools/rag_admin.py bundled-data-check
python tools/rag_admin.py init
python tools/rag_admin.py seed
python tools/rag_admin.py status

# 2) 源站：必须听 0.0.0.0（只听回环时 L3 收不到包）
python tools/origin_server.py --host 0.0.0.0 --port 8000

# 3) 另开管理员终端起提供端（config.json 的 l3.enabled 置 true）
python -m colorproxy.main config.json
```

- 源站启动时会打印「请求者身份」映射表，应能看到 `10.99.1.1 → b2b2…`（来自 `config.json` 的
  `l3.peers[]`）。如果打印的是「没有读到 l3.peers[]」，说明所有人都会按 default 策略处理。
- 提供端启动日志里，每条 path 各有一行「已发布 L3 内容 http://172.10.9.2:8000/...」，共 26 行。
- 用 `netstat -ano | findstr :8000` 确认左列是 `0.0.0.0:8000`。端口被别的进程占着时，源站会直接
  报错退出，不会和它抢端口。

## 3. 消费端怎么访问

1. `config-consumer.json` 的 `l3.enabled` 置 true，以管理员身份起消费端（同 `docs/M4-acceptance.md` §1）。
2. **浏览器不能走任何代理**：不能用 `:8910`（那是 v1），也不能用 Clash 等系统代理。要把 `172.10.9.2`
   加进代理绕过列表，或者用一个不设代理的浏览器配置文件。走了代理，请求就进不了 tun。
3. 打开 `http://172.10.9.2:8000/showcase.html`，从导航进入各页面。

命令行冒烟（同样要绕开代理）：

```powershell
curl --noproxy "*" http://172.10.9.2:8000/hello.html
curl --noproxy "*" -H "X-API-Key: monitor-demo-key" "http://172.10.9.2:8000/api/monitor/location-a/recent?limit=3"
curl --noproxy "*" -N "http://172.10.9.2:8000/api/monitor/location-a/stream?api_key=monitor-demo-key"
curl --noproxy "*" -N "http://172.10.9.2:8000/slow?segs=5&size=10&delay=1"   # 应每秒到一段
```

## 4. 与 v1 版的区别

| 项目 | v1（color-proxy-restful） | L3（本仓库） |
|---|---|---|
| 浏览器怎么到达 | HTTP 代理 `127.0.0.1:8910` | 直连 `172.10.9.2:8000`，由 tun 捕获，不设代理 |
| 地址 | `172.10.0.2:8000` | `172.10.9.2:8000`（D18 虚服务地址） |
| 每个请求 | 独立 SegID 握手：GET → 隧道 DATA → ACK 推请求 | 新连接按端口 SID 发 GET（D19）；每个请求按 URL SID 发 GET（D20），放行后字节走端口级隧道 |
| SSE / 长响应 | 提供端回源 worker 逐片 cut-through | TCP 段原样过隧道，中间没有任何一跳缓冲整条响应 |
| 主动停止 | 消费端发 `STREAM_CANCEL`，按 SegID 取消 worker | 浏览器关连接，FIN 经隧道到源站，源站下一次写入失败就停。不需要额外报文 |
| 请求者身份 | 提供端注入 `X-CoLoR-Requester-NID` | 源站按 TCP 对端地址查 `l3.peers[]`，请求头一律忽略（§5） |
| 访问控制粒度 | 每个 URL 一条 SID | 同样每个 URL 一条 SID（D20），另有端口级 SID 管「能不能连」 |

以下内容**没有迁移**：
- v1 提供端的 HMAC 身份绑定和防重放日志（`identity.py`、`replay_journal.py`）。L3 下提供端不解析
  HTTP，用不上它们。
- 消费端的 `STREAM_CANCEL`。
- `/bulk/*` 压测端点和性能文档。按约定，性能测试只放在 `perf/bench` 分支。

## 5. 源站为 L3 做的适配

- **身份。** L3 下提供端不改写 HTTP，没人替你删掉浏览器伪造的 `X-CoLoR-Requester-NID`。信了它，
  任何消费端都能冒充 `d4…` 拿到 P3 权限。所以源站只看 TCP 对端地址：它就是消费端的 tun 地址，
  提供端已按 D14 校验过（内层源地址必须是这个 NID 在 `l3.peers[]` 里登记的 tun 地址）。地址查不到
  （比如本机直连）时，按 `provider-policy.json` 的 default 处理，只有 P0。`--config` 可以指定从哪个
  配置读 `l3.peers[]`，默认读仓库根的 `config.json`。
- **SSE 结束时源站主动关连接**（`Connection: close`）。v1 的提供端回源时强制加了 close；L3 下浏览器
  发的是 keep-alive，而 SSE 没有 Content-Length，不关的话浏览器永远等不到这条响应结束。
- **关闭 Nagle**（`disable_nagle_algorithm`）。SSE 事件和模型 token 都是小写入，不关的话会在隧道往返
  上被攒成一批。
- **模型流在客户端断开时立刻关掉到 DeepSeek 的上游连接**，源站打一行「客户端断开：模型 SSE …，已停止生成」。
- **对端复位只打一行日志**：「连接被对端复位/中止（客户端关闭或 D20 准入拒绝）」。D20 拒绝请求时
  也会给源站发 RST，标准库默认每次打一整段回溯。
- **`/favicon.ico` 已发布，返回 204**。浏览器会自动请求它，没发布的话每次打开页面都会多一次 reset。
- **Windows 上独占绑定端口**，不会出现两个进程同时听 8000、谁接连接说不准的情况。

## 6. 「RESTful API 六类测试」在 L3 下怎么做

需要带 ACL 的 RM，ACL 的配法见 `docs/M4-acceptance.md` §4c。

| 测试 | 做法 | 预期 |
|---|---|---|
| 基本功能 | 打开 `monitor.html` | 自动拉到 `location-a/recent`。提供端打出 26 条内容 SID 的发布日志，消费端 `http_admit_ok` 上涨 |
| 访问管控 | 在 RM 上拒绝本消费端访问 `.../api/monitor/location-b/recent` 的 URL SID | 位置 A 正常；切到位置 B 时约 5 s 后连接被 reset，消费端打出「内容级准入超时」，`http_admit_timeout` +1 |
| 动态管控 | 保持页面打开，在 RM 上把 A 改成 allow → deny → allow，每次点「拉取最新数据」 | **下一个请求就生效**：D20 对每个请求都重新发 GET，不缓存放行结果 |
| API 密钥 | 用 curl 去掉 `X-API-Key` | 401。key 在 TCP 里端到端传递，L3 不碰它 |
| 长连接 | `realtimemonitor.html` 开始监控；`model.html` 打开流式开关提问 | 曲线每秒推进；回答逐 token 出现。800 s 的 ODC 空闲过期不会触发，因为 SSE 每秒都有下行数据 |
| 主动停止 | 点「停止监控」或「停止生成」 | 源站日志出现「客户端断开：…」，模型流同时断开到 DeepSeek 的连接 |

两点说明：
- 已经在跑的 SSE，**不会因为 ACL 改成拒绝而被中途掐断**：准入只在请求开始时做，这一点与 v1 相同。
  要验证「拒绝生效」，就停掉流再重新开始。
- 同一条 keep-alive 连接上，先发一个放行的请求、再发一个被拒的请求：第一个响应完整拿到，第二个请求
  会让整条连接被 reset。浏览器会为后续请求另开新连接。

## 7. 加一个新路由

源站和两份配置要一起改，缺任何一处，浏览器访问这个路由都会被 reset：

1. `tools/origin_server.py`：实现路由，并加进 `PUBLISHED_PATHS`。
2. `config.json`：加进 8000 条目的 `paths`。
3. `config-consumer.json`：在 `sids[]` 里加 `http://172.10.9.2:8000<path>`。这一条是没有 RM 时的
   降级路径，有 RM 时 SID 表会自动同步过来。
4. 运行 `python tests/test_restful_origin.py`，它会核对这三处是否一致。

路径必须**逐字一致**：不做 `%xx` 解码，不消 `/./`，不合并 `//`，见设计 §8.7。query 不参与 SID，
所以 `?id=`、`?q=`、`?api_key=` 都可以随便带。

## 8. 常见坑

| 现象 | 原因 |
|---|---|
| 所有页面都超时 | 源站只听 `127.0.0.1`；或浏览器走了代理（Clash / `:8910`），请求没进 tun |
| 某个页面立刻 reset，消费端 `http_url_miss` +1 | 这个 path 没发布，见 §7 |
| 打开 DevTools 后多出几次 reset | Chrome 会请求 `/.well-known/appspecific/...`，没有发布，属正常现象 |
| 模型回答显示 `rag_backend_unavailable` | 缺 `mysql-connector-python`、`rag.env` 没配，或 MySQL 没起。先跑 `python tools/rag_admin.py status` |
| 模型回答里 `requester_nid` 是 `DIRECT` | 源站没读到 `l3.peers[]`（看启动打印）；或消费端 tun 地址与 `peers[]` 登记的不一致（那样提供端早就 `src_bind_drop` 了） |
| 页面能打开，换成 b2 以外的消费端后 P2 内容消失 | 正常：P2/P3 权限按 NID 配在 `provider-policy.json`，新消费端要在里面登记 |
