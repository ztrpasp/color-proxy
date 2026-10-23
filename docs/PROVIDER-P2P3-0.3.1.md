# Provider-side Minimal P2/P3 for RAG (0.3.1)

这一版只在 Provider / Origin / RAG 侧铺最小策略钩子，不复制 Gateway Policy Engine，也不修改 RM/BR。

> **迁到 L3 后的变化（2026-10）**：本仓库走 L3 隧道，提供端不终结 HTTP，也就不再注入
> `X-CoLoR-Requester-NID`。请求者 NID 改由源站 `tools/origin_server.py` 按 **TCP 对端地址**
> （消费端的 tun 地址）查 `config.json` 的 `l3.peers[]` 得到；任何请求头都不参与身份判定。
> 第 4 节同时列出了 v1 原版的做法作对照。部署与测试见 `docs/RESTFUL-L3.md`。

## 1. 目标

P2：检索前最小权限过滤。

```text
CoLoR consumer NID
        ↓
L3：TCP 对端地址（消费端 tun 地址）→ config.json l3.peers[] → NID
        ↓
provider-policy.json
        ↓
allowed RAG SID set
        ↓
MySQL retriever SID filter
        ↓
only authorized chunks enter LLM context
```

P3：响应 provenance 出域控制。

```text
retrieved chunks
   ↓
provenance = [{sid, chunk_id, privacy_level}, ...]
   ↓
P3 provenance preflight
   ↓
ALLOW / BLOCK
```

当前 P3 规则非常小：如果 provenance 中包含 `privacy_level=P3` 的 SID，且 requester 的 `export_sids` 不包含该 SID，则 `BLOCK`。当前没有实现 REDACT 文本算法；接口与返回结构为后续扩展保留 `decision`。

## 2. RAG logical SID

这些 SID 是应用层 RAG 内容标签，用于内容权限与 provenance；它们不替换 CoLoR/RM/BR 使用的 Web Service SID。

```text
SID_MED_PUBLIC
SID_MED_PRIVATE_P2
SID_MED_PRIVATE_P3
SID_EDU_PUBLIC
SID_EDU_PRIVATE_P2
SID_EDU_PRIVATE_P3
```

Bundled 10,500 chunks 映射：

```text
medical public       6000 -> SID_MED_PUBLIC        / P0
medical privacy      1400 -> SID_MED_PRIVATE_P2    / P2
medical privacy       600 -> SID_MED_PRIVATE_P3    / P3
education public      500 -> SID_EDU_PUBLIC        / P0
education privacy    1500 -> SID_EDU_PRIVATE_P2    / P2
education privacy     500 -> SID_EDU_PRIVATE_P3    / P3
```

## 3. Chunk metadata

数据库中的 `rag_chunks.metadata` 会显式保存或运行时补齐：

```json
{
  "sid": "SID_MED_PRIVATE_P3",
  "privacy_level": "P3",
  "record_id": "MEDREC-MOCK-0042-09",
  "record_type": "M09_MENTAL_HEALTH",
  "subject_id": "PAT-MOCK-0042",
  "allowed_role": ["medical_privileged"],
  "privacy": {
    "privacy_class": "P3_HIGH_SENSITIVE"
  }
}
```

`allowed_user` / `allowed_role` 是可选的 chunk ACL。第一层 SID allow-set 是主过滤；这两个字段作为 Provider 侧额外约束。

## 4. Requester NID 来源

**L3（本仓库）**：内层 IP 包原样穿过隧道，源站看到的 TCP 对端地址就是消费端的 tun 地址
（如 `10.99.1.1`）。提供端在 L3 数据面已按 D14 校验过「内层源地址必须是该消费端在
`l3.peers[]` 里登记的 tun 地址」，所以这个地址可信。源站启动时读 `config.json` 的
`l3.peers[]` 建一张 `tun_ip → NID` 表，每个请求按 `client_address` 查表：

- 查到：用表里的 NID 解析 `provider-policy.json`；
- 查不到（例如本机直接访问 `127.0.0.1:8000`）：按 `DIRECT`/default 处理，默认只允许 P0；
- 浏览器自带的 `X-CoLoR-Requester-NID` 等头**一律忽略**——L3 下没有提供端替你删掉它，
  信了它就能冒充 `d4...d4` 拿 P3。

**v1（color-proxy-restful 原版，仅作对照）**：Provider 从 CoLoR GET/ACK 得到 `consumer_nid`，
`OriginWorker` 回源时删除浏览器带来的同名头，再注入真实值。本仓库的 v1 提供端没有这段注入。

## 5. provider-policy.json

默认文件：仓库根目录的 `provider-policy.json`。可通过 `PROVIDER_POLICY_FILE` 指向其他文件。

```json
{
  "default": {
    "roles": ["public"],
    "allowed_sids": ["SID_MED_PUBLIC", "SID_EDU_PUBLIC"],
    "export_sids": ["SID_MED_PUBLIC", "SID_EDU_PUBLIC"]
  },
  "users": {
    "<requester-nid>": {
      "roles": ["medical_researcher"],
      "allowed_sids": ["SID_MED_PUBLIC", "SID_MED_PRIVATE_P2"],
      "export_sids": ["SID_MED_PUBLIC", "SID_MED_PRIVATE_P2"]
    }
  }
}
```

当前 bundled demo 有三个示例：

- `b2...b2`：P0 + P2 检索/导出；这正好对应当前 `config-consumer.json` 的消费端 NID。
- `c3...c3`：允许检索 P3，但没有 P3 export；用于演示 P3 BLOCK。
- `d4...d4`：允许检索并导出 P3；用于演示高权限 ALLOW。

查看某 NID 权限，不需要 MySQL：

```bash
python tools/rag_admin.py policy --nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
```

## 6. P2 retrieval metadata

内部 `RetrievedChunk` 结构包含：

```json
{
  "sid": "SID_MED_PRIVATE_P3",
  "chunk_id": 8123,
  "privacy_level": "P3",
  "text": "<content stored in RetrievedChunk.content>"
}
```

REST/SSE 对外响应只显示 metadata，不额外复制完整 chunk body，避免调试信息本身再次泄露内容：

```json
{
  "rag": {
    "retrieval_metadata": {
      "chunks": [
        {
          "sid": "SID_MED_PRIVATE_P3",
          "chunk_id": 8123,
          "privacy_level": "P3",
          "title": "...",
          "score": 0.9342
        }
      ],
      "sid_set": ["SID_MED_PRIVATE_P3"]
    }
  }
}
```

MySQL 查询中先使用 allowed SID set 做条件过滤；通过后才构造 `RetrievedChunk`。未通过的 P3 chunk 不进入 LLM context。

## 7. Response provenance

成功响应新增顶层：

```json
{
  "answer": "...",
  "provenance": [
    {
      "sid": "SID_MED_PUBLIC",
      "chunk_id": 7,
      "privacy_level": "P0"
    }
  ],
  "provider_policy": {
    "requester_nid": "...",
    "allowed_sids": ["..."],
    "export_sids": ["..."],
    "p2_retrieval": "FILTERED_BEFORE_LLM_CONTEXT",
    "p3_egress": {
      "decision": "ALLOW",
      "reason": "..."
    }
  }
}
```

P3 BLOCK 的普通 REST 请求返回 HTTP 403：

```json
{
  "error": "response_egress_blocked",
  "answer": null,
  "provenance": [
    {
      "sid": "SID_MED_PRIVATE_P3",
      "chunk_id": 8123,
      "privacy_level": "P3"
    }
  ],
  "provider_policy": {
    "p3_egress": {
      "decision": "BLOCK",
      "blocked_sids": ["SID_MED_PRIVATE_P3"]
    }
  }
}
```

SSE 不能在已经发出 token 后撤回内容。因此 v0.3.1 在 DeepSeek 调用前根据已知 provenance 做 P3 preflight。BLOCK 时不会调用 DeepSeek，也不会发送 token，只发送 `meta`、`policy`、`done(finish_reason=policy_block)`。

## 8. 数据库兼容

新 `seed` / `seed-privacy` 会把 `sid` 与 `privacy_level` 写进 chunk metadata。

已有 10,500-row 数据库也能运行：检索 SQL 会根据旧版 `privacy.privacy_class + domain` 推导 logical SID/P0/P2/P3。为了让数据库中的 metadata 本身完整，建议执行一次：

```bash
python tools/rag_admin.py seed
```

这是基于固定 source URI 的 upsert，不会把 10,500 条无限重复追加。

## 9. 设计边界

0.3.1 Provider 侧只负责：

```text
NID -> allowed SID set
chunk SID/privacy metadata
retrieval filter
provenance
P3 provenance egress ALLOW/BLOCK
```

它没有实现 Gateway 的统一审批、身份体系、跨域策略编排、文本敏感语义检测、REDACT/SANITIZE 算法或完整审计系统。这些能力后续仍放在 Gateway/Provider Guard 的上层策略机制中。
