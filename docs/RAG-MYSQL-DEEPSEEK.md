# MySQL RAG + DeepSeek 设计说明

## 1. 现实约束

实验 Server：11 代 Intel 移动 CPU、16 GB RAM、无独立 GPU，同时还需要运行 Python CoLoR Provider、抓发包组件和浏览器/系统服务。

因此本版刻意避免：

- 本地 7B/8B 模型推理；
- PyTorch / CUDA；
- sentence-transformers 常驻 embedding 模型；
- FAISS 本地向量库；
- 为演示单独启动较重的模型服务框架。

生成能力交给远端 DeepSeek，本机做轻量 RAG。

## 2. 数据面

```text
                    Provider host
                         │
CoLoR request ──> origin_server.py
                         │
              ┌──────────┴──────────┐
              │                     │
         MySQL 8.x             DeepSeek API
    rag_documents/chunks      /chat/completions
       ngram FULLTEXT            stream=true
              │                     │
              └──── context ───────>│
                                    │
                         answer / SSE delta
                                    │
                              CoLoR response
```

MySQL 可以和 Provider 同机，也可以放到后续独立数据库节点；Python 只依赖 `MYSQL_HOST/PORT/...`，应用接口不变。

## 3. Retriever

中文使用 MySQL 内置 ngram FULLTEXT parser：

```sql
FULLTEXT KEY ft_rag_chunks (title, content) WITH PARSER ngram
```

查询：

```sql
MATCH(title, content) AGAINST (? IN NATURAL LANGUAGE MODE)
```

先取 `RAG_CANDIDATE_K` 个候选，再在 Python 里用字符 bigram overlap 做一个很小的二次排序：

```text
final_score = 0.78 * normalized_mysql_fulltext_score
            + 0.22 * lexical_bigram_overlap
```

这样没有 embedding 常驻内存，也能对中文问句得到较稳定的领域检索结果。

若短查询未命中 FULLTEXT，会退化到最多 4 个 bigram 的有界 `LIKE` 查询，用于处理“选课？”、“血压？”这类极短输入。

## 4. Chunk

默认：

```text
RAG_CHUNK_CHARS=1100
RAG_CHUNK_OVERLAP_CHARS=140
RAG_TOP_K=6
RAG_MAX_CONTEXT_CHARS=10000
```

优先按段落、句末标点切分。超长无标点文本才硬切。

这组参数更适合当前 CPU-only 演示机：chunk 数量不会过多，一次 DeepSeek 请求的上下文也保持可控。


## 4.1 Bundled demo corpus

为了让实验机首次启动后可以直接演示，本项目随 Server 打包四套 QA/记录语料：

```text
data/medical/huatuo26m_test_6000.jsonl                 6000
data/education/tmu_style_education_500.jsonl            500
data/medical/synthetic_private_medical_2000.jsonl      2000
data/education/synthetic_private_education_2000.jsonl  2000
                                                           -------
                                                             10500
```

`rag_admin.py seed` 把四份数据按“一条 JSONL = 一个 chunk”导入，因此默认 MySQL 中是 10500 个 chunks。若已有旧版 6500 chunks，只需执行 `rag_admin.py seed-privacy` 追加/刷新两个隐私 Mock document。

医疗公开数据保持 Huatuo-26M test dataset 的 `questions/answers` 原始格式；学校基础数据是 synthetic/mock，借鉴 Tokyo Metropolitan University e-learning FAQ dataset 的 11 类组织方式生成。新增隐私数据全部为明确标记 `synthetic=true` 的可联结 Mock 记录，使用稳定的 `subject_id/linkage_group` 连接同一虚构患者或学生的多条记录。

可以在没有 MySQL 的机器上先做文件校验：

```bash
python tools/rag_admin.py bundled-data-check
```

## 5. DeepSeek

`deepseek_client.py` 直接使用 Python `urllib.request` 调用 OpenAI-compatible Chat Completions：

```text
POST https://api.deepseek.com/chat/completions
```

默认：

```text
DEEPSEEK_MODEL=deepseek-v4-flash
DEEPSEEK_THINKING=disabled
DEEPSEEK_MAX_TOKENS=900
```

关闭 thinking 是有意的：这个演示重点是 RAG、跨区 API、SSE 和 Tunnel；一般知识问答不需要额外的长推理阶段。

complete 模式读取一个 JSON；stream 模式直接消费 DeepSeek SSE，并把内容增量转换为现有页面理解的：

```text
event: meta
event: token
event: done
```

这里的 `token` 是 DeepSeek 实际返回的 stream delta。单个 delta 可能包含一个或多个 tokenizer token，Server 不再人为 sleep 或逐字模拟。

## 6. Domain separation

两个对外服务仍然独立：

```text
/api/model/medical
/api/model/education
```

检索时强制：

```sql
WHERE domain = 'medical'
```

或：

```sql
WHERE domain = 'education'
```

所以医疗文档不会进入教务模型的 RAG context，后续也可以继续增加 `finance`、`network` 等领域。

## 7. Secret boundary

浏览器只知道测试服务 key：

```text
model-demo-key
```

Server 私有：

```text
MYSQL_PASSWORD
DEEPSEEK_API_KEY
```

后两者只从 `rag.env` / OS environment 读取。正式部署应由 secret manager/systemd EnvironmentFile/Windows service environment 管理。

## 8. 后续数据库服务接轨

使用 MySQL 后，可以自然增加：

```text
service_registry       服务元数据
api_access_log         REST 调用日志
rag_documents          知识源
rag_chunks             RAG 分片
model_sessions         会话
policy_audit           管控/审批审计
monitor_timeseries     监控历史（若后续也希望持久化）
```

这些表可以先共用一个 MySQL Server、分 schema 管理；规模上升后再把 MySQL 独立成数据库服务节点。对 CoLoR 的 HTTP API 和 RM/BR 不需要因此改变。
