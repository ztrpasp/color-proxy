# Bundled RAG demo datasets

本目录提供一套可以直接导入 MySQL RAG 的演示数据。`python tools/rag_admin.py seed` 会把四份 JSONL 按 **一条记录 = 一个 rag_chunk** 导入，默认知识库是 **10500 个 chunks**：

| domain | 文件 | 条目数 | 用途 |
|---|---|---:|---|
| `medical` | `medical/huatuo26m_test_6000.jsonl` | 6000 | 中文医疗问答检索 |
| `medical` | `medical/synthetic_private_medical_2000.jsonl` | 2000 | 200 个虚构患者 × 10 类隐私记录 |
| `education` | `education/tmu_style_education_500.jsonl` | 500 | 中文在线教学 / 教务 FAQ 检索 |
| `education` | `education/synthetic_private_education_2000.jsonl` | 2000 | 250 个虚构学生 × 8 类隐私记录 |
|  | **总计** | **10500** |  |

## Medical: Huatuo-26M test dataset

`huatuo26m_test_6000.jsonl` 是用户提供并随本项目打包的 Huatuo-26M test dataset 副本，保持原始两字段格式：

```json
{"questions":"...","answers":"..."}
```

上游：`FreedomIntelligence/huatuo26M-testdatasets`

- Dataset: https://huggingface.co/datasets/FreedomIntelligence/huatuo26M-testdatasets
- Paper: https://arxiv.org/abs/2305.01526
- License: Apache-2.0
- Rows: 6000

本项目不修改原始问答内容，也不将该数据视为临床诊疗规范。它只作为跨网 RAG 服务的实验检索语料。

## Education: TMU-style synthetic FAQ 500

`tmu_style_education_500.jsonl` 是本项目生成的 **synthetic/mock 数据**。它借鉴 Tokyo Metropolitan University e-learning FAQ dataset 的组织方式与 11 个类别，不复制、声称或模拟东京首都大学现行制度、系统参数或真实校规。

参考来源：

- Yasunobu Sumikawa et al., *An FAQ dataset for E-learning system used on a Japanese University*, Data in Brief 25 (2019) 104001.
- DOI: https://doi.org/10.1016/j.dib.2019.104001
- PMC: https://pmc.ncbi.nlm.nih.gov/articles/PMC6595272/
- 原数据集为 CC BY 4.0，包含 427 个问题、79 个答案和 11 个类别。

本项目生成版改为 **500 问 / 500 答，一问一答**。类别比例按原数据集中 427 个问题的类别分布近似缩放：

| ID | 原类别 | 中文类别 | Mock 问答数 |
|---|---|---|---:|
| C1 | Documents | 文档资料 | 59 |
| C2 | Assignments | 作业 | 80 |
| C3 | Test/Questionnaire | 测验与问卷 | 104 |
| C4 | Contents | 课程内容 | 18 |
| C5 | Uploading | 文件上传 | 22 |
| C6 | Registration | 课程注册 | 77 |
| C7 | Aggregation | 汇总统计 | 29 |
| C8 | Login | 登录认证 | 13 |
| C9 | Contact | 通知与联系 | 52 |
| C10 | Students | 学生与成员 | 18 |
| C11 | Basic Usage | 基本使用 | 28 |
|  |  | **合计** | **500** |

每条记录额外包含 `category_id/category/tag/role/source_type/source_basis/synthetic` 等元数据。所有具体平台规则（例如 200 MB 上传限制、约 10 分钟注册同步）都是为了构造内部一致的虚拟校园服务环境而设定的 Mock 规则。

若需要重新生成：

```bash
python tools/generate_education_mock.py
python tools/rag_admin.py bundled-data-check
```


## Synthetic privacy corpus

两份 `synthetic_private_*.jsonl` 全部为项目本地生成的虚构数据，并显式携带 `subject_id`、`record_type` 与 `privacy` metadata。它们用于后续：

- 基于内容名字 / 主体 ID 的出域访问控制；
- `ALLOW / BLOCK / SANITIZE / APPROVAL` 策略；
- PII / PHI / EDUCATION_RECORD / FINANCIAL 等敏感标签；
- 同一主体多记录关联后的泄露测试；
- 脱敏、审批与可信审计。

完整 schema 和记录类型见 `../docs/PRIVACY-MOCK-DATA.md`。

## Provider 0.3.1 SID / privacy metadata

导入 MySQL 时，chunk metadata 会补齐应用层 RAG SID 与 `privacy_level`：

```text
medical public      -> SID_MED_PUBLIC       / P0
medical private P2  -> SID_MED_PRIVATE_P2   / P2
medical private P3  -> SID_MED_PRIVATE_P3   / P3
education public    -> SID_EDU_PUBLIC       / P0
education private P2-> SID_EDU_PRIVATE_P2   / P2
education private P3-> SID_EDU_PRIVATE_P3   / P3
```

隐私 JSONL 生成器本身也会写出 `sid / privacy_level / allowed_role`。Huatuo 原始 6000 条文件继续保持原样，P0/SID 在 importer 写入 MySQL metadata 时补齐。详细策略见 `../docs/PROVIDER-P2P3-0.3.1.md`。
