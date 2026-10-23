# Synthetic Privacy RAG Dataset

这批数据用于后续跨网数据访问管控、审批、脱敏、最小化披露、敏感语义识别和可信审计实验。所有主体、证件号、联系方式、地址、病历号、校园卡号、费用、成绩、诊疗内容等均为算法生成的 synthetic/mock 数据，不对应真实个人。

## 1. 规模

| domain | 主体 | 每主体记录 | 总记录 |
|---|---:|---:|---:|
| medical | 200 个虚构患者 | 10 | 2000 |
| education | 250 个虚构学生 | 8 | 2000 |
| 合计 | 450 个虚构主体 | - | 4000 |

和原有 6500 条基础知识一起导入后，默认 MySQL RAG 为 10500 chunks。

## 2. 医院 10 类记录

1. `M01_IDENTITY_REGISTRATION` 身份与挂号
2. `M02_CONTACT_EMERGENCY` 联系方式与紧急联系人
3. `M03_ENCOUNTER_DIAGNOSIS` 门诊就诊与诊断
4. `M04_MEDICATION` 用药与处方
5. `M05_LAB_RESULT` 检验结果
6. `M06_IMAGING_REPORT` 影像检查
7. `M07_ALLERGY` 过敏史
8. `M08_INSURANCE_BILLING` 医保与费用
9. `M09_MENTAL_HEALTH` 心理与精神健康
10. `M10_GENETIC_FAMILY` 遗传与家族史

每个患者共享一个稳定的 `PAT-MOCK-xxxx` subject ID，因此可以测试跨记录关联。例如 `PAT-MOCK-0042` 同时拥有身份、联系方式、诊断、检验、心理健康等十条记录。

## 3. 学校 8 类记录

1. `E01_IDENTITY_CONTACT` 身份与联系方式
2. `E02_ENROLLMENT_STATUS` 学籍与培养信息
3. `E03_GRADES_TRANSCRIPT` 成绩与学业记录
4. `E04_ATTENDANCE_ACTIVITY` 考勤与学习活动
5. `E05_TUITION_FINANCIAL_AID` 学费与资助
6. `E06_DORM_EMERGENCY` 住宿与紧急联系人
7. `E07_CONDUCT_COUNSELING` 处分与咨询
8. `E08_INTERNSHIP_CAREER` 实习与就业

每个学生共享一个稳定的 `STU-MOCK-xxxx` subject ID。

## 4. JSONL schema

每行仍然可作为一个独立 QA chunk：

```json
{
  "id": "MED-PRIV-0042-09",
  "record_id": "MEDREC-MOCK-0042-09",
  "questions": "查询 PAT-MOCK-0042（模拟患者0042号）的心理健康随访记录。",
  "answers": "...",
  "category": "心理与精神健康",
  "record_type": "M09_MENTAL_HEALTH",
  "subject_id": "PAT-MOCK-0042",
  "subject_type": "patient",
  "linkage_group": "PAT-MOCK-0042",
  "synthetic": true,
  "source_type": "synthetic_private_mock",
  "privacy": {
    "privacy_class": "P3_HIGH_SENSITIVE",
    "sensitivity_types": ["PHI", "MENTAL_HEALTH"],
    "data_owner": "mock-hospital",
    "approval_required": true,
    "deidentify_on_export": true,
    "default_cross_domain_action": "APPROVAL",
    "allowed_purposes": ["AUTHORIZED_SERVICE", "AUTHORIZED_RESEARCH"],
    "synthetic": true
  }
}
```

## 5. 隐私等级

当前先使用两级，后续可以直接映射到 Gateway PolicyDecision：

```text
P2_SENSITIVE
  -> PII / PHI / EDUCATION_RECORD / CONTACT / GRADES / ACTIVITY ...
  -> 推荐默认策略：SANITIZE 或 APPROVAL

P3_HIGH_SENSITIVE
  -> MENTAL_HEALTH / GENETIC / FINANCIAL / DISCIPLINARY / COUNSELING ...
  -> 推荐默认策略：APPROVAL；未授权跨域可 BLOCK
```

当前 4000 条分布：

```text
medical:
  P2_SENSITIVE       1400
  P3_HIGH_SENSITIVE   600

education:
  P2_SENSITIVE       1500
  P3_HIGH_SENSITIVE   500
```

## 6. 为后续机制保留的字段

`rag_chunks.metadata` 会保留：

- `record_id`
- `record_type`
- `subject_id`
- `subject_type`
- `linkage_group`
- `synthetic`
- 完整 `privacy` 对象

Provider-side 0.3.1 已经实际使用这些 metadata 补齐 `sid / privacy_level / allowed_role`，并实现最小 P2/P3 baseline：

```text
consumer NID
   -> allowed SID set
   -> retriever filter                         # P2
   -> context assembly
   -> provenance [{sid,chunk_id,privacy_level}]
   -> P3 export preflight
   -> ALLOW / BLOCK
   -> DeepSeek / response release
```

完整实现见 `PROVIDER-P2P3-0.3.1.md`。后续仍可在 Gateway/Provider Guard 上增加 SANITIZE、APPROVAL、敏感语义检测和完整审计。

## 7. 导入

已有 6500 条数据时，只追加隐私数据：

```bash
python tools/rag_admin.py bundled-data-check
python tools/rag_admin.py seed-privacy
python tools/rag_admin.py status
```

全量刷新/初始化：

```bash
python tools/rag_admin.py init
python tools/rag_admin.py seed
python tools/rag_admin.py status
```

`seed` 和 `seed-privacy` 都是基于稳定 source URI 的 upsert，不会因为重复运行而无限追加同一份 bundled corpus。

## 8. 重新生成

```bash
python tools/generate_privacy_mock.py
python tools/rag_admin.py bundled-data-check
```

生成器不依赖 Faker 或第三方包，Windows/Linux 都可以直接运行。
