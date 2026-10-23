# huatuo26m_test_6000.jsonl

随项目携带的 Huatuo-26M test dataset：6000 条中文医疗问答，格式为 `questions` / `answers`。

上游：<https://huggingface.co/datasets/FreedomIntelligence/huatuo26M-testdatasets>

License: Apache-2.0。该语料用于 RAG 演示和实验，不应作为个体化医疗诊断或处方依据。

## synthetic_private_medical_2000.jsonl

额外包含 200 个完全虚构患者 × 10 类记录 = 2000 条隐私 Mock。所有记录均有稳定 `subject_id`、`record_type` 和 `privacy` metadata，用于访问控制/脱敏/审批/审计实验。任何身份、联系方式、地址、病历、诊疗和财务字段都不对应真实个人。

详见 `../../docs/PRIVACY-MOCK-DATA.md`。
