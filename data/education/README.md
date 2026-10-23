# tmu_style_education_500.jsonl

500 条中文 synthetic e-learning FAQ，一条问题对应一条独立回答。

结构示例：

```json
{
  "id": "EDU-C2-0001",
  "questions": "...",
  "answers": "...",
  "category_id": "C2",
  "category": "作业",
  "category_en": "Assignments",
  "tag": "...",
  "role": "student",
  "source_type": "synthetic_mock",
  "source_basis": "Tokyo Metropolitan University e-learning FAQ 11-category scheme",
  "synthetic": true,
  "version": "1.0"
}
```

它只参考公开 TMU FAQ 数据集的 11 类组织框架，内容由本项目重新生成，不代表 Tokyo Metropolitan University 的真实制度或服务说明。

## synthetic_private_education_2000.jsonl

额外包含 250 个完全虚构学生 × 8 类记录 = 2000 条隐私 Mock。每个学生的学籍、成绩、考勤、资助、住宿、咨询和实习记录通过稳定 `subject_id` 可联结，便于后续测试跨记录隐私泄露与访问控制。所有内容均为 synthetic。

详见 `../../docs/PRIVACY-MOCK-DATA.md`。
