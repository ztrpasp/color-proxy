from __future__ import annotations

import json
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parents[1]
MED_OUT = SERVER_DIR / "data" / "medical" / "synthetic_private_medical_2000.jsonl"
EDU_OUT = SERVER_DIR / "data" / "education" / "synthetic_private_education_2000.jsonl"

MED_OUT.parent.mkdir(parents=True, exist_ok=True)
EDU_OUT.parent.mkdir(parents=True, exist_ok=True)


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


def privacy_meta(*, level: str, labels: list[str], owner: str, approval: bool = True) -> dict:
    return {
        "privacy_class": level,
        "sensitivity_types": labels,
        "data_owner": owner,
        "approval_required": approval,
        "deidentify_on_export": True,
        "default_cross_domain_action": "APPROVAL" if approval else "SANITIZE",
        "allowed_purposes": ["AUTHORIZED_SERVICE", "AUTHORIZED_RESEARCH"],
        "synthetic": True,
    }


# ------------------------- Medical: 200 patients x 10 record types -------------------------
CONDITIONS = [
    "上呼吸道感染", "高血压随访", "偏头痛", "慢性胃炎", "过敏性鼻炎",
    "2型糖尿病随访", "腰背肌劳损", "睡眠障碍", "湿疹", "高脂血症随访",
]
MEDICATIONS = {
    "上呼吸道感染": "对症处理并按医嘱使用退热镇痛药，注意补液和休息",
    "高血压随访": "继续既往降压方案，记录家庭血压并按期复诊",
    "偏头痛": "发作期按医嘱使用镇痛药，记录诱因与发作频率",
    "慢性胃炎": "短期抑酸与胃黏膜保护治疗，避免刺激性饮食",
    "过敏性鼻炎": "按医嘱使用抗组胺药和鼻用制剂，减少过敏原暴露",
    "2型糖尿病随访": "继续生活方式管理及既往降糖方案，监测空腹血糖",
    "腰背肌劳损": "短期对症处理，减少负重并进行适度康复训练",
    "睡眠障碍": "先行睡眠卫生干预，必要时由专科评估进一步治疗",
    "湿疹": "加强皮肤保湿，按医嘱外用药物并避免已知刺激物",
    "高脂血症随访": "继续饮食运动干预，并按计划复查血脂",
}
ALLERGIES = ["青霉素类", "磺胺类", "花粉", "尘螨", "海鲜", "无已知药物过敏"]
MENTAL_NOTES = ["近期工作压力增大，情绪紧张", "近两周睡眠浅、易醒", "偶有焦虑但日常功能基本稳定", "近期情绪总体平稳", "考试或项目周期内压力明显"]
FAMILY_HISTORY = ["父系有高血压家族史", "母系有2型糖尿病家族史", "一级亲属无明确重大遗传病史", "家族中有高脂血症记录", "家族中有偏头痛病史"]

medical_rows: list[dict] = []
for i in range(1, 201):
    pid = f"PAT-MOCK-{i:04d}"
    name = f"模拟患者{i:04d}号"
    sex = "男" if i % 2 else "女"
    year = 1958 + (i * 7) % 48
    month = 1 + (i * 5) % 12
    day = 1 + (i * 11) % 27
    birth = f"{year:04d}-{month:02d}-{day:02d}"
    condition = CONDITIONS[(i - 1) % len(CONDITIONS)]
    allergy = ALLERGIES[(i - 1) % len(ALLERGIES)]
    blood = ["A", "B", "O", "AB"][i % 4]
    subject_common = {
        "subject_id": pid,
        "subject_type": "patient",
        "linkage_group": pid,
        "synthetic": True,
        "source_type": "synthetic_private_mock",
        "version": "1.0",
    }

    records = [
        (
            "M01_IDENTITY_REGISTRATION", "身份与挂号",
            f"查询 {pid}（{name}）的身份与挂号信息。",
            f"这是完全虚构的患者隐私 Mock 记录。患者标识为 {pid}，姓名为“{name}”，性别为{sex}，出生日期为{birth}，血型{blood}型。模拟证件号为 000000{birth.replace('-', '')}00X，院内病历号为 MRN-MOCK-{i:06d}。最近一次挂号科室为综合内科，挂号序号为 REG-MOCK-{i:06d}。这些字段只用于隐私管控、脱敏和审计实验。",
            privacy_meta(level="P2_SENSITIVE", labels=["PII", "PHI", "IDENTITY"], owner="mock-hospital"),
        ),
        (
            "M02_CONTACT_EMERGENCY", "联系方式与紧急联系人",
            f"查询 {pid}（{name}）的联系方式和紧急联系人。",
            f"这是完全虚构的联系信息。患者 {pid} 的模拟联系电话为 000-10{i % 100:02d}-{i:04d}，电子邮箱为 patient{i:04d}@example.invalid，通信地址为“示范市演示区测试街道{i:03d}号”。紧急联系人为“模拟联系人{i:04d}”，关系为{['家属','朋友','同事'][i % 3]}，联系电话为 000-20{i % 100:02d}-{(9000+i)%10000:04d}。",
            privacy_meta(level="P2_SENSITIVE", labels=["PII", "CONTACT", "PHI"], owner="mock-hospital"),
        ),
        (
            "M03_ENCOUNTER_DIAGNOSIS", "门诊就诊与诊断",
            f"查询 {pid}（{name}）最近一次门诊就诊和诊断记录。",
            f"患者 {pid} 的虚构门诊记录：就诊日期为 2026-{1 + i % 8:02d}-{1 + i % 27:02d}，主诉为“近期出现与{condition}相关的不适”，门诊诊断记录为“{condition}”。生命体征示例：体温 {36.1 + (i % 8) * 0.1:.1f}℃，收缩压 {108 + i % 34} mmHg，舒张压 {68 + i % 22} mmHg。医生备注：当前记录仅用于系统演示，不构成真实诊疗建议。",
            privacy_meta(level="P2_SENSITIVE", labels=["PHI", "DIAGNOSIS", "ENCOUNTER"], owner="mock-hospital"),
        ),
        (
            "M04_MEDICATION", "用药与处方",
            f"查询 {pid}（{name}）的近期用药和处方记录。",
            f"患者 {pid} 的虚构处方记录与诊断“{condition}”关联。处置摘要：{MEDICATIONS[condition]}。处方编号 RX-MOCK-{i:06d}，开具日期 2026-{1 + i % 8:02d}-{2 + i % 26:02d}。药物名称和剂量在本 Mock 数据中不映射到真实处方，仅用于测试处方信息属于 PHI 时的访问控制、脱敏和审计。",
            privacy_meta(level="P2_SENSITIVE", labels=["PHI", "MEDICATION", "PRESCRIPTION"], owner="mock-hospital"),
        ),
        (
            "M05_LAB_RESULT", "检验结果",
            f"查询 {pid}（{name}）最近一次实验室检验结果。",
            f"患者 {pid} 的虚构检验单 LAB-MOCK-{i:06d}：空腹血糖 {4.2 + (i % 35) * 0.1:.1f} mmol/L，总胆固醇 {3.6 + (i % 28) * 0.1:.1f} mmol/L，血红蛋白 {118 + i % 45} g/L，白细胞计数 {4.0 + (i % 38) * 0.1:.1f}×10^9/L。采样日期为 2026-{1 + i % 8:02d}-{3 + i % 25:02d}。数值为算法生成的演示值。",
            privacy_meta(level="P2_SENSITIVE", labels=["PHI", "LAB_RESULT"], owner="mock-hospital"),
        ),
        (
            "M06_IMAGING_REPORT", "影像检查",
            f"查询 {pid}（{name}）最近一次影像检查报告。",
            f"患者 {pid} 的虚构影像记录 IMG-MOCK-{i:06d}，检查日期 2026-{1 + i % 8:02d}-{4 + i % 24:02d}，项目为{['胸部X线','腹部超声','颈椎X线','头颅CT示例扫描'][i % 4]}。报告摘要：未见需要紧急处理的明显异常征象，建议结合临床症状由医生判断。此报告为 Mock 文本，不对应真实影像。",
            privacy_meta(level="P2_SENSITIVE", labels=["PHI", "IMAGING"], owner="mock-hospital"),
        ),
        (
            "M07_ALLERGY", "过敏史",
            f"查询 {pid}（{name}）登记的过敏史。",
            f"患者 {pid} 的虚构过敏史记录：{allergy}。若为已知过敏项，模拟备注为“历史就诊时由患者自述，需在再次用药前复核”；若显示无已知药物过敏，也只代表本次 Mock 登记状态。记录编号 ALG-MOCK-{i:06d}。",
            privacy_meta(level="P2_SENSITIVE", labels=["PHI", "ALLERGY"], owner="mock-hospital"),
        ),
        (
            "M08_INSURANCE_BILLING", "医保与费用",
            f"查询 {pid}（{name}）的医保和费用结算记录。",
            f"患者 {pid} 的虚构结算记录：医保标识 INS-MOCK-{i:06d}，结算单号 BILL-MOCK-{i:06d}，本次模拟总费用 {120 + (i * 37) % 1380:.2f} 元，个人支付 {20 + (i * 13) % 260:.2f} 元。支付账户仅以 PAY-MOCK-{i:06d} 表示，不包含真实银行卡号。该记录同时标记为医疗隐私和财务敏感信息。",
            privacy_meta(level="P3_HIGH_SENSITIVE", labels=["PHI", "FINANCIAL", "INSURANCE"], owner="mock-hospital"),
        ),
        (
            "M09_MENTAL_HEALTH", "心理与精神健康",
            f"查询 {pid}（{name}）的心理健康随访记录。",
            f"患者 {pid} 的虚构心理健康随访摘要：{MENTAL_NOTES[i % len(MENTAL_NOTES)]}。模拟量表结果为“轻度风险观察级别 {1 + i % 3}”，未记录真实诊断。建议由专业人员结合完整情况评估。该类记录被标记为 P3 高敏感数据，默认跨域访问需显式审批。",
            privacy_meta(level="P3_HIGH_SENSITIVE", labels=["PHI", "MENTAL_HEALTH"], owner="mock-hospital"),
        ),
        (
            "M10_GENETIC_FAMILY", "遗传与家族史",
            f"查询 {pid}（{name}）的遗传和家族病史记录。",
            f"患者 {pid} 的虚构家族史记录：{FAMILY_HISTORY[i % len(FAMILY_HISTORY)]}。模拟遗传筛查标识 GEN-MOCK-{i:06d}，结果字段只写为“演示性风险标签 G{i % 5}”，不对应任何真实基因位点或临床结论。该记录用于测试遗传类高敏感信息的访问审批、最小化披露与审计。",
            privacy_meta(level="P3_HIGH_SENSITIVE", labels=["PHI", "GENETIC", "FAMILY_HISTORY"], owner="mock-hospital"),
        ),
    ]

    for rec_idx, (record_type, category, question, answer, privacy) in enumerate(records, start=1):
        privacy_level = "P3" if str(privacy.get("privacy_class", "")).startswith("P3") else "P2"
        medical_rows.append({
            "id": f"MED-PRIV-{i:04d}-{rec_idx:02d}",
            "record_id": f"MEDREC-MOCK-{i:04d}-{rec_idx:02d}",
            "questions": question,
            "answers": answer,
            "category": category,
            "record_type": record_type,
            "sid": "SID_MED_PRIVATE_P3" if privacy_level == "P3" else "SID_MED_PRIVATE_P2",
            "privacy_level": privacy_level,
            "allowed_role": ["medical_privileged"] if privacy_level == "P3" else ["medical_staff", "medical_researcher"],
            **subject_common,
            "privacy": privacy,
        })


# ------------------------- Education: 250 students x 8 record types -------------------------
DEPARTMENTS = ["计算机学院", "电子信息学院", "机械工程学院", "经济管理学院", "数学学院", "外国语学院"]
PROGRAMS = ["计算机科学与技术", "网络空间安全", "电子信息工程", "机械工程", "信息管理", "应用数学"]
COURSES = [
    ("MOCK-CS101", "程序设计基础"), ("MOCK-NET202", "计算机网络"),
    ("MOCK-AI203", "人工智能导论"), ("MOCK-DB204", "数据库系统"),
    ("MOCK-MATH201", "概率与统计"), ("MOCK-SE301", "软件工程"),
]
COUNSELING = ["学习压力咨询", "时间管理咨询", "职业规划咨询", "住宿适应咨询", "人际沟通咨询"]

education_rows: list[dict] = []
for i in range(1, 251):
    sid = f"STU-MOCK-{i:04d}"
    name = f"模拟学生{i:04d}号"
    sex = "男" if i % 2 else "女"
    dept = DEPARTMENTS[(i - 1) % len(DEPARTMENTS)]
    program = PROGRAMS[(i - 1) % len(PROGRAMS)]
    grade = 2022 + i % 5
    course1 = COURSES[i % len(COURSES)]
    course2 = COURSES[(i + 2) % len(COURSES)]
    subject_common = {
        "subject_id": sid,
        "subject_type": "student",
        "linkage_group": sid,
        "synthetic": True,
        "source_type": "synthetic_private_mock",
        "version": "1.0",
    }

    records = [
        (
            "E01_IDENTITY_CONTACT", "身份与联系方式",
            f"查询 {sid}（{name}）的学生身份和联系方式。",
            f"这是完全虚构的学生隐私 Mock 记录。学生标识 {sid}，姓名“{name}”，性别{sex}，模拟证件号 000000{2000 + i % 7}0101000X，校园卡号 CARD-MOCK-{i:06d}。联系电话为 000-30{i % 100:02d}-{i:04d}，邮箱 student{i:04d}@example.invalid，通信地址为“示范市大学城演示路{i:03d}号”。",
            privacy_meta(level="P2_SENSITIVE", labels=["PII", "EDUCATION_RECORD", "CONTACT"], owner="mock-university"),
        ),
        (
            "E02_ENROLLMENT_STATUS", "学籍与培养信息",
            f"查询 {sid}（{name}）的学籍和培养方案信息。",
            f"学生 {sid} 的虚构学籍记录：{grade} 级，所属{dept}，专业为{program}，学籍状态“正常”，培养层次“本科”，当前模拟学期为 2026 秋季学期。导师字段为“模拟导师{1 + i % 25:02d}号”。该记录属于受保护的教育记录。",
            privacy_meta(level="P2_SENSITIVE", labels=["EDUCATION_RECORD", "ACADEMIC_STATUS"], owner="mock-university"),
        ),
        (
            "E03_GRADES_TRANSCRIPT", "成绩与学业记录",
            f"查询 {sid}（{name}）的课程成绩和学业记录。",
            f"学生 {sid} 的虚构成绩记录：{course1[0]}《{course1[1]}》成绩 {60 + (i * 7) % 41} 分，{course2[0]}《{course2[1]}》成绩 {60 + (i * 11) % 41} 分；累计获得学分 {40 + i % 90}，模拟 GPA 为 {2.0 + (i % 20) * 0.1:.1f}/4.0。成绩单编号 TRANS-MOCK-{i:06d}。",
            privacy_meta(level="P2_SENSITIVE", labels=["EDUCATION_RECORD", "GRADES"], owner="mock-university"),
        ),
        (
            "E04_ATTENDANCE_ACTIVITY", "考勤与学习活动",
            f"查询 {sid}（{name}）的考勤和学习平台活动记录。",
            f"学生 {sid} 的虚构考勤记录：本学期已统计课程活动 {48 + i % 35} 次，出勤 {42 + i % 30} 次，请假 {i % 4} 次，迟到 {i % 3} 次。学习平台最近一次登录时间为 2026-{1 + i % 8:02d}-{1 + i % 27:02d} 20:{i % 60:02d}，累计在线学习时长 {20 + i % 75} 小时。",
            privacy_meta(level="P2_SENSITIVE", labels=["EDUCATION_RECORD", "ATTENDANCE", "ACTIVITY_LOG"], owner="mock-university"),
        ),
        (
            "E05_TUITION_FINANCIAL_AID", "学费与资助",
            f"查询 {sid}（{name}）的学费缴纳和资助信息。",
            f"学生 {sid} 的虚构财务记录：2026 学年应缴费用 {6000 + (i % 6) * 800:.2f} 元，已缴 {5000 + (i % 7) * 700:.2f} 元，结算单号 TUITION-MOCK-{i:06d}。资助状态为{['无资助','校级助学金','综合奖学金','临时困难补助'][i % 4]}，资助金额 {0 if i % 4 == 0 else 1000 + (i % 5) * 500:.2f} 元。支付账户仅使用 PAY-MOCK-{i:06d} 占位。",
            privacy_meta(level="P3_HIGH_SENSITIVE", labels=["EDUCATION_RECORD", "FINANCIAL", "AID"], owner="mock-university"),
        ),
        (
            "E06_DORM_EMERGENCY", "住宿与紧急联系人",
            f"查询 {sid}（{name}）的宿舍和紧急联系人信息。",
            f"学生 {sid} 的虚构住宿记录：入住“示范大学演示校区 {1 + i % 8} 号宿舍楼”，房间 ROOM-MOCK-{1 + i % 8:02d}-{100 + i % 500:03d}。紧急联系人“模拟家属{i:04d}”，关系为{['父母','亲属','监护人'][i % 3]}，联系电话 000-40{i % 100:02d}-{(8000+i)%10000:04d}。宿舍门禁卡号 ACCESS-MOCK-{i:06d}。",
            privacy_meta(level="P2_SENSITIVE", labels=["PII", "EDUCATION_RECORD", "LOCATION", "CONTACT"], owner="mock-university"),
        ),
        (
            "E07_CONDUCT_COUNSELING", "处分与咨询",
            f"查询 {sid}（{name}）的学生事务处分或咨询记录。",
            f"学生 {sid} 的虚构高敏感学生事务记录：当前处分状态为{['无处分','书面提醒（Mock）','行为改进观察（Mock）'][i % 3]}；最近一次咨询类型为“{COUNSELING[i % len(COUNSELING)]}”，咨询编号 COUNSEL-MOCK-{i:06d}。正文不包含真实心理诊断，只用于模拟受限学生事务信息。默认跨域访问需要显式审批并记录审计日志。",
            privacy_meta(level="P3_HIGH_SENSITIVE", labels=["EDUCATION_RECORD", "DISCIPLINARY", "COUNSELING"], owner="mock-university"),
        ),
        (
            "E08_INTERNSHIP_CAREER", "实习与就业",
            f"查询 {sid}（{name}）的实习申请和就业服务记录。",
            f"学生 {sid} 的虚构实习与就业记录：申请编号 INTERN-MOCK-{i:06d}，意向岗位为{['后端开发','网络工程','数据分析','算法工程','系统运维'][i % 5]}，意向城市为{['示范市','演示市','测试市'][i % 3]}。简历版本 CV-MOCK-{i:04d}-V{1 + i % 3}，辅导状态为{['待预约','已完成一次辅导','等待材料修改'][i % 3]}。该记录属于受保护的教育与职业服务数据。",
            privacy_meta(level="P2_SENSITIVE", labels=["EDUCATION_RECORD", "CAREER", "PII"], owner="mock-university"),
        ),
    ]

    for rec_idx, (record_type, category, question, answer, privacy) in enumerate(records, start=1):
        privacy_level = "P3" if str(privacy.get("privacy_class", "")).startswith("P3") else "P2"
        education_rows.append({
            "id": f"EDU-PRIV-{i:04d}-{rec_idx:02d}",
            "record_id": f"EDUREC-MOCK-{i:04d}-{rec_idx:02d}",
            "questions": question,
            "answers": answer,
            "category": category,
            "record_type": record_type,
            "sid": "SID_EDU_PRIVATE_P3" if privacy_level == "P3" else "SID_EDU_PRIVATE_P2",
            "privacy_level": privacy_level,
            "allowed_role": ["school_privileged"] if privacy_level == "P3" else ["school_staff", "academic_advisor"],
            **subject_common,
            "privacy": privacy,
        })


assert len(medical_rows) == 2000
assert len(education_rows) == 2000
assert len({x["id"] for x in medical_rows}) == 2000
assert len({x["questions"] for x in medical_rows}) == 2000
assert len({x["id"] for x in education_rows}) == 2000
assert len({x["questions"] for x in education_rows}) == 2000
assert len({x["subject_id"] for x in medical_rows}) == 200
assert len({x["subject_id"] for x in education_rows}) == 250
assert all(x["synthetic"] and x["privacy"]["synthetic"] for x in medical_rows + education_rows)

write_jsonl(MED_OUT, medical_rows)
write_jsonl(EDU_OUT, education_rows)

print(f"wrote medical privacy rows: {len(medical_rows)} -> {MED_OUT}")
print(f"wrote education privacy rows: {len(education_rows)} -> {EDU_OUT}")
print(f"medical subjects: {len({x['subject_id'] for x in medical_rows})}, records/subject=10")
print(f"education subjects: {len({x['subject_id'] for x in education_rows})}, records/subject=8")
