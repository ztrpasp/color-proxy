"""Administration CLI for the MySQL RAG knowledge base.

Bundled demo corpus:
- medical public: 6,000 Huatuo-26M test Q&A records (user-provided copy)
- education public/mock: 500 synthetic Chinese e-learning FAQ Q&A records
- medical privacy mock: 200 synthetic patients x 10 record types = 2,000 records
- education privacy mock: 250 synthetic students x 8 record types = 2,000 records

Total after ``seed``: 10,500 RAG chunks.

Examples:
  python tools/rag_admin.py bundled-data-check
  python tools/rag_admin.py init
  python tools/rag_admin.py seed
  python tools/rag_admin.py seed-privacy
  python tools/rag_admin.py status
  python tools/rag_admin.py ingest-qa --domain education custom.jsonl
  python tools/rag_admin.py ingest --domain medical knowledge/medical/*.md
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Iterable

try:
    from mysql_rag import MySQLRAGStore, RAGDatabaseError
    from provider_policy import annotate_metadata, get_provider_policy
    from rag_documents import chunk_text, load_text
except ImportError:
    from tools.mysql_rag import MySQLRAGStore, RAGDatabaseError  # type: ignore
    from tools.provider_policy import annotate_metadata, get_provider_policy  # type: ignore
    from tools.rag_documents import chunk_text, load_text  # type: ignore

_SERVER_DIR = Path(__file__).resolve().parents[1]
_DATA_DIR = _SERVER_DIR / "data"
_BUNDLED_MEDICAL = _DATA_DIR / "medical" / "huatuo26m_test_6000.jsonl"
_BUNDLED_EDUCATION = _DATA_DIR / "education" / "tmu_style_education_500.jsonl"
_BUNDLED_MEDICAL_PRIVATE = _DATA_DIR / "medical" / "synthetic_private_medical_2000.jsonl"
_BUNDLED_EDUCATION_PRIVATE = _DATA_DIR / "education" / "synthetic_private_education_2000.jsonl"

_MEDICAL_SOURCE_URI = "https://huggingface.co/datasets/FreedomIntelligence/huatuo26M-testdatasets"
_EDUCATION_SOURCE_URI = "synthetic://tmu-style/e-learning-faq-500-v1"
_MEDICAL_PRIVATE_SOURCE_URI = "synthetic://mock-hospital/private-records-200x10-v1"
_EDUCATION_PRIVATE_SOURCE_URI = "synthetic://mock-university/private-records-250x8-v1"


def _pick_text(obj: dict[str, Any], fields: Iterable[str]) -> str:
    for field in fields:
        value = obj.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _qa_chunks_from_jsonl(
    path: Path,
    *,
    question_fields: tuple[str, ...] = ("questions", "question"),
    answer_fields: tuple[str, ...] = ("answers", "answer"),
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Load one JSONL Q&A record as one RAG chunk.

    This deliberately does not run the generic 1,100-character document chunker.  Q&A corpora
    already provide a meaningful retrieval unit, and keeping the question with its complete
    reference answer improves lexical retrieval and source attribution.
    """
    chunks: list[dict[str, Any]] = []
    categories: dict[str, int] = {}
    with path.open("r", encoding="utf-8-sig", errors="strict") as handle:
        for line_no, raw in enumerate(handle, start=1):
            raw = raw.strip()
            if not raw:
                continue
            obj = json.loads(raw)
            if not isinstance(obj, dict):
                raise ValueError(f"{path.name}:{line_no}: JSONL row must be an object")
            question = _pick_text(obj, question_fields)
            answer = _pick_text(obj, answer_fields)
            if not question or not answer:
                raise ValueError(
                    f"{path.name}:{line_no}: missing question/answer; "
                    f"question fields={question_fields}, answer fields={answer_fields}"
                )

            # Keep source metadata compact.  The actual Q&A stays in title/content.
            meta = {
                "kind": "qa",
                "line": line_no,
            }
            for key in (
                "id", "category_id", "category", "category_en", "tag", "role", "role_zh",
                "source_type", "source_basis", "synthetic", "version",
                "record_id", "record_type", "subject_id", "subject_type", "linkage_group",
                "sid", "privacy_level", "allowed_user", "allowed_role", "privacy",
            ):
                if key in obj:
                    meta[key] = obj[key]
            category = str(obj.get("category_id") or obj.get("category") or "").strip()
            if category:
                categories[category] = categories.get(category, 0) + 1

            chunks.append({
                "title": question,
                "content": f"问题：{question}\n参考回答：{answer}",
                "metadata": meta,
            })

    return chunks, {
        "rows": len(chunks),
        "categories": categories,
        "question_fields": list(question_fields),
        "answer_fields": list(answer_fields),
    }


def _seed_qa_file(
    store: MySQLRAGStore,
    *,
    domain: str,
    path: Path,
    source_name: str,
    source_uri: str,
    expected_rows: int,
    extra_metadata: dict[str, Any],
) -> tuple[int, int]:
    data = path.read_bytes()
    chunks, stats = _qa_chunks_from_jsonl(path)
    if stats["rows"] != expected_rows:
        raise ValueError(f"{path.name}: expected {expected_rows} rows, got {stats['rows']}")
    metadata = {
        "kind": "qa_corpus",
        "rows": expected_rows,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        **extra_metadata,
    }
    if stats["categories"]:
        metadata["category_counts"] = stats["categories"]
    return store.upsert_document(
        domain=domain,
        source_name=source_name,
        source_uri=source_uri,
        checksum=metadata["sha256"],
        chunks=chunks,
        metadata=metadata,
    )


def _check_bundled() -> dict[str, Any]:
    checks: dict[str, Any] = {}
    specs = (
        ("medical_public", _BUNDLED_MEDICAL, 6000),
        ("education_public", _BUNDLED_EDUCATION, 500),
        ("medical_private", _BUNDLED_MEDICAL_PRIVATE, 2000),
        ("education_private", _BUNDLED_EDUCATION_PRIVATE, 2000),
    )
    for key, path, expected in specs:
        if not path.exists():
            raise ValueError(f"missing bundled dataset: {path}")
        raw = path.read_bytes()
        chunks, stats = _qa_chunks_from_jsonl(path)
        if len(chunks) != expected:
            raise ValueError(f"{path.name}: expected {expected} rows, got {len(chunks)}")
        sid_counts: dict[str, int] = {}
        privacy_level_counts: dict[str, int] = {}
        domain = "medical" if key.startswith("medical") else "education"
        for chunk in chunks:
            meta = annotate_metadata(domain, chunk.get("metadata", {}))
            sid = str(meta.get("sid") or "UNKNOWN")
            level = str(meta.get("privacy_level") or "UNKNOWN")
            sid_counts[sid] = sid_counts.get(sid, 0) + 1
            privacy_level_counts[level] = privacy_level_counts.get(level, 0) + 1
        item: dict[str, Any] = {
            "path": str(path.relative_to(_SERVER_DIR)),
            "rows": len(chunks),
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "categories": stats["categories"],
            "sid_counts": sid_counts,
            "privacy_levels": privacy_level_counts,
        }
        if key.endswith("_private"):
            subject_ids = {str(c["metadata"].get("subject_id") or "") for c in chunks}
            privacy_classes: dict[str, int] = {}
            for chunk in chunks:
                privacy = chunk["metadata"].get("privacy")
                if not isinstance(privacy, dict) or privacy.get("synthetic") is not True:
                    raise ValueError(f"{path.name}: privacy record missing synthetic privacy metadata")
                level = str(privacy.get("privacy_class") or "UNKNOWN")
                privacy_classes[level] = privacy_classes.get(level, 0) + 1
            item["subjects"] = len(subject_ids - {""})
            item["privacy_classes"] = privacy_classes
        checks[key] = item
    checks["total_rows"] = sum(int(checks[key]["rows"]) for key, _, _ in specs)
    checks["privacy_rows"] = checks["medical_private"]["rows"] + checks["education_private"]["rows"]
    return checks


def _seed_privacy(store: MySQLRAGStore) -> tuple[tuple[int, int], tuple[int, int]]:
    med_private = _seed_qa_file(
        store,
        domain="medical",
        path=_BUNDLED_MEDICAL_PRIVATE,
        source_name="Synthetic hospital privacy records (200 patients x 10)",
        source_uri=_MEDICAL_PRIVATE_SOURCE_URI,
        expected_rows=2000,
        extra_metadata={
            "dataset": "synthetic-private-medical-2000",
            "synthetic": True,
            "privacy_mock": True,
            "subjects": 200,
            "records_per_subject": 10,
            "language": "zh",
            "bundled": True,
        },
    )
    edu_private = _seed_qa_file(
        store,
        domain="education",
        path=_BUNDLED_EDUCATION_PRIVATE,
        source_name="Synthetic campus privacy records (250 students x 8)",
        source_uri=_EDUCATION_PRIVATE_SOURCE_URI,
        expected_rows=2000,
        extra_metadata={
            "dataset": "synthetic-private-education-2000",
            "synthetic": True,
            "privacy_mock": True,
            "subjects": 250,
            "records_per_subject": 8,
            "language": "zh",
            "bundled": True,
        },
    )
    return med_private, edu_private


def main() -> int:
    parser = argparse.ArgumentParser(description="color-proxy MySQL RAG 管理工具")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="创建 rag_documents / rag_chunks 表")
    sub.add_parser("status", help="检查 MySQL、ngram 配置和各领域文档/chunk 数量")
    sub.add_parser(
        "seed",
        help="导入全部内置数据：6500 条基础 QA + 4000 条隐私 Mock（共 10500 chunks）",
    )
    sub.add_parser("seed-privacy", help="只导入 2000 条医院 + 2000 条学校隐私 Mock 数据")
    sub.add_parser("bundled-data-check", help="不连接 MySQL，校验内置 10500 条 JSONL 数据及 SID/P0/P2/P3 标注")
    policy = sub.add_parser("policy", help="不连接 MySQL，查看某个 requester NID 的 Provider P2/P3 权限")
    policy.add_argument("--nid", required=True, help="128-bit NID hex，例如 b2b2...b2")

    clear = sub.add_parser("clear", help="删除某个领域的全部 RAG 文档")
    clear.add_argument("--domain", choices=["medical", "education"], required=True)

    ingest = sub.add_parser("ingest", help="导入 txt/md/json/jsonl/csv/xml 普通文档并自动分块")
    ingest.add_argument("--domain", choices=["medical", "education"], required=True)
    ingest.add_argument("paths", nargs="+", help="文档路径，可传多个")

    ingest_qa = sub.add_parser("ingest-qa", help="按一条 JSONL = 一条 QA chunk 导入问答语料")
    ingest_qa.add_argument("--domain", choices=["medical", "education"], required=True)
    ingest_qa.add_argument("--question-field", default="questions")
    ingest_qa.add_argument("--answer-field", default="answers")
    ingest_qa.add_argument("paths", nargs="+", help="JSONL 路径，可传多个")

    args = parser.parse_args()

    if args.command == "bundled-data-check":
        try:
            print(json.dumps(_check_bundled(), ensure_ascii=False, indent=2))
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
    if args.command == "policy":
        print(json.dumps(get_provider_policy().resolve(args.nid).as_public_dict(), ensure_ascii=False, indent=2))
        return 0

    store = MySQLRAGStore()
    try:
        if args.command == "init":
            store.ensure_schema()
            print("RAG schema ready.")
            return 0
        if args.command == "status":
            print(json.dumps(store.ping(), ensure_ascii=False, indent=2, default=str))
            return 0
        if args.command == "seed":
            # Validate both files before mutating MySQL so a damaged bundle cannot leave a
            # half-seeded corpus.
            _check_bundled()
            store.ensure_schema()
            med = _seed_qa_file(
                store,
                domain="medical",
                path=_BUNDLED_MEDICAL,
                source_name="Huatuo-26M test dataset (6000 QA)",
                source_uri=_MEDICAL_SOURCE_URI,
                expected_rows=6000,
                extra_metadata={
                    "dataset": "FreedomIntelligence/huatuo26M-testdatasets",
                    "license": "Apache-2.0",
                    "language": "zh",
                    "bundled": True,
                },
            )
            edu = _seed_qa_file(
                store,
                domain="education",
                path=_BUNDLED_EDUCATION,
                source_name="Synthetic e-learning FAQ (TMU-style, 500 QA)",
                source_uri=_EDUCATION_SOURCE_URI,
                expected_rows=500,
                extra_metadata={
                    "dataset": "tmu-style-education-faq-500",
                    "synthetic": True,
                    "language": "zh",
                    "bundled": True,
                    "basis": "Tokyo Metropolitan University e-learning FAQ 11-category scheme",
                },
            )
            med_private, edu_private = _seed_privacy(store)
            print(f"medical public: document_id={med[0]} chunks={med[1]}")
            print(f"education public: document_id={edu[0]} chunks={edu[1]}")
            print(f"medical private mock: document_id={med_private[0]} chunks={med_private[1]}")
            print(f"education private mock: document_id={edu_private[0]} chunks={edu_private[1]}")
            print(f"total chunks={med[1] + edu[1] + med_private[1] + edu_private[1]}")
            return 0
        if args.command == "seed-privacy":
            checks = _check_bundled()
            if checks["privacy_rows"] != 4000:
                raise ValueError("bundled privacy corpus must contain exactly 4000 records")
            store.ensure_schema()
            med_private, edu_private = _seed_privacy(store)
            print(f"medical private mock: document_id={med_private[0]} chunks={med_private[1]}")
            print(f"education private mock: document_id={edu_private[0]} chunks={edu_private[1]}")
            print(f"privacy chunks={med_private[1] + edu_private[1]}")
            return 0
        if args.command == "clear":
            deleted = store.delete_domain(args.domain)
            print(f"deleted documents: {deleted}")
            return 0
        if args.command == "ingest":
            store.ensure_schema()
            total = 0
            for raw_path in args.paths:
                path = Path(raw_path).expanduser().resolve()
                data = path.read_bytes()
                text = load_text(path)
                chunks = chunk_text(text, title=path.stem)
                document_id, count = store.upsert_document(
                    domain=args.domain,
                    source_name=path.name,
                    source_uri=path.as_uri(),
                    checksum=hashlib.sha256(data).hexdigest(),
                    chunks=chunks,
                    metadata={"file_suffix": path.suffix.lower(), "bytes": len(data)},
                )
                total += count
                print(f"{path.name}: document_id={document_id}, chunks={count}")
            print(f"ingested chunks: {total}")
            return 0
        if args.command == "ingest-qa":
            store.ensure_schema()
            total = 0
            for raw_path in args.paths:
                path = Path(raw_path).expanduser().resolve()
                data = path.read_bytes()
                chunks, stats = _qa_chunks_from_jsonl(
                    path,
                    question_fields=(args.question_field,),
                    answer_fields=(args.answer_field,),
                )
                document_id, count = store.upsert_document(
                    domain=args.domain,
                    source_name=path.name,
                    source_uri=path.as_uri(),
                    checksum=hashlib.sha256(data).hexdigest(),
                    chunks=chunks,
                    metadata={
                        "kind": "qa_corpus",
                        "rows": stats["rows"],
                        "file_suffix": path.suffix.lower(),
                        "bytes": len(data),
                    },
                )
                total += count
                print(f"{path.name}: document_id={document_id}, chunks={count}")
            print(f"ingested QA chunks: {total}")
            return 0
    except (RAGDatabaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
