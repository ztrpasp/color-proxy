"""Domain RAG orchestration: Provider P2 filter -> MySQL retrieval -> provenance -> P3 egress -> DeepSeek."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Iterator

try:
    from deepseek_client import DeepSeekClient, DeepSeekError
    from mysql_rag import MySQLRAGStore, RAGDatabaseError, RetrievedChunk
    from provider_policy import EgressDecision, RequesterPolicy, get_provider_policy
    from rag_config import DEEPSEEK, RAG
except ImportError:
    from tools.deepseek_client import DeepSeekClient, DeepSeekError  # type: ignore
    from tools.mysql_rag import MySQLRAGStore, RAGDatabaseError, RetrievedChunk  # type: ignore
    from tools.provider_policy import EgressDecision, RequesterPolicy, get_provider_policy  # type: ignore
    from tools.rag_config import DEEPSEEK, RAG  # type: ignore


class RAGServiceError(RuntimeError):
    pass


class RAGPolicyBlocked(RAGServiceError):
    """Raised for non-stream requests blocked by the minimal response egress rule."""

    def __init__(self, payload: dict[str, Any]) -> None:
        super().__init__(str(payload.get("message") or "response blocked by provider policy"))
        self.payload = payload


@dataclass(frozen=True)
class DomainProfile:
    key: str
    name: str
    domain_label: str
    system_prompt: str


PROFILES = {
    "medical": DomainProfile(
        key="medical",
        name="HospitalMed-RAG",
        domain_label="医院医疗知识服务",
        system_prompt=(
            "你是 HospitalMed-RAG，面向医院与健康知识场景提供中文问答。"
            "优先依据检索到的知识库上下文回答，并把事实性结论保持在上下文和可靠的一般医学知识范围内。"
            "不要替代医生进行个体化诊断或处方调整；涉及急症危险信号时应明确提示及时就医。"
            "如果上下文不足以支持非常具体的结论，请说明哪些信息仍需确认，避免编造。"
        ),
    ),
    "education": DomainProfile(
        key="education",
        name="CampusEdu-RAG",
        domain_label="学校教务知识服务",
        system_prompt=(
            "你是 CampusEdu-RAG，面向学校教务、培养方案和校园服务场景提供中文问答。"
            "优先依据检索到的学校知识库上下文回答。对于会随学校、学院、年级或学期变化的规则，"
            "必须区分已检索到的确定信息与一般性建议；没有依据时不要编造具体日期、学分、地点或审批结果。"
        ),
    ),
}


def _source_view(chunks: list[RetrievedChunk]) -> list[dict[str, Any]]:
    """Public retrieval metadata view; no chunk body is exposed here."""
    result: list[dict[str, Any]] = []
    for i, item in enumerate(chunks):
        source: dict[str, Any] = {
            "rank": i + 1,
            "sid": item.sid,
            "chunk_id": item.chunk_id,
            "privacy_level": item.privacy_level,
            "source_name": item.source_name,
            "source_uri": item.source_uri,
            "title": item.title,
            "score": round(item.score, 4),
        }
        policy_meta: dict[str, Any] = {}
        for key in (
            "record_id", "record_type", "subject_id", "subject_type", "linkage_group",
            "synthetic", "allowed_user", "allowed_role",
        ):
            if key in item.metadata:
                policy_meta[key] = item.metadata[key]
        privacy = item.metadata.get("privacy")
        if isinstance(privacy, dict):
            policy_meta["privacy"] = privacy
        if policy_meta:
            source["metadata"] = policy_meta
        result.append(source)
    return result


def _provenance(chunks: list[RetrievedChunk]) -> list[dict[str, Any]]:
    """Minimal provenance contract consumed by Provider/Gateway egress guards."""
    return [
        {
            "sid": item.sid,
            "chunk_id": item.chunk_id,
            "privacy_level": item.privacy_level,
        }
        for item in chunks
    ]


def _retrieval_metadata(chunks: list[RetrievedChunk]) -> dict[str, Any]:
    """Internal-style metadata showing exactly what passed P2 and may enter LLM context."""
    return {
        "chunks": [
            {
                "sid": item.sid,
                "chunk_id": item.chunk_id,
                "privacy_level": item.privacy_level,
                "title": item.title,
                "score": round(item.score, 4),
            }
            for item in chunks
        ],
        "sid_set": sorted({item.sid for item in chunks}),
    }


def _context_text(chunks: list[RetrievedChunk]) -> str:
    if not chunks:
        return "（本次没有检索到经过 Provider P2 策略允许的直接匹配知识库片段。）"
    blocks: list[str] = []
    used = 0
    for i, item in enumerate(chunks, start=1):
        header = (
            f"[{i}] SID={item.sid} | privacy={item.privacy_level} | "
            f"来源: {item.source_name} | {item.source_uri or 'local'}"
        )
        if item.title:
            header += f" | {item.title}"
        block = f"{header}\n{item.content.strip()}"
        if used + len(block) > RAG.max_context_chars:
            remaining = RAG.max_context_chars - used
            if remaining > 200:
                blocks.append(block[:remaining])
            break
        blocks.append(block)
        used += len(block)
    return "\n\n".join(blocks)


@dataclass(frozen=True)
class PreparedRAG:
    profile: DomainProfile
    chunks: list[RetrievedChunk]
    messages: list[dict[str, str]]
    retrieval_ms: float
    requester_policy: RequesterPolicy
    provenance: list[dict[str, Any]]
    egress: EgressDecision


class RAGService:
    def __init__(self) -> None:
        self.store = MySQLRAGStore()
        self.llm = DeepSeekClient()
        self.policy = get_provider_policy()

    def _profile(self, model_key: str) -> DomainProfile:
        try:
            return PROFILES[model_key]
        except KeyError as exc:
            raise RAGServiceError(f"unknown model: {model_key}") from exc

    def prepare(
        self, model_key: str, question: str, *, requester_nid: str | int | None = None
    ) -> PreparedRAG:
        profile = self._profile(model_key)
        question = question.strip()
        if not question:
            raise RAGServiceError("question is empty")

        requester_policy = self.policy.resolve(requester_nid)
        started = time.perf_counter()
        try:
            chunks = self.store.search(
                profile.key,
                question,
                top_k=RAG.top_k,
                allowed_sids=requester_policy.allowed_sids,
                requester_nid=requester_policy.nid,
                requester_roles=requester_policy.roles,
            )
        except RAGDatabaseError as exc:
            raise RAGServiceError(str(exc)) from exc
        retrieval_ms = (time.perf_counter() - started) * 1000.0

        provenance = _provenance(chunks)
        # Streaming responses cannot be retracted after tokens are emitted.  Because the v0.3.1
        # P3 rule depends only on provenance, we can safely preflight it before invoking DeepSeek.
        egress = self.policy.egress_decision(requester_policy, provenance)

        context = _context_text(chunks)
        messages = [
            {"role": "system", "content": profile.system_prompt},
            {
                "role": "system",
                "content": (
                    "下面是经过 Provider 侧 P2 SID/ACL 检索过滤后的 MySQL RAG 上下文。"
                    "回答时优先使用这些内容。如果引用了某个片段中的具体事实，可以用 [1]、[2] 这样的编号标注来源。\n\n"
                    + context
                ),
            },
            {"role": "user", "content": question},
        ]
        return PreparedRAG(
            profile=profile,
            chunks=chunks,
            messages=messages,
            retrieval_ms=retrieval_ms,
            requester_policy=requester_policy,
            provenance=provenance,
            egress=egress,
        )

    @staticmethod
    def _policy_block_payload(prepared: PreparedRAG, question: str) -> dict[str, Any]:
        return {
            "error": "response_egress_blocked",
            "message": "Provider P3 egress policy blocked this response before model output was released.",
            "question": question,
            "answer": None,
            "provenance": prepared.provenance,
            "provider_policy": {
                **prepared.requester_policy.as_public_dict(),
                "p2_retrieval": "FILTERED_BEFORE_LLM_CONTEXT",
                "p3_egress": prepared.egress.as_dict(),
            },
            "rag": {
                "backend": "mysql-fulltext-ngram",
                "retrieval_ms": round(prepared.retrieval_ms, 2),
                "retrieval_metadata": _retrieval_metadata(prepared.chunks),
                "sources": _source_view(prepared.chunks),
            },
        }

    def complete(
        self, model_key: str, question: str, *, requester_nid: str | int | None = None
    ) -> dict[str, Any]:
        prepared = self.prepare(model_key, question, requester_nid=requester_nid)
        if prepared.egress.decision == "BLOCK":
            raise RAGPolicyBlocked(self._policy_block_payload(prepared, question))

        started = time.perf_counter()
        try:
            result = self.llm.complete(prepared.messages)
        except DeepSeekError as exc:
            raise RAGServiceError(str(exc)) from exc
        llm_ms = (time.perf_counter() - started) * 1000.0
        return {
            "model": prepared.profile.name,
            "model_key": model_key,
            "backend_model": result.model,
            "question": question,
            "answer": result.content,
            "mode": "complete",
            "provenance": prepared.provenance,
            "provider_policy": {
                **prepared.requester_policy.as_public_dict(),
                "p2_retrieval": "FILTERED_BEFORE_LLM_CONTEXT",
                "p3_egress": prepared.egress.as_dict(),
            },
            "rag": {
                "backend": "mysql-fulltext-ngram",
                "retrieval_ms": round(prepared.retrieval_ms, 2),
                "retrieval_metadata": _retrieval_metadata(prepared.chunks),
                "sources": _source_view(prepared.chunks),
            },
            "llm_ms": round(llm_ms, 2),
            "usage": result.usage,
            "generated_at": round(time.time(), 3),
        }

    def stream(
        self, model_key: str, question: str, *, requester_nid: str | int | None = None
    ) -> Iterator[tuple[str, dict[str, Any]]]:
        prepared = self.prepare(model_key, question, requester_nid=requester_nid)
        common = {
            "model": prepared.profile.name,
            "model_key": model_key,
            "backend_model": DEEPSEEK.model,
            "question": question,
            "stream_format": "deepseek-sse-delta",
            "provenance": prepared.provenance,
            "provider_policy": {
                **prepared.requester_policy.as_public_dict(),
                "p2_retrieval": "FILTERED_BEFORE_LLM_CONTEXT",
                "p3_egress": prepared.egress.as_dict(),
            },
            "rag": {
                "backend": "mysql-fulltext-ngram",
                "retrieval_ms": round(prepared.retrieval_ms, 2),
                "retrieval_metadata": _retrieval_metadata(prepared.chunks),
                "sources": _source_view(prepared.chunks),
            },
        }
        yield "meta", common

        if prepared.egress.decision == "BLOCK":
            yield "policy", self._policy_block_payload(prepared, question)
            yield "done", {
                "finish_reason": "policy_block",
                "chunks": 0,
                "llm_ms": 0.0,
                "usage": {},
            }
            return

        index = 0
        usage: dict[str, Any] = {}
        finish_reason = "stop"
        started = time.perf_counter()
        try:
            for event in self.llm.stream(prepared.messages):
                if event["type"] == "delta":
                    yield "token", {"index": index, "delta": event["delta"]}
                    index += 1
                elif event["type"] == "usage":
                    usage = event["usage"]
                elif event["type"] == "finish":
                    finish_reason = event["finish_reason"]
        except DeepSeekError as exc:
            raise RAGServiceError(str(exc)) from exc
        yield "done", {
            "finish_reason": finish_reason,
            "chunks": index,
            "llm_ms": round((time.perf_counter() - started) * 1000.0, 2),
            "usage": usage,
        }


_SERVICE: RAGService | None = None


def get_rag_service() -> RAGService:
    global _SERVICE
    if _SERVICE is None:
        _SERVICE = RAGService()
    return _SERVICE
