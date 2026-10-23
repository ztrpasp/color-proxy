from __future__ import annotations

import sys
import unittest
from pathlib import Path

SERVER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER))
sys.path.insert(0, str(SERVER / "tools"))

from tools.mysql_rag import RetrievedChunk  # noqa: E402
from tools.provider_policy import (  # noqa: E402
    SID_MED_P2, SID_MED_P3, SID_MED_PUBLIC, ProviderPolicy,
)
from tools.rag_service import RAGPolicyBlocked, RAGService  # noqa: E402


class FakeStore:
    def __init__(self, chunk: RetrievedChunk) -> None:
        self.chunk = chunk
        self.calls = []

    def search(self, domain, query, **kwargs):
        self.calls.append((domain, query, kwargs))
        allowed = kwargs.get("allowed_sids")
        return [self.chunk] if self.chunk.sid in allowed else []


class FakeResult:
    model = "fake-deepseek"
    content = "fake answer"
    usage = {"total_tokens": 3}


class FakeLLM:
    def __init__(self) -> None:
        self.complete_calls = 0

    def complete(self, messages):
        self.complete_calls += 1
        return FakeResult()

    def stream(self, messages):
        yield {"type": "delta", "delta": "ok"}
        yield {"type": "finish", "finish_reason": "stop"}


def p3_chunk() -> RetrievedChunk:
    return RetrievedChunk(
        chunk_id=99,
        document_id=1,
        domain="medical",
        sid=SID_MED_P3,
        privacy_level="P3",
        title="PAT-MOCK-0042 心理健康记录",
        content="P3 synthetic content",
        source_name="privacy mock",
        source_uri="synthetic://privacy",
        metadata={
            "sid": SID_MED_P3,
            "privacy_level": "P3",
            "allowed_role": ["medical_privileged"],
        },
        fulltext_score=1.0,
        lexical_score=1.0,
        score=1.0,
    )


class ProviderP2P3Tests(unittest.TestCase):
    def setUp(self):
        self.policy = ProviderPolicy(SERVER / "provider-policy.json")

    def service(self):
        svc = RAGService()
        svc.policy = self.policy
        svc.store = FakeStore(p3_chunk())
        svc.llm = FakeLLM()
        return svc

    def test_default_client_b2_p2_filter_excludes_p3(self):
        svc = self.service()
        prepared = svc.prepare(
            "medical", "心理健康记录",
            requester_nid="b2" * 16,
        )
        self.assertEqual(prepared.chunks, [])
        self.assertNotIn(SID_MED_P3, prepared.requester_policy.allowed_sids)
        self.assertEqual(prepared.egress.decision, "ALLOW")

    def test_c3_can_retrieve_p3_but_egress_blocks(self):
        svc = self.service()
        with self.assertRaises(RAGPolicyBlocked) as ctx:
            svc.complete("medical", "心理健康记录", requester_nid="c3" * 16)
        payload = ctx.exception.payload
        self.assertEqual(payload["provider_policy"]["p3_egress"]["decision"], "BLOCK")
        self.assertEqual(payload["provenance"][0]["sid"], SID_MED_P3)
        self.assertEqual(svc.llm.complete_calls, 0, "BLOCK preflight must not call DeepSeek")

    def test_d4_can_retrieve_and_export_p3(self):
        svc = self.service()
        result = svc.complete("medical", "心理健康记录", requester_nid="d4" * 16)
        self.assertEqual(result["answer"], "fake answer")
        self.assertEqual(result["provider_policy"]["p3_egress"]["decision"], "ALLOW")
        self.assertEqual(result["provenance"][0]["privacy_level"], "P3")
        self.assertEqual(svc.llm.complete_calls, 1)

    def test_policy_public_and_p2_constants_present(self):
        b2 = self.policy.resolve("b2" * 16)
        self.assertIn(SID_MED_PUBLIC, b2.allowed_sids)
        self.assertIn(SID_MED_P2, b2.allowed_sids)


if __name__ == "__main__":
    unittest.main()
