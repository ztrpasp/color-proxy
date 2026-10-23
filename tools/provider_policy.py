"""Minimal Provider-side P2/P3 policy support for the RAG demo.

This module intentionally stays small.  It is not a second Gateway policy engine.  It only
provides the two provider-local controls needed by the 0.3.1 demo:

P2 retrieval gate
    requester NID -> allowed RAG SID set -> retriever filter

P3 response egress gate
    provenance SID set -> if a P3 SID is present and that SID is not export-authorized, BLOCK

Under L3 the requester NID comes from ``tools/origin_server.py``: it maps the TCP peer address
(the consumer's tun IP, already source-bound by the provider per D14) to a NID through
``config.json`` ``l3.peers[]``.  Request headers are never trusted for identity.
"""
from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

SERVER_DIR = Path(__file__).resolve().parents[1]
DEFAULT_POLICY_FILE = SERVER_DIR / "provider-policy.json"

# Application-level RAG content SIDs.  They are metadata labels for retrieved knowledge chunks;
# they do not replace or alter the 72-bit/hex CoLoR service SID used by RM/BR routing.
SID_MED_PUBLIC = "SID_MED_PUBLIC"
SID_MED_P2 = "SID_MED_PRIVATE_P2"
SID_MED_P3 = "SID_MED_PRIVATE_P3"
SID_EDU_PUBLIC = "SID_EDU_PUBLIC"
SID_EDU_P2 = "SID_EDU_PRIVATE_P2"
SID_EDU_P3 = "SID_EDU_PRIVATE_P3"

PUBLIC_SIDS = frozenset({SID_MED_PUBLIC, SID_EDU_PUBLIC})
ALL_SIDS = frozenset({
    SID_MED_PUBLIC, SID_MED_P2, SID_MED_P3,
    SID_EDU_PUBLIC, SID_EDU_P2, SID_EDU_P3,
})

_DOMAIN_LEVEL_SID = {
    ("medical", "P0"): SID_MED_PUBLIC,
    ("medical", "P2"): SID_MED_P2,
    ("medical", "P3"): SID_MED_P3,
    ("education", "P0"): SID_EDU_PUBLIC,
    ("education", "P2"): SID_EDU_P2,
    ("education", "P3"): SID_EDU_P3,
}

_DEFAULT_ALLOWED_ROLES = {
    ("medical", "P2"): ["medical_staff", "medical_researcher"],
    ("medical", "P3"): ["medical_privileged"],
    ("education", "P2"): ["school_staff", "academic_advisor"],
    ("education", "P3"): ["school_privileged"],
}


def normalize_nid(value: str | int | None) -> str:
    """Return a stable lowercase requester identifier used as a policy key."""
    if value is None:
        return "DIRECT"
    if isinstance(value, int):
        return f"{value:032x}"
    text = str(value).strip()
    if not text:
        return "DIRECT"
    lowered = text.lower()
    if lowered.startswith("0x"):
        lowered = lowered[2:]
    # Preserve non-hex labels such as DIRECT for local tests, but normalize actual NIDs.
    if lowered and all(ch in "0123456789abcdef" for ch in lowered):
        return lowered.zfill(32)
    return text


def privacy_level_from_metadata(metadata: dict[str, Any] | None) -> str:
    meta = metadata or {}
    explicit = str(meta.get("privacy_level") or "").strip().upper()
    if explicit in {"P0", "P2", "P3"}:
        return explicit
    privacy = meta.get("privacy")
    if isinstance(privacy, dict):
        raw = str(privacy.get("privacy_class") or "").upper()
        if raw.startswith("P3"):
            return "P3"
        if raw.startswith("P2"):
            return "P2"
    return "P0"


def sid_from_metadata(domain: str, metadata: dict[str, Any] | None) -> str:
    meta = metadata or {}
    explicit = str(meta.get("sid") or "").strip()
    if explicit:
        return explicit
    level = privacy_level_from_metadata(meta)
    return _DOMAIN_LEVEL_SID.get((domain, level), f"SID_{domain.upper()}_{level}")


def annotate_metadata(domain: str, metadata: dict[str, Any] | None) -> dict[str, Any]:
    """Return metadata with stable SID/privacy labels and optional role ACL hints.

    Public corpora become P0.  Existing P2/P3 privacy metadata is preserved.  Synthetic private
    chunks receive conservative example ``allowed_role`` hints only when the source record did
    not already provide an ACL.  NID-to-SID permission remains authoritative in ProviderPolicy.
    """
    meta = dict(metadata or {})
    level = privacy_level_from_metadata(meta)
    meta.setdefault("privacy_level", level)
    meta.setdefault("sid", sid_from_metadata(domain, meta))
    roles = _DEFAULT_ALLOWED_ROLES.get((domain, level))
    if roles and "allowed_role" not in meta:
        meta["allowed_role"] = list(roles)
    return meta


def _string_set(value: Any) -> frozenset[str]:
    if value is None:
        return frozenset()
    if isinstance(value, str):
        return frozenset({value}) if value else frozenset()
    if isinstance(value, (list, tuple, set, frozenset)):
        return frozenset(str(x) for x in value if str(x))
    return frozenset({str(value)})


@dataclass(frozen=True)
class RequesterPolicy:
    nid: str
    roles: frozenset[str]
    allowed_sids: frozenset[str]
    export_sids: frozenset[str]
    source: str = "default"

    def retrieval_allows(self, sid: str) -> bool:
        return sid in self.allowed_sids

    def export_allows(self, sid: str) -> bool:
        return sid in self.export_sids

    def as_public_dict(self) -> dict[str, Any]:
        return {
            "requester_nid": self.nid,
            "roles": sorted(self.roles),
            "allowed_sids": sorted(self.allowed_sids),
            "export_sids": sorted(self.export_sids),
            "policy_source": self.source,
        }


@dataclass(frozen=True)
class EgressDecision:
    decision: str
    reason: str
    blocked_sids: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"decision": self.decision, "reason": self.reason}
        if self.blocked_sids:
            data["blocked_sids"] = list(self.blocked_sids)
        return data


class ProviderPolicy:
    """Tiny file-backed NID -> SID permission resolver."""

    def __init__(self, path: Path | None = None) -> None:
        configured = os.getenv("PROVIDER_POLICY_FILE", "").strip()
        self.path = Path(configured).expanduser() if configured else (path or DEFAULT_POLICY_FILE)
        self._lock = threading.Lock()
        self._mtime_ns: int | None = None
        self._data: dict[str, Any] = {}

    def _load(self) -> dict[str, Any]:
        try:
            stat = self.path.stat()
            mtime_ns = stat.st_mtime_ns
        except OSError:
            return {}
        with self._lock:
            if self._mtime_ns == mtime_ns:
                return self._data
            try:
                obj = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                obj = {}
            self._data = obj if isinstance(obj, dict) else {}
            self._mtime_ns = mtime_ns
            return self._data

    @staticmethod
    def _entry_to_policy(nid: str, entry: dict[str, Any], source: str) -> RequesterPolicy:
        allowed = _string_set(entry.get("allowed_sids")) & ALL_SIDS
        export = _string_set(entry.get("export_sids")) & ALL_SIDS
        roles = _string_set(entry.get("roles"))
        return RequesterPolicy(
            nid=nid,
            roles=roles,
            allowed_sids=allowed,
            export_sids=export,
            source=source,
        )

    def resolve(self, requester_nid: str | int | None) -> RequesterPolicy:
        nid = normalize_nid(requester_nid)
        data = self._load()
        default_entry = data.get("default") if isinstance(data.get("default"), dict) else {}
        # Safe built-in fallback if provider-policy.json is missing or malformed: P0 only.
        if not default_entry:
            default_entry = {
                "roles": ["public"],
                "allowed_sids": sorted(PUBLIC_SIDS),
                "export_sids": sorted(PUBLIC_SIDS),
            }
        users = data.get("users") if isinstance(data.get("users"), dict) else {}
        matched: dict[str, Any] | None = None
        for key, value in users.items():
            if isinstance(value, dict) and normalize_nid(key) == nid:
                matched = value
                break
        if matched is None:
            return self._entry_to_policy(nid, default_entry, "default")

        # User entries are explicit, but inherit missing keys from default for convenience.
        merged = dict(default_entry)
        merged.update(matched)
        return self._entry_to_policy(nid, merged, f"user:{nid}")

    @staticmethod
    def chunk_acl_allows(
        metadata: dict[str, Any], *, requester_nid: str, requester_roles: Iterable[str]
    ) -> bool:
        """Optional per-chunk allowed_user / allowed_role check.

        Empty/missing lists impose no extra restriction.  This is subordinate to the SID gate.
        """
        allowed_users = _string_set(metadata.get("allowed_user"))
        if allowed_users and normalize_nid(requester_nid) not in {normalize_nid(x) for x in allowed_users}:
            return False
        allowed_roles = _string_set(metadata.get("allowed_role"))
        if allowed_roles and not (allowed_roles & frozenset(str(x) for x in requester_roles)):
            return False
        return True

    @staticmethod
    def egress_decision(policy: RequesterPolicy, provenance: list[dict[str, Any]]) -> EgressDecision:
        """Minimal P3 rule: P3 provenance without export permission -> BLOCK."""
        blocked = sorted({
            str(item.get("sid") or "")
            for item in provenance
            if str(item.get("privacy_level") or "").upper() == "P3"
            and str(item.get("sid") or "") not in policy.export_sids
        } - {""})
        if blocked:
            return EgressDecision(
                decision="BLOCK",
                reason="P3 provenance contains SID(s) without requester export permission.",
                blocked_sids=tuple(blocked),
            )
        return EgressDecision(
            decision="ALLOW",
            reason="No non-exportable P3 SID is present in retrieval provenance.",
        )


_POLICY: ProviderPolicy | None = None


def get_provider_policy() -> ProviderPolicy:
    global _POLICY
    if _POLICY is None:
        _POLICY = ProviderPolicy()
    return _POLICY
