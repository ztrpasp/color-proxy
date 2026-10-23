"""Small, cross-platform document loader and chunker for the RAG demo.

Supported with the Python standard library: .txt, .md, .json, .jsonl, .csv and .xml.
This deliberately avoids heavyweight local embedding/model dependencies on the 16 GB CPU-only
experiment laptop.
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

try:
    from rag_config import RAG
except ImportError:
    from tools.rag_config import RAG  # type: ignore


def _flatten_json(value: Any, prefix: str = "") -> list[str]:
    out: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_prefix = f"{prefix}.{key}" if prefix else str(key)
            out.extend(_flatten_json(child, child_prefix))
    elif isinstance(value, list):
        for child in value:
            out.extend(_flatten_json(child, prefix))
    elif value is not None:
        text = str(value).strip()
        if text:
            out.append(f"{prefix}: {text}" if prefix else text)
    return out


def load_text(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in {".txt", ".md"}:
        return path.read_text(encoding="utf-8-sig", errors="replace")
    if suffix == ".json":
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        return "\n".join(_flatten_json(data))
    if suffix == ".jsonl":
        lines: list[str] = []
        for raw in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
            raw = raw.strip()
            if raw:
                lines.extend(_flatten_json(json.loads(raw)))
        return "\n".join(lines)
    if suffix == ".csv":
        lines = []
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                parts = [f"{k}: {v}" for k, v in row.items() if v not in (None, "")]
                if parts:
                    lines.append(" | ".join(parts))
        return "\n".join(lines)
    if suffix == ".xml":
        root = ET.parse(path).getroot()
        return "\n".join(x.strip() for x in root.itertext() if x and x.strip())
    raise ValueError(f"暂不支持的文档类型: {path.suffix}")


def checksum_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def chunk_text(
    text: str,
    *,
    title: str = "",
    chunk_chars: int = RAG.chunk_chars,
    overlap_chars: int = RAG.chunk_overlap_chars,
) -> list[dict[str, Any]]:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    paragraphs = [re.sub(r"\s+", " ", part).strip() for part in re.split(r"\n\s*\n+", text)]
    paragraphs = [part for part in paragraphs if part]
    if not paragraphs and text.strip():
        paragraphs = [re.sub(r"\s+", " ", text).strip()]

    chunks: list[str] = []
    buf = ""
    for para in paragraphs:
        if len(para) > chunk_chars:
            # Preserve sentence boundaries when possible.
            pieces = [x.strip() for x in re.split(r"(?<=[。！？.!?；;])", para) if x.strip()]
        else:
            pieces = [para]
        for piece in pieces:
            if len(buf) + len(piece) + 1 <= chunk_chars:
                buf = f"{buf}\n{piece}".strip()
                continue
            if buf:
                chunks.append(buf)
                tail = buf[-overlap_chars:] if overlap_chars else ""
                buf = f"{tail}\n{piece}".strip()
            else:
                # Hard split pathological unpunctuated blocks.
                step = max(1, chunk_chars - overlap_chars)
                for start in range(0, len(piece), step):
                    chunks.append(piece[start:start + chunk_chars])
                buf = ""
    if buf:
        chunks.append(buf)

    return [
        {"title": title, "content": body, "metadata": {"char_count": len(body)}}
        for body in chunks if body.strip()
    ]
