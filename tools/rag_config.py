"""Configuration for the lightweight MySQL + DeepSeek RAG backend.

No dotenv dependency is required.  Values are read from the process environment and, when
present, ``rag.env`` at the repository root.  Process environment variables take precedence.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

_SERVER_DIR = Path(__file__).resolve().parents[1]
_DEFAULT_ENV = _SERVER_DIR / "rag.env"


def _load_env_file(path: Path = _DEFAULT_ENV) -> None:
    if not path.exists():
        return
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            os.environ.setdefault(key, value)


_load_env_file()


def _env_int(name: str, default: int, *, minimum: int | None = None, maximum: int | None = None) -> int:
    raw = os.getenv(name)
    try:
        value = int(raw) if raw not in (None, "") else default
    except ValueError:
        value = default
    if minimum is not None:
        value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


def _env_float(name: str, default: float, *, minimum: float | None = None) -> float:
    raw = os.getenv(name)
    try:
        value = float(raw) if raw not in (None, "") else default
    except ValueError:
        value = default
    if minimum is not None:
        value = max(minimum, value)
    return value


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on", "enabled"}


@dataclass(frozen=True)
class MySQLSettings:
    host: str = os.getenv("MYSQL_HOST", "127.0.0.1")
    port: int = _env_int("MYSQL_PORT", 3306, minimum=1, maximum=65535)
    user: str = os.getenv("MYSQL_USER", "colorproxy")
    password: str = os.getenv("MYSQL_PASSWORD", "")
    database: str = os.getenv("MYSQL_DATABASE", "colorproxy_rag")
    pool_size: int = _env_int("MYSQL_POOL_SIZE", 4, minimum=1, maximum=16)
    connect_timeout: int = _env_int("MYSQL_CONNECT_TIMEOUT", 5, minimum=1, maximum=60)


@dataclass(frozen=True)
class DeepSeekSettings:
    api_key: str = os.getenv("DEEPSEEK_API_KEY", "")
    base_url: str = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com").rstrip("/")
    model: str = os.getenv("DEEPSEEK_MODEL", "deepseek-v4-flash")
    thinking: bool = _env_bool("DEEPSEEK_THINKING", False)
    max_tokens: int = _env_int("DEEPSEEK_MAX_TOKENS", 900, minimum=64, maximum=8192)
    timeout_seconds: float = _env_float("DEEPSEEK_TIMEOUT_SECONDS", 90.0, minimum=5.0)
    temperature: float = _env_float("DEEPSEEK_TEMPERATURE", 0.25, minimum=0.0)


@dataclass(frozen=True)
class RAGSettings:
    top_k: int = _env_int("RAG_TOP_K", 6, minimum=1, maximum=20)
    candidate_k: int = _env_int("RAG_CANDIDATE_K", 14, minimum=2, maximum=50)
    max_context_chars: int = _env_int("RAG_MAX_CONTEXT_CHARS", 10000, minimum=1000, maximum=50000)
    chunk_chars: int = _env_int("RAG_CHUNK_CHARS", 1100, minimum=300, maximum=4000)
    chunk_overlap_chars: int = _env_int("RAG_CHUNK_OVERLAP_CHARS", 140, minimum=0, maximum=800)


MYSQL = MySQLSettings()
DEEPSEEK = DeepSeekSettings()
RAG = RAGSettings()
