"""MySQL-backed sparse retriever for the color-proxy RAG demo.

The schema uses MySQL's built-in CJK ngram FULLTEXT parser.  mysql-connector-python is imported
lazily so the rest of color-proxy can still start when only non-model demos are being used.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass
from typing import Any, Iterable

try:
    from rag_config import MYSQL, RAG, MySQLSettings
    from provider_policy import (
        ProviderPolicy, annotate_metadata, normalize_nid, privacy_level_from_metadata,
        sid_from_metadata,
    )
except ImportError:
    from tools.rag_config import MYSQL, RAG, MySQLSettings  # type: ignore
    from tools.provider_policy import (  # type: ignore
        ProviderPolicy, annotate_metadata, normalize_nid, privacy_level_from_metadata,
        sid_from_metadata,
    )


class RAGDatabaseError(RuntimeError):
    pass


@dataclass(frozen=True)
class RetrievedChunk:
    chunk_id: int
    document_id: int
    domain: str
    sid: str
    privacy_level: str
    title: str
    content: str
    source_name: str
    source_uri: str
    metadata: dict[str, Any]
    fulltext_score: float
    lexical_score: float
    score: float


def _require_connector():
    try:
        import mysql.connector  # type: ignore
        from mysql.connector import pooling  # type: ignore
    except ImportError as exc:
        raise RAGDatabaseError(
            "缺少 mysql-connector-python。请在仓库根目录执行: pip install mysql-connector-python"
        ) from exc
    return mysql.connector, pooling


def _ngrams(text: str, n: int = 2) -> set[str]:
    compact = re.sub(r"\s+", "", text.lower())
    if len(compact) < n:
        return {compact} if compact else set()
    return {compact[i:i + n] for i in range(len(compact) - n + 1)}


def _lexical_overlap(query: str, content: str) -> float:
    q = _ngrams(query)
    if not q:
        return 0.0
    c = _ngrams(content[:5000])
    return len(q & c) / len(q)


class MySQLRAGStore:
    def __init__(self, settings: MySQLSettings = MYSQL) -> None:
        self.settings = settings
        self._pool = None
        self._lock = threading.Lock()

    def _ensure_pool(self):
        if self._pool is not None:
            return self._pool
        with self._lock:
            if self._pool is not None:
                return self._pool
            connector, pooling = _require_connector()
            try:
                self._pool = pooling.MySQLConnectionPool(
                    pool_name="colorproxy_rag",
                    pool_size=self.settings.pool_size,
                    pool_reset_session=True,
                    host=self.settings.host,
                    port=self.settings.port,
                    user=self.settings.user,
                    password=self.settings.password,
                    database=self.settings.database,
                    charset="utf8mb4",
                    use_unicode=True,
                    connection_timeout=self.settings.connect_timeout,
                    autocommit=False,
                )
            except connector.Error as exc:
                raise RAGDatabaseError(f"连接 MySQL 失败: {exc}") from exc
        return self._pool

    def connection(self):
        try:
            return self._ensure_pool().get_connection()
        except Exception as exc:
            if isinstance(exc, RAGDatabaseError):
                raise
            raise RAGDatabaseError(f"获取 MySQL 连接失败: {exc}") from exc

    def ping(self) -> dict[str, Any]:
        conn = self.connection()
        try:
            cur = conn.cursor(dictionary=True)
            cur.execute("SELECT VERSION() AS version, @@ngram_token_size AS ngram_token_size")
            row = cur.fetchone() or {}
            cur.execute("SELECT COUNT(*) AS documents FROM rag_documents")
            docs = int((cur.fetchone() or {}).get("documents", 0))
            cur.execute("SELECT COUNT(*) AS chunks FROM rag_chunks")
            chunks = int((cur.fetchone() or {}).get("chunks", 0))
            cur.execute("SELECT domain, COUNT(*) AS chunks FROM rag_chunks GROUP BY domain ORDER BY domain")
            chunks_by_domain = {str(r["domain"]): int(r["chunks"]) for r in cur.fetchall()}
            cur.execute("SELECT domain, COUNT(*) AS documents FROM rag_documents GROUP BY domain ORDER BY domain")
            documents_by_domain = {str(r["domain"]): int(r["documents"]) for r in cur.fetchall()}
            cur.execute(
                """
                SELECT domain,
                       JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.privacy.privacy_class')) AS privacy_class,
                       COUNT(*) AS chunks
                FROM rag_chunks
                WHERE JSON_EXTRACT(metadata, '$.privacy') IS NOT NULL
                GROUP BY domain, privacy_class
                ORDER BY domain, privacy_class
                """
            )
            privacy_chunks_by_domain: dict[str, dict[str, int]] = {}
            privacy_chunks = 0
            for r in cur.fetchall():
                domain = str(r.get("domain") or "")
                level = str(r.get("privacy_class") or "UNKNOWN")
                count = int(r.get("chunks") or 0)
                privacy_chunks_by_domain.setdefault(domain, {})[level] = count
                privacy_chunks += count

            cur.execute(
                """
                SELECT domain,
                       COALESCE(
                         NULLIF(JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.sid')), ''),
                         CASE
                           WHEN domain='medical' AND JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.privacy.privacy_class')) LIKE 'P3%' THEN 'SID_MED_PRIVATE_P3'
                           WHEN domain='medical' AND JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.privacy.privacy_class')) LIKE 'P2%' THEN 'SID_MED_PRIVATE_P2'
                           WHEN domain='education' AND JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.privacy.privacy_class')) LIKE 'P3%' THEN 'SID_EDU_PRIVATE_P3'
                           WHEN domain='education' AND JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.privacy.privacy_class')) LIKE 'P2%' THEN 'SID_EDU_PRIVATE_P2'
                           WHEN domain='medical' THEN 'SID_MED_PUBLIC'
                           WHEN domain='education' THEN 'SID_EDU_PUBLIC'
                           ELSE CONCAT('SID_', UPPER(domain), '_P0')
                         END
                       ) AS logical_sid,
                       COUNT(*) AS chunks
                FROM rag_chunks
                GROUP BY domain, logical_sid
                ORDER BY domain, logical_sid
                """
            )
            chunks_by_sid: dict[str, dict[str, int]] = {}
            for r in cur.fetchall():
                chunks_by_sid.setdefault(str(r["domain"]), {})[str(r["logical_sid"])] = int(r["chunks"])
            return {
                "ok": True,
                "documents": docs,
                "chunks": chunks,
                "documents_by_domain": documents_by_domain,
                "chunks_by_domain": chunks_by_domain,
                "privacy_chunks": privacy_chunks,
                "privacy_chunks_by_domain": privacy_chunks_by_domain,
                "chunks_by_sid": chunks_by_sid,
                **row,
            }
        except Exception as exc:
            raise RAGDatabaseError(f"MySQL RAG 状态检查失败: {exc}") from exc
        finally:
            conn.close()

    def ensure_schema(self) -> None:
        conn = self.connection()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS rag_documents (
                    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                    source_key CHAR(64) NOT NULL,
                    domain VARCHAR(32) NOT NULL,
                    source_name VARCHAR(255) NOT NULL,
                    source_uri VARCHAR(1024) NOT NULL,
                    checksum CHAR(64) NOT NULL,
                    metadata JSON NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    PRIMARY KEY (id),
                    UNIQUE KEY uk_rag_documents_source_key (source_key),
                    KEY idx_rag_documents_domain (domain)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS rag_chunks (
                    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                    document_id BIGINT UNSIGNED NOT NULL,
                    domain VARCHAR(32) NOT NULL,
                    chunk_index INT UNSIGNED NOT NULL,
                    title VARCHAR(512) NOT NULL DEFAULT '',
                    content MEDIUMTEXT NOT NULL,
                    metadata JSON NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (id),
                    UNIQUE KEY uk_rag_chunk_order (document_id, chunk_index),
                    KEY idx_rag_chunks_domain (domain),
                    CONSTRAINT fk_rag_chunks_document
                        FOREIGN KEY (document_id) REFERENCES rag_documents(id)
                        ON DELETE CASCADE,
                    FULLTEXT KEY ft_rag_chunks (title, content) WITH PARSER ngram
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
                """
            )
            conn.commit()
        except Exception as exc:
            conn.rollback()
            raise RAGDatabaseError(
                "创建 RAG 表失败。请确认使用 MySQL 8.x、数据库已创建且账号有 DDL 权限。"
                f" 原始错误: {exc}"
            ) from exc
        finally:
            conn.close()

    def upsert_document(
        self,
        *,
        domain: str,
        source_name: str,
        source_uri: str,
        checksum: str,
        chunks: Iterable[dict[str, Any]],
        metadata: dict[str, Any] | None = None,
    ) -> tuple[int, int]:
        source_key = hashlib.sha256(f"{domain}\0{source_uri}".encode("utf-8")).hexdigest()
        chunk_list = list(chunks)
        conn = self.connection()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO rag_documents
                    (source_key, domain, source_name, source_uri, checksum, metadata)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    id=LAST_INSERT_ID(id), source_name=VALUES(source_name), checksum=VALUES(checksum),
                    metadata=VALUES(metadata), updated_at=CURRENT_TIMESTAMP
                """,
                (source_key, domain, source_name, source_uri, checksum, json.dumps(metadata or {}, ensure_ascii=False)),
            )
            document_id = int(cur.lastrowid)
            cur.execute("DELETE FROM rag_chunks WHERE document_id=%s", (document_id,))
            rows = []
            for idx, chunk in enumerate(chunk_list):
                chunk_meta = annotate_metadata(domain, chunk.get("metadata", {}))
                rows.append((
                    document_id,
                    domain,
                    idx,
                    str(chunk.get("title", ""))[:512],
                    str(chunk.get("content", "")),
                    json.dumps(chunk_meta, ensure_ascii=False),
                ))
            if rows:
                cur.executemany(
                    """
                    INSERT INTO rag_chunks
                        (document_id, domain, chunk_index, title, content, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    rows,
                )
            conn.commit()
            return document_id, len(rows)
        except Exception as exc:
            conn.rollback()
            raise RAGDatabaseError(f"写入 RAG 文档失败: {exc}") from exc
        finally:
            conn.close()

    def delete_domain(self, domain: str) -> int:
        conn = self.connection()
        try:
            cur = conn.cursor()
            cur.execute("DELETE FROM rag_documents WHERE domain=%s", (domain,))
            count = int(cur.rowcount)
            conn.commit()
            return count
        except Exception as exc:
            conn.rollback()
            raise RAGDatabaseError(f"删除领域知识失败: {exc}") from exc
        finally:
            conn.close()

    def search(
        self,
        domain: str,
        query: str,
        *,
        top_k: int | None = None,
        allowed_sids: set[str] | frozenset[str] | None = None,
        requester_nid: str | int | None = None,
        requester_roles: set[str] | frozenset[str] | tuple[str, ...] = (),
    ) -> list[RetrievedChunk]:
        """Search one domain with the minimal Provider-side P2 retrieval gate.

        ``allowed_sids`` is applied inside the MySQL query.  Unauthorized SID groups therefore
        do not become RAG candidates and cannot enter the LLM context.  Optional per-chunk
        ``allowed_user`` / ``allowed_role`` metadata is checked after row decoding and before a
        ``RetrievedChunk`` is returned.

        The SQL expressions deliberately infer SID/privacy from legacy privacy metadata when a
        database was seeded by the previous 10,500-row build.  Re-running ``seed`` is recommended
        because new imports persist explicit ``sid`` and ``privacy_level`` metadata, but it is not
        required for this filter to work.
        """
        query = query.strip()
        if not query:
            return []
        wanted = top_k or RAG.top_k
        candidate_k = max(wanted, RAG.candidate_k)
        query_limit = min(max(candidate_k * 3, wanted), 100)
        requester = normalize_nid(requester_nid)
        roles = frozenset(str(x) for x in requester_roles)

        sid_expr = """
            COALESCE(
                NULLIF(JSON_UNQUOTE(JSON_EXTRACT(c.metadata, '$.sid')), ''),
                CASE
                    WHEN c.domain='medical' AND JSON_UNQUOTE(JSON_EXTRACT(c.metadata, '$.privacy.privacy_class')) LIKE 'P3%'
                        THEN 'SID_MED_PRIVATE_P3'
                    WHEN c.domain='medical' AND JSON_UNQUOTE(JSON_EXTRACT(c.metadata, '$.privacy.privacy_class')) LIKE 'P2%'
                        THEN 'SID_MED_PRIVATE_P2'
                    WHEN c.domain='education' AND JSON_UNQUOTE(JSON_EXTRACT(c.metadata, '$.privacy.privacy_class')) LIKE 'P3%'
                        THEN 'SID_EDU_PRIVATE_P3'
                    WHEN c.domain='education' AND JSON_UNQUOTE(JSON_EXTRACT(c.metadata, '$.privacy.privacy_class')) LIKE 'P2%'
                        THEN 'SID_EDU_PRIVATE_P2'
                    WHEN c.domain='medical' THEN 'SID_MED_PUBLIC'
                    WHEN c.domain='education' THEN 'SID_EDU_PUBLIC'
                    ELSE CONCAT('SID_', UPPER(c.domain), '_P0')
                END
            )
        """
        privacy_expr = """
            COALESCE(
                NULLIF(JSON_UNQUOTE(JSON_EXTRACT(c.metadata, '$.privacy_level')), ''),
                CASE
                    WHEN JSON_UNQUOTE(JSON_EXTRACT(c.metadata, '$.privacy.privacy_class')) LIKE 'P3%' THEN 'P3'
                    WHEN JSON_UNQUOTE(JSON_EXTRACT(c.metadata, '$.privacy.privacy_class')) LIKE 'P2%' THEN 'P2'
                    ELSE 'P0'
                END
            )
        """

        sid_values: list[str] | None
        if allowed_sids is None:
            sid_values = None
            sid_clause = ""
        else:
            sid_values = sorted({str(x) for x in allowed_sids if str(x)})
            if not sid_values:
                return []
            placeholders = ",".join(["%s"] * len(sid_values))
            sid_clause = f" AND ({sid_expr}) IN ({placeholders})"

        conn = self.connection()
        try:
            cur = conn.cursor(dictionary=True)
            sql = f"""
                SELECT
                    c.id AS chunk_id, c.document_id, c.domain, c.title, c.content,
                    c.metadata AS chunk_metadata,
                    d.source_name, d.source_uri,
                    ({sid_expr}) AS logical_sid,
                    ({privacy_expr}) AS logical_privacy_level,
                    MATCH(c.title, c.content) AGAINST (%s IN NATURAL LANGUAGE MODE) AS ft_score
                FROM rag_chunks c
                JOIN rag_documents d ON d.id=c.document_id
                WHERE c.domain=%s
                  AND MATCH(c.title, c.content) AGAINST (%s IN NATURAL LANGUAGE MODE)
                  {sid_clause}
                ORDER BY ft_score DESC, c.id ASC
                LIMIT %s
            """
            params: list[Any] = [query, domain, query]
            if sid_values is not None:
                params.extend(sid_values)
            params.append(query_limit)
            cur.execute(sql, tuple(params))
            rows = list(cur.fetchall())

            # For very short queries, a bigram index may return nothing.  The same SID gate is
            # kept on the bounded LIKE fallback.
            if not rows:
                needles = [x for x in _ngrams(query) if x][:4]
                if needles:
                    where = " OR ".join(["c.content LIKE %s" for _ in needles])
                    fallback_sql = f"""
                        SELECT c.id AS chunk_id, c.document_id, c.domain, c.title, c.content,
                               c.metadata AS chunk_metadata, d.source_name, d.source_uri,
                               ({sid_expr}) AS logical_sid,
                               ({privacy_expr}) AS logical_privacy_level,
                               0.0 AS ft_score
                        FROM rag_chunks c JOIN rag_documents d ON d.id=c.document_id
                        WHERE c.domain=%s AND ({where}) {sid_clause}
                        ORDER BY c.id ASC LIMIT %s
                    """
                    fallback_params: list[Any] = [domain, *[f"%{x}%" for x in needles]]
                    if sid_values is not None:
                        fallback_params.extend(sid_values)
                    fallback_params.append(query_limit)
                    cur.execute(fallback_sql, tuple(fallback_params))
                    rows = list(cur.fetchall())
        except Exception as exc:
            raise RAGDatabaseError(f"MySQL FULLTEXT 检索失败: {exc}") from exc
        finally:
            conn.close()

        if not rows:
            return []
        max_ft = max(float(row.get("ft_score") or 0.0) for row in rows) or 1.0
        ranked: list[RetrievedChunk] = []
        for row in rows:
            raw_meta = row.get("chunk_metadata")
            if isinstance(raw_meta, str):
                try:
                    meta = json.loads(raw_meta)
                except ValueError:
                    meta = {}
            else:
                meta = raw_meta if isinstance(raw_meta, dict) else {}
            meta = annotate_metadata(str(row.get("domain") or domain), meta)

            sid = str(row.get("logical_sid") or sid_from_metadata(domain, meta))
            privacy_level = str(
                row.get("logical_privacy_level") or privacy_level_from_metadata(meta)
            ).upper()
            meta["sid"] = sid
            meta["privacy_level"] = privacy_level

            if allowed_sids is not None and sid not in allowed_sids:
                continue
            if not ProviderPolicy.chunk_acl_allows(
                meta, requester_nid=requester, requester_roles=roles
            ):
                continue

            ft = float(row.get("ft_score") or 0.0)
            lexical = _lexical_overlap(query, f"{row.get('title', '')}\n{row.get('content', '')}")
            normalized_ft = ft / max_ft if ft > 0 else 0.0
            score = normalized_ft * 0.78 + lexical * 0.22
            ranked.append(RetrievedChunk(
                chunk_id=int(row["chunk_id"]),
                document_id=int(row["document_id"]),
                domain=str(row["domain"]),
                sid=sid,
                privacy_level=privacy_level,
                title=str(row.get("title") or ""),
                content=str(row.get("content") or ""),
                source_name=str(row.get("source_name") or ""),
                source_uri=str(row.get("source_uri") or ""),
                metadata=meta,
                fulltext_score=ft,
                lexical_score=lexical,
                score=score,
            ))
        ranked.sort(key=lambda item: (-item.score, -item.fulltext_score, item.chunk_id))
        return ranked[:wanted]

