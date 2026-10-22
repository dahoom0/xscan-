"""
XScan Database Migrations
=========================
Version-tracked, append-only migration runner.

Migrations are plain SQL strings keyed by integer version.
The runner applies only migrations whose version > current schema version.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from xscan.errors import MigrationError

if TYPE_CHECKING:
    from xscan.storage.database import Database

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Migration definitions
# ---------------------------------------------------------------------------
# Format: {version: (description, sql_statement_or_list)}
# Append new entries at the end — never edit existing ones.

MIGRATIONS: dict[int, tuple[str, str | list[str]]] = {
    1: (
        "initial schema",
        [
            """
            CREATE TABLE IF NOT EXISTS schema_version (
                version     INTEGER PRIMARY KEY,
                description TEXT    NOT NULL,
                applied_at  TEXT    NOT NULL DEFAULT (datetime('now'))
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS scans (
                id            TEXT PRIMARY KEY,
                target_url    TEXT NOT NULL,
                target_host   TEXT NOT NULL,
                profile       TEXT NOT NULL DEFAULT 'balanced',
                workflow_name TEXT NOT NULL DEFAULT 'xss-balanced',
                status        TEXT NOT NULL DEFAULT 'pending',
                no_llm        INTEGER NOT NULL DEFAULT 0,
                research_on   INTEGER NOT NULL DEFAULT 0,
                auth_session  TEXT,
                project       TEXT,
                error         TEXT,
                created_at    TEXT NOT NULL,
                started_at    TEXT,
                finished_at   TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS workflow_runs (
                id               TEXT PRIMARY KEY,
                scan_id          TEXT NOT NULL REFERENCES scans(id),
                workflow_name    TEXT NOT NULL,
                workflow_version TEXT NOT NULL DEFAULT '1.0',
                status           TEXT NOT NULL DEFAULT 'pending',
                started_at       TEXT,
                finished_at      TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS node_results (
                id            TEXT PRIMARY KEY,
                run_id        TEXT NOT NULL REFERENCES workflow_runs(id),
                node_id       TEXT NOT NULL,
                status        TEXT NOT NULL DEFAULT 'pending',
                output_json   TEXT NOT NULL DEFAULT '{}',
                error         TEXT,
                metrics_json  TEXT NOT NULL DEFAULT '{}',
                started_at    TEXT,
                finished_at   TEXT,
                UNIQUE(run_id, node_id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS evidence_nodes (
                id           TEXT PRIMARY KEY,
                scan_id      TEXT NOT NULL REFERENCES scans(id),
                dag_node_id  TEXT NOT NULL DEFAULT '',
                type         TEXT NOT NULL,
                url          TEXT NOT NULL DEFAULT '',
                summary      TEXT NOT NULL DEFAULT '',
                data_json    TEXT NOT NULL DEFAULT '{}',
                parent_ids   TEXT NOT NULL DEFAULT '[]',
                created_at   TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS evidence_edges (
                id       TEXT PRIMARY KEY,
                from_id  TEXT NOT NULL REFERENCES evidence_nodes(id),
                to_id    TEXT NOT NULL REFERENCES evidence_nodes(id),
                label    TEXT NOT NULL DEFAULT ''
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS artifacts (
                id            TEXT PRIMARY KEY,
                evidence_id   TEXT NOT NULL REFERENCES evidence_nodes(id),
                filename      TEXT NOT NULL,
                mime_type     TEXT NOT NULL DEFAULT 'application/octet-stream',
                size_bytes    INTEGER NOT NULL DEFAULT 0,
                storage_path  TEXT NOT NULL DEFAULT '',
                created_at    TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS findings (
                id            TEXT PRIMARY KEY,
                scan_id       TEXT NOT NULL REFERENCES scans(id),
                type          TEXT NOT NULL,
                severity      TEXT NOT NULL,
                status        TEXT NOT NULL DEFAULT 'unconfirmed',
                url           TEXT NOT NULL,
                parameter     TEXT NOT NULL DEFAULT '',
                payload       TEXT NOT NULL DEFAULT '',
                description   TEXT NOT NULL DEFAULT '',
                remediation   TEXT NOT NULL DEFAULT '',
                llm_reasoning TEXT NOT NULL DEFAULT '',
                evidence_ids  TEXT NOT NULL DEFAULT '[]',
                created_at    TEXT NOT NULL,
                confirmed_at  TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id         TEXT PRIMARY KEY,
                scan_id    TEXT,
                event_type TEXT NOT NULL,
                payload    TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """,
        ],
    ),
}


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_migrations(db: Database) -> None:
    """Apply all pending migrations in order."""
    current = _get_version(db)
    pending = {v: m for v, m in MIGRATIONS.items() if v > current}

    if not pending:
        logger.debug("Database schema up to date (version %d)", current)
        return

    for version in sorted(pending):
        description, sql = pending[version]
        logger.info("Applying migration %d: %s", version, description)
        statements = [sql] if isinstance(sql, str) else sql
        try:
            with db.cursor() as cur:
                for stmt in statements:
                    cur.execute(stmt.strip())
                cur.execute(
                    "INSERT OR REPLACE INTO schema_version (version, description) VALUES (?, ?)",
                    (version, description),
                )
        except Exception as exc:
            raise MigrationError(
                f"Migration {version} ({description}) failed: {exc}"
            ) from exc

    logger.info("Migrations complete. Schema now at version %d", max(pending))


def _get_version(db: Database) -> int:
    """Return the current schema version, or 0 if no version table exists."""
    try:
        row = db.fetchone(
            "SELECT MAX(version) as v FROM schema_version"
        )
        return int(row["v"]) if row and row["v"] is not None else 0
    except Exception:
        return 0
