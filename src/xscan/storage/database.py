"""
XScan Database
==============
Thin SQLite abstraction.

Design:
  - Database owns the connection and schema migrations.
  - Repositories use Database for their queries.
  - No ORM — plain SQL with named parameters.
  - Thread-safe via check_same_thread=False + an internal lock.
"""
from __future__ import annotations

import logging
import sqlite3
import threading
from pathlib import Path
from typing import Any

from xscan.errors import StorageError

logger = logging.getLogger(__name__)

_LOCK = threading.Lock()


class Database:
    """
    Manages a single SQLite connection for the XScan process.

    Usage::

        db = Database(path)
        db.connect()
        db.migrate()

        with db.cursor() as cur:
            cur.execute("SELECT ...", {...})
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._conn: sqlite3.Connection | None = None

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def connect(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._conn = sqlite3.connect(
                str(self.path),
                check_same_thread=False,
                detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            logger.debug("Database connected: %s", self.path)
        except sqlite3.Error as exc:
            raise StorageError(f"Cannot open database {self.path}: {exc}") from exc

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def _require_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise StorageError("Database not connected. Call connect() first.")
        return self._conn

    # ------------------------------------------------------------------
    # Cursor context manager
    # ------------------------------------------------------------------

    def cursor(self) -> CursorContext:
        return CursorContext(self._require_conn(), _LOCK)

    # ------------------------------------------------------------------
    # Migrations
    # ------------------------------------------------------------------

    def migrate(self) -> None:
        """Apply all pending schema migrations."""
        from xscan.storage.migrations import run_migrations
        run_migrations(self)

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def execute(self, sql: str, params: dict[str, Any] | tuple[Any, ...] = ()) -> None:
        with self.cursor() as cur:
            cur.execute(sql, params)

    def fetchall(self, sql: str, params: dict[str, Any] | tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with self.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchall()

    def fetchone(self, sql: str, params: dict[str, Any] | tuple[Any, ...] = ()) -> sqlite3.Row | None:
        with self.cursor() as cur:
            cur.execute(sql, params)
            result: sqlite3.Row | None = cur.fetchone()
            return result


class CursorContext:
    def __init__(self, conn: sqlite3.Connection, lock: threading.Lock) -> None:
        self._conn = conn
        self._lock = lock
        self._cur: sqlite3.Cursor | None = None

    def __enter__(self) -> sqlite3.Cursor:
        self._lock.acquire()
        self._cur = self._conn.cursor()
        return self._cur

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        try:
            if exc_type is None:
                self._conn.commit()
            else:
                self._conn.rollback()
        finally:
            if self._cur:
                self._cur.close()
            self._lock.release()


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_db_instance: Database | None = None


def get_db() -> Database:
    """Return the process-wide Database instance (auto-connects on first call)."""
    global _db_instance
    if _db_instance is None:
        from xscan.config import get_settings
        settings = get_settings()
        _db_instance = Database(settings.storage.db_path)
        _db_instance.connect()
        _db_instance.migrate()
    return _db_instance
