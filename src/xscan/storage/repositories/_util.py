"""Shared helpers for repository row conversion."""
from __future__ import annotations

from typing import Any


def row_to_dict(row: Any) -> dict[str, Any]:
    """Convert a sqlite3.Row to a plain dict[str, Any]."""
    return {k: row[k] for k in row.keys()}  # noqa: SIM118 — sqlite3.Row requires .keys()
