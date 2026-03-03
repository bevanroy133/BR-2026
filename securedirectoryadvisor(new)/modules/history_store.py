"""
history_store.py - SQLite-backed storage for scan history.

This module separates history persistence from config persistence so settings
remain lightweight JSON while scan artifacts live in a durable local database.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading

log = logging.getLogger(__name__)

HISTORY_DB_PATH = os.path.expanduser("~/.secure_file_advisor_history.db")
DEFAULT_MAX_HISTORY = 100


class HistoryStore:
    """Thread-safe local SQLite store for scan history entries."""

    def __init__(self, db_path: str = HISTORY_DB_PATH, max_entries: int = DEFAULT_MAX_HISTORY):
        self.db_path = db_path
        self.max_entries = max(1, int(max_entries))
        self._lock = threading.RLock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        # Open short-lived connections per operation for reliability across
        # multiple threads and app restarts.
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        db_dir = os.path.dirname(self.db_path) or "."
        try:
            os.makedirs(db_dir, exist_ok=True)
            with self._connect() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS scan_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scanned_at TEXT,
                        payload TEXT NOT NULL,
                        created_at TEXT NOT NULL DEFAULT (datetime('now'))
                    )
                    """
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_scan_history_scanned_at ON scan_history(scanned_at)"
                )
                conn.commit()
        except sqlite3.Error as exc:
            log.warning("Could not initialize history DB %s: %s", self.db_path, exc)

    def _prune_locked(self, conn: sqlite3.Connection):
        # Keep history size bounded to preserve previous app behavior and avoid
        # unbounded growth on low-storage systems.
        conn.execute(
            """
            DELETE FROM scan_history
            WHERE id NOT IN (
                SELECT id FROM scan_history
                ORDER BY id DESC
                LIMIT ?
            )
            """,
            (self.max_entries,),
        )

    def add_entry(self, entry: dict):
        if not isinstance(entry, dict):
            return
        try:
            payload = json.dumps(entry, ensure_ascii=False)
        except (TypeError, ValueError) as exc:
            log.warning("Could not serialize history entry: %s", exc)
            return

        scanned_at = str(entry.get("scanned_at", "")).strip() or None
        with self._lock:
            try:
                with self._connect() as conn:
                    conn.execute(
                        "INSERT INTO scan_history (scanned_at, payload) VALUES (?, ?)",
                        (scanned_at, payload),
                    )
                    self._prune_locked(conn)
                    conn.commit()
            except sqlite3.Error as exc:
                log.warning("Could not add history entry: %s", exc)

    def list_entries(self, limit: int | None = None) -> list[dict]:
        if limit is None:
            limit = self.max_entries
        try:
            cap = max(0, int(limit))
        except (TypeError, ValueError):
            cap = self.max_entries
        if cap <= 0:
            return []

        entries: list[dict] = []
        with self._lock:
            try:
                with self._connect() as conn:
                    rows = conn.execute(
                        """
                        SELECT payload
                        FROM scan_history
                        ORDER BY id DESC
                        LIMIT ?
                        """,
                        (cap,),
                    ).fetchall()
            except sqlite3.Error as exc:
                log.warning("Could not read history entries: %s", exc)
                return []

        for row in rows:
            try:
                payload = json.loads(row["payload"])
            except (json.JSONDecodeError, TypeError, KeyError):
                continue
            if isinstance(payload, dict):
                entries.append(payload)
        return entries

    def clear_entries(self):
        with self._lock:
            try:
                with self._connect() as conn:
                    conn.execute("DELETE FROM scan_history")
                    conn.commit()
            except sqlite3.Error as exc:
                log.warning("Could not clear history entries: %s", exc)

    def replace_entries(self, entries: list[dict]):
        if not isinstance(entries, list):
            self.clear_entries()
            return

        normalized = [entry for entry in entries if isinstance(entry, dict)]
        with self._lock:
            try:
                with self._connect() as conn:
                    conn.execute("DELETE FROM scan_history")
                    # Input is expected newest-first; insert oldest-first so
                    # descending IDs preserve the original order when read back.
                    for entry in reversed(normalized):
                        payload = json.dumps(entry, ensure_ascii=False)
                        scanned_at = str(entry.get("scanned_at", "")).strip() or None
                        conn.execute(
                            "INSERT INTO scan_history (scanned_at, payload) VALUES (?, ?)",
                            (scanned_at, payload),
                        )
                    self._prune_locked(conn)
                    conn.commit()
            except sqlite3.Error as exc:
                log.warning("Could not replace history entries: %s", exc)

    def migrate_legacy_entries(self, entries: list[dict]) -> int:
        """Migrate legacy JSON history only when DB is currently empty."""
        if not isinstance(entries, list) or not entries:
            return 0
        normalized = [entry for entry in entries if isinstance(entry, dict)]
        if not normalized:
            return 0

        with self._lock:
            try:
                with self._connect() as conn:
                    row = conn.execute("SELECT COUNT(1) AS count FROM scan_history").fetchone()
                    existing = int(row["count"]) if row else 0
                    if existing > 0:
                        return 0

                    inserted = 0
                    for entry in reversed(normalized):
                        payload = json.dumps(entry, ensure_ascii=False)
                        scanned_at = str(entry.get("scanned_at", "")).strip() or None
                        conn.execute(
                            "INSERT INTO scan_history (scanned_at, payload) VALUES (?, ?)",
                            (scanned_at, payload),
                        )
                        inserted += 1
                    self._prune_locked(conn)
                    conn.commit()
                    return inserted
            except sqlite3.Error as exc:
                log.warning("Could not migrate legacy scan history: %s", exc)
                return 0

