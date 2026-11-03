"""Persist a bounded digest cache so accepted authenticated frames cannot replay after restart."""

import sqlite3
import threading
from pathlib import Path


class PersistentFrameReplayCache:
    """Remember accepted frame digests across process restarts without storing payloads."""

    def __init__(self, path: str | Path, capacity: int) -> None:
        if capacity <= 0:
            raise ValueError("replay cache capacity must be positive")
        database_path = Path(path)
        database_path.parent.mkdir(parents=True, exist_ok=True)
        self._capacity = capacity
        self._lock = threading.Lock()
        self._connection = sqlite3.connect(
            database_path,
            timeout=5.0,
            check_same_thread=False,
        )
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS accepted_frames ("
            "fingerprint TEXT PRIMARY KEY, accepted_at TEXT NOT NULL DEFAULT "
            "CURRENT_TIMESTAMP)"
        )
        self._connection.commit()

    def record(self, fingerprint: str) -> bool:
        """Return false for a previously accepted frame; retain only the newest digests."""
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "INSERT OR IGNORE INTO accepted_frames (fingerprint) VALUES (?)",
                (fingerprint,),
            )
            if cursor.rowcount == 0:
                return False
            self._connection.execute(
                "DELETE FROM accepted_frames WHERE fingerprint IN ("
                "SELECT fingerprint FROM accepted_frames ORDER BY accepted_at DESC, "
                "rowid DESC LIMIT -1 OFFSET ?)",
                (self._capacity,),
            )
            return True

    def close(self) -> None:
        """Close the SQLite handle after receiver shutdown."""
        with self._lock:
            self._connection.close()
