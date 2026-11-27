"""SQLite WAL Repository Adapter for Community Votes (100% parameterized SQL)."""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

from radar_core.domain.models import CommunityTally, VoteCommand, VoteDirection
from radar_core.domain.policies import CommunityQuorumPolicy


class SqliteVoteRepository:
    """Thread-safe Repository Pattern implementation backed by SQLite in WAL mode."""

    MAX_STORED_VOTES = 50_000

    def __init__(self, db_path: str | Path = "cache/community_votes.db") -> None:
        self._db_path = Path(db_path)
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._db_path), timeout=5.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA temp_store=MEMORY")
        return conn

    def _init_schema(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS community_votes (
                        target_key TEXT NOT NULL,
                        voter_hash TEXT NOT NULL,
                        subnet_hash TEXT NOT NULL,
                        vote TEXT NOT NULL CHECK(vote IN ('up', 'down')),
                        reason_tag TEXT NOT NULL,
                        updated_at INTEGER NOT NULL,
                        PRIMARY KEY (target_key, voter_hash)
                    )
                    """
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_votes_target_subnet ON community_votes(target_key, subnet_hash)"
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_votes_updated ON community_votes(updated_at)"
                )
            finally:
                conn.close()

    def upsert_vote(self, command: VoteCommand) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    """
                    INSERT INTO community_votes (target_key, voter_hash, subnet_hash, vote, reason_tag, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(target_key, voter_hash) DO UPDATE SET
                        subnet_hash = excluded.subnet_hash,
                        vote = excluded.vote,
                        reason_tag = excluded.reason_tag,
                        updated_at = excluded.updated_at
                    """,
                    (
                        command.target_key,
                        command.voter_hash,
                        command.subnet_hash,
                        command.vote.value,
                        command.reason_tag.value,
                        command.created_at,
                    ),
                )
                total_rows = conn.execute("SELECT COUNT(*) FROM community_votes").fetchone()[0]
                if total_rows > self.MAX_STORED_VOTES:
                    excess = total_rows - self.MAX_STORED_VOTES + 500
                    conn.execute(
                        """
                        DELETE FROM community_votes
                        WHERE rowid IN (
                            SELECT rowid FROM community_votes ORDER BY updated_at ASC LIMIT ?
                        )
                        """,
                        (excess,),
                    )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()

    def has_voter_voted(self, target_key: str, voter_hash: str) -> bool:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT 1 FROM community_votes WHERE target_key = ? AND voter_hash = ? LIMIT 1",
                (target_key, voter_hash),
            ).fetchone()
            return row is not None
        finally:
            conn.close()

    def count_distinct_voters_in_subnet(self, target_key: str, subnet_hash: str) -> int:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT COUNT(DISTINCT voter_hash) FROM community_votes WHERE target_key = ? AND subnet_hash = ?",
                (target_key, subnet_hash),
            ).fetchone()
            return int(row[0]) if row else 0
        finally:
            conn.close()

    def get_tally(self, target_key: str) -> CommunityTally:
        return self.get_tallies_bulk([target_key]).get(
            target_key, CommunityQuorumPolicy.build_tally(target_key, 0, 0, 0, {})
        )

    def get_tallies_bulk(self, target_keys: list[str]) -> dict[str, CommunityTally]:
        unique_keys = list(dict.fromkeys(k for k in target_keys if k))
        if not unique_keys:
            return {}
        placeholders = ",".join("?" for _ in unique_keys)
        conn = self._connect()
        try:
            agg_rows = conn.execute(
                f"""
                SELECT
                    target_key,
                    SUM(CASE WHEN vote = 'up' THEN 1 ELSE 0 END) AS up_cnt,
                    SUM(CASE WHEN vote = 'down' THEN 1 ELSE 0 END) AS down_cnt,
                    COUNT(DISTINCT subnet_hash) AS subnet_cnt
                FROM community_votes
                WHERE target_key IN ({placeholders})
                GROUP BY target_key
                """,
                tuple(unique_keys),
            ).fetchall()

            reason_rows = conn.execute(
                f"""
                SELECT target_key, reason_tag, COUNT(*)
                FROM community_votes
                WHERE target_key IN ({placeholders})
                GROUP BY target_key, reason_tag
                """,
                tuple(unique_keys),
            ).fetchall()
        finally:
            conn.close()

        reasons_by_key: dict[str, dict[str, int]] = {k: {} for k in unique_keys}
        for t_key, r_tag, cnt in reason_rows:
            reasons_by_key.setdefault(t_key, {})[str(r_tag)] = int(cnt)

        result: dict[str, CommunityTally] = {}
        for t_key, up_cnt, down_cnt, subnet_cnt in agg_rows:
            result[str(t_key)] = CommunityQuorumPolicy.build_tally(
                str(t_key),
                int(up_cnt or 0),
                int(down_cnt or 0),
                int(subnet_cnt or 0),
                reasons_by_key.get(str(t_key), {}),
            )
        for k in unique_keys:
            if k not in result:
                result[k] = CommunityQuorumPolicy.build_tally(k, 0, 0, 0, {})
        return result

    def get_voter_votes(self, voter_hash: str, target_keys: list[str]) -> dict[str, dict[str, str]]:
        unique_keys = list(dict.fromkeys(k for k in target_keys if k))
        if not voter_hash or not unique_keys:
            return {}
        placeholders = ",".join("?" for _ in unique_keys)
        conn = self._connect()
        try:
            rows = conn.execute(
                f"""
                SELECT target_key, vote, reason_tag
                FROM community_votes
                WHERE voter_hash = ? AND target_key IN ({placeholders})
                """,
                (voter_hash, *unique_keys),
            ).fetchall()
            return {
                str(t_key): {"vote": str(vote), "tag": str(tag)}
                for t_key, vote, tag in rows
                if vote in {VoteDirection.UP.value, VoteDirection.DOWN.value}
            }
        finally:
            conn.close()
