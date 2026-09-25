from __future__ import annotations

import json
import sqlite3
from typing import Any

from app.core.errors import ConflictError
from app.repositories.base import row_dict, rows_dict


SENSITIVE_KEYS = {"password", "password_hash", "token", "token_digest", "secret", "authorization"}


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: redact(item) for key, item in value.items() if key.casefold() not in SENSITIVE_KEYS}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


class AuditRepository:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def append(
        self,
        *,
        actor_user_id: int | None,
        actor_name: str,
        action: str,
        resource_type: str,
        resource_id: str | int | None,
        outcome: str,
        before: dict | None,
        after: dict | None,
        metadata: dict | None,
        correlation_id: str | None,
        created_at: str,
        seq: int,
        prev_digest: str,
        digest: str,
    ) -> int:
        cursor = self.connection.execute(
            "INSERT INTO audit_events(actor_user_id,actor_name,action,resource_type,resource_id,outcome,"
            "before_json,after_json,metadata_json,correlation_id,created_at,seq,prev_digest,digest) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                actor_user_id,
                actor_name,
                action,
                resource_type,
                str(resource_id) if resource_id is not None else None,
                outcome,
                json.dumps(redact(before), ensure_ascii=False, sort_keys=True) if before is not None else None,
                json.dumps(redact(after), ensure_ascii=False, sort_keys=True) if after is not None else None,
                json.dumps(redact(metadata or {}), ensure_ascii=False, sort_keys=True),
                correlation_id,
                created_at,
                seq,
                prev_digest,
                digest,
            ),
        )
        return int(cursor.lastrowid)

    def list(
        self,
        *,
        actor_user_id: int | None,
        resource_type: str | None,
        action: str | None,
        outcome: str | None,
        limit: int,
        offset: int,
    ) -> list[dict]:
        conditions: list[str] = []
        params: list[Any] = []
        for column, value in (
            ("actor_user_id", actor_user_id),
            ("resource_type", resource_type),
            ("action", action),
            ("outcome", outcome),
        ):
            if value is not None:
                conditions.append(f"{column}=?")
                params.append(value)
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        params.extend([limit, offset])
        return rows_dict(self.connection.execute(
            "SELECT * FROM audit_events" + where + " ORDER BY id DESC LIMIT ? OFFSET ?",
            tuple(params),
        ).fetchall())

    # ---- 链状态（单行顺序器，保证并发写入得到唯一顺序） ----

    def chain_state(self) -> dict | None:
        return row_dict(self.connection.execute("SELECT * FROM audit_chain_state WHERE id=1").fetchone())

    def insert_chain_state(self, *, last_seq: int, head_digest: str, updated_at: str) -> None:
        self.connection.execute(
            "INSERT INTO audit_chain_state(id,last_seq,head_digest,updated_at) VALUES(1,?,?,?)",
            (last_seq, head_digest, updated_at),
        )

    def advance_chain_state(self, *, expected_last_seq: int, last_seq: int, head_digest: str, updated_at: str) -> None:
        cursor = self.connection.execute(
            "UPDATE audit_chain_state SET last_seq=?,head_digest=?,updated_at=? WHERE id=1 AND last_seq=?",
            (last_seq, head_digest, updated_at, expected_last_seq),
        )
        if cursor.rowcount != 1:
            raise ConflictError("审计链顺序器冲突，请重试")

    # ---- 历史存量封存 ----

    def legacy_events(self) -> list[dict]:
        return rows_dict(self.connection.execute("SELECT * FROM audit_events WHERE seq IS NULL ORDER BY id").fetchall())

    def count_legacy_events(self) -> int:
        return int(self.connection.execute("SELECT COUNT(*) FROM audit_events WHERE seq IS NULL").fetchone()[0])

    def assign_chain_fields(self, event_id: int, *, seq: int, prev_digest: str, digest: str) -> None:
        self.connection.execute(
            "UPDATE audit_events SET seq=?,prev_digest=?,digest=? WHERE id=?",
            (seq, prev_digest, digest, event_id),
        )

    # ---- 检查点 ----

    def insert_checkpoint(
        self,
        *,
        seq_start: int,
        seq_end: int,
        event_count: int,
        chain_head_digest: str,
        prev_checkpoint_digest: str,
        digest: str,
        created_at: str,
    ) -> int:
        cursor = self.connection.execute(
            "INSERT INTO audit_checkpoints(seq_start,seq_end,event_count,chain_head_digest,prev_checkpoint_digest,digest,created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (seq_start, seq_end, event_count, chain_head_digest, prev_checkpoint_digest, digest, created_at),
        )
        return int(cursor.lastrowid)

    def last_checkpoint(self) -> dict | None:
        return row_dict(self.connection.execute("SELECT * FROM audit_checkpoints ORDER BY seq_end DESC LIMIT 1").fetchone())

    def checkpoints(self) -> list[dict]:
        return rows_dict(self.connection.execute("SELECT * FROM audit_checkpoints ORDER BY seq_end").fetchall())

    def count_checkpoints(self) -> int:
        return int(self.connection.execute("SELECT COUNT(*) FROM audit_checkpoints").fetchone()[0])

    # ---- 校验读取 ----

    def events_range(self, from_seq: int, to_seq: int) -> list[dict]:
        return rows_dict(self.connection.execute(
            "SELECT * FROM audit_events WHERE seq BETWEEN ? AND ? ORDER BY seq",
            (from_seq, to_seq),
        ).fetchall())

    def event_at_seq(self, seq: int) -> dict | None:
        return row_dict(self.connection.execute("SELECT * FROM audit_events WHERE seq=?", (seq,)).fetchone())

    # ---- 截断锚点（保留策略清理后，链条从锚点继续验证） ----

    def latest_truncation(self) -> dict | None:
        return row_dict(self.connection.execute("SELECT * FROM audit_chain_truncations ORDER BY seq_through DESC LIMIT 1").fetchone())

    def insert_truncation(self, *, seq_through: int, head_digest: str, deleted_count: int, created_at: str) -> None:
        self.connection.execute(
            "INSERT INTO audit_chain_truncations(seq_through,head_digest,deleted_count,created_at) VALUES(?,?,?,?)",
            (seq_through, head_digest, deleted_count, created_at),
        )

    # ---- 增量校验进度（失败与重启后可继续） ----

    def verify_state(self) -> dict | None:
        return row_dict(self.connection.execute("SELECT * FROM audit_verify_state WHERE id=1").fetchone())

    def insert_verify_state(self, *, last_verified_seq: int, last_verified_digest: str | None, updated_at: str) -> None:
        self.connection.execute(
            "INSERT INTO audit_verify_state(id,last_verified_seq,last_verified_digest,last_run_at,last_status) VALUES(1,?,?,?,'never')",
            (last_verified_seq, last_verified_digest, updated_at),
        )

    def update_verify_state(
        self,
        *,
        last_verified_seq: int,
        last_verified_digest: str | None,
        last_run_at: str,
        last_status: str,
        failure_json: str | None,
        completed: bool,
    ) -> None:
        self.connection.execute(
            "UPDATE audit_verify_state SET last_verified_seq=?,last_verified_digest=?,last_run_at=?,last_status=?,"
            "failure_json=?,runs_completed=runs_completed+? WHERE id=1",
            (last_verified_seq, last_verified_digest, last_run_at, last_status, failure_json, 1 if completed else 0),
        )
