from __future__ import annotations

import json
import sqlite3
from typing import Any

from app.core.audit_chain import GENESIS_DIGEST, event_digest
from app.core.errors import ConflictError
from app.repositories.audit_chain import insert_checkpoint
from app.repositories.base import rows_dict


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
        checkpoint_size: int,
    ) -> int:
        before_json = json.dumps(redact(before), ensure_ascii=False, sort_keys=True) if before is not None else None
        after_json = json.dumps(redact(after), ensure_ascii=False, sort_keys=True) if after is not None else None
        metadata_json = json.dumps(redact(metadata or {}), ensure_ascii=False, sort_keys=True)
        resource_id_text = str(resource_id) if resource_id is not None else None

        def write() -> int:
            state = self.connection.execute("SELECT last_seq,last_digest FROM audit_chain_state WHERE id=1").fetchone()
            if state is None:
                self.connection.execute(
                    "INSERT INTO audit_chain_state(id,last_seq,last_digest,updated_at) VALUES(1,0,?,?)",
                    (GENESIS_DIGEST, created_at),
                )
                last_seq, last_digest = 0, GENESIS_DIGEST
            else:
                last_seq, last_digest = int(state[0]), str(state[1])
            seq = last_seq + 1
            event = {
                "seq": seq,
                "actor_user_id": actor_user_id,
                "actor_name": actor_name,
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id_text,
                "outcome": outcome,
                "before_json": before_json,
                "after_json": after_json,
                "metadata_json": metadata_json,
                "correlation_id": correlation_id,
                "created_at": created_at,
                "prev_digest": last_digest,
            }
            digest = event_digest(event)
            cursor = self.connection.execute(
                "INSERT INTO audit_events(actor_user_id,actor_name,action,resource_type,resource_id,outcome,"
                "before_json,after_json,metadata_json,correlation_id,created_at,seq,prev_digest,digest) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    actor_user_id,
                    actor_name,
                    action,
                    resource_type,
                    resource_id_text,
                    outcome,
                    before_json,
                    after_json,
                    metadata_json,
                    correlation_id,
                    created_at,
                    seq,
                    last_digest,
                    digest,
                ),
            )
            updated = self.connection.execute(
                "UPDATE audit_chain_state SET last_seq=?,last_digest=?,updated_at=? WHERE id=1 AND last_seq=?",
                (seq, digest, created_at, last_seq),
            )
            if updated.rowcount != 1:
                raise ConflictError("审计链状态发生并发冲突，写入已回滚")
            if seq % checkpoint_size == 0:
                insert_checkpoint(self.connection, start_seq=seq - checkpoint_size + 1, end_seq=seq, created_at=created_at)
            return int(cursor.lastrowid)

        # 并发写入通过 BEGIN IMMEDIATE 串行化，链状态行条件更新保证序号唯一且连续。
        if self.connection.in_transaction:
            return write()
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            event_id = write()
        except Exception:
            self.connection.rollback()
            raise
        else:
            self.connection.commit()
            return event_id

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
