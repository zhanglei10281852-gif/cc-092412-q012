from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from app.core.audit_chain import (
    GENESIS_DIGEST,
    checkpoint_digest,
    checkpoint_document,
    checkpoint_interval,
    event_digest,
    event_document,
    stored_event_content,
)
from app.core.clock import Clock, SystemClock, to_storage
from app.database import ensure_transaction
from app.repositories.audit import AuditRepository, redact


@dataclass(slots=True)
class AuditContext:
    actor_user_id: int | None
    actor_name: str
    correlation_id: str | None = None


class AuditService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None) -> None:
        self.connection = connection
        self.repository = AuditRepository(connection)
        self.clock = clock or SystemClock()

    def record(
        self,
        context: AuditContext,
        *,
        action: str,
        resource_type: str,
        resource_id: str | int | None = None,
        outcome: str = "success",
        before: dict | None = None,
        after: dict | None = None,
        metadata: dict | None = None,
    ) -> int:
        # 敏感字段先入链前剔除，摘要只覆盖脱敏后的规范化内容
        payload = {
            "actor_user_id": context.actor_user_id,
            "actor_name": context.actor_name,
            "action": action,
            "resource_type": resource_type,
            "resource_id": str(resource_id) if resource_id is not None else None,
            "outcome": outcome,
            "before": redact(before) if before is not None else None,
            "after": redact(after) if after is not None else None,
            "metadata": redact(metadata or {}),
            "correlation_id": context.correlation_id,
            "created_at": to_storage(self.clock.now()),
        }
        with ensure_transaction(self.connection):
            return self._append_chained(payload)

    def initialize_chain(self) -> dict:
        """为历史存量从明确起点（首条记录，prev 为创世摘要）建立链状态，幂等。"""
        with ensure_transaction(self.connection):
            state, created, backfilled, checkpoints = self._ensure_chain_state()
        return {
            "initialized": created,
            "backfilled_events": backfilled,
            "checkpoints_created": checkpoints,
            "last_seq": state["last_seq"],
            "head_digest": state["head_digest"],
        }

    def _append_chained(self, payload: dict) -> int:
        state, _, _, _ = self._ensure_chain_state()
        seq = state["last_seq"] + 1
        prev = state["head_digest"]
        digest = event_digest(event_document(seq=seq, prev_digest=prev, **payload))
        event_id = self.repository.append(**payload, seq=seq, prev_digest=prev, digest=digest)
        now = to_storage(self.clock.now())
        self.repository.advance_chain_state(
            expected_last_seq=state["last_seq"], last_seq=seq, head_digest=digest, updated_at=now
        )
        interval = checkpoint_interval()
        if seq % interval == 0:
            self._create_checkpoint(seq - interval + 1, seq, digest, now)
        return event_id

    def _ensure_chain_state(self) -> tuple[dict, bool, int, int]:
        state = self.repository.chain_state()
        if state is not None:
            return state, False, 0, 0
        now = to_storage(self.clock.now())
        last_seq = 0
        head = GENESIS_DIGEST
        checkpoints = 0
        interval = checkpoint_interval()
        for row in self.repository.legacy_events():
            last_seq += 1
            document = event_document(seq=last_seq, prev_digest=head, **stored_event_content(row))
            head = event_digest(document)
            self.repository.assign_chain_fields(row["id"], seq=last_seq, prev_digest=document["prev_digest"], digest=head)
            if last_seq % interval == 0:
                self._create_checkpoint(last_seq - interval + 1, last_seq, head, now)
                checkpoints += 1
        self.repository.insert_chain_state(last_seq=last_seq, head_digest=head, updated_at=now)
        return {"last_seq": last_seq, "head_digest": head}, True, last_seq, checkpoints

    def _create_checkpoint(self, seq_start: int, seq_end: int, chain_head_digest: str, now: str) -> None:
        last = self.repository.last_checkpoint()
        prev_checkpoint = last["digest"] if last else GENESIS_DIGEST
        document = checkpoint_document(
            seq_start=seq_start,
            seq_end=seq_end,
            event_count=seq_end - seq_start + 1,
            chain_head_digest=chain_head_digest,
            prev_checkpoint_digest=prev_checkpoint,
        )
        self.repository.insert_checkpoint(
            seq_start=seq_start,
            seq_end=seq_end,
            event_count=document["event_count"],
            chain_head_digest=chain_head_digest,
            prev_checkpoint_digest=prev_checkpoint,
            digest=checkpoint_digest(document),
            created_at=now,
        )
