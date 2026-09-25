from __future__ import annotations

import json
import sqlite3
from typing import Iterator

from app.core.audit_chain import GENESIS_DIGEST, checkpoint_digest, event_digest, merkle_root
from app.core.errors import ConflictError
from app.repositories.base import row_dict, rows_dict


def insert_checkpoint(connection: sqlite3.Connection, *, start_seq: int, end_seq: int, created_at: str) -> dict:
    """为 [start_seq, end_seq] 区间的事件生成检查点，调用方必须处于写事务中。"""
    rows = connection.execute(
        "SELECT digest FROM audit_events WHERE seq BETWEEN ? AND ? ORDER BY seq",
        (start_seq, end_seq),
    ).fetchall()
    digests = [str(row[0]) for row in rows]
    expected = end_seq - start_seq + 1
    if len(digests) != expected:
        raise ConflictError(
            "审计事件序号不连续，无法生成检查点",
            context={"start_seq": start_seq, "end_seq": end_seq, "found": len(digests)},
        )
    previous = connection.execute("SELECT digest FROM audit_checkpoints ORDER BY end_seq DESC LIMIT 1").fetchone()
    checkpoint = {
        "start_seq": start_seq,
        "end_seq": end_seq,
        "event_count": expected,
        "root_digest": merkle_root(digests),
        "prev_checkpoint_digest": str(previous[0]) if previous else GENESIS_DIGEST,
    }
    digest = checkpoint_digest(checkpoint)
    cursor = connection.execute(
        "INSERT INTO audit_checkpoints(start_seq,end_seq,event_count,root_digest,prev_checkpoint_digest,digest,created_at) "
        "VALUES(?,?,?,?,?,?,?)",
        (start_seq, end_seq, expected, checkpoint["root_digest"], checkpoint["prev_checkpoint_digest"], digest, created_at),
    )
    return {"id": int(cursor.lastrowid), **checkpoint, "digest": digest, "created_at": created_at}


class AuditChainRepository:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def ensure_chain_state(self, now: str) -> dict:
        self.connection.execute(
            "INSERT OR IGNORE INTO audit_chain_state(id,last_seq,last_digest,updated_at) VALUES(1,0,?,?)",
            (GENESIS_DIGEST, now),
        )
        return self.chain_head()

    def chain_head(self) -> dict:
        row = self.connection.execute("SELECT last_seq,last_digest,updated_at FROM audit_chain_state WHERE id=1").fetchone()
        if row is None:
            return {"last_seq": 0, "last_digest": GENESIS_DIGEST, "updated_at": None}
        return dict(row)

    def advance_chain_state(self, *, expected_seq: int, new_seq: int, new_digest: str, now: str) -> None:
        cursor = self.connection.execute(
            "UPDATE audit_chain_state SET last_seq=?,last_digest=?,updated_at=? WHERE id=1 AND last_seq=?",
            (new_seq, new_digest, now, expected_seq),
        )
        if cursor.rowcount != 1:
            raise ConflictError("审计链状态发生并发冲突，写入已回滚")

    def event_at(self, seq: int) -> dict | None:
        return row_dict(self.connection.execute("SELECT * FROM audit_events WHERE seq=?", (seq,)).fetchone())

    def iter_events(self, start_seq: int, end_seq: int) -> Iterator[dict]:
        cursor = self.connection.execute(
            "SELECT * FROM audit_events WHERE seq BETWEEN ? AND ? ORDER BY seq",
            (start_seq, end_seq),
        )
        for row in cursor:
            yield dict(row)

    def unanchored_count(self) -> int:
        return int(self.connection.execute("SELECT COUNT(*) FROM audit_events WHERE seq IS NULL").fetchone()[0])

    def checkpoint_at_end(self, end_seq: int) -> dict | None:
        return row_dict(self.connection.execute("SELECT * FROM audit_checkpoints WHERE end_seq=?", (end_seq,)).fetchone())

    def latest_checkpoint_before(self, seq: int) -> dict | None:
        return row_dict(self.connection.execute(
            "SELECT * FROM audit_checkpoints WHERE end_seq<? ORDER BY end_seq DESC LIMIT 1",
            (seq,),
        ).fetchone())

    def list_checkpoints(self, *, limit: int, offset: int) -> list[dict]:
        return rows_dict(self.connection.execute(
            "SELECT * FROM audit_checkpoints ORDER BY end_seq DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall())

    def count_checkpoints(self) -> int:
        return int(self.connection.execute("SELECT COUNT(*) FROM audit_checkpoints").fetchone()[0])

    def list_checkpoints_upto(self, end_seq: int) -> list[dict]:
        return rows_dict(self.connection.execute(
            "SELECT * FROM audit_checkpoints WHERE end_seq<=? ORDER BY end_seq",
            (end_seq,),
        ).fetchall())

    def create_run(self, *, target_seq: int, target_digest: str, chunk_size: int, triggered_by: str, now: str) -> dict:
        cursor = self.connection.execute(
            "INSERT INTO audit_verification_runs(status,start_seq,next_seq,target_seq,target_digest,checked_count,chunk_size,triggered_by,created_at,updated_at) "
            "VALUES('running',1,1,?,?,0,?,?,?,?)",
            (target_seq, target_digest, chunk_size, triggered_by, now, now),
        )
        return self.require_run(int(cursor.lastrowid))

    def get_run(self, run_id: int) -> dict | None:
        return row_dict(self.connection.execute("SELECT * FROM audit_verification_runs WHERE id=?", (run_id,)).fetchone())

    def require_run(self, run_id: int) -> dict:
        run = self.get_run(run_id)
        if run is None:
            raise ConflictError("校验任务不存在", context={"run_id": run_id})
        return run

    def latest_run(self) -> dict | None:
        return row_dict(self.connection.execute("SELECT * FROM audit_verification_runs ORDER BY id DESC LIMIT 1").fetchone())

    def latest_resumable_run(self) -> dict | None:
        """执行中断（running）或执行错误失败（无完整性结论）的任务可以从断点继续。"""
        return row_dict(self.connection.execute(
            "SELECT * FROM audit_verification_runs "
            "WHERE status='running' OR (status='failed' AND first_failure_json IS NULL) "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone())

    def reactivate_run(self, run_id: int, *, now: str) -> None:
        """执行错误失败（无完整性结论）的任务恢复为 running，从断点继续。"""
        self.connection.execute(
            "UPDATE audit_verification_runs SET status='running',error_message=NULL,updated_at=? "
            "WHERE id=? AND status='failed' AND first_failure_json IS NULL",
            (now, run_id),
        )

    def update_run(
        self,
        run_id: int,
        *,
        status: str,
        next_seq: int,
        checked_count: int,
        now: str,
        first_failure: dict | None = None,
        error: str | None = None,
    ) -> None:
        failure_json = json.dumps(first_failure, ensure_ascii=False, sort_keys=True) if first_failure else None
        self.connection.execute(
            "UPDATE audit_verification_runs SET status=?,next_seq=?,checked_count=?,first_failure_json=?,error_message=?,updated_at=? "
            "WHERE id=? AND status='running'",
            (status, next_seq, checked_count, failure_json, error, now, run_id),
        )

    def fail_run_with_error(self, run_id: int, *, message: str, now: str) -> None:
        self.connection.execute(
            "UPDATE audit_verification_runs SET status='failed',error_message=?,updated_at=? WHERE id=? AND status='running'",
            (message[:1000], now, run_id),
        )

    def anchor_legacy_events(self, *, checkpoint_size: int, now: str) -> dict:
        """把尚未入链的历史事件按 id 顺序补入链，从明确起点（首个序号）建立检查点。"""
        state = self.ensure_chain_state(now)
        rows = self.connection.execute("SELECT * FROM audit_events WHERE seq IS NULL ORDER BY id").fetchall()
        checkpoints_created = 0
        first_seq: int | None = None
        if rows:
            last_seq = int(state["last_seq"])
            last_digest = str(state["last_digest"])
            first_seq = last_seq + 1
            for row in rows:
                seq = last_seq + 1
                event = dict(row)
                event["seq"] = seq
                event["prev_digest"] = last_digest
                digest = event_digest(event)
                cursor = self.connection.execute(
                    "UPDATE audit_events SET seq=?,prev_digest=?,digest=? WHERE id=? AND seq IS NULL",
                    (seq, last_digest, digest, row["id"]),
                )
                if cursor.rowcount != 1:
                    raise ConflictError("审计事件锚定发生冲突", context={"id": row["id"]})
                last_seq, last_digest = seq, digest
                if seq % checkpoint_size == 0:
                    insert_checkpoint(self.connection, start_seq=seq - checkpoint_size + 1, end_seq=seq, created_at=now)
                    checkpoints_created += 1
            self.advance_chain_state(expected_seq=int(state["last_seq"]), new_seq=last_seq, new_digest=last_digest, now=now)
        head = self.chain_head()
        return {
            "anchored": len(rows),
            "first_seq": first_seq,
            "last_seq": head["last_seq"],
            "head_digest": head["last_digest"],
            "checkpoints_created": checkpoints_created,
        }
