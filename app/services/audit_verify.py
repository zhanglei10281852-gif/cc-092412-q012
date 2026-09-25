from __future__ import annotations

import json
import sqlite3

from app.core.audit_chain import (
    EXPORT_FORMAT,
    GENESIS_DIGEST,
    checkpoint_digest,
    checkpoint_document,
    checkpoint_interval,
    document_from_row,
    event_digest,
    stored_event_content,
    verify_chunk_size,
)
from app.core.clock import Clock, SystemClock, to_storage
from app.database import ensure_transaction
from app.repositories.audit import AuditRepository, redact
from app.services.audit import AuditService


class AuditVerifyService:
    """审计链校验：定位第一处断裂、缺号或重排，而不是只返回真假。"""

    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None) -> None:
        self.connection = connection
        self.repository = AuditRepository(connection)
        self.clock = clock or SystemClock()

    # ---- 状态总览 ----

    def status(self) -> dict:
        state = self.repository.chain_state()
        verify = self.repository.verify_state()
        return {
            "initialized": state is not None,
            "pending_legacy_events": self.repository.count_legacy_events(),
            "last_seq": state["last_seq"] if state else 0,
            "head_digest": state["head_digest"] if state else None,
            "checkpoint_interval": checkpoint_interval(),
            "checkpoints": {"total": self.repository.count_checkpoints(), "last": self.repository.last_checkpoint()},
            "truncation": self.repository.latest_truncation(),
            "verification": verify,
        }

    # ---- 全量/区间校验 ----

    def verify(self, from_seq: int | None = None, to_seq: int | None = None) -> dict:
        state = self.repository.chain_state()
        if state is None:
            return {
                "status": "uninitialized",
                "pending_legacy_events": self.repository.count_legacy_events(),
                "first_failure": None,
                "checkpoints": None,
                "verified_at": to_storage(self.clock.now()),
            }
        truncation = self.repository.latest_truncation()
        anchor_seq = truncation["seq_through"] if truncation else 0
        anchor_digest = truncation["head_digest"] if truncation else GENESIS_DIGEST
        lo = max(from_seq if from_seq is not None else anchor_seq + 1, anchor_seq + 1)
        hi = min(to_seq if to_seq is not None else state["last_seq"], state["last_seq"])
        base = {
            "anchor": {"kind": "truncation" if truncation else "genesis", "seq": anchor_seq},
            "verified_at": to_storage(self.clock.now()),
        }
        if hi < lo:
            walk = {"ok": True, "checked": 0, "head_digest": anchor_digest, "failure": None}
            # 截断点恰为链头时，顺序器链头必须与截断锚点一致
            if truncation and anchor_seq == state["last_seq"] and anchor_digest != state["head_digest"]:
                return self._broken(base, lo, hi, 0, {
                    "kind": "state_mismatch",
                    "seq": state["last_seq"],
                    "message": "链头摘要与截断锚点不一致，链尾可能被回卷",
                    "expected": anchor_digest,
                    "actual": state["head_digest"],
                })
        else:
            if lo == anchor_seq + 1:
                anchor = anchor_digest
            else:
                predecessor = self.repository.event_at_seq(lo - 1)
                if predecessor is None:
                    return self._broken(base, lo, hi, 0, {"kind": "missing", "seq": lo - 1, "message": f"序号 {lo - 1} 的事件缺失，无法锚定校验起点"})
                anchor = predecessor["digest"]
            walk = self._walk(lo, hi, anchor)
        if not walk["ok"]:
            return self._broken(base, lo, hi, walk["checked"], walk["failure"])
        if hi >= lo and hi == state["last_seq"] and walk["head_digest"] != state["head_digest"]:
            return self._broken(base, lo, hi, walk["checked"], {
                "kind": "state_mismatch",
                "seq": state["last_seq"],
                "message": "链头摘要与顺序器状态不一致，链尾可能被回卷",
                "expected": walk["head_digest"],
                "actual": state["head_digest"],
            })
        checkpoints = self._verify_checkpoints(state)
        result = {
            "status": "ok" if checkpoints["first_failure"] is None else "broken",
            "range": {"from_seq": lo, "to_seq": hi, "events_checked": walk["checked"]},
            "first_failure": checkpoints["first_failure"],
            "checkpoints": checkpoints,
            "head_digest": walk["head_digest"],
            **base,
        }
        return result

    def _broken(self, base: dict, lo: int, hi: int, checked: int, failure: dict) -> dict:
        return {
            "status": "broken",
            "range": {"from_seq": lo, "to_seq": hi, "events_checked": checked},
            "first_failure": failure,
            "checkpoints": None,
            **base,
        }

    def _walk(self, lo: int, hi: int, anchor_digest: str) -> dict:
        """按序号顺序逐条重算并比对，返回第一处失败或走到的链头。"""
        expected = lo
        prev = anchor_digest
        checked = 0
        for row in self.repository.events_range(lo, hi):
            seq = row["seq"]
            if seq != expected:
                return {"ok": False, "checked": checked, "failure": {
                    "kind": "missing", "seq": expected,
                    "message": f"序号 {expected} 的事件缺失（实际遇到序号 {seq}），中间记录可能被删除",
                }}
            recomputed = event_digest(document_from_row(row))
            if recomputed != row["digest"]:
                return {"ok": False, "checked": checked, "failure": {
                    "kind": "digest_mismatch", "seq": seq,
                    "message": "事件摘要与规范化内容不符，内容或序号可能被篡改",
                    "expected": recomputed, "actual": row["digest"],
                }}
            if row["prev_digest"] != prev:
                return {"ok": False, "checked": checked, "failure": {
                    "kind": "chain_break", "seq": seq,
                    "message": "事件与前序摘要不衔接，链条在此断裂或被重排",
                    "expected_prev": prev, "actual_prev": row["prev_digest"],
                }}
            prev = row["digest"]
            expected += 1
            checked += 1
        if expected <= hi:
            return {"ok": False, "checked": checked, "failure": {
                "kind": "missing", "seq": expected,
                "message": f"序号 {expected} 起的事件缺失，链尾记录可能被删除",
            }}
        return {"ok": True, "checked": checked, "head_digest": prev, "failure": None}

    def _verify_checkpoints(self, state: dict) -> dict:
        interval = checkpoint_interval()
        checkpoints = self.repository.checkpoints()
        by_end = {row["seq_end"]: row for row in checkpoints}
        # 先按固定批次边界定位缺失的检查点
        boundary = interval
        while boundary <= state["last_seq"]:
            if boundary not in by_end:
                return {"checked": 0, "first_failure": {
                    "kind": "checkpoint_missing", "seq": boundary,
                    "message": f"序号 {boundary} 处缺少固定批次检查点",
                }}
            boundary += interval
        prev_checkpoint = GENESIS_DIGEST
        expected_start = 1
        checked = 0
        for row in checkpoints:
            if row["seq_end"] > state["last_seq"]:
                return {"checked": checked, "first_failure": {
                    "kind": "checkpoint_beyond_head", "seq": row["seq_end"],
                    "message": "检查点覆盖的序号超出当前链头，链尾可能被回卷",
                }}
            if row["seq_start"] != expected_start:
                return {"checked": checked, "first_failure": {
                    "kind": "checkpoint_missing", "seq": expected_start - 1,
                    "message": f"序号 {expected_start - 1} 处检查点覆盖区间不连续",
                }}
            document = checkpoint_document(
                seq_start=row["seq_start"],
                seq_end=row["seq_end"],
                event_count=row["event_count"],
                chain_head_digest=row["chain_head_digest"],
                prev_checkpoint_digest=row["prev_checkpoint_digest"],
            )
            if checkpoint_digest(document) != row["digest"]:
                return {"checked": checked, "first_failure": {
                    "kind": "checkpoint_mismatch", "seq": row["seq_end"],
                    "message": "检查点摘要与其规范化内容不符",
                }}
            if row["prev_checkpoint_digest"] != prev_checkpoint:
                return {"checked": checked, "first_failure": {
                    "kind": "checkpoint_chain_break", "seq": row["seq_end"],
                    "message": "检查点与前序检查点不衔接",
                }}
            event = self.repository.event_at_seq(row["seq_end"])
            if event is not None and event["digest"] != row["chain_head_digest"]:
                return {"checked": checked, "first_failure": {
                    "kind": "checkpoint_mismatch", "seq": row["seq_end"],
                    "message": "检查点记录的链头摘要与对应事件不一致",
                }}
            prev_checkpoint = row["digest"]
            expected_start = row["seq_end"] + 1
            checked += 1
        return {"checked": checked, "first_failure": None}

    # ---- 增量校验（失败与重启后可继续） ----

    def run_incremental(self, *, chunk_size: int | None = None, max_chunks: int | None = None) -> dict:
        with ensure_transaction(self.connection):
            return self._run_incremental(chunk_size=chunk_size, max_chunks=max_chunks)

    def _run_incremental(self, *, chunk_size: int | None, max_chunks: int | None) -> dict:
        chunk = chunk_size or verify_chunk_size()
        AuditService(self.connection, self.clock).initialize_chain()
        state = self.repository.chain_state()
        truncation = self.repository.latest_truncation()
        anchor_seq = truncation["seq_through"] if truncation else 0
        anchor_digest = truncation["head_digest"] if truncation else GENESIS_DIGEST
        progress = self.repository.verify_state()
        now = to_storage(self.clock.now())
        if progress is None:
            self.repository.insert_verify_state(last_verified_seq=anchor_seq, last_verified_digest=anchor_digest, updated_at=now)
            progress = self.repository.verify_state()
        # 上一轮已走完全链时，从锚点开启新一轮全量复核，历史区段的篡改才能被发现；
        # 否则从持久化位置继续，失败和重启后不重头再来。
        pass_completed = progress["last_status"] == "ok" and progress["last_verified_seq"] >= state["last_seq"]
        if pass_completed:
            verified_upto = anchor_seq
            head_digest = anchor_digest
        else:
            verified_upto = max(progress["last_verified_seq"], anchor_seq)
            head_digest = progress["last_verified_digest"] if verified_upto == progress["last_verified_seq"] else anchor_digest
            head_digest = head_digest or anchor_digest
        verified_this_run = 0
        chunks = 0
        while verified_upto < state["last_seq"] and (max_chunks is None or chunks < max_chunks):
            end = min(verified_upto + chunk, state["last_seq"])
            walk = self._walk(verified_upto + 1, end, head_digest)
            if not walk["ok"]:
                self.repository.update_verify_state(
                    last_verified_seq=verified_upto,
                    last_verified_digest=head_digest,
                    last_run_at=now,
                    last_status="broken",
                    failure_json=json.dumps(walk["failure"], ensure_ascii=False, sort_keys=True),
                    completed=False,
                )
                return {
                    "status": "broken",
                    "first_failure": walk["failure"],
                    "last_verified_seq": verified_upto,
                    "verified_events": verified_this_run,
                    "has_more": True,
                    "finished_at": now,
                }
            verified_upto = end
            head_digest = walk["head_digest"]
            verified_this_run += walk["checked"]
            chunks += 1
            self.repository.update_verify_state(
                last_verified_seq=verified_upto,
                last_verified_digest=head_digest,
                last_run_at=now,
                last_status="ok",
                failure_json=None,
                completed=False,
            )
        caught_up = verified_upto >= state["last_seq"]
        final_failure = None
        if caught_up:
            if head_digest != state["head_digest"]:
                final_failure = {
                    "kind": "state_mismatch",
                    "seq": state["last_seq"],
                    "message": "链头摘要与顺序器状态不一致，链尾可能被回卷",
                    "expected": head_digest,
                    "actual": state["head_digest"],
                }
            else:
                final_failure = self._verify_checkpoints(state)["first_failure"]
        self.repository.update_verify_state(
            last_verified_seq=verified_upto,
            last_verified_digest=head_digest,
            last_run_at=now,
            last_status="broken" if final_failure else "ok",
            failure_json=json.dumps(final_failure, ensure_ascii=False, sort_keys=True) if final_failure else None,
            completed=caught_up and final_failure is None,
        )
        if final_failure:
            return {
                "status": "broken",
                "first_failure": final_failure,
                "last_verified_seq": verified_upto,
                "verified_events": verified_this_run,
                "has_more": False,
                "finished_at": now,
            }
        return {
            "status": "ok",
            "first_failure": None,
            "last_verified_seq": verified_upto,
            "verified_events": verified_this_run,
            "has_more": not caught_up,
            "finished_at": now,
        }

    # ---- 导出验证材料（不含任何密钥或明文凭据） ----

    def export_bundle(self, from_seq: int | None = None, to_seq: int | None = None) -> dict:
        state = self.repository.chain_state()
        truncation = self.repository.latest_truncation()
        anchor_seq = truncation["seq_through"] if truncation else 0
        last_seq = state["last_seq"] if state else 0
        lo = max(from_seq if from_seq is not None else anchor_seq + 1, anchor_seq + 1)
        hi = min(to_seq if to_seq is not None else last_seq, last_seq)
        events = []
        if hi >= lo:
            for row in self.repository.events_range(lo, hi):
                content = stored_event_content(row)
                # 入库时已剔除敏感键，导出前再过滤一次作为纵深防御
                for key in ("before", "after", "metadata"):
                    content[key] = redact(content[key])
                events.append({
                    "seq": row["seq"],
                    "prev_digest": row["prev_digest"],
                    "digest": row["digest"],
                    "content": content,
                })
        return {
            "format": EXPORT_FORMAT,
            "exported_at": to_storage(self.clock.now()),
            "chain": {"last_seq": last_seq, "head_digest": state["head_digest"] if state else None},
            "truncation": truncation,
            "range": {"from_seq": lo, "to_seq": hi},
            "events": events,
            "checkpoints": self.repository.checkpoints(),
        }
