from __future__ import annotations

import json
import sqlite3

from app.core.audit_chain import GENESIS_DIGEST, checkpoint_digest, event_digest, merkle_root
from app.core.clock import Clock, SystemClock, to_storage
from app.core.config import Settings
from app.core.errors import NotFoundError, ValidationError
from app.repositories.audit_chain import AuditChainRepository


class AuditIntegrityService:
    """审计链完整性：顺序校验、历史锚定、可恢复定期校验和验证材料导出。"""

    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        self.chain = AuditChainRepository(connection)
        self.settings = Settings.load()

    def verify(self, *, start_seq: int | None = None, end_seq: int | None = None) -> dict:
        """按序号顺序校验，返回第一处断裂、缺号或重排的位置，而不是只返回真假。"""
        head = self.chain.chain_head()
        start = start_seq if start_seq is not None else 1
        if start < 1:
            raise ValidationError("start_seq 必须不小于 1")
        end = end_seq if end_seq is not None else int(head["last_seq"])
        if end < start:
            scan = self._empty_scan(start)
        else:
            scan = self._scan(start, end)
        failure = scan["first_failure"]
        if failure is None and end == int(head["last_seq"]) and int(head["last_seq"]) > 0:
            if scan["last_digest"] != head["last_digest"]:
                failure = {
                    "kind": "head_mismatch",
                    "seq": head["last_seq"],
                    "message": "链头摘要与审计链状态表不一致，链状态可能被改写",
                    "expected_digest": scan["last_digest"],
                    "actual_digest": head["last_digest"],
                }
        if failure is None:
            unanchored = self.chain.unanchored_count()
            if unanchored:
                failure = {
                    "kind": "unanchored_events",
                    "seq": None,
                    "message": f"存在 {unanchored} 条未锚定的审计事件，需要先执行锚定",
                    "count": unanchored,
                }
        result = {
            "ok": failure is None,
            "checked": scan["checked"],
            "checkpoints_checked": scan["checkpoints_checked"],
            "range": {"start_seq": start, "end_seq": end},
            "head_seq": head["last_seq"],
            "verified_at": to_storage(self.clock.now()),
        }
        if failure is not None:
            result["first_failure"] = failure
        else:
            result["head_digest"] = head["last_digest"]
        return result

    def anchor(self, *, triggered_by: str) -> dict:
        """把历史存量事件补入链中，从明确起点建立首个检查点；可重复调用。"""
        result = self.chain.anchor_legacy_events(
            checkpoint_size=self.settings.audit_checkpoint_size,
            now=to_storage(self.clock.now()),
        )
        result["triggered_by"] = triggered_by
        return result

    def list_checkpoints(self, *, limit: int, offset: int) -> dict:
        return {
            "total": self.chain.count_checkpoints(),
            "data": self.chain.list_checkpoints(limit=limit, offset=offset),
        }

    def start_or_resume_run(self, *, triggered_by: str, chunk_size: int | None = None) -> dict:
        size = chunk_size if chunk_size is not None else self.settings.audit_verify_chunk_size
        if size < 1:
            raise ValidationError("chunk_size 必须不小于 1")
        run = self.chain.latest_resumable_run()
        if run is not None:
            if run["status"] == "failed":
                self.chain.reactivate_run(int(run["id"]), now=to_storage(self.clock.now()))
                run = self.chain.require_run(int(run["id"]))
            return {"run": self._public_run(run), "resumed": True}
        head = self.chain.chain_head()
        run = self.chain.create_run(
            target_seq=int(head["last_seq"]),
            target_digest=str(head["last_digest"]),
            chunk_size=size,
            triggered_by=triggered_by,
            now=to_storage(self.clock.now()),
        )
        return {"run": self._public_run(run), "resumed": False}

    def process_run(self, run_id: int, *, chunks: int = 1) -> dict:
        run = self.chain.get_run(run_id)
        if run is None:
            raise NotFoundError("校验任务不存在")
        for _ in range(max(1, chunks)):
            if run["status"] != "running":
                break
            run = self._process_chunk(run)
        return self._public_run(run)

    def latest_run(self) -> dict | None:
        return self._public_run(self.chain.latest_run())

    def export_material(self, *, include_events: bool = False) -> dict:
        """导出验证材料：只含序号与摘要，不含任何密钥、口令或业务明文。"""
        head = self.chain.chain_head()
        checkpoints = [
            {
                "start_seq": checkpoint["start_seq"],
                "end_seq": checkpoint["end_seq"],
                "event_count": checkpoint["event_count"],
                "root_digest": checkpoint["root_digest"],
                "prev_checkpoint_digest": checkpoint["prev_checkpoint_digest"],
                "digest": checkpoint["digest"],
                "created_at": checkpoint["created_at"],
            }
            for checkpoint in self.chain.list_checkpoints_upto(int(head["last_seq"]))
        ]
        material = {
            "format": "township-audit-integrity/v1",
            "generated_at": to_storage(self.clock.now()),
            "checkpoint_size": self.settings.audit_checkpoint_size,
            "chain_head": {"last_seq": head["last_seq"], "last_digest": head["last_digest"]},
            "checkpoints": checkpoints,
            "latest_run": self.latest_run(),
        }
        if include_events:
            material["events"] = [
                {"seq": event["seq"], "prev_digest": event["prev_digest"], "digest": event["digest"]}
                for event in self.chain.iter_events(1, int(head["last_seq"]))
            ]
        return material

    def _process_chunk(self, run: dict) -> dict:
        run_id = int(run["id"])
        next_seq = int(run["next_seq"])
        target = int(run["target_seq"])
        try:
            if next_seq <= target:
                scan = self._scan(next_seq, min(next_seq + int(run["chunk_size"]) - 1, target))
            else:
                scan = self._empty_scan(next_seq)
        except Exception as exc:
            self.chain.fail_run_with_error(run_id, message=str(exc), now=to_storage(self.clock.now()))
            raise
        checked = int(run["checked_count"]) + scan["checked"]
        failure = scan["first_failure"]
        finished = scan["next_seq"] > target
        if failure is None and finished:
            if scan["last_digest"] != run["target_digest"]:
                failure = {
                    "kind": "head_mismatch",
                    "seq": target,
                    "message": "链头摘要与任务起点记录的链状态不一致，链状态可能被改写",
                    "expected_digest": scan["last_digest"],
                    "actual_digest": run["target_digest"],
                }
            else:
                unanchored = self.chain.unanchored_count()
                if unanchored:
                    failure = {
                        "kind": "unanchored_events",
                        "seq": None,
                        "message": f"存在 {unanchored} 条未锚定的审计事件，需要先执行锚定",
                        "count": unanchored,
                    }
        now = to_storage(self.clock.now())
        if failure is not None:
            self.chain.update_run(run_id, status="failed", next_seq=scan["next_seq"], checked_count=checked, first_failure=failure, now=now)
        elif finished:
            self.chain.update_run(run_id, status="completed", next_seq=scan["next_seq"], checked_count=checked, now=now)
        else:
            self.chain.update_run(run_id, status="running", next_seq=scan["next_seq"], checked_count=checked, now=now)
        return self.chain.require_run(run_id)

    def _scan(self, start_seq: int, end_seq: int) -> dict:
        """顺序扫描 [start_seq, end_seq]，遇到第一处问题即停并返回其位置。"""
        size = self.settings.audit_checkpoint_size
        if start_seq <= 1:
            expected_prev = GENESIS_DIGEST
            last_checkpoint_digest = GENESIS_DIGEST
        else:
            previous = self.chain.event_at(start_seq - 1)
            if previous is None:
                return {
                    "checked": 0,
                    "checkpoints_checked": 0,
                    "next_seq": start_seq,
                    "last_digest": None,
                    "first_failure": {
                        "kind": "sequence_gap",
                        "seq": start_seq - 1,
                        "message": f"序号 {start_seq - 1} 的审计事件缺失",
                        "expected_seq": start_seq - 1,
                        "actual_seq": None,
                    },
                }
            expected_prev = previous["digest"]
            checkpoint = self.chain.latest_checkpoint_before(start_seq)
            last_checkpoint_digest = checkpoint["digest"] if checkpoint else GENESIS_DIGEST
        expected_seq = start_seq
        checked = 0
        checkpoints_checked = 0
        first_failure: dict | None = None
        for event in self.chain.iter_events(start_seq, end_seq):
            seq = int(event["seq"])
            if seq != expected_seq:
                if seq > expected_seq:
                    first_failure = {
                        "kind": "sequence_gap",
                        "seq": expected_seq,
                        "message": f"序号 {expected_seq} 的审计事件缺失（实际下一条序号为 {seq}）",
                        "expected_seq": expected_seq,
                        "actual_seq": seq,
                    }
                else:
                    first_failure = {
                        "kind": "sequence_reorder",
                        "seq": seq,
                        "message": f"序号 {seq} 出现在期望序号 {expected_seq} 的位置，存在重排或重复",
                        "expected_seq": expected_seq,
                        "actual_seq": seq,
                    }
                break
            if event["prev_digest"] != expected_prev:
                first_failure = {
                    "kind": "chain_break",
                    "seq": seq,
                    "message": f"第 {seq} 条事件绑定前一条摘要与上一条的摘要不衔接",
                    "expected_prev_digest": expected_prev,
                    "actual_prev_digest": event["prev_digest"],
                }
                break
            recomputed = event_digest(event)
            if recomputed != event["digest"]:
                first_failure = {
                    "kind": "digest_mismatch",
                    "seq": seq,
                    "message": f"第 {seq} 条事件的摘要与其规范化内容不一致，内容可能被替换",
                    "expected_digest": recomputed,
                    "actual_digest": event["digest"],
                }
                break
            checked += 1
            expected_prev = event["digest"]
            if seq % size == 0:
                checkpoint_failure, verified_digest = self._verify_checkpoint(seq, last_checkpoint_digest)
                if checkpoint_failure is not None:
                    first_failure = checkpoint_failure
                    break
                last_checkpoint_digest = verified_digest
                checkpoints_checked += 1
            expected_seq = seq + 1
        if first_failure is None and expected_seq <= end_seq:
            first_failure = {
                "kind": "sequence_gap",
                "seq": expected_seq,
                "message": f"序号 {expected_seq} 起的审计事件缺失",
                "expected_seq": expected_seq,
                "actual_seq": None,
            }
        return {
            "checked": checked,
            "checkpoints_checked": checkpoints_checked,
            "next_seq": expected_seq,
            "last_digest": expected_prev,
            "first_failure": first_failure,
        }

    def _verify_checkpoint(self, end_seq: int, expected_prev_digest: str) -> tuple[dict | None, str | None]:
        checkpoint = self.chain.checkpoint_at_end(end_seq)
        if checkpoint is None:
            return {
                "kind": "checkpoint_missing",
                "seq": end_seq,
                "message": f"序号 {end_seq} 处缺少按固定批次生成的检查点",
            }, None
        recomputed = checkpoint_digest(checkpoint)
        if recomputed != checkpoint["digest"]:
            return {
                "kind": "checkpoint_digest_mismatch",
                "seq": end_seq,
                "message": f"序号 {end_seq} 处检查点的摘要与其内容不一致",
                "expected_digest": recomputed,
                "actual_digest": checkpoint["digest"],
            }, None
        events = list(self.chain.iter_events(int(checkpoint["start_seq"]), end_seq))
        root = merkle_root([event["digest"] for event in events])
        if len(events) != int(checkpoint["event_count"]) or root != checkpoint["root_digest"]:
            return {
                "kind": "checkpoint_root_mismatch",
                "seq": end_seq,
                "message": f"序号 {end_seq} 处检查点的 Merkle 根与批次事件不一致",
                "expected_root": root,
                "actual_root": checkpoint["root_digest"],
            }, None
        if checkpoint["prev_checkpoint_digest"] != expected_prev_digest:
            return {
                "kind": "checkpoint_chain_break",
                "seq": end_seq,
                "message": f"序号 {end_seq} 处检查点与上一检查点不衔接",
                "expected_prev_digest": expected_prev_digest,
                "actual_prev_digest": checkpoint["prev_checkpoint_digest"],
            }, None
        return None, checkpoint["digest"]

    def _empty_scan(self, next_seq: int) -> dict:
        return {
            "checked": 0,
            "checkpoints_checked": 0,
            "next_seq": next_seq,
            "last_digest": self._digest_before(next_seq),
            "first_failure": None,
        }

    def _digest_before(self, seq: int) -> str:
        if seq <= 1:
            return GENESIS_DIGEST
        previous = self.chain.event_at(seq - 1)
        return previous["digest"] if previous else GENESIS_DIGEST

    @staticmethod
    def _public_run(run: dict | None) -> dict | None:
        if run is None:
            return None
        result = dict(run)
        failure = result.pop("first_failure_json", None)
        result["first_failure"] = json.loads(failure) if failure else None
        return result
