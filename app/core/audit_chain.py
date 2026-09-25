"""审计链的规范化与摘要计算。

链上摘要不使用任何密钥（纯 SHA-256），因此导出的验证材料天然不含密钥；
敏感字段在写入前已由 redact 剔除，摘要只覆盖脱敏后的规范化内容。
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

CHAIN_VERSION = 1
GENESIS_DIGEST = "0" * 64
EXPORT_FORMAT = "township-audit-chain/1"


def checkpoint_interval() -> int:
    """固定批次的检查点间隔（事件条数）。"""
    return max(1, int(os.getenv("TOWNSHIP_AUDIT_CHECKPOINT_INTERVAL", "100")))


def verify_chunk_size() -> int:
    """增量校验单次推进的最大事件数。"""
    return max(1, int(os.getenv("TOWNSHIP_AUDIT_VERIFY_CHUNK", "500")))


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def event_document(
    *,
    seq: int,
    prev_digest: str,
    actor_user_id: int | None,
    actor_name: str,
    action: str,
    resource_type: str,
    resource_id: str | None,
    outcome: str,
    before: Any,
    after: Any,
    metadata: Any,
    correlation_id: str | None,
    created_at: str,
) -> dict:
    """事件的规范化内容（v1）。键集合与顺序固定，任何字段改动都会改变摘要。"""
    return {
        "v": CHAIN_VERSION,
        "seq": seq,
        "prev_digest": prev_digest,
        "actor_user_id": actor_user_id,
        "actor_name": actor_name,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "outcome": outcome,
        "before": before,
        "after": after,
        "metadata": metadata,
        "correlation_id": correlation_id,
        "created_at": created_at,
    }


def event_digest(document: dict) -> str:
    return digest_text(canonical_json(document))


def checkpoint_document(
    *,
    seq_start: int,
    seq_end: int,
    event_count: int,
    chain_head_digest: str,
    prev_checkpoint_digest: str,
) -> dict:
    """检查点的规范化内容，检查点之间同样成链。"""
    return {
        "v": CHAIN_VERSION,
        "kind": "checkpoint",
        "seq_start": seq_start,
        "seq_end": seq_end,
        "event_count": event_count,
        "chain_head_digest": chain_head_digest,
        "prev_checkpoint_digest": prev_checkpoint_digest,
    }


def checkpoint_digest(document: dict) -> str:
    return digest_text(canonical_json(document))


def stored_event_content(row: dict) -> dict:
    """从库存字段还原事件内容（JSON 文本解析为对象），键与 event_document 对应。"""
    return {
        "actor_user_id": row["actor_user_id"],
        "actor_name": row["actor_name"],
        "action": row["action"],
        "resource_type": row["resource_type"],
        "resource_id": row["resource_id"],
        "outcome": row["outcome"],
        "before": json.loads(row["before_json"]) if row["before_json"] is not None else None,
        "after": json.loads(row["after_json"]) if row["after_json"] is not None else None,
        "metadata": json.loads(row["metadata_json"]) if row["metadata_json"] is not None else None,
        "correlation_id": row["correlation_id"],
        "created_at": row["created_at"],
    }


def document_from_row(row: dict) -> dict:
    """按库存行重建规范化事件文档，用于校验时重算摘要。"""
    return event_document(seq=row["seq"], prev_digest=row["prev_digest"], **stored_event_content(row))
