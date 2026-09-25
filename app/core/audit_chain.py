from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence

# 链起点使用固定的创世摘要，任何一方都能独立重算，不依赖任何密钥。
GENESIS_DIGEST = "0" * 64

EVENT_CHAIN_FIELDS = (
    "seq",
    "actor_user_id",
    "actor_name",
    "action",
    "resource_type",
    "resource_id",
    "outcome",
    "before_json",
    "after_json",
    "metadata_json",
    "correlation_id",
    "created_at",
    "prev_digest",
)

CHECKPOINT_CHAIN_FIELDS = (
    "start_seq",
    "end_seq",
    "event_count",
    "root_digest",
    "prev_checkpoint_digest",
)


def _canonical(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_event(event: Mapping[str, Any]) -> str:
    """事件的规范化内容：只取链字段，键序固定、分隔符固定，保证可独立重算。"""
    return _canonical({field: event.get(field) for field in EVENT_CHAIN_FIELDS})


def event_digest(event: Mapping[str, Any]) -> str:
    """事件摘要，绑定前一条摘要（prev_digest）与自身规范化内容。"""
    return _sha256_text(canonical_event(event))


def canonical_checkpoint(checkpoint: Mapping[str, Any]) -> str:
    return _canonical({field: checkpoint.get(field) for field in CHECKPOINT_CHAIN_FIELDS})


def checkpoint_digest(checkpoint: Mapping[str, Any]) -> str:
    return _sha256_text(canonical_checkpoint(checkpoint))


def merkle_root(digests: Sequence[str]) -> str:
    """由有序事件摘要计算 Merkle 根；奇数节点复制末尾节点补齐。"""
    if not digests:
        return _sha256_text("")
    level = [bytes.fromhex(digest) for digest in digests]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [hashlib.sha256(level[index] + level[index + 1]).digest() for index in range(0, len(level), 2)]
    return level[0].hex()
