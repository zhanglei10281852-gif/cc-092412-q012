from __future__ import annotations

import json
import threading

import pytest

from app.core.audit_chain import (
    GENESIS_DIGEST,
    checkpoint_digest,
    checkpoint_document,
    event_digest,
    event_document,
)


@pytest.fixture()
def chain_env(monkeypatch):
    monkeypatch.setenv("TOWNSHIP_AUDIT_CHECKPOINT_INTERVAL", "3")
    monkeypatch.setenv("TOWNSHIP_AUDIT_VERIFY_CHUNK", "4")


def record_events(count: int, *, action_prefix: str = "test.event") -> list[int]:
    from app.database import get_connection, transaction
    from app.services.audit import AuditContext, AuditService

    ids = []
    with transaction(immediate=True) as connection:
        service = AuditService(connection)
        for index in range(count):
            ids.append(
                service.record(
                    AuditContext(None, "测试员"),
                    action=f"{action_prefix}.{index}",
                    resource_type="test",
                    metadata={"index": index},
                )
            )
    return ids


def verify_service():
    from app.database import get_connection
    from app.services.audit_verify import AuditVerifyService

    return AuditVerifyService(get_connection())


def test_chain_assigns_unique_order_and_links(client, chain_env):
    record_events(5)
    from app.database import get_connection

    rows = get_connection().execute("SELECT seq,prev_digest,digest FROM audit_events ORDER BY seq").fetchall()
    assert [row["seq"] for row in rows] == [1, 2, 3, 4, 5]
    assert rows[0]["prev_digest"] == GENESIS_DIGEST
    for previous, current in zip(rows, rows[1:]):
        assert current["prev_digest"] == previous["digest"]
    state = get_connection().execute("SELECT * FROM audit_chain_state WHERE id=1").fetchone()
    assert state["last_seq"] == 5
    assert state["head_digest"] == rows[-1]["digest"]


def test_checkpoints_created_at_fixed_batches(client, chain_env):
    record_events(7)
    from app.database import get_connection

    checkpoints = get_connection().execute("SELECT * FROM audit_checkpoints ORDER BY seq_end").fetchall()
    assert [(row["seq_start"], row["seq_end"]) for row in checkpoints] == [(1, 3), (4, 6)]
    assert checkpoints[0]["prev_checkpoint_digest"] == GENESIS_DIGEST
    assert checkpoints[1]["prev_checkpoint_digest"] == checkpoints[0]["digest"]
    document = checkpoint_document(
        seq_start=1,
        seq_end=3,
        event_count=3,
        chain_head_digest=checkpoints[0]["chain_head_digest"],
        prev_checkpoint_digest=GENESIS_DIGEST,
    )
    assert checkpoint_digest(document) == checkpoints[0]["digest"]
    head = get_connection().execute("SELECT digest FROM audit_events WHERE seq=3").fetchone()
    assert checkpoints[0]["chain_head_digest"] == head["digest"]


def test_verify_intact_chain(client, chain_env):
    record_events(7)
    result = verify_service().verify()
    assert result["status"] == "ok"
    assert result["range"] == {"from_seq": 1, "to_seq": 7, "events_checked": 7}
    assert result["checkpoints"] == {"checked": 2, "first_failure": None}
    assert result["first_failure"] is None
    # 空区间（起点超过链头）不应误报链头不一致
    empty = verify_service().verify(from_seq=99)
    assert empty["status"] == "ok"
    assert empty["range"]["events_checked"] == 0


def test_verify_locates_content_tamper(client, chain_env):
    record_events(6)
    from app.database import get_connection

    get_connection().execute("UPDATE audit_events SET after_json=? WHERE seq=4", ('{"被改": true}',))
    result = verify_service().verify()
    assert result["status"] == "broken"
    assert result["first_failure"]["kind"] == "digest_mismatch"
    assert result["first_failure"]["seq"] == 4


def test_verify_locates_deleted_event(client, chain_env):
    record_events(6)
    from app.database import get_connection

    get_connection().execute("DELETE FROM audit_events WHERE seq=3")
    result = verify_service().verify()
    assert result["status"] == "broken"
    assert result["first_failure"]["kind"] == "missing"
    assert result["first_failure"]["seq"] == 3


def test_verify_locates_reordered_events(client, chain_env):
    record_events(5)
    from app.database import get_connection

    connection = get_connection()
    connection.execute("UPDATE audit_events SET seq=-1 WHERE seq=2")
    connection.execute("UPDATE audit_events SET seq=2 WHERE seq=3")
    connection.execute("UPDATE audit_events SET seq=3 WHERE seq=-1")
    result = verify_service().verify()
    assert result["status"] == "broken"
    assert result["first_failure"]["kind"] == "digest_mismatch"
    assert result["first_failure"]["seq"] == 2


def test_verify_locates_rewritten_link(client, chain_env):
    record_events(5)
    from app.database import get_connection
    from app.core.audit_chain import stored_event_content

    connection = get_connection()
    row = dict(connection.execute("SELECT * FROM audit_events WHERE seq=4").fetchone())
    forged_prev = "f" * 64
    document = event_document(seq=4, prev_digest=forged_prev, **stored_event_content(row))
    connection.execute(
        "UPDATE audit_events SET prev_digest=?,digest=? WHERE seq=4",
        (forged_prev, event_digest(document)),
    )
    result = verify_service().verify()
    assert result["status"] == "broken"
    assert result["first_failure"]["kind"] == "chain_break"
    assert result["first_failure"]["seq"] == 4


def test_verify_locates_head_state_tamper(client, chain_env):
    record_events(4)
    from app.database import get_connection

    get_connection().execute("UPDATE audit_chain_state SET head_digest=? WHERE id=1", ("0" * 63 + "1",))
    result = verify_service().verify()
    assert result["status"] == "broken"
    assert result["first_failure"]["kind"] == "state_mismatch"


def test_verify_locates_missing_checkpoint(client, chain_env):
    record_events(6)
    from app.database import get_connection

    get_connection().execute("DELETE FROM audit_checkpoints WHERE seq_end=3")
    result = verify_service().verify()
    assert result["status"] == "broken"
    assert result["first_failure"]["kind"] == "checkpoint_missing"
    assert result["first_failure"]["seq"] == 3


def test_concurrent_writes_get_unique_order(client, chain_env):
    from app.database import close_connection, get_connection, transaction
    from app.services.audit import AuditContext, AuditService

    record_events(1)  # 先初始化链，聚焦测试并发序号唯一性

    def worker(count: int) -> None:
        try:
            for _ in range(count):
                with transaction(immediate=True) as connection:
                    AuditService(connection).record(
                        AuditContext(None, "并发写入"), action="test.concurrent", resource_type="test"
                    )
        finally:
            close_connection()

    threads = [threading.Thread(target=worker, args=(5,)) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    seqs = [row[0] for row in get_connection().execute("SELECT seq FROM audit_events ORDER BY seq").fetchall()]
    assert seqs == list(range(1, 32))
    assert verify_service().verify()["status"] == "ok"


def test_legacy_stock_sealed_from_genesis(client, chain_env):
    from app.database import get_connection, transaction
    from app.services.audit import AuditService

    connection = get_connection()
    for index in range(5):
        connection.execute(
            "INSERT INTO audit_events(actor_name,action,resource_type,outcome,metadata_json,created_at) "
            "VALUES(?,?,?,?,?,?)",
            ("历史操作者", f"legacy.action.{index}", "legacy", "success", "{}", "2026-09-20T08:00:00+00:00"),
        )
    status = verify_service().status()
    assert status["initialized"] is False
    assert status["pending_legacy_events"] == 5

    result = AuditService(connection).initialize_chain()
    assert result["initialized"] is True
    assert result["backfilled_events"] == 5
    assert result["checkpoints_created"] == 1

    rows = connection.execute("SELECT seq,prev_digest FROM audit_events ORDER BY seq").fetchall()
    assert [row["seq"] for row in rows] == [1, 2, 3, 4, 5]
    assert rows[0]["prev_digest"] == GENESIS_DIGEST
    checkpoint = connection.execute("SELECT * FROM audit_checkpoints ORDER BY seq_end").fetchone()
    assert (checkpoint["seq_start"], checkpoint["seq_end"]) == (1, 3)
    assert verify_service().verify()["status"] == "ok"

    again = AuditService(connection).initialize_chain()
    assert again["initialized"] is False
    assert again["backfilled_events"] == 0


def test_incremental_verification_resumes_after_failure(client, chain_env):
    from app.database import get_connection, transaction

    record_events(10)
    with transaction(immediate=True):
        first = verify_service().run_incremental(max_chunks=1)
    assert first["status"] == "ok"
    assert first["last_verified_seq"] == 4
    assert first["has_more"] is True

    get_connection().execute("UPDATE audit_events SET after_json=? WHERE seq=7", ('{"被改": true}',))
    with transaction(immediate=True):
        broken = verify_service().run_incremental(max_chunks=1)
    assert broken["status"] == "broken"
    assert broken["first_failure"]["kind"] == "digest_mismatch"
    assert broken["first_failure"]["seq"] == 7
    assert broken["last_verified_seq"] == 4

    # 重启后（新的服务对象）从持久化进度继续，仍定位同一处断裂
    with transaction(immediate=True):
        resumed = verify_service().run_incremental(max_chunks=1)
    assert resumed["status"] == "broken"
    assert resumed["first_failure"]["seq"] == 7
    assert resumed["last_verified_seq"] == 4

    state = get_connection().execute("SELECT * FROM audit_verify_state WHERE id=1").fetchone()
    assert state["last_status"] == "broken"
    assert json.loads(state["failure_json"])["seq"] == 7


def test_incremental_rechecks_history_on_next_pass(client, chain_env):
    from app.database import get_connection, transaction

    record_events(6)
    with transaction(immediate=True):
        assert verify_service().run_incremental()["status"] == "ok"
    # 数据库管理员直接改库：篡改已经被校验过的历史记录
    get_connection().execute("UPDATE audit_events SET after_json=? WHERE seq=2", ('{"被改": 1}',))
    with transaction(immediate=True):
        result = verify_service().run_incremental()
    assert result["status"] == "broken"
    assert result["first_failure"]["kind"] == "digest_mismatch"
    assert result["first_failure"]["seq"] == 2


def test_incremental_verification_completes_and_verifies_only_new_tail(client, chain_env):
    from app.database import transaction

    record_events(10)
    with transaction(immediate=True):
        result = verify_service().run_incremental()
    assert result["status"] == "ok"
    assert result["last_verified_seq"] == 10
    assert result["has_more"] is False

    record_events(3)
    with transaction(immediate=True):
        tail = verify_service().run_incremental()
    assert tail["status"] == "ok"
    assert tail["verified_events"] == 3
    assert tail["last_verified_seq"] == 13

    state = verify_service().status()["verification"]
    assert state["last_status"] == "ok"
    assert state["runs_completed"] == 2


def test_export_bundle_has_no_secrets_and_recomputes(client, chain_env):
    from app.database import get_connection, transaction
    from app.services.audit import AuditContext, AuditService

    with transaction(immediate=True) as connection:
        service = AuditService(connection)
        service.record(
            AuditContext(None, "测试员"),
            action="user.create",
            resource_type="user",
            after={"username": "someone", "password": "Plain!23456", "password_hash": "pbkdf2$secret"},
            metadata={"authorization": "Bearer raw-token", "token": "tok-123", "note": "保留字段"},
        )
    record_events(2)

    bundle = verify_service().export_bundle()
    serialized = json.dumps(bundle, ensure_ascii=False)
    for leaked in ("Plain!23456", "pbkdf2$secret", "Bearer raw-token", "tok-123"):
        assert leaked not in serialized
    assert "保留字段" in serialized

    previous = GENESIS_DIGEST
    for event in bundle["events"]:
        document = event_document(seq=event["seq"], prev_digest=event["prev_digest"], **event["content"])
        assert event_digest(document) == event["digest"]
        assert event["prev_digest"] == previous
        previous = event["digest"]
    assert bundle["chain"]["head_digest"] == previous

    checkpoint_previous = GENESIS_DIGEST
    for checkpoint in bundle["checkpoints"]:
        document = checkpoint_document(
            seq_start=checkpoint["seq_start"],
            seq_end=checkpoint["seq_end"],
            event_count=checkpoint["event_count"],
            chain_head_digest=checkpoint["chain_head_digest"],
            prev_checkpoint_digest=checkpoint["prev_checkpoint_digest"],
        )
        assert checkpoint_digest(document) == checkpoint["digest"]
        assert checkpoint["prev_checkpoint_digest"] == checkpoint_previous
        checkpoint_previous = checkpoint["digest"]


def test_prune_keeps_chain_verifiable(client, chain_env):
    from app.core.security import Principal
    from app.database import get_connection, transaction
    from app.services.maintenance import MaintenanceService

    record_events(7)
    connection = get_connection()
    connection.execute("UPDATE audit_events SET created_at='2020-01-01T00:00:00+00:00' WHERE seq<=6")
    principal = Principal(
        user_id=1, username="admin", display_name="管理员", department_id=None,
        permissions=frozenset({"jobs.run"}), session_id=1,
    )
    with transaction(immediate=True) as txn:
        result = MaintenanceService(txn).prune_audit(principal)
    assert result["deleted_events"] == 6
    assert result["seq_through"] == 6

    remaining = [row[0] for row in connection.execute("SELECT seq FROM audit_events ORDER BY seq").fetchall()]
    assert remaining == [7]
    verification = verify_service().verify()
    assert verification["status"] == "ok"
    assert verification["anchor"] == {"kind": "truncation", "seq": 6}
    assert verification["range"]["from_seq"] == 7

    bundle = verify_service().export_bundle()
    assert bundle["truncation"]["seq_through"] == 6
    assert [event["seq"] for event in bundle["events"]] == [7]
    # 被清理区段的检查点仍保留，作为历史证明
    assert [row["seq_end"] for row in bundle["checkpoints"]] == [3, 6]


def test_old_schema_database_is_migrated_and_sealed(tmp_path, monkeypatch, chain_env):
    import sqlite3

    db_path = tmp_path / "old.db"
    legacy = sqlite3.connect(str(db_path))
    legacy.executescript(
        """
        CREATE TABLE audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_user_id INTEGER, actor_name TEXT NOT NULL, action TEXT NOT NULL,
            resource_type TEXT NOT NULL, resource_id TEXT,
            outcome TEXT NOT NULL CHECK(outcome IN ('success','denied','failure')),
            before_json TEXT, after_json TEXT, metadata_json TEXT NOT NULL DEFAULT '{}',
            correlation_id TEXT, created_at TEXT NOT NULL
        );
        """
    )
    for index in range(2):
        legacy.execute(
            "INSERT INTO audit_events(actor_name,action,resource_type,outcome,metadata_json,created_at) "
            "VALUES(?,?,?,?,?,?)",
            ("旧管理员", f"legacy.action.{index}", "legacy", "success", "{}", "2026-09-01T08:00:00+00:00"),
        )
    legacy.commit()
    legacy.close()

    monkeypatch.setenv("TOWNSHIP_DATABASE_PATH", str(db_path))
    from app.database import close_connection, get_connection, init_db

    close_connection()
    init_db()
    columns = {row[1] for row in get_connection().execute("PRAGMA table_info(audit_events)").fetchall()}
    assert {"seq", "prev_digest", "digest"} <= columns

    from app.services.audit import AuditService

    result = AuditService(get_connection()).initialize_chain()
    assert result["backfilled_events"] == 2
    assert result["checkpoints_created"] == 0  # 不足一个固定批次，等待后续事件补齐
    assert verify_service().verify()["status"] == "ok"
    record_events(1)
    checkpoints = get_connection().execute("SELECT seq_start,seq_end FROM audit_checkpoints").fetchall()
    assert [(row[0], row[1]) for row in checkpoints] == [(1, 3)]
    close_connection()


def test_chain_api_endpoints(client, admin, chain_env):
    status = client.get("/api/audit/chain/status", headers=admin["headers"])
    assert status.status_code == 200
    body = status.json()
    assert body["initialized"] is True
    assert body["last_seq"] >= 2

    verify = client.get("/api/audit/verify", headers=admin["headers"])
    assert verify.status_code == 200
    assert verify.json()["status"] == "ok"

    run = client.post("/api/audit/verify/run", headers=admin["headers"])
    assert run.status_code == 200
    assert run.json()["status"] == "ok"
    assert run.json()["has_more"] is False

    export = client.get("/api/audit/chain/export", headers=admin["headers"])
    assert export.status_code == 200
    bundle = export.json()
    assert bundle["format"] == "township-audit-chain/1"
    assert "Admin!23456" not in json.dumps(bundle, ensure_ascii=False)


def test_chain_api_requires_permission(client, admin):
    assert client.get("/api/audit/verify").status_code == 401
    created = client.post(
        "/api/users",
        headers=admin["headers"],
        json={"username": "no.perm", "password": "NoPerm!23456", "display_name": "无权限用户", "role_codes": []},
    )
    assert created.status_code == 201
    login = client.post("/api/auth/login", json={"username": "no.perm", "password": "NoPerm!23456", "client_label": "tests"})
    headers = {"Authorization": f"Bearer {login.json()['token']}"}
    assert client.get("/api/audit/verify", headers=headers).status_code == 403
    assert client.get("/api/audit/chain/status", headers=headers).status_code == 403
    assert client.post("/api/audit/verify/run", headers=headers).status_code == 403
