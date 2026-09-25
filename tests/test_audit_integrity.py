from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.core.audit_chain import GENESIS_DIGEST, checkpoint_digest


@pytest.fixture()
def admin_batch2(client, monkeypatch):
    """在首次审计写入之前把检查点批次固定为 2。"""
    monkeypatch.setenv("TOWNSHIP_AUDIT_CHECKPOINT_SIZE", "2")
    response = client.post("/api/auth/bootstrap", json={"username": "admin", "password": "Admin!23456", "client_label": "tests"})
    assert response.status_code == 201, response.text
    login = client.post("/api/auth/login", json={"username": "admin", "password": "Admin!23456", "client_label": "tests"})
    assert login.status_code == 200, login.text
    return {"headers": {"Authorization": f"Bearer {login.json()['token']}"}}


def _verify(client, admin) -> dict:
    response = client.get("/api/audit/integrity/verify", headers=admin["headers"])
    assert response.status_code == 200, response.text
    return response.json()


def _create_user(client, admin, username: str) -> None:
    response = client.post(
        "/api/users",
        headers=admin["headers"],
        json={"username": username, "password": "Clerk!23456", "display_name": "经办员", "role_codes": []},
    )
    assert response.status_code == 201, response.text


def test_events_form_verifiable_chain(client, admin):
    _create_user(client, admin, "chain.user")
    body = _verify(client, admin)
    assert body["ok"] is True
    assert body["checked"] == body["head_seq"] >= 3
    assert body["head_digest"]

    events = client.get("/api/audit?size=100", headers=admin["headers"]).json()["data"]
    by_seq = sorted(events, key=lambda event: event["seq"])
    assert [event["seq"] for event in by_seq] == list(range(1, len(by_seq) + 1))
    assert by_seq[0]["prev_digest"] == GENESIS_DIGEST
    for previous, current in zip(by_seq, by_seq[1:]):
        assert current["prev_digest"] == previous["digest"]
    assert all(event["digest"] for event in by_seq)


def test_verify_locates_modified_event(client, admin):
    from app.database import get_connection

    get_connection().execute("UPDATE audit_events SET action='auth.logout' WHERE seq=2")
    body = _verify(client, admin)
    assert body["ok"] is False
    assert body["first_failure"]["kind"] == "digest_mismatch"
    assert body["first_failure"]["seq"] == 2
    assert body["checked"] == 1


def test_verify_locates_deleted_event(client, admin):
    from app.database import get_connection

    _create_user(client, admin, "gap.user")
    get_connection().execute("DELETE FROM audit_events WHERE seq=2")
    body = _verify(client, admin)
    assert body["ok"] is False
    assert body["first_failure"]["kind"] == "sequence_gap"
    assert body["first_failure"]["seq"] == 2


def test_verify_locates_relinked_event(client, admin):
    from app.database import get_connection

    get_connection().execute("UPDATE audit_events SET prev_digest=? WHERE seq=2", ("f" * 64,))
    body = _verify(client, admin)
    assert body["ok"] is False
    assert body["first_failure"]["kind"] == "chain_break"
    assert body["first_failure"]["seq"] == 2


def test_checkpoints_created_per_fixed_batch(client, admin_batch2):
    for index in range(4):
        _create_user(client, admin_batch2, f"batch.user{index}")

    checkpoints = client.get("/api/audit/integrity/checkpoints", headers=admin_batch2["headers"])
    assert checkpoints.status_code == 200
    listed = checkpoints.json()
    assert listed["total"] == 3  # 启动与登录产生 2 条，新增 4 条，共 6 条，每 2 条一个检查点
    first = sorted(listed["data"], key=lambda item: item["end_seq"])[0]
    assert (first["start_seq"], first["end_seq"], first["event_count"]) == (1, 2, 2)
    assert first["prev_checkpoint_digest"] == GENESIS_DIGEST

    body = _verify(client, admin_batch2)
    assert body["ok"] is True
    assert body["checkpoints_checked"] == 3


def test_verify_locates_missing_checkpoint(client, admin_batch2):
    _create_user(client, admin_batch2, "checkpoint.user")

    from app.database import get_connection

    get_connection().execute("DELETE FROM audit_checkpoints WHERE end_seq=2")
    body = _verify(client, admin_batch2)
    assert body["ok"] is False
    assert body["first_failure"]["kind"] == "checkpoint_missing"
    assert body["first_failure"]["seq"] == 2


def test_verify_locates_rewritten_checkpoint(client, admin_batch2):
    _create_user(client, admin_batch2, "checkpoint.rewrite1")
    _create_user(client, admin_batch2, "checkpoint.rewrite2")

    from app.database import get_connection

    connection = get_connection()
    row = connection.execute("SELECT * FROM audit_checkpoints WHERE end_seq=4").fetchone()
    forged = {
        "start_seq": row["start_seq"],
        "end_seq": row["end_seq"],
        "event_count": row["event_count"],
        "root_digest": "e" * 64,
        "prev_checkpoint_digest": row["prev_checkpoint_digest"],
    }
    connection.execute(
        "UPDATE audit_checkpoints SET root_digest=?,digest=? WHERE end_seq=4",
        (forged["root_digest"], checkpoint_digest(forged)),
    )
    body = _verify(client, admin_batch2)
    assert body["ok"] is False
    assert body["first_failure"]["kind"] == "checkpoint_root_mismatch"
    assert body["first_failure"]["seq"] == 4


def test_anchor_legacy_events_from_clear_start(client, monkeypatch):
    monkeypatch.setenv("TOWNSHIP_AUDIT_CHECKPOINT_SIZE", "3")
    from app.database import get_connection, init_db

    connection = get_connection()
    for index in range(5):
        connection.execute(
            "INSERT INTO audit_events(actor_name,action,resource_type,outcome,metadata_json,created_at) VALUES(?,?,?,?,?,?)",
            ("历史系统", "legacy.import", "legacy", "success", "{}", f"2026-01-0{index + 1}T00:00:00+00:00"),
        )

    init_db()  # 启动迁移应自动锚定历史存量
    head = connection.execute("SELECT last_seq,last_digest FROM audit_chain_state WHERE id=1").fetchone()
    assert head["last_seq"] == 5
    first = connection.execute("SELECT seq,prev_digest FROM audit_events ORDER BY seq LIMIT 1").fetchone()
    assert first["seq"] == 1 and first["prev_digest"] == GENESIS_DIGEST
    checkpoints = connection.execute("SELECT start_seq,end_seq,event_count FROM audit_checkpoints ORDER BY end_seq").fetchall()
    assert [(row["start_seq"], row["end_seq"], row["event_count"]) for row in checkpoints] == [(1, 3, 3)]

    from app.services.audit_integrity import AuditIntegrityService

    assert AuditIntegrityService(connection).verify()["ok"] is True
    again = AuditIntegrityService(connection).chain.anchor_legacy_events(checkpoint_size=3, now="2026-09-25T00:00:00+00:00")
    assert again["anchored"] == 0


def test_anchor_endpoint_requires_permission(client, admin):
    _create_user(client, admin, "no.jobs")
    login = client.post("/api/auth/login", json={"username": "no.jobs", "password": "Clerk!23456", "client_label": "tests"})
    response = client.post("/api/audit/integrity/anchor", headers={"Authorization": f"Bearer {login.json()['token']}"})
    assert response.status_code == 403
    allowed = client.post("/api/audit/integrity/anchor", headers=admin["headers"])
    assert allowed.status_code == 200
    assert allowed.json()["anchored"] == 0


def test_verification_run_resumes_and_completes(client, admin):
    for index in range(3):
        _create_user(client, admin, f"run.user{index}")

    first = client.post("/api/audit/integrity/verification-runs?chunk_size=2", headers=admin["headers"])
    assert first.status_code == 201, first.text
    run = first.json()["run"]
    assert first.json()["resumed"] is False
    assert run["status"] == "running"
    assert (run["checked_count"], run["next_seq"], run["target_seq"]) == (2, 3, 5)

    second = client.post("/api/audit/integrity/verification-runs?chunk_size=2", headers=admin["headers"])
    assert second.json()["resumed"] is True
    assert second.json()["run"]["checked_count"] == 4

    third = client.post("/api/audit/integrity/verification-runs?chunk_size=2", headers=admin["headers"])
    run = third.json()["run"]
    assert run["status"] == "completed"
    assert run["checked_count"] == 5

    latest = client.get("/api/audit/integrity/verification-runs/latest", headers=admin["headers"])
    assert latest.status_code == 200
    assert latest.json()["run"]["status"] == "completed"


def test_verification_run_finds_first_failure_and_restarts(client, admin):
    for index in range(3):
        _create_user(client, admin, f"fail.user{index}")

    from app.database import get_connection

    get_connection().execute("UPDATE audit_events SET outcome='denied' WHERE seq=4")
    drained = client.post("/api/audit/integrity/verification-runs?chunk_size=2&chunks=10", headers=admin["headers"])
    run = drained.json()["run"]
    assert run["status"] == "failed"
    assert run["first_failure"]["kind"] == "digest_mismatch"
    assert run["first_failure"]["seq"] == 4

    # 完整性失败的不会续跑，下一次从起点重新校验并再次定位同一处
    again = client.post("/api/audit/integrity/verification-runs?chunk_size=2&chunks=10", headers=admin["headers"])
    assert again.json()["resumed"] is False
    assert again.json()["run"]["first_failure"]["seq"] == 4


def test_verification_run_continues_after_execution_failure(client, admin):
    _create_user(client, admin, "resume.user")
    started = client.post("/api/audit/integrity/verification-runs?chunk_size=1", headers=admin["headers"])
    run_id = started.json()["run"]["id"]

    from app.database import get_connection

    get_connection().execute(
        "UPDATE audit_verification_runs SET status='failed',error_message='模拟执行中断' WHERE id=?",
        (run_id,),
    )
    resumed = client.post("/api/audit/integrity/verification-runs?chunk_size=100&chunks=10", headers=admin["headers"])
    assert resumed.json()["resumed"] is True
    run = resumed.json()["run"]
    assert run["id"] == run_id
    assert run["status"] == "completed"
    assert run["checked_count"] == run["target_seq"]


def test_export_material_contains_only_digests(client, admin):
    _create_user(client, admin, "export.user")
    response = client.get("/api/audit/integrity/export?include_events=true", headers=admin["headers"])
    assert response.status_code == 200
    material = response.json()
    assert material["format"] == "township-audit-integrity/v1"
    assert material["chain_head"]["last_seq"] >= 3
    assert set(material["events"][0].keys()) == {"seq", "prev_digest", "digest"}

    serialized = json.dumps(material, ensure_ascii=False)
    for leaked in ("Clerk!23456", "Admin!23456", "password", "token", "secret", "authorization"):
        assert leaked not in serialized


def test_prune_audit_refuses_to_delete_chained_events(client, admin):
    from app.database import get_connection

    get_connection().execute("UPDATE audit_events SET created_at='2020-01-01T00:00:00+00:00' WHERE seq=1")
    response = client.post("/api/maintenance/prune/audit", headers=admin["headers"])
    assert response.status_code == 409


def test_concurrent_appends_get_unique_sequence(tmp_path, monkeypatch):
    monkeypatch.setenv("TOWNSHIP_DATABASE_PATH", str(tmp_path / "concurrent.db"))
    monkeypatch.setenv("TOWNSHIP_AUDIT_CHECKPOINT_SIZE", "4")
    from app.database import close_connection, database_path, init_db

    close_connection()
    init_db()
    path = database_path()

    def write_batch(worker: int) -> int:
        from app.repositories.audit import AuditRepository

        connection = sqlite3.connect(path, check_same_thread=False, timeout=30, isolation_level=None)
        try:
            connection.execute("PRAGMA busy_timeout=30000")
            repository = AuditRepository(connection)
            for index in range(5):
                repository.append(
                    actor_user_id=None,
                    actor_name=f"worker-{worker}",
                    action="load.test",
                    resource_type="load",
                    resource_id=index,
                    outcome="success",
                    before=None,
                    after=None,
                    metadata={"worker": worker},
                    correlation_id=None,
                    created_at="2026-09-25T00:00:00+00:00",
                    checkpoint_size=4,
                )
            return worker
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sorted(pool.map(write_batch, range(8))) == list(range(8))

    connection = sqlite3.connect(path, isolation_level=None)
    connection.row_factory = sqlite3.Row
    try:
        seqs = [row["seq"] for row in connection.execute("SELECT seq FROM audit_events ORDER BY seq")]
        assert seqs == list(range(1, 41))
        assert connection.execute("SELECT COUNT(*) FROM audit_checkpoints").fetchone()[0] == 10

        from app.services.audit_integrity import AuditIntegrityService

        result = AuditIntegrityService(connection).verify()
        assert result["ok"] is True
        assert result["checked"] == 40
    finally:
        connection.close()
        close_connection()
