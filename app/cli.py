from __future__ import annotations

import argparse
import json

from fastapi.testclient import TestClient

from app.database import database_path, get_connection, init_db, transaction
from app.main import app


def command_init() -> int:
    init_db()
    print(json.dumps({"database": str(database_path()), "status": "initialized"}, ensure_ascii=False))
    return 0


def command_check() -> int:
    init_db()
    connection = get_connection()
    result = {
        "database": str(database_path()),
        "integrity": connection.execute("PRAGMA integrity_check").fetchone()[0],
        "foreign_keys": connection.execute("PRAGMA foreign_keys").fetchone()[0],
        "journal_mode": connection.execute("PRAGMA journal_mode").fetchone()[0],
        "tables": connection.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0],
    }
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["integrity"] == "ok" and result["foreign_keys"] == 1 else 1


def command_smoke() -> int:
    with TestClient(app) as client:
        root = client.get("/")
        health = client.get("/api/system/health")
    result = {"root": root.json(), "health": health.json(), "status_codes": [root.status_code, health.status_code]}
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["status_codes"] == [200, 200] else 1


def command_audit_chain_init() -> int:
    """为历史存量从明确起点建立首个检查点（幂等）。"""
    from app.services.audit import AuditService

    init_db()
    with transaction(immediate=True) as connection:
        result = AuditService(connection).initialize_chain()
    print(json.dumps({"database": str(database_path()), **result}, ensure_ascii=False))
    return 0


def command_audit_verify() -> int:
    """执行增量校验；每推进一块就提交一次进度，失败和重启后可继续。"""
    from app.services.audit_verify import AuditVerifyService

    init_db()
    while True:
        with transaction(immediate=True) as connection:
            result = AuditVerifyService(connection).run_incremental(max_chunks=1)
        if result["status"] == "broken" or not result["has_more"]:
            break
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["status"] == "ok" else 1


def main() -> int:
    parser = argparse.ArgumentParser(prog="township-service", description="乡镇政务协同服务维护入口")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("init-db", help="初始化 SQLite 数据库")
    subparsers.add_parser("check-db", help="检查数据库完整性")
    subparsers.add_parser("smoke", help="执行本地 API 冒烟检查")
    subparsers.add_parser("audit-chain-init", help="为历史审计记录建立哈希链与首个检查点")
    subparsers.add_parser("audit-verify", help="执行一轮增量审计链校验（可周期运行）")
    args = parser.parse_args()
    handlers = {
        "init-db": command_init,
        "check-db": command_check,
        "smoke": command_smoke,
        "audit-chain-init": command_audit_chain_init,
        "audit-verify": command_audit_verify,
    }
    return handlers[args.command]()


if __name__ == "__main__":
    raise SystemExit(main())
