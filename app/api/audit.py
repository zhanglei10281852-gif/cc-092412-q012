from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.api.dependencies import current_principal
from app.core.pagination import Page, page_result
from app.core.security import Principal
from app.database import get_connection, transaction
from app.repositories.audit import AuditRepository
from app.services.audit_verify import AuditVerifyService

router = APIRouter(prefix="/api/audit", tags=["审计记录"])


@router.get("")
def list_audit_events(
    actor_user_id: int | None = None,
    resource_type: str | None = None,
    action: str | None = None,
    outcome: str | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    principal: Principal = Depends(current_principal),
) -> dict:
    principal.require("audit.read")
    pagination = Page(page, size)
    repository = AuditRepository(get_connection())
    rows = repository.list(
        actor_user_id=actor_user_id,
        resource_type=resource_type,
        action=action,
        outcome=outcome,
        limit=size,
        offset=pagination.offset,
    )
    conditions: list[str] = []
    params: list = []
    for column, value in (("actor_user_id", actor_user_id), ("resource_type", resource_type), ("action", action), ("outcome", outcome)):
        if value is not None:
            conditions.append(f"{column}=?")
            params.append(value)
    query = "SELECT COUNT(*) FROM audit_events" + (" WHERE " + " AND ".join(conditions) if conditions else "")
    total = int(get_connection().execute(query, tuple(params)).fetchone()[0])
    return page_result(total=total, page=pagination, rows=rows)


@router.get("/chain/status")
def chain_status(principal: Principal = Depends(current_principal)) -> dict:
    principal.require("audit.read")
    return AuditVerifyService(get_connection()).status()


@router.get("/chain/export")
def export_chain(
    from_seq: int | None = None,
    to_seq: int | None = None,
    principal: Principal = Depends(current_principal),
) -> dict:
    """导出验证材料：仅含脱敏后的规范化内容与摘要，不含任何密钥或明文凭据。"""
    principal.require("audit.read")
    return AuditVerifyService(get_connection()).export_bundle(from_seq, to_seq)


@router.get("/verify")
def verify_chain(
    from_seq: int | None = None,
    to_seq: int | None = None,
    principal: Principal = Depends(current_principal),
) -> dict:
    """校验链条连续性，定位第一处断裂、缺号或重排。"""
    principal.require("audit.read")
    return AuditVerifyService(get_connection()).verify(from_seq, to_seq)


@router.post("/verify/run")
def run_verification(
    chunk_size: int | None = Query(default=None, ge=1),
    principal: Principal = Depends(current_principal),
) -> dict:
    """执行一轮增量校验；进度落库，失败和重启后可从上次位置继续。"""
    principal.require("jobs.run")
    with transaction(immediate=True) as connection:
        return AuditVerifyService(connection).run_incremental(chunk_size=chunk_size)
