from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.api.dependencies import current_principal
from app.core.pagination import Page, page_result
from app.core.security import Principal
from app.database import get_connection, transaction
from app.repositories.audit import AuditRepository
from app.services.audit_integrity import AuditIntegrityService

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


@router.get("/integrity/verify")
def verify_audit_integrity(
    start_seq: int | None = Query(None, ge=1),
    end_seq: int | None = Query(None, ge=1),
    principal: Principal = Depends(current_principal),
) -> dict:
    """顺序校验审计链，定位第一处断裂、缺号或重排。"""
    principal.require("audit.read")
    return AuditIntegrityService(get_connection()).verify(start_seq=start_seq, end_seq=end_seq)


@router.get("/integrity/checkpoints")
def list_audit_checkpoints(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    principal: Principal = Depends(current_principal),
) -> dict:
    principal.require("audit.read")
    pagination = Page(page, size)
    result = AuditIntegrityService(get_connection()).list_checkpoints(limit=size, offset=pagination.offset)
    return page_result(total=result["total"], page=pagination, rows=result["data"])


@router.get("/integrity/export")
def export_audit_integrity(
    include_events: bool = False,
    principal: Principal = Depends(current_principal),
) -> dict:
    """导出验证材料：只含序号与摘要，不含任何密钥或明文凭据。"""
    principal.require("audit.read")
    return AuditIntegrityService(get_connection()).export_material(include_events=include_events)


@router.get("/integrity/verification-runs/latest")
def latest_audit_verification_run(principal: Principal = Depends(current_principal)) -> dict:
    principal.require("audit.read")
    return {"run": AuditIntegrityService(get_connection()).latest_run()}


@router.post("/integrity/anchor")
def anchor_audit_integrity(principal: Principal = Depends(current_principal)) -> dict:
    """把历史存量事件锚定入链，从明确起点建立首个检查点；可重复调用。"""
    principal.require("jobs.run")
    with transaction(immediate=True) as connection:
        return AuditIntegrityService(connection).anchor(triggered_by=principal.username)


@router.post("/integrity/verification-runs", status_code=201)
def run_audit_verification(
    chunk_size: int | None = Query(None, ge=1, le=100_000),
    chunks: int = Query(1, ge=1, le=100),
    principal: Principal = Depends(current_principal),
) -> dict:
    """启动或断点续跑定期校验任务，每次调用处理指定数量的分块。"""
    principal.require("jobs.run")
    service = AuditIntegrityService(get_connection())
    started = service.start_or_resume_run(triggered_by=principal.username, chunk_size=chunk_size)
    run = service.process_run(started["run"]["id"], chunks=chunks)
    return {"run": run, "resumed": started["resumed"]}
