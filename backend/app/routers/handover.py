"""调查交割清单 API：建立交割、导出/登记正式证据、补传更正、重核收与回查。"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel, Field

from app.services import handover

router = APIRouter(prefix="/api/handover", tags=["调查交割清单"])


class HandoverCreate(BaseModel):
    patrol_ids: list[int]
    operator: str = "巡护组"
    receiver: str = "威胁评估组"
    mode: str = "issue"  # issue=正式发交割；missing=缺件登记
    remark: str = ""


class CorrectionCreate(BaseModel):
    patrol_id: int
    threat_position: str | None = None
    coordinate: str | None = None
    source: str | None = None
    operator: str = "巡护组"
    remark: str = ""


class OperatorPayload(BaseModel):
    operator: str = "夜班"


class ReacceptPayload(BaseModel):
    correction_id: int
    operator: str = "威胁评估组"


class ResubmitPayload(BaseModel):
    patrol_ids: list[int]
    operator: str = "夜班"


def _require(handover_no: str) -> dict:
    record = handover.get_handover(handover_no)
    if record is None:
        raise HTTPException(status_code=404, detail=f"交割清单 {handover_no} 不存在")
    return record


@router.get("")
def list_handovers() -> dict:
    return {"items": handover.list_handovers(), "total": len(handover.list_handovers())}


@router.post("")
def create(payload: HandoverCreate) -> dict:
    result = handover.create_handover(
        payload.patrol_ids,
        operator=payload.operator,
        receiver=payload.receiver,
        mode=payload.mode,
        remark=payload.remark,
    )
    if not result.get("ok", True):
        raise HTTPException(status_code=400, detail=result)
    return result


@router.post("/resubmit")
def resubmit(payload: ResubmitPayload) -> dict:
    return handover.resubmit(payload.patrol_ids, operator=payload.operator)


@router.get("/todos")
def list_todos() -> dict:
    return {"items": handover.list_todos()}


@router.get("/{handover_no}")
def detail(handover_no: str) -> dict:
    return _require(handover_no)


@router.get("/{handover_no}/basis")
def basis(handover_no: str) -> dict:
    result = handover.basis(handover_no)
    if result is None:
        raise HTTPException(status_code=404, detail=f"交割清单 {handover_no} 不存在")
    return result


@router.get("/{handover_no}/export")
def export_package(handover_no: str, operator: str = "夜班") -> Response:
    record, content = handover.export_snapshot(handover_no, operator=operator)
    if record is None:
        raise HTTPException(status_code=400, detail=content)
    return Response(
        content=content.encode("utf-8"),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{handover_no}.csv"',
            "X-Handover-No": handover_no,
            "X-Handover-Version": str(record["版本"]),
        },
    )


@router.post("/{handover_no}/register-evidence")
def register_evidence(handover_no: str, payload: OperatorPayload) -> dict:
    record, message = handover.register_formal_evidence(handover_no, operator=payload.operator)
    if record is None:
        raise HTTPException(status_code=400, detail=message)
    return {"ok": True, "message": message, "handover": record}


@router.get("/{handover_no}/corrections")
def list_corrections(handover_no: str) -> dict:
    _require(handover_no)
    items = handover.list_corrections(handover_no)
    return {"items": items, "total": len(items)}


@router.post("/{handover_no}/corrections")
def add_correction(handover_no: str, payload: CorrectionCreate) -> dict:
    result = handover.add_correction(
        handover_no,
        payload.patrol_id,
        threat_position=payload.threat_position,
        coordinate=payload.coordinate,
        source=payload.source,
        operator=payload.operator,
        remark=payload.remark,
    )
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result)
    return result


@router.post("/{handover_no}/reaccept")
def reaccept(handover_no: str, payload: ReacceptPayload) -> dict:
    result = handover.reaccept(handover_no, payload.correction_id, operator=payload.operator)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result)
    return result
