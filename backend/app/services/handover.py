"""调查交割清单领域服务。

巡护日志只有「已审阅」才可能成为签发证据；草稿只能登记缺件，不能冒充复核材料。
交割清单在交接时冻结一份现场证据快照，后续更正不会改写原快照，只会作为关联更正
单独登记。威胁评估「开始评估」必须引用有效交割里的日志，「签发报告」再把结果同步
到现场补勘待办。

并发约束：
  * 同一批巡护日志只允许存在一份有效交割；夜班重投若命中已有有效交割，只登记重投
    记录并返回原交割，不再新增一次复核。
  * 补传更正可以晚于导出到达，仍挂在同一交割编号下；重核收只更新「有效快照」，
    原快照与更正关联都保留，不会把一次巡护算成两次独立复核。
"""
from __future__ import annotations

import csv
import io
import threading
from datetime import datetime
from typing import Any

from app.store import store

# 交割状态
DRAFT = "草稿"
MISSING = "缺件登记"
ISSUED = "已交割"
EXPORTED = "已导出（待登记正式证据）"
REGISTERED = "已登记正式证据"
SUPERSEDED = "已重核收"

VALID_STATUSES = {ISSUED, EXPORTED, REGISTERED}

_lock = threading.RLock()
_handovers: list[dict[str, Any]] = []
_corrections: list[dict[str, Any]] = []
_todos: list[dict[str, Any]] = []
_counters: dict[str, int] = {}


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _next_seq(prefix: str) -> int:
    _counters[prefix] = _counters.get(prefix, 0) + 1
    return _counters[prefix]


def _patrol_snapshot(patrol: dict[str, Any]) -> dict[str, Any]:
    """冻结一条巡护日志的证据字段；后续日志再改也不影响这份快照。"""
    return {
        "id": int(patrol.get("id", 0)),
        "巡护路线": str(patrol.get("巡护路线", "")),
        "巡护人员": str(patrol.get("巡护人员", "")),
        "威胁类型": str(patrol.get("威胁类型", "")),
        "威胁位置": str(patrol.get("威胁位置", "")),
        "坐标描述": str(patrol.get("坐标描述", "")),
        "证据来源": str(patrol.get("证据来源", "")),
        "巡护日期": str(patrol.get("巡护日期", "")),
        "发现情况": str(patrol.get("发现情况", "")),
        "审阅状态": str(patrol.get("status", "")),
    }


def _missing_items(patrols: list[dict[str, Any]]) -> list[str]:
    """列出草稿/缺件登记需要补齐的材料。"""
    items: list[str] = []
    for patrol in patrols:
        pid = patrol.get("id")
        if patrol.get("status") != "已审阅":
            items.append(f"巡护日志 #{pid} 尚未审阅（当前 {patrol.get('status')}），不能作为签发证据")
        if not str(patrol.get("证据来源") or "").strip():
            items.append(f"巡护日志 #{pid} 缺少现场证据来源")
        if not str(patrol.get("威胁位置") or "").strip():
            items.append(f"巡护日志 #{pid} 缺少威胁位置")
        if not str(patrol.get("坐标描述") or "").strip():
            items.append(f"巡护日志 #{pid} 缺少坐标描述")
    return items


def _survey_scope(snapshot: list[dict[str, Any]]) -> str:
    positions = []
    for item in snapshot:
        position = str(item.get("威胁位置", "")).strip()
        if position and position not in positions:
            positions.append(position)
    return "；".join(positions)


def format_basis(item: dict[str, Any], handover_no: str, version: int) -> str:
    return (
        f"{handover_no} v{version}：巡护日志 #{item.get('id')}，"
        f"威胁位置 {item.get('威胁位置', '')}，坐标 {item.get('坐标描述', '')}，"
        f"来源 {item.get('证据来源', '')}"
    )


def _find(handover_no: str) -> dict[str, Any] | None:
    for record in _handovers:
        if record["交割编号"] == handover_no or str(record["id"]) == str(handover_no):
            return record
    return None


def _active_valid_for(patrol_ids: set[int]) -> dict[str, Any] | None:
    """找到覆盖这些巡护日志且仍然有效的交割（用于重投幂等）。"""
    for record in _handovers:
        if not record.get("有效"):
            continue
        if patrol_ids & set(record["巡护日志"]):
            return record
    return None


def _covered_by(patrol_ids: set[int]) -> dict[int, dict[str, Any]]:
    """每条巡护日志当前已落在哪份有效交割里。"""
    covered: dict[int, dict[str, Any]] = {}
    for record in _handovers:
        if not record.get("有效"):
            continue
        for pid in record["巡护日志"]:
            covered.setdefault(int(pid), record)
    return covered


def review_count(record: dict[str, Any]) -> int:
    """一次巡护只算一次独立复核，重投/重核收不重复计数。"""
    return len(set(record.get("巡护日志", [])))


def create_handover(
    patrol_ids: list[int],
    *,
    operator: str,
    receiver: str = "威胁评估组",
    mode: str = "issue",
    remark: str = "",
) -> dict[str, Any]:
    """创建交割清单。mode=issue 要求全部已审阅；mode=missing 允许草稿登记缺件。"""
    with _lock:
        patrols = [store.find("patrol_record", int(pid)) for pid in patrol_ids]
        if any(patrol is None for patrol in patrols):
            missing_ids = [pid for pid, patrol in zip(patrol_ids, patrols) if patrol is None]
            return {"ok": False, "message": f"巡护日志不存在：{missing_ids}"}
        found = [patrol for patrol in patrols if patrol is not None]
        if not found:
            return {"ok": False, "message": "至少要选择一条巡护日志"}

        issues = _missing_items(found)
        reviewed = [patrol for patrol in found if patrol.get("status") == "已审阅"]
        if mode == "issue":
            if issues:
                return {
                    "ok": False,
                    "message": "只有审阅通过的巡护日志才能签发交割；草稿请改用缺件登记",
                    "missing": issues,
                }
            target = reviewed
            status = ISSUED
        else:
            target = found
            status = MISSING
            issues = issues or ["缺件登记：所选日志均无缺件，可改用正式发交割"]

        # 并发/重投：同一批日志已有有效交割时不再制造第二份有效交割。
        if mode == "issue":
            requested = {int(patrol["id"]) for patrol in target}
            covered = _covered_by(requested)
            existing = _active_valid_for(requested)
            if existing is not None:
                existing["重投记录"].append({
                    "时间": _now(),
                    "操作人": operator,
                    "说明": "夜班重投命中已有有效交割，只登记重投，不新增复核",
                })
                existing["备注"] = (existing.get("备注") or "") + "；重投已并入原交割"
                message = f"重复投递已并入已有有效交割 {existing['交割编号']}，不重复计复核"
                if covered and set(covered) != requested:
                    # 部分日志已交割：只把尚未交割的日志补进原交割，仍然只有一份有效交割。
                    extra = [pid for pid in requested if pid not in covered]
                    for patrol in target:
                        if int(patrol["id"]) in extra:
                            item = _patrol_snapshot(patrol)
                            existing["巡护日志"].append(int(patrol["id"]))
                            existing["日志摘要"].append(item)
                            existing["有效快照"].append(dict(item))
                    existing["后续勘查范围"] = _survey_scope(existing["有效快照"])
                    existing["复核次数"] = len(set(existing["巡护日志"]))
                    existing["版本"] = int(existing.get("版本", 1)) + 1
                    message += f"，并补入未交割日志 {extra}"
                return {
                    "ok": True,
                    "deduplicated": True,
                    "message": message,
                    "handover": existing,
                }

        seq = _next_seq(datetime.now().strftime("%Y%m%d"))
        handover_no = f"JH-{datetime.now().strftime('%Y%m%d')}-{seq:04d}"
        snapshot = [_patrol_snapshot(patrol) for patrol in target]
        record: dict[str, Any] = {
            "id": len(_handovers) + 1,
            "交割编号": handover_no,
            "状态": status,
            "交接人": operator,
            "接收人": receiver,
            "巡护日志": [int(patrol["id"]) for patrol in target],
            "日志摘要": snapshot,
            # 有效快照：重核收时只改这一份，原快照永远保留。
            "有效快照": [dict(item) for item in snapshot],
            "现场证据": "；".join(
                f"#{item['id']} {item['证据来源']}" for item in snapshot if item.get("证据来源")
            ),
            "后续勘查范围": _survey_scope(snapshot),
            "缺件": issues,
            "正式证据": False,
            "有效": status == ISSUED,
            "版本": 1,
            "导出状态": "未导出",
            "导出时间": "",
            "导出快照时间": "",
            "导出记录": [],
            "更正关联": [],
            "重投记录": [],
            "复核次数": len({int(patrol["id"]) for patrol in target}),
            "备注": remark,
            "创建时间": _now(),
        }
        _handovers.append(record)
        return {
            "ok": True,
            "deduplicated": False,
            "message": f"交割清单 {handover_no} 已建立" + ("（缺件登记）" if mode != "issue" else ""),
            "handover": record,
        }


def list_handovers() -> list[dict[str, Any]]:
    with _lock:
        return [
            dict(record, 日志摘要=[dict(i) for i in record["日志摘要"]],
                 有效快照=[dict(i) for i in record["有效快照"]])
            for record in _handovers
        ]


def _copy(record: dict[str, Any]) -> dict[str, Any]:
    """返回给调用方的副本：嵌套快照也要复制，避免外部顺手改到账本。"""
    copy = dict(record)
    copy["日志摘要"] = [dict(item) for item in record["日志摘要"]]
    copy["有效快照"] = [dict(item) for item in record["有效快照"]]
    copy["更正关联"] = list(record["更正关联"])
    copy["重投记录"] = [dict(item) for item in record["重投记录"]]
    copy["缺件"] = list(record["缺件"])
    copy["巡护日志"] = list(record["巡护日志"])
    return copy


def get_handover(handover_no: str) -> dict[str, Any] | None:
    with _lock:
        record = _find(handover_no)
        return _copy(record) if record else None


def export_snapshot(handover_no: str, *, operator: str = "夜班") -> tuple[dict[str, Any] | None, str]:
    """导出交割包。

    导出内容取当前「有效快照」，并把这一次导出所用的快照单独留档；此后到达的更正
    不算进已导出的包内。对外材料始终能按交割编号 + 导出版本取回当时的复核依据。
    """
    with _lock:
        record = _find(handover_no)
        if record is None:
            return None, "交割清单不存在"
        if not record["有效"]:
            return None, "缺件登记的交割不能作为正式证据导出"
        exported_at = _now()
        export_version = int(record.get("版本", 1))
        record["导出状态"] = "已导出（待登记正式证据）"
        record["导出时间"] = exported_at
        record["导出快照时间"] = exported_at
        record["状态"] = EXPORTED
        record["正式证据"] = False
        record.setdefault("导出记录", []).append({
            "导出版本": export_version,
            "导出时间": exported_at,
            "操作人": operator,
            "快照": [dict(item) for item in record["有效快照"]],
        })

        output = io.StringIO()
        output.write("﻿")
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow([
            "交割编号", "导出版本", "巡护日志", "巡护路线", "威胁类型",
            "威胁位置", "坐标描述", "证据来源", "巡护日期", "审阅状态",
        ])
        for item in record["有效快照"]:
            writer.writerow([
                record["交割编号"], export_version, item["id"], item["巡护路线"],
                item["威胁类型"], item["威胁位置"], item["坐标描述"],
                item["证据来源"], item["巡护日期"], item["审阅状态"],
            ])
        return record, output.getvalue()


def register_formal_evidence(handover_no: str, *, operator: str = "夜班") -> tuple[dict[str, Any] | None, str]:
    """夜班把导出的包登记为正式证据。"""
    with _lock:
        record = _find(handover_no)
        if record is None:
            return None, "交割清单不存在"
        if not record["有效"]:
            return None, "缺件登记的交割不能登记为正式证据"
        if record["状态"] == ISSUED:
            return None, "交割包尚未导出，不能登记为正式证据"
        record["正式证据"] = True
        record["状态"] = REGISTERED
        record["正式证据登记人"] = operator
        record["正式证据登记时间"] = _now()
        return record, f"交割 {handover_no} 已登记为正式证据"


def add_correction(
    handover_no: str,
    patrol_id: int,
    *,
    threat_position: str | None = None,
    coordinate: str | None = None,
    source: str | None = None,
    operator: str = "巡护组",
    remark: str = "",
) -> dict[str, Any]:
    """补传迟到更正：更新巡护日志本身，同时在交割下登记一条待核收更正。"""
    with _lock:
        record = _find(handover_no)
        if record is None:
            return {"ok": False, "message": "交割清单不存在"}
        if int(patrol_id) not in record["巡护日志"]:
            return {"ok": False, "message": f"巡护日志 #{patrol_id} 不在交割 {handover_no} 内"}
        patrol = store.find("patrol_record", int(patrol_id))
        if patrol is None:
            return {"ok": False, "message": f"巡护日志 #{patrol_id} 不存在"}

        original = next(
            (item for item in record["日志摘要"] if int(item["id"]) == int(patrol_id)), None
        )
        old_position = str(original.get("威胁位置", "")) if original else str(patrol.get("威胁位置", ""))
        old_coord = str(original.get("坐标描述", "")) if original else str(patrol.get("坐标描述", ""))
        new_position = str(threat_position if threat_position is not None else patrol.get("威胁位置", ""))
        new_coord = str(coordinate if coordinate is not None else patrol.get("坐标描述", ""))

        # 迟到更正同步回巡护日志，便于下一次巡护按图作业；但不动已冻结的快照。
        patrol["威胁位置"] = new_position
        if coordinate is not None:
            patrol["坐标描述"] = new_coord
        if source is not None:
            patrol["证据来源"] = source

        correction = {
            "id": len(_corrections) + 1,
            "更正编号": f"GZ-{datetime.now().strftime('%Y%m%d')}-{len(_corrections) + 1:04d}",
            "交割编号": handover_no,
            "巡护日志": int(patrol_id),
            "原威胁位置": old_position,
            "新威胁位置": new_position,
            "原坐标描述": old_coord,
            "新坐标描述": new_coord,
            "来源": source or str(patrol.get("证据来源", "")),
            "状态": "待核收",
            "操作人": operator,
            "到达时间": _now(),
            "说明": remark,
        }
        _corrections.append(correction)
        record["更正关联"].append(correction["更正编号"])
        # 状态保持原样，等评估员决定从已交割材料继续还是取更正后重核收。
        record["待核收更正"] = sum(
            1 for item in _corrections
            if item["交割编号"] == handover_no and item["状态"] == "待核收"
        )
        after_export = bool(record["导出时间"]) and correction["到达时间"] >= record["导出时间"]
        return {
            "ok": True,
            "message": f"更正 {correction['更正编号']} 已登记到交割 {handover_no}，待评估员核收",
            "correction": correction,
            "arrived_after_export": after_export,
            "entry_point": f"/api/handover/{handover_no}/corrections",
            "handover": record,
        }


def list_corrections(handover_no: str) -> list[dict[str, Any]]:
    with _lock:
        return [
            dict(item) for item in _corrections
            if item["交割编号"] == handover_no
        ]


def reaccept(handover_no: str, correction_id: int, *, operator: str = "威胁评估组") -> dict[str, Any]:
    """评估员取更正后重核收：更新有效快照，原快照与更正关联保留。"""
    with _lock:
        record = _find(handover_no)
        if record is None:
            return {"ok": False, "message": "交割清单不存在"}
        correction = next(
            (item for item in _corrections
             if item["id"] == int(correction_id) and item["交割编号"] == handover_no),
            None,
        )
        if correction is None:
            return {"ok": False, "message": f"交割 {handover_no} 下没有更正 #{correction_id}"}
        if correction["状态"] == "已核收":
            return {"ok": False, "message": f"更正 {correction['更正编号']} 已核收，不重复计入复核"}

        for item in record["有效快照"]:
            if int(item["id"]) == int(correction["巡护日志"]):
                item["威胁位置"] = correction["新威胁位置"]
                item["坐标描述"] = correction["新坐标描述"]
                item["证据来源"] = correction["来源"]
                break
        correction["状态"] = "已核收"
        correction["核收人"] = operator
        correction["核收时间"] = _now()
        record["版本"] = int(record.get("版本", 1)) + 1
        record["后续勘查范围"] = _survey_scope(record["有效快照"])
        record["待核收更正"] = sum(
            1 for item in _corrections
            if item["交割编号"] == handover_no and item["状态"] == "待核收"
        )
        # 重核收不新增交割、不新增复核次数，只保留更正关联。
        return {
            "ok": True,
            "message": f"交割 {handover_no} 已按更正 {correction['更正编号']} 重核收，版本 v{record['版本']}",
            "handover": record,
            "correction": correction,
        }


def resubmit(patrol_ids: list[int], *, operator: str = "夜班") -> dict[str, Any]:
    """夜班重投：命中有效交割就并入，不制造第二份有效交割。"""
    with _lock:
        existing = _active_valid_for({int(pid) for pid in patrol_ids})
        if existing is None:
            return create_handover(patrol_ids, operator=operator, mode="issue", remark="夜班重投")
        existing["重投记录"].append({
            "时间": _now(),
            "操作人": operator,
            "说明": "夜班重投并入已有有效交割，不重复计复核",
        })
        return {
            "ok": True,
            "deduplicated": True,
            "message": f"重投并入已有有效交割 {existing['交割编号']}，只保留一份有效交割",
            "handover": existing,
        }


def basis(handover_no: str) -> dict[str, Any] | None:
    """按采用的交割编号取回复核依据：原快照 + 有效快照 + 更正关联 + 引用它的签发。"""
    with _lock:
        record = _find(handover_no)
        if record is None:
            return None
        assessments = [
            row for row in store.rows("threat_assessment")
            if str(row.get("交割编号", "")) == handover_no
        ]
        return {
            "交割编号": record["交割编号"],
            "状态": record["状态"],
            "版本": record["版本"],
            "有效": record["有效"],
            "原快照": [dict(item) for item in record["日志摘要"]],
            "有效快照": [dict(item) for item in record["有效快照"]],
            "导出记录": [
                {
                    "导出版本": export.get("导出版本"),
                    "导出时间": export.get("导出时间"),
                    "操作人": export.get("操作人"),
                    "快照": [dict(item) for item in export.get("快照", [])],
                }
                for export in record.get("导出记录", [])
            ],
            "更正": [
                dict(item) for item in _corrections
                if item["交割编号"] == handover_no
            ],
            "复核次数": review_count(record),
            "签发引用": [
                {
                    "评估id": row.get("id"),
                    "评估对象": row.get("评估对象"),
                    "状态": row.get("status"),
                    "复核依据": row.get("复核依据"),
                    "有效威胁位置": row.get("有效威胁位置"),
                }
                for row in assessments
            ],
        }


def effective_logs(handover_no: str) -> list[dict[str, Any]]:
    """返回交割当前有效的日志快照；缺件/无效交割返回空列表。"""
    with _lock:
        record = _find(handover_no)
        if record is None or not record["有效"]:
            return []
        return [dict(item) for item in record["有效快照"]]


def effective_item(handover_no: str, patrol_id: int) -> dict[str, Any] | None:
    for item in effective_logs(handover_no):
        if int(item["id"]) == int(patrol_id):
            return item
    return None


def review_count_for_patrol(patrol_id: int) -> int:
    """一条巡护即使经历重投、更正、重核收，也只算一次独立复核。"""
    with _lock:
        return sum(
            1 for record in _handovers
            if record["有效"] and int(patrol_id) in record["巡护日志"]
        )


def create_survey_todo(
    *,
    assessment_id: int,
    handover_no: str,
    segment: str,
    coordinate: str,
    source: str,
    operator: str,
) -> dict[str, Any]:
    """签发后生成现场补勘待办；同一评估只保留一条，重复签发不重复派工。"""
    with _lock:
        for todo in _todos:
            if int(todo["评估id"]) == int(assessment_id):
                return todo
        todo = {
            "id": len(_todos) + 1,
            "待办编号": f"BK-{datetime.now().strftime('%Y%m%d')}-{len(_todos) + 1:04d}",
            "评估id": int(assessment_id),
            "交割编号": handover_no,
            "勘查段": segment,
            "坐标描述": coordinate,
            "来源": source,
            "状态": "待派工",
            "生成人": operator,
            "生成时间": _now(),
        }
        _todos.append(todo)
        return dict(todo)


def list_todos() -> list[dict[str, Any]]:
    with _lock:
        return [dict(todo) for todo in _todos]


def latest_todo() -> dict[str, Any] | None:
    with _lock:
        return dict(_todos[-1]) if _todos else None


# ---------------------------------------------------------------------------
# 种子：一条历史签发 + 其交割依据，保证「已有签发」可按编号回查。
# ---------------------------------------------------------------------------
def _seed() -> None:
    with _lock:
        if _handovers:
            return
        patrol = store.find("patrol_record", 3)
        if patrol is None:
            return
        snapshot = [_patrol_snapshot(patrol)]
        record = {
            "id": 1,
            "交割编号": "JH-20261128-0001",
            "状态": REGISTERED,
            "交接人": "巡护组-韩青",
            "接收人": "威胁评估组",
            "巡护日志": [3],
            "日志摘要": snapshot,
            "有效快照": [dict(item) for item in snapshot],
            "现场证据": "；".join(item["证据来源"] for item in snapshot),
            "后续勘查范围": _survey_scope(snapshot),
            "缺件": [],
            "正式证据": True,
            "有效": True,
            "版本": 1,
            "导出状态": "已导出（待登记正式证据）",
            "导出时间": "2026-11-28T08:10:00",
            "导出快照时间": "2026-11-28T08:10:00",
            "导出记录": [
                {
                    "导出版本": 1,
                    "导出时间": "2026-11-28T08:10:00",
                    "操作人": "夜班",
                    "快照": [dict(item) for item in snapshot],
                }
            ],
            "正式证据登记人": "夜班",
            "正式证据登记时间": "2026-11-28T08:20:00",
            "更正关联": [],
            "重投记录": [],
            "复核次数": 1,
            "备注": "南沟中段历史交割，供已签发评估回查",
            "创建时间": "2026-11-28T08:00:00",
        }
        _handovers.append(record)
        _todos.append({
            "id": 1,
            "待办编号": "BK-20261128-0001",
            "评估id": 1,
            "交割编号": "JH-20261128-0001",
            "勘查段": "南沟中段-1号样线",
            "坐标描述": "N31.1882 E121.3921",
            "来源": "现场照片8张、GPS轨迹",
            "状态": "已完成",
            "生成人": "评估组-何川",
            "生成时间": "2026-11-24T10:00:00",
        })
        _counters["20261128"] = 1


_seed()
