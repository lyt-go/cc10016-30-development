"""威胁评估领域服务：评估与签发的入口都绑定调查交割清单。

规则：
  * 「开始评估」必须关联一份仍然有效的交割编号，并在其有效快照里指定巡护日志；
    草稿或带缺件的交割不算有效材料。
  * 「签发报告」把采用的交割编号、有效威胁位置、坐标描述、来源固化成复核依据，
    并同步生成一条现场补勘待办。
  * 已签发评估始终能凭交割编号回查原交割坐标与来源；即使交割后来被重核收，
    签发时采用的版本与描述也不变。
"""
from __future__ import annotations

from typing import Any

from app.services import handover
from app.services.base import BaseModuleService
from app.store import store


class ThreatAssessmentService(BaseModuleService):
    MODULE = "threat_assessment"
    ENTITY = "评估报告"
    OPERATION_TERM = "开始评估"
    LIST_FIELDS = [
        "评估对象", "威胁类别", "威胁程度", "影响范围", "缓解建议",
        "评估人", "评估日期", "交割编号", "复核依据", "有效威胁位置", "有效坐标描述", "备注说明",
    ]
    REQUIRED_FIELDS = ["评估对象", "威胁类别", "威胁程度"]
    STATUS_ORDER = ["待评估", "评估中", "已签发", "需更新"]
    ACTION_RULES = {"开始评估": "评估中", "签发报告": "已签发", "申请更新": "需更新"}
    NEGATIVE_ACTIONS = []

    def run_action(
        self,
        entry_id: int,
        action: str,
        params: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any] | None, str]:
        params = params or {}
        if action == "开始评估":
            return self._start(entry_id, params)
        if action == "签发报告":
            return self._issue(entry_id, params)
        return super().run_action(entry_id, action, params)

    def _start(self, entry_id: int, params: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
        entry = store.find(self.MODULE, entry_id)
        if entry is None:
            return None, f"{self.ENTITY} {entry_id} 不存在或已归档"
        handover_no = str(params.get("handover_no") or "").strip()
        if not handover_no:
            return None, "开始评估必须关联调查交割清单编号（handover_no）"

        record = handover.get_handover(handover_no)
        if record is None:
            return None, f"交割清单 {handover_no} 不存在"
        if not record.get("有效"):
            return None, f"交割 {handover_no} 当前状态为「{record.get('状态')}」，不能作为有效复核材料"

        patrol_id = params.get("patrol_id")
        items = handover.effective_logs(handover_no)
        if patrol_id not in (None, ""):
            item = handover.effective_item(handover_no, int(patrol_id))
            if item is None:
                return None, f"巡护日志 #{patrol_id} 不在交割 {handover_no} 的有效日志里"
        elif items:
            # 未指定日志时优先取与评估对象同名的巡护路线，否则取第一条。
            current_object = str(entry.get("评估对象", "")).strip()
            item = next(
                (candidate for candidate in items
                 if str(candidate.get("巡护路线", "")).strip() == current_object),
                items[0],
            )
        else:
            return None, f"交割 {handover_no} 没有可用于评估的有效日志"

        # 允许评估员从有效快照继续，或先取更正再核收：这里始终读「有效快照」。
        entry["status"] = "评估中"
        entry["pending"] = True
        entry["abnormal"] = False
        # 评估对象与所绑定的巡护日志必须一致，避免把 A 段的证据算到 B 段的评估上。
        route = str(item.get("巡护路线", "")).strip()
        current_object = str(entry.get("评估对象", "")).strip()
        if route and current_object and route != current_object:
            return None, (
                f"评估对象「{current_object}」与巡护日志 #{item['id']} 的路线「{route}」不一致，"
                "请选择对应的巡护日志或另建评估"
            )

        entry["交割编号"] = handover_no
        entry["交割版本"] = int(record.get("版本", 1))
        entry["关联巡护日志"] = int(item["id"])
        entry["有效威胁位置"] = item.get("威胁位置", "")
        entry["有效坐标描述"] = item.get("坐标描述", "")
        entry["评估对象"] = route or current_object
        entry["威胁类别"] = str(item.get("威胁类型", "")).strip() or entry.get("威胁类别", "")
        entry["影响范围"] = item.get("威胁位置", "") or entry.get("影响范围", "")
        entry["复核依据"] = handover.format_basis(item, handover_no, int(record.get("版本", 1)))
        return entry, f"评估已开始，依据交割 {handover_no} 的巡护日志 #{item['id']}"

    def _issue(self, entry_id: int, params: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
        entry = store.find(self.MODULE, entry_id)
        if entry is None:
            return None, f"{self.ENTITY} {entry_id} 不存在或已归档"
        handover_no = str(entry.get("交割编号") or "").strip()
        if not handover_no:
            return None, "评估尚未关联交割清单，不能签发"
        record = handover.get_handover(handover_no)
        if record is None:
            return None, f"交割清单 {handover_no} 不存在"

        patrol_id = int(entry.get("关联巡护日志") or 0) or None
        item = handover.effective_item(handover_no, patrol_id) if patrol_id else None
        if item is None:
            return None, f"交割 {handover_no} 中找不到关联巡护日志，不能签发"

        # 签发时把采用的版本与描述固化下来，后续交割重核收也不改写已签发内容。
        version = int(record.get("版本", 1))
        entry["status"] = "已签发"
        entry["pending"] = False
        entry["abnormal"] = False
        entry["交割编号"] = handover_no
        entry["交割版本"] = version
        entry["有效威胁位置"] = item.get("威胁位置", "")
        entry["有效坐标描述"] = item.get("坐标描述", "")
        entry["复核依据"] = handover.format_basis(item, handover_no, version)

        todo = handover.create_survey_todo(
            assessment_id=int(entry["id"]),
            handover_no=handover_no,
            segment=item.get("威胁位置", ""),
            coordinate=item.get("坐标描述", ""),
            source=item.get("证据来源", ""),
            operator=str(entry.get("评估人", "评估组")),
        )
        return entry, f"评估已签发，现场补勘待办 {todo['待办编号']} 已生成（{todo['勘查段']}）"
