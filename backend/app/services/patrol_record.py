"""巡护日志领域服务：巡护发现是调查交割清单的唯一证据来源。

只有「已审阅」的日志能进入正式交割；草稿只能登记缺件。威胁位置/坐标/证据来源
是交接时冻结的关键字段，后续更正走交割清单的更正登记，不直接改写已交割快照。
"""
from __future__ import annotations

from app.services.base import BaseModuleService


class PatrolRecordService(BaseModuleService):
    MODULE = "patrol_record"
    ENTITY = "巡护日志"
    OPERATION_TERM = "提交日志"
    LIST_FIELDS = [
        "巡护路线", "巡护人员", "发现情况", "威胁类型", "威胁位置", "坐标描述",
        "处置措施", "巡护日期", "环境条件", "证据来源", "备注说明",
    ]
    REQUIRED_FIELDS = ["巡护路线", "巡护人员", "发现情况"]
    STATUS_ORDER = ["待填写", "已填写", "已审阅", "需跟进"]
    ACTION_RULES = {"提交日志": "已填写", "审阅通过": "已审阅", "标记跟进": "需跟进"}
    NEGATIVE_ACTIONS = []
