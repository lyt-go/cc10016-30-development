"""调查交割清单业务断言。

覆盖用户给出的关键场景：
  * 只有已审阅巡护日志能发交割；草稿只能缺件登记，不能当复核材料；
  * 导出期间收到迟到更正：导出包保持原快照，更正单独登记；
  * 评估员可选择从已交割材料继续，或取更正后重核收；
  * 补传更正与夜班重投并发到达：只有一份有效交割，更正关联保留，复核只算一次；
  * 已签发评估仍可按采用的交割编号回查到原坐标描述与来源；
  * 签发结果同步到现场补勘待办。
"""
from __future__ import annotations

import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services import handover
from app.services.threat_assessment import ThreatAssessmentService
from app.store import store


class HandoverBase(unittest.TestCase):
    """每个用例前重置交割账本，避免用例间互相影响。"""

    def setUp(self) -> None:
        handover._handovers.clear()
        handover._corrections.clear()
        handover._todos.clear()
        handover._counters.clear()
        handover._seed()
        store._tables["patrol_record"] = [dict(row) for row in _PATROLS]

    def issue_handover(self, patrol_ids: list[int], mode: str = "issue") -> dict:
        result = handover.create_handover(patrol_ids, operator="巡护组", mode=mode)
        self.assertTrue(result["ok"], result)
        return result["handover"]


_PATROLS = [
    {"id": 1, "status": "已审阅", "pending": False, "abnormal": False,
     "巡护路线": "北沟东段", "巡护人员": "周岚", "发现情况": "猎套3处",
     "威胁类型": "盗猎", "威胁位置": "北沟东段-2号样线",
     "坐标描述": "N31.2041 E121.4162", "证据来源": "现场照片12张", "巡护日期": "2026-11-25"},
    {"id": 2, "status": "已审阅", "pending": False, "abnormal": False,
     "巡护路线": "北沟西段", "巡护人员": "陈砚", "发现情况": "可疑人员",
     "威胁类型": "人为干扰", "威胁位置": "北沟西段-5号林班",
     "坐标描述": "N31.2098 E121.4044", "证据来源": "红外相机影像2段", "巡护日期": "2026-11-25"},
    {"id": 3, "status": "已审阅", "pending": False, "abnormal": False,
     "巡护路线": "南沟中段", "巡护人员": "韩青", "发现情况": "废弃营地",
     "威胁类型": "栖息地破坏", "威胁位置": "南沟中段-1号样线",
     "坐标描述": "N31.1882 E121.3921", "证据来源": "现场照片8张、GPS轨迹", "巡护日期": "2026-11-24"},
    {"id": 4, "status": "已填写", "pending": True, "abnormal": False,
     "巡护路线": "北沟南坡", "巡护人员": "李禾", "发现情况": "兽夹一处",
     "威胁类型": "盗猎", "威胁位置": "北沟南坡-临时点",
     "坐标描述": "N31.2010 E121.4101", "证据来源": "手机照片3张", "巡护日期": "2026-11-26"},
]


class TestIssueHandover(HandoverBase):
    def test_reviewed_logs_issue(self):
        record = self.issue_handover([1, 2])
        self.assertEqual(record["状态"], handover.ISSUED)
        self.assertTrue(record["有效"])
        self.assertEqual(record["巡护日志"], [1, 2])
        self.assertIn("北沟东段-2号样线", record["后续勘查范围"])

    def test_draft_cannot_issue(self):
        result = handover.create_handover([4], operator="巡护组", mode="issue")
        self.assertFalse(result["ok"])
        self.assertEqual(handover.list_handovers().__len__(), 1)  # 只有种子交割

    def test_draft_missing_registration(self):
        result = handover.create_handover([4], operator="巡护组", mode="missing")
        self.assertTrue(result["ok"])
        record = result["handover"]
        self.assertEqual(record["状态"], handover.MISSING)
        self.assertFalse(record["有效"])
        self.assertTrue(record["缺件"])
        self.assertIn("尚未审阅", "；".join(record["缺件"]))

    def test_missing_handover_cannot_export_or_start(self):
        record = handover.create_handover([4], operator="巡护组", mode="missing")["handover"]
        _, message = handover.export_snapshot(record["交割编号"])
        self.assertIn("缺件", message)
        svc = ThreatAssessmentService()
        entry, message = svc.run_action(2, "开始评估", {"handover_no": record["交割编号"]})
        self.assertIsNone(entry)
        self.assertIn("缺件登记", message)


class TestLateCorrection(HandoverBase):
    def test_export_is_frozen_and_correction_separate(self):
        record = self.issue_handover([1, 2])
        no = record["交割编号"]
        _, first = handover.export_snapshot(no)

        result = handover.add_correction(
            no, 2, threat_position="西沟北坡-7号林班",
            coordinate="N31.2140 E121.3877", source="补传红外影像3段")
        self.assertTrue(result["ok"])
        self.assertTrue(result["arrived_after_export"])
        self.assertEqual(result["entry_point"], f"/api/handover/{no}/corrections")

        # 导出后再取包内容不变；原快照仍是北沟，有效快照在核收前也不变。
        _, second = handover.export_snapshot(no)
        self.assertEqual(first, second)
        basis = handover.basis(no)
        self.assertIn("北沟西段-5号林班", basis["原快照"][1]["威胁位置"])
        self.assertIn("北沟西段-5号林班", basis["有效快照"][1]["威胁位置"])

    def test_reaccept_updates_effective_but_keeps_original(self):
        record = self.issue_handover([1, 2])
        no = record["交割编号"]
        result = handover.add_correction(no, 2, threat_position="西沟北坡-7号林班",
                                         coordinate="N31.2140 E121.3877")
        correction_id = result["correction"]["id"]
        reaccept = handover.reaccept(no, correction_id)
        self.assertTrue(reaccept["ok"])

        basis = handover.basis(no)
        self.assertEqual(basis["版本"], 2)
        self.assertIn("北沟西段-5号林班", basis["原快照"][1]["威胁位置"])
        self.assertIn("西沟北坡-7号林班", basis["有效快照"][1]["威胁位置"])
        self.assertEqual(len(basis["更正"]), 1)
        self.assertEqual(basis["复核次数"], 2)  # 两条日志，不因更正变三条

    def test_reaccept_twice_is_rejected(self):
        record = self.issue_handover([1, 2])
        no = record["交割编号"]
        cid = handover.add_correction(no, 2, threat_position="西沟")["correction"]["id"]
        self.assertTrue(handover.reaccept(no, cid)["ok"])
        second = handover.reaccept(no, cid)
        self.assertFalse(second["ok"])
        self.assertIn("已核收", second["message"])


class TestConcurrentResubmit(HandoverBase):
    def test_resubmit_deduplicates(self):
        record = self.issue_handover([1, 2])
        result = handover.resubmit([1, 2])
        self.assertTrue(result["ok"])
        self.assertTrue(result["deduplicated"])
        self.assertEqual(result["handover"]["交割编号"], record["交割编号"])
        valid = [h for h in handover.list_handovers() if h["有效"] and set(h["巡护日志"]) & {1, 2}]
        self.assertEqual(len(valid), 1)

    def test_concurrent_resubmit_and_correction(self):
        record = self.issue_handover([1, 2])
        no = record["交割编号"]
        outcomes: dict[str, object] = {}

        def do_resubmit() -> None:
            outcomes["resubmit"] = handover.resubmit([1, 2])

        def do_correction() -> None:
            outcomes["correction"] = handover.add_correction(no, 1, threat_position="北沟东段-3号样线")

        threads = [threading.Thread(target=do_resubmit), threading.Thread(target=do_correction)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertTrue(outcomes["resubmit"]["deduplicated"])
        self.assertTrue(outcomes["correction"]["ok"])
        valid = [h for h in handover.list_handovers() if h["有效"] and set(h["巡护日志"]) & {1, 2}]
        self.assertEqual(len(valid), 1)
        basis = handover.basis(no)
        self.assertEqual(basis["复核次数"], 2)
        self.assertEqual(len(basis["更正"]), 1)
        self.assertIn(outcomes["correction"]["correction"]["更正编号"], record["更正关联"])

    def test_partial_overlap_does_not_create_second_valid(self):
        record = self.issue_handover([1])
        result = handover.create_handover([1, 2], operator="夜班", mode="issue")
        self.assertTrue(result["deduplicated"])
        merged = result["handover"]
        self.assertEqual(merged["交割编号"], record["交割编号"])
        self.assertEqual(sorted(merged["巡护日志"]), [1, 2])
        self.assertEqual(merged["复核次数"], 2)


class TestAssessmentLifecycle(HandoverBase):
    def test_start_requires_valid_handover(self):
        svc = ThreatAssessmentService()
        entry, message = svc.run_action(2, "开始评估", {})
        self.assertIsNone(entry)
        self.assertIn("必须关联", message)

        entry, message = svc.run_action(2, "开始评估", {"handover_no": "不存在"})
        self.assertIsNone(entry)
        self.assertIn("不存在", message)

    def test_start_then_issue_syncs_todo(self):
        record = self.issue_handover([1, 2])
        no = record["交割编号"]
        svc = ThreatAssessmentService()
        entry, _ = svc.run_action(3, "开始评估", {"handover_no": no, "patrol_id": 2})
        self.assertEqual(entry["status"], "评估中")
        self.assertEqual(entry["有效威胁位置"], "北沟西段-5号林班")
        self.assertEqual(entry["评估对象"], "北沟西段")

        entry, message = svc.run_action(3, "签发报告")
        self.assertEqual(entry["status"], "已签发")
        todo = handover.latest_todo()
        self.assertEqual(todo["勘查段"], "北沟西段-5号林班")
        self.assertEqual(todo["交割编号"], no)
        self.assertIn("BK-", message)

    def test_start_rejects_mismatched_route(self):
        record = self.issue_handover([1, 2])
        svc = ThreatAssessmentService()
        # 评估对象是「北沟东段」，却去绑西段的巡护日志 #2。
        entry, message = svc.run_action(2, "开始评估", {"handover_no": record["交割编号"], "patrol_id": 2})
        self.assertIsNone(entry)
        self.assertIn("不一致", message)

    def test_issue_is_single_todo(self):
        record = self.issue_handover([1, 2])
        svc = ThreatAssessmentService()
        svc.run_action(3, "开始评估", {"handover_no": record["交割编号"], "patrol_id": 2})
        svc.run_action(3, "签发报告")
        count = len(handover.list_todos())
        svc.run_action(3, "签发报告")
        self.assertEqual(len(handover.list_todos()), count)

    def test_issued_assessment_traces_original_basis(self):
        record = self.issue_handover([1, 2])
        no = record["交割编号"]
        svc = ThreatAssessmentService()
        svc.run_action(3, "开始评估", {"handover_no": no, "patrol_id": 2})
        issued, _ = svc.run_action(3, "签发报告")
        self.assertEqual(issued["有效坐标描述"], "N31.2098 E121.4044")
        self.assertIn("红外相机影像2段", issued["复核依据"])

        # 即使交割后来重核收，已签发的复核依据仍然指向签发时的描述与来源。
        cid = handover.add_correction(no, 2, threat_position="西沟北坡-7号林班",
                                      coordinate="N31.2140 E121.3877")["correction"]["id"]
        handover.reaccept(no, cid)
        basis = handover.basis(no)
        issued_ref = basis["签发引用"][0]
        self.assertEqual(issued_ref["交割编号"] if "交割编号" in issued_ref else no, no)
        self.assertIn("N31.2098 E121.4044", issued_ref["复核依据"])
        self.assertIn("北沟西段-5号林班", issued_ref["复核依据"])

    def test_seeded_issued_assessment_can_be_traced(self):
        basis = handover.basis("JH-20261128-0001")
        self.assertIsNotNone(basis)
        self.assertEqual(basis["签发引用"][0]["状态"], "已签发")
        self.assertIn("N31.1882 E121.3921", basis["原快照"][0]["坐标描述"])

    def test_exported_package_retrievable_by_handover_number(self):
        """对外签发的材料一定能按采用的交割编号取回当时的导出依据。"""
        record = self.issue_handover([1, 2])
        no = record["交割编号"]
        handover.export_snapshot(no)
        # 导出后才到的更正、重核收都不改写这次导出留档。
        cid = handover.add_correction(no, 2, threat_position="西沟北坡-7号林班",
                                      coordinate="N31.2140 E121.3877")["correction"]["id"]
        handover.reaccept(no, cid)

        basis = handover.basis(no)
        self.assertEqual(len(basis["导出记录"]), 1)
        exported = basis["导出记录"][0]
        self.assertEqual(exported["导出版本"], 1)
        exported_log2 = next(item for item in exported["快照"] if int(item["id"]) == 2)
        self.assertEqual(exported_log2["威胁位置"], "北沟西段-5号林班")
        self.assertEqual(exported_log2["坐标描述"], "N31.2098 E121.4044")
        self.assertEqual(exported_log2["证据来源"], "红外相机影像2段")


class TestPatrolTriggerGuard(unittest.TestCase):
    def test_draft_cannot_trigger_assessment(self):
        from app.cross_module import trigger_threat_from_patrol
        result = trigger_threat_from_patrol(4)
        self.assertIn("error", result)
        self.assertIn("尚未审阅", result["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
