"""跨模块数据流引擎：将追踪、观测、普查等多源数据串联为迁徙路线、行为分析、年度总结。

真实跨模块业务链路（全部可审计、可复现）：
  1. location_record -> migration_track    : 位置数据汇聚为迁徙路线
  2. behavior_observe -> data_analysis     : 行为观测驱动行为模式分析
  3. patrol_record -> threat_assessment    : 巡护发现自动触发威胁评估
  4. population_census -> species_register : 普查数据更新物种种群数量
  5. rescue_record -> species_register     : 救护记录关联物种分布更新
  6. tracking_device -> location_record    : 设备信号状态影响数据质量标注
  7. genetic_sample -> research_output     : 遗传分析推动研究成果产出
  8. data_analysis + others -> annual_summary : 多源汇总为年度报告
"""
from __future__ import annotations

import math
from datetime import datetime, date
from typing import Any

from app.services import service_for


def build_migration_from_locations(track_individual: str) -> dict[str, Any]:
    """从 location_record 表为该追踪个体聚合位置数据，生成迁徙路线信息。"""
    loc_svc = service_for("location_record")
    if not loc_svc:
        return {"error": "位置记录服务未就绪"}
    from app.store import store
    all_locs = [
        row for row in store.rows("location_record")
        if row.get("设备编号", "").startswith(track_individual[:4]) or track_individual in str(row.get("设备编号", ""))
    ]
    if not all_locs:
        return {"error": f"未找到追踪个体 {track_individual} 的位置数据", "location_count": 0}

    lats = []
    lngs = []
    for row in all_locs:
        coord = str(row.get("经纬度", "")).replace("°", ",").replace(" ", "")
        parts = coord.split(",")
        try:
            if len(parts) >= 2:
                lats.append(float(parts[0].strip()))
                lngs.append(float(parts[1].strip()))
        except (ValueError, IndexError):
            continue

    if len(lats) < 2:
        return {"error": f"位置数据不足以计算迁徙路线，至少需要2个有效坐标点", "location_count": len(lats)}

    start_lat, start_lng = lats[0], lngs[0]
    end_lat, end_lng = lats[-1], lngs[-1]
    mid_lat, mid_lng = lats[len(lats) // 2], lngs[len(lats) // 2]

    total_distance = sum(
        _haversine_distance(lats[i], lngs[i], lats[i + 1], lngs[i + 1])
        for i in range(len(lats) - 1)
    )

    start_region = f"({start_lat:.2f},{start_lng:.2f})"
    mid_region = f"({mid_lat:.2f},{mid_lng:.2f})"
    end_region = f"({end_lat:.2f},{end_lng:.2f})"

    records_sorted = sorted(all_locs, key=lambda r: str(r.get("记录时间", "")))
    time_start = records_sorted[0].get("记录时间", "") if records_sorted else ""
    time_end = records_sorted[-1].get("记录时间", "") if records_sorted else ""

    return {
        "track_individual": track_individual,
        "start_region": start_region,
        "via_region": mid_region,
        "end_region": end_region,
        "distance_km": round(total_distance, 2),
        "location_count": len(all_locs),
        "record_period": f"{time_start} 至 {time_end}",
        "source_records": [r["id"] for r in records_sorted],
    }


def analyze_behavior_for_data_analysis(species_name: str) -> dict[str, Any]:
    """从 behavior_observe 抽取指定物种行为类型与频次统计，供数据分析模块使用。"""
    from app.store import store
    observations = [
        row for row in store.rows("behavior_observe")
        if species_name in str(row.get("观测对象", ""))
    ]
    if not observations:
        return {"error": f"未找到物种 {species_name} 的行为观测数据", "observation_count": 0}

    behavior_types: dict[str, int] = {}
    total_individuals = 0
    for row in observations:
        btype = str(row.get("行为类型", "未分类"))
        behavior_types[btype] = behavior_types.get(btype, 0) + 1
        try:
            total_individuals += int(row.get("参与个体数", 0))
        except (ValueError, TypeError):
            pass

    dominant_behavior = max(behavior_types, key=behavior_types.get) if behavior_types else "未知"

    return {
        "species": species_name,
        "observation_count": len(observations),
        "behavior_distribution": behavior_types,
        "dominant_behavior": dominant_behavior,
        "total_participants": total_individuals,
        "avg_group_size": round(total_individuals / len(observations), 2) if observations else 0,
        "source_record_ids": [r["id"] for r in observations],
    }


def trigger_threat_from_patrol(patrol_id: int) -> dict[str, Any]:
    """当巡护记录发现威胁时，自动创建对应的威胁评估条目。

    只有已审阅的巡护日志才能成为签发证据；草稿在此被拒绝，避免未复核材料流入评估。
    """
    from app.store import store
    patrol = store.find("patrol_record", patrol_id)
    if not patrol:
        return {"error": f"巡护记录 {patrol_id} 不存在"}
    if patrol.get("status") != "已审阅":
        return {
            "error": f"巡护记录 {patrol_id} 尚未审阅（当前 {patrol.get('status')}），不能作为评估证据",
            "patrol_status": patrol.get("status"),
        }
    threat_type = str(patrol.get("威胁类型", ""))
    finding = str(patrol.get("发现情况", ""))
    if not threat_type or threat_type in ("无", "正常", "安全"):
        return {"error": f"巡护记录 {patrol_id} 无明确威胁类型", "threat_type": threat_type}

    rows = store.rows("threat_assessment")
    new_id = max((int(r.get("id", 0)) for r in rows), default=0) + 1
    assessment = {
        "id": new_id,
        "评估对象": str(patrol.get("巡护路线", "")),
        "威胁类别": threat_type,
        "威胁程度": "中",
        "影响范围": finding,
        "缓解建议": f"基于巡护发现：{finding}，建议开展专项评估",
        "评估人": str(patrol.get("巡护人员", "系统")),
        "评估日期": str(patrol.get("巡护日期", date.today().isoformat())),
        "备注说明": f"由巡护记录 #{patrol_id} 自动触发",
        "交割编号": "",
        "复核依据": "",
        "有效威胁位置": "",
        "有效坐标描述": "",
        "status": "待评估",
        "pending": True,
        "abnormal": bool(patrol.get("abnormal")),
    }
    rows.append(assessment)
    return {"created": True, "assessment_id": new_id, "assessment": assessment}


def update_species_population_from_census(census_id: int) -> dict[str, Any]:
    """将普查记录中的目击数量同步更新到物种登记表中。"""
    from app.store import store
    census = store.find("population_census", census_id)
    if not census:
        return {"error": f"普查记录 {census_id} 不存在"}

    species_name = str(census.get("目标物种", ""))
    count = census.get("目击数量", 0)
    try:
        count = int(count)
    except (ValueError, TypeError):
        count = 0

    species_rows = store.rows("species_register")
    matched = [r for r in species_rows if species_name in str(r.get("物种名称", ""))]
    updated_ids = []
    for row in matched:
        row["种群数量"] = count
        row["status"] = "已更新"
        row["pending"] = True
        updated_ids.append(row["id"])

    return {
        "census_id": census_id,
        "species_name": species_name,
        "new_population": count,
        "updated_species_ids": updated_ids,
        "matched_count": len(matched),
    }


def link_rescue_to_species(rescue_id: int) -> dict[str, Any]:
    """救护记录与物种登记建立关联，更新物种档案中的分布信息。"""
    from app.store import store
    rescue = store.find("rescue_record", rescue_id)
    if not rescue:
        return {"error": f"救护记录 {rescue_id} 不存在"}

    species_name = str(rescue.get("救护对象", ""))
    location = str(rescue.get("发现地点", ""))
    rescue_status = str(rescue.get("康复状态", ""))

    species_rows = store.rows("species_register")
    matched = [r for r in species_rows if species_name in str(r.get("物种名称", ""))]
    updated_ids = []
    for row in matched:
        if location:
            row["分布区域"] = f'{row.get("分布区域", "")} [救护: {location}]'
        row["pending"] = True
        updated_ids.append(row["id"])

    return {
        "rescue_id": rescue_id,
        "species_name": species_name,
        "rescue_location": location,
        "rescue_status": rescue_status,
        "linked_species_ids": updated_ids,
        "matched_count": len(matched),
    }


def check_device_signal_for_locations(device_code: str) -> dict[str, Any]:
    """检查设备信号状态，标注异常位置数据。"""
    from app.store import store
    device = None
    for row in store.rows("tracking_device"):
        if str(row.get("设备编号", "")) == device_code:
            device = row
            break
    if not device:
        return {"error": f"设备 {device_code} 不存在"}

    device_status = str(device.get("status", ""))
    battery = str(device.get("电池续航", ""))

    locs = [
        row for row in store.rows("location_record")
        if str(row.get("设备编号", "")) == device_code
    ]

    abnormal_count = 0
    for row in locs:
        if device_status in ("已回收", "待部署") or "低" in battery:
            row["status"] = "异常数据"
            row["abnormal"] = True
            row["pending"] = False
            abnormal_count += 1

    return {
        "device_code": device_code,
        "device_status": device_status,
        "battery": battery,
        "linked_locations": len(locs),
        "marked_abnormal": abnormal_count,
        "signal_issue": device_status in ("已回收", "待部署"),
    }


def link_genetic_to_research(sample_id: int) -> dict[str, Any]:
    """将遗传样本送检结果关联到研究成果模块。"""
    from app.store import store
    sample = store.find("genetic_sample", sample_id)
    if not sample:
        return {"error": f"遗传样本 {sample_id} 不存在"}

    if sample.get("status") != "已送检":
        return {"error": f"样本 {sample_id} 尚未送检，当前状态：{sample.get('status')}"}

    species = str(sample.get("来源个体", ""))
    sample_type = str(sample.get("样本类型", ""))

    rows = store.rows("research_output")
    new_id = max((int(r.get("id", 0)) for r in rows), default=0) + 1
    output = {
        "id": new_id,
        "成果标题": f"{species}遗传分析报告",
        "研究主题": f"{species}种群遗传多样性",
        "作者团队": str(sample.get("采集人", "研究组")),
        "发表渠道": "内部研究报告",
        "发表年份": str(date.today().year),
        "引用次数": "0",
        "登记人": str(sample.get("采集人", "")),
        "备注说明": f"基于遗传样本 #{sample_id}（{sample_type}）分析",
        "status": "待登记",
        "pending": True,
        "abnormal": False,
    }
    rows.append(output)
    return {"created": True, "research_id": new_id, "research_output": output}


def build_annual_summary(year: int) -> dict[str, Any]:
    """汇总全年追踪、观测、普查、救护、研究成果等多源数据，生成年度总结信息。"""
    from app.store import store

    def _count(module: str, status_filter: str | None = None) -> int:
        rows = store.rows(module)
        if status_filter:
            return sum(1 for r in rows if r.get("status") == status_filter)
        return len(rows)

    def _sum_field(module: str, field: str) -> int:
        total = 0
        for row in store.rows(module):
            try:
                total += int(row.get(field, 0))
            except (ValueError, TypeError):
                pass
        return total

    # 汇总各模块年度数据
    species_count = _count("species_register")
    device_count = _count("tracking_device")
    location_count = _count("location_record")
    observation_count = _count("behavior_observe")
    census_count = _count("population_census", "已确认")
    rescue_count = _count("rescue_record", "已放归")
    migration_count = _count("migration_track", "已验证")
    genetic_count = _count("genetic_sample", "已入库")
    patrol_count = _count("patrol_record", "已审阅")
    research_count = _count("research_output", "已发表")
    threat_count = _count("threat_assessment", "已签发")

    # 自动创建年度总结记录
    rows = store.rows("annual_summary")
    new_id = max((int(r.get("id", 0)) for r in rows), default=0) + 1
    existing = [r for r in rows if str(r.get("报告年份", "")) == str(year)]
    if existing:
        summary = existing[0]
    else:
        species_list = [r.get("物种名称", "") for r in store.rows("species_register") if r.get("物种名称")]
        main_findings = (
            f"{year}年累计追踪{location_count}条位置数据，"
            f"记录{observation_count}次行为观测，完成{census_count}次种群普查，"
            f"救护放归{rescue_count}个体，验证{genetic_count}份遗传样本。"
        )
        total_data = species_count + location_count + observation_count + census_count + rescue_count + genetic_count
        summary = {
            "id": new_id,
            "报告年份": str(year),
            "覆盖物种": "、".join(species_list[:5]) if species_list else "全物种",
            "主要发现": main_findings,
            "数据总量": str(total_data),
            "保护建议": f"根据{threat_count}项威胁评估，建议加强巡护与栖息地保护",
            "编制人": "系统汇总",
            "报告状态": "编制中",
            "备注说明": f"自动汇总{year}年度数据，含{species_count}个物种、{device_count}台设备",
            "status": "编制中",
            "pending": True,
            "abnormal": False,
        }
        rows.append(summary)

    return {
        "year": year,
        "summary": {
            "species": species_count,
            "devices": device_count,
            "locations": location_count,
            "observations": observation_count,
            "confirmed_census": census_count,
            "released_rescues": rescue_count,
            "verified_migrations": migration_count,
            "stored_genetic": genetic_count,
            "reviewed_patrols": patrol_count,
            "published_research": research_count,
            "issued_threats": threat_count,
        },
        "annual_summary_entry": summary,
    }


def _haversine_distance(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    """计算两点间球面距离（km），Haversine 公式。"""
    R = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlng = math.radians(lng2 - lng1)
    a = (
        math.sin(dlat / 2) ** 2
        + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlng / 2) ** 2
    )
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c