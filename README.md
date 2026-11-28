# 野生动物追踪与研究系统

生态学家、野外考察队员和数据分析师共同追踪野生动物活动轨迹，记录行为观测数据，分析种群迁徙规律后按研究周期汇总报告。

这是一个前后端分离的管理平台：前端 Vue 3 + Vite + TypeScript，后端 FastAPI（Python）。
两边各自独立启动，前端 dev server 已关掉自动打开页面，启动后按终端打印的地址手工打开。

## 目录结构

```text
.
├── frontend/                 Vue 3 + Vite + TypeScript 前端
│   ├── src/views/WorkbenchView.vue|tsx  全部模块共享工作台
│   ├── src/data/modules.ts              18个业务模块配置
│   ├── src/api/              统一请求封装
│   └── vite.config.ts        dev server 配置（open: false）
├── backend/                  FastAPI（Python） 后端
│   ├── app/routers/resource.py  通用查询/导出/登记/动作接口
│   ├── app/services/<key>.py    每个模块独立领域逻辑
│   ├── app/services/base.py     共享服务骨架
│   └── app/store.py          内存数据仓库与示例数据
├── .gitignore
└── docker-compose.yml
```

## 启动

### 后端

```bash
cd backend
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
./run.sh
```

健康检查：`curl http://127.0.0.1:8000/api/health`

### 前端

```bash
cd frontend
npm ci
npm run dev
```

前端默认监听 `http://127.0.0.1:5173/`，dev server 不会自动打开浏览器，
需要自己访问。`/api` 由 vite 代理到后端 `http://127.0.0.1:8000`。

## 业务模块

| 模块 | 目录 | 业务对象 | 主要字段 |
| --- | --- | --- | --- |
| 物种登记 | `species_register` | 物种档案 | 物种名称、保护等级、分布区域 |
| 追踪设备 | `tracking_device` | 设备档案 | 设备编号、设备类型、佩戴对象 |
| 位置记录 | `location_record` | 位置数据 | 设备编号、经纬度、海拔高度 |
| 行为观测 | `behavior_observe` | 观测记录 | 观测对象、行为类型、起止时间 |
| 栖息地调查 | `habitat_survey` | 调查数据 | 调查区域、植被类型、水源距离 |
| 种群普查 | `population_census` | 普查记录 | 普查区域、目标物种、调查方法 |
| 迁徙路线 | `migration_track` | 迁徙路径 | 追踪个体、起点区域、途经区域 |
| 救护记录 | `rescue_record` | 救护档案 | 救护对象、发现地点、伤病情況 |
| 遗传样本 | `genetic_sample` | 样本档案 | 样本编号、来源个体、样本类型 |
| 巡护记录 | `patrol_record` | 巡护日志 | 巡护路线、巡护人员、发现情况、威胁位置、证据来源 |
| 影像档案 | `photo_archive` | 影像记录 | 拍摄对象、拍摄地点、影像类型 |
| 研究成果 | `research_output` | 研究产出 | 成果标题、研究主题、作者团队 |
| 威胁评估 | `threat_assessment` | 评估报告 | 评估对象、威胁类别、威胁程度、交割编号、复核依据 |
| 装备管理 | `equipment_mgmt` | 装备档案 | 装备名称、装备类型、购入日期 |
| 公众宣教 | `public_education` | 宣教资料 | 资料名称、宣教主题、目标受众 |
| 合作项目 | `cooperation_project` | 项目档案 | 项目名称、合作机构、项目周期 |
| 数据分析 | `data_analysis` | 分析记录 | 分析主题、数据来源、分析方法 |
| 年度总结 | `annual_summary` | 总结报告 | 报告年份、覆盖物种、主要发现 |

## 调查交割清单（巡护 → 威胁评估）

巡护日志缺少带现场证据的交接出口，为此新增 `handover` 领域（页面 `/handover`，
接口 `/api/handover`），把「审阅 → 交割 → 评估 → 补勘」串成可回查的链路：

- **只有已审阅的巡护日志能正式发交割**；草稿只能做「缺件登记」，缺件清单随交割留存，
  且缺件交割不能导出、也不能被评估引用。
- **导出即冻结**：`GET /api/handover/{交割编号}/export` 按导出时刻的有效快照打包并单独留档，
  之后到达的更正不进入已下载的包。夜班再 `POST .../register-evidence` 登记为正式证据。
- **迟到更正**：`POST .../corrections` 登记更正并关联交割，评估员可在
  `GET .../corrections` 看到入口，选择从已交割材料继续，或 `POST .../reaccept`
  取更正后重核收（更新有效快照、保留原快照与更正关联）。
- **并发/重投**：`POST /api/handover/resubmit` 命中已有有效交割时只登记重投，
  同一批巡护只保留一份有效交割；一条巡护无论更正或重核收都只算一次独立复核。
- **威胁评估**：`开始评估` 通过动作参数 `handover_no`（可选 `patrol_id`）关联有效交割；
  路线与评估对象不一致会被拒绝。`签发报告` 固化复核依据并生成现场补勘待办。
- **回查**：`GET /api/handover/{交割编号}/basis` 返回原快照、有效快照、导出留档、
  更正关联与引用该交割的签发，已签发评估始终能核对原坐标描述与来源。

## 约定

- 全部模块共享`frontend/src/views/WorkbenchView.vue|tsx`和一套资源路由。
- 每个模块仍保留独立`backend/app/services/<模块>.py`；纯前端保留
  `frontend/src/domain/<模块>.ts`，用于承载真实业务差异并维持36题位容量。
- 列表接口统一返回 `{ items, total, page, size }`，动作接口统一返回 `{ ok, message }`。
- 动作可携带业务参数：`POST /api/{module}/{id}/actions` 的 `params` 字段，
  例如威胁评估「开始评估」传入 `{"handover_no": "...", "patrol_id": 2}`。
- 状态流转只允许在 `app/services` 里改，路由层不做业务判断。

领域：应用开发
子方向：web前端/全栈开发
