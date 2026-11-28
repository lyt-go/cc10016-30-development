<template>
  <div class="app-shell">
    <aside class="app-side">
      <h1 class="app-title">野生动物追踪与研究系统</h1>
      <nav class="nav-list">
        <RouterLink v-for="item in navItems" :key="item.path" :to="item.path" class="nav-item">
          {{ item.label }}
        </RouterLink>
      </nav>
    </aside>
    <main class="app-main">
      <header class="app-head">
        <span class="head-desc">生态学家、野外考察队员和数据分析师共同追踪野生动物活动轨迹，记录行为观测数据，分析种群迁徙规律后按研究周期汇总报告。</span>
        <span class="head-user">当前值班：应用开发组</span>
      </header>
      <RouterView />
    </main>
  </div>
</template>

<script setup lang="ts">
const navItems = [{ label: "运营概览", path: "/" }, { label: "调查交割清单", path: "/handover" }, { label: "物种登记", path: "/species_register" }, { label: "追踪设备", path: "/tracking_device" }, { label: "位置记录", path: "/location_record" }, { label: "行为观测", path: "/behavior_observe" }, { label: "栖息地调查", path: "/habitat_survey" }, { label: "种群普查", path: "/population_census" }, { label: "迁徙路线", path: "/migration_track" }, { label: "救护记录", path: "/rescue_record" }, { label: "遗传样本", path: "/genetic_sample" }, { label: "巡护记录", path: "/patrol_record" }, { label: "影像档案", path: "/photo_archive" }, { label: "研究成果", path: "/research_output" }, { label: "威胁评估", path: "/threat_assessment" }, { label: "装备管理", path: "/equipment_mgmt" }, { label: "公众宣教", path: "/public_education" }, { label: "合作项目", path: "/cooperation_project" }, { label: "数据分析", path: "/data_analysis" }, { label: "年度总结", path: "/annual_summary" }]
</script>
