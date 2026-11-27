<template>
  <main class="waf-page">
    <h2 class="page-title">{{ scope === 'rule' ? `域名 WAF 配置：${domain}` : '全局 WAF 配置' }}</h2>
    <div class="protection-summary">
      <div class="setting-heading"><strong>防护开关</strong><span>选择此配置的防护方式</span></div>
      <a-select v-if="scope === 'global'" v-model="globalProtectionMode" class="mode-select"><a-option value="disabled">禁用</a-option><a-option value="custom">开启防护</a-option><a-option value="observe">仅观察</a-option></a-select>
      <a-select v-else :model-value="overrideProtectionMode" class="mode-select" @change="setProtectionMode"><a-option value="inherit">跟随全局</a-option><a-option value="disabled">禁用</a-option><a-option value="custom">开启防护</a-option><a-option value="observe">仅观察</a-option></a-select>
      <div class="effective-summary">当前状态：<strong>{{ modeName(effectiveMode) }}</strong><span>{{ scope === 'rule' ? '已启用' : '已配置' }}自定义规则：{{ effectiveCustomRuleCount }} 条</span></div>
      <p v-if="effectiveMode === 'disabled'" class="setting-note">当前不执行规则；下面的配置会在开启防护后生效。</p>
      <p v-else-if="effectiveMode === 'observe'" class="setting-note">仅观察命中，不拦截请求。</p>
    </div>
    <div v-if="tab !== 'logs'" class="setting-row">
      <div class="setting-heading"><strong>读取请求体</strong><span>系统或自定义规则需要检查 POST 表单参数、REQUEST_BODY 等请求体内容时开启；可能增加内存占用。</span></div>
      <a-switch :model-value="effectiveRequestBodyAccess" :disabled="followingGlobal" @change="setRequestBodyAccess" />
    </div>
    <a-tabs v-model:active-key="tab">
      <a-tab-pane key="system" title="系统规则">
        <div class="setting-row">
          <div class="setting-heading"><strong>防护强度</strong><span>{{ ['极少误报，绝大多数业务、新手、多站点托管，生产首选。', '少量误报，安全要求偏高、能接受少量自定义调整。', '较多误报，高安全业务（金融、内部系统）。', '大量误报，极高安全隔离环境，上线前必须大量白名单豁免。'][effectiveParanoiaLevel - 1] }}</span></div>
          <a-select :model-value="effectiveParanoiaLevel" :disabled="followingGlobal" class="strength-select" @change="setParanoiaLevel"><a-option v-for="(name, index) in ['平衡', '增强', '严格', '极限']" :key="index" :value="index + 1">{{ name }}（PL{{ index + 1 }}）</a-option></a-select>
        </div>
        <a-table :columns="systemColumns" :data="categories" :pagination="false" :expandable="{}" row-key="name">
          <template #expand-row="{ record }">
            <a-table :columns="ruleColumns" :data="categoryRules(record.name)" :pagination="false" row-key="id">
              <template #ruleEnabled="{ record: rule }">
                <a-switch :model-value="ruleEnabled(rule.id)" :disabled="followingGlobal || !categoryEnabled(rule.file)" @change="value => setRuleState(rule.id, value)" />
              </template>
            </a-table>
          </template>
          <template #enabled="{ record }">
            <a-switch :model-value="categoryEnabled(record.name)" :disabled="followingGlobal" @change="value => setCategory(record.name, value)" />
          </template>
        </a-table>
      </a-tab-pane>
      <a-tab-pane key="custom" title="自定义规则">
        <a-button v-if="scope === 'global'" :disabled="!!inlineDraft" @click="startInlineAdd">添加规则</a-button>
        <a-table :columns="customColumns" :data="visibleRules" :pagination="false" row-key="key">
          <template #id="{ record }"><span v-if="record.draft" class="id-entry"><strong v-if="inlineDraft.editingId">{{ inlineDraft.editingId }}</strong><template v-else><strong>100</strong><a-input v-model="inlineDraft.suffix" :max-length="4" placeholder="后四位" /></template></span><span v-else>{{ record.id }}</span></template>
          <template #rule="{ record }"><a-textarea v-if="record.draft" v-model="inlineDraft.rule" :auto-size="{ minRows: 3, maxRows: 8 }" placeholder='SecRule REQUEST_URI "@streq /admin" "id:1000000,phase:1,deny"' /><code v-else>{{ record.rule }}</code></template>
          <template #enabled="{ record }"><a-switch v-if="!record.draft && scope === 'rule'" :model-value="customRuleEnabled(record.id)" :disabled="followingGlobal" @change="value => setCustomRuleState(record.id, value)" /><span v-else-if="!record.draft">域名中配置</span></template>
          <template #operation="{ record }">
            <template v-if="record.draft"><a-link @click="saveInlineRule">确定</a-link><a-link @click="inlineDraft = null">取消</a-link></template>
            <template v-if="scope === 'global' && !record.draft">
              <a-link :disabled="!!inlineDraft" @click="editRule(record)">编辑</a-link>
              <a-link status="danger" :disabled="!!inlineDraft" @click="removeRule(record.key)">删除</a-link>
            </template>
          </template>
        </a-table>
        <div v-if="scope === 'global'" class="rule-input">
            <div class="visual-form">
              <a-input-number v-model="visualForm.id" :min="1000000" :precision="0" placeholder="规则 ID" />
              <a-select v-model="visualForm.type" placeholder="匹配条件">
                <a-option value="pathExact">路径精确匹配</a-option>
                <a-option value="pathContains">路径包含</a-option>
                <a-option value="method">请求方法</a-option>
                <a-option value="ip">客户端 IP/CIDR</a-option>
                <a-option value="header">请求头包含</a-option>
                <a-option value="advanced">通用 SecRule</a-option>
              </a-select>
              <template v-if="visualForm.type === 'advanced'">
                <a-input v-model="visualForm.variable" placeholder="匹配变量，例如 ARGS、REQUEST_COOKIES、RESPONSE_BODY" />
                <a-input v-model="visualForm.operator" placeholder="操作符，例如 @rx (?i)attack" />
                <a-input v-model="visualForm.actions" placeholder="动作，例如 phase:2,deny,status:403,log" />
                <div v-for="(condition, index) in visualForm.extraConditions" :key="index" class="chained-condition">
                  <a-input v-model="condition.variable" :placeholder="`条件 ${index + 2} 的变量，例如 ARGS`" />
                  <a-input v-model="condition.operator" placeholder="操作符，例如 @contains attack" />
                  <a-input v-model="condition.actions" placeholder="动作，例如 t:none；可留空" />
                  <a-button @click="visualForm.extraConditions.splice(index, 1)">移除条件</a-button>
                </div>
                <a-button @click="addCondition">添加 AND 条件</a-button>
              </template>
              <a-input v-else-if="visualForm.type === 'header'" v-model="visualForm.header" placeholder="请求头名称，例如 User-Agent" />
              <a-select v-if="visualForm.type === 'method'" v-model="visualForm.value" placeholder="请求方法">
                <a-option v-for="method in methods" :key="method" :value="method">{{ method }}</a-option>
              </a-select>
              <a-input v-else-if="visualForm.type !== 'advanced'" v-model="visualForm.value" :placeholder="visualForm.type === 'ip' ? '例如 192.0.2.0/24' : '匹配值'" />
            </div>
            <p class="rule-hint">快捷条件命中后返回 403。通用 SecRule 可填写 Coraza 支持的变量、操作符和动作；多个条件按 AND 链接。保存时检查格式和规则 ID，完整语法由网关加载时检验。</p>
        </div>
        <a-space v-if="scope === 'global'">
          <a-button @click="addRule">{{ editingKey ? '更新规则' : '添加可视化规则' }}</a-button>
          <a-button v-if="editingKey" @click="resetEditor">取消编辑</a-button>
        </a-space>
      </a-tab-pane>
      <a-tab-pane key="logs" title="防护日志">
        <a-spin v-if="checkingMetrics" tip="正在检查流量监测应用" />
        <a-alert v-else-if="metricsError" type="error" class="scope-note">{{ metricsError }} <a-link @click="loadLogs">重试</a-link></a-alert>
        <a-alert v-else-if="!hasMetrics" type="warning" class="scope-note">未安装流量监测应用，安装后可查看防护日志。<a-link @click="installTraffic">去安装</a-link></a-alert>
        <template v-else>
          <a-alert type="info" class="scope-note">显示监控组件保存的最近一小时 WAF 拦截记录。</a-alert>
          <a-button :loading="loadingLogs" @click="loadLogs">刷新</a-button>
          <a-table :columns="logColumns" :data="logs" :loading="loadingLogs" row-key="key" class="log-table" />
        </template>
      </a-tab-pane>
    </a-tabs>
    <div v-if="tab !== 'logs'" class="actions"><a-button type="primary" :loading="saving" @click="save">保存配置</a-button></div>
  </main>
</template>

<script>
import { loadWafConfig, saveWafConfig } from './backend.mjs'
import { buildVisualRule, parseVisualRule, replaceRuleId, validateCustomRules } from './rules.mjs'
import { fetchWafLogs, openTrafficInstall, trafficInstalled } from './logs.mjs'

const clone = value => JSON.parse(JSON.stringify(value || {}))
const props = () => window.$wujie?.props || {}

export default {
  data() {
    return {
      categories: [], systemRules: [], globalRuleStates: {}, ruleOverrides: {}, customRuleStates: {}, inlineDraft: null, paranoiaLevel: 1, ownParanoiaLevel: null, globalParanoiaLevel: 1, globalProtectionMode: 'disabled', overrideProtectionMode: 'inherit', methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'],
      tab: 'system', scope: 'global', domain: '',
      globalRequestBodyAccess: false, requestBodyAccessOverride: null, globalCategories: {}, overrides: {}, globalRules: [], customRules: [],
      visualForm: { id: 1000000, type: 'pathExact', value: '', header: '', variable: '', operator: '', actions: 'phase:1,deny,status:403', extraConditions: [] },
      editingKey: '', saving: false, loadingLogs: false, checkingMetrics: false, hasMetrics: false, metricsError: '', logs: [],
      systemColumns: [{ title: '防护类别', dataIndex: 'titleZh' }, { title: '状态', slotName: 'enabled', width: 230 }],
      ruleColumns: [{ title: 'ID', dataIndex: 'id', width: 100 }, { title: '防护名称', dataIndex: 'nameZh' }, { title: '严格程度', dataIndex: 'paranoiaLevel', render: ({ record }) => record.paranoiaLevel ? `PL${record.paranoiaLevel}` : '默认', width: 100 }, { title: '状态', slotName: 'ruleEnabled', width: 230 }],
      customColumns: [{ title: '规则 ID', slotName: 'id', width: 130 }, { title: 'SecRule', slotName: 'rule' }, { title: '启用', slotName: 'enabled', width: 100 }, { title: '操作', slotName: 'operation', width: 140 }],
      logColumns: [{ title: '时间', dataIndex: 'time' }, { title: '域名', dataIndex: 'domain' }, { title: '路径', dataIndex: 'path' }, { title: '状态码', dataIndex: 'status' }],
    }
  },
  computed: {
    followingGlobal() { return this.scope === 'rule' && this.overrideProtectionMode === 'inherit' },
    effectiveMode() { return this.scope === 'rule' && !this.followingGlobal ? this.overrideProtectionMode : this.globalProtectionMode },
    effectiveRequestBodyAccess() { return this.scope === 'rule' && !this.followingGlobal && this.requestBodyAccessOverride !== null ? this.requestBodyAccessOverride : this.globalRequestBodyAccess },
    effectiveParanoiaLevel() { return this.scope === 'rule' && !this.followingGlobal ? this.ownParanoiaLevel ?? this.globalParanoiaLevel : this.globalParanoiaLevel },
    effectiveCustomRuleCount() { return this.scope === 'global' ? this.customRules.length : this.followingGlobal ? 0 : this.globalRules.filter(rule => this.customRuleStates[rule.id] === true).length },
    visibleRules() {
      const rows = (this.scope === 'rule' ? this.globalRules : this.customRules)
        .filter(item => item.id !== this.inlineDraft?.editingId)
        .map(item => ({ ...item, key: `rule-${item.id}` }))
      if (this.inlineDraft && this.scope === 'global') rows.push({ ...this.inlineDraft, key: 'draft', draft: true })
      return rows
    },
  },
  created() { this.load() },
  watch: { tab(value) { if (value === 'logs') this.loadLogs() } },
  methods: {
    modeName(mode) { return { disabled: '禁用', custom: '开启防护', observe: '仅观察' }[mode] || '禁用' },
    setProtectionMode(value) { this.overrideProtectionMode = value },
    setParanoiaLevel(value) {
      this.paranoiaLevel = value
      if (this.scope === 'rule') this.ownParanoiaLevel = value
    },
    setRequestBodyAccess(value) {
      if (this.scope === 'rule') this.requestBodyAccessOverride = value
      else this.globalRequestBodyAccess = value
    },
    async load() {
      const context = props()
      this.scope = context.configScope === 'rule' ? 'rule' : 'global'
      this.domain = context.domain || ''
      if (typeof context.panelProxy !== 'function') return this.$message.error('当前面板未提供服务代理接口')
      try {
        const data = await loadWafConfig(context)
        this.globalRequestBodyAccess = data.global?.requestBodyAccess === true
        this.requestBodyAccessOverride = typeof data.overrides?.requestBodyAccess === 'boolean' ? data.overrides.requestBodyAccess : null
        this.categories = Array.isArray(data.catalog?.files) ? data.catalog.files : []
        this.systemRules = Array.isArray(data.catalog?.rules) ? data.catalog.rules.filter(rule => !rule.internal && rule.message) : []
        this.globalRuleStates = clone(data.global?.ruleStates)
        this.ruleOverrides = clone(data.overrides?.ruleStates)
        this.customRuleStates = clone(data.overrides?.customRuleStates)
        this.inlineDraft = null
        this.globalParanoiaLevel = data.global?.paranoiaLevel || 1
        this.ownParanoiaLevel = data.overrides?.paranoiaLevel ?? null
        this.paranoiaLevel = this.scope === 'rule' ? this.ownParanoiaLevel ?? this.globalParanoiaLevel : this.globalParanoiaLevel
        this.globalProtectionMode = data.global?.protectionMode || 'disabled'
        this.overrideProtectionMode = data.overrides?.protectionMode || 'inherit'
        this.globalCategories = clone(data.global?.categories)
        this.globalRules = Array.isArray(data.global?.customRules) ? clone(data.global.customRules) : []
        this.overrides = clone(data.overrides?.categories)
        this.customRules = this.scope === 'global' ? clone(this.globalRules) : []
        this.resetEditor()
      } catch (error) { this.$message.error(error?.message || '加载 WAF 配置失败') }
    },
    categoryEnabled(id) {
      return this.scope === 'rule' && !this.followingGlobal && Object.hasOwn(this.overrides, id)
        ? this.overrides[id] : this.globalCategories[id] !== false
    },
    setCategory(id, value) {
      if (this.scope === 'rule') this.overrides[id] = value
      else this.globalCategories[id] = value
    },
    categoryRules(name) { return this.systemRules.filter(rule => rule.file === name) },
    ruleEnabled(id) {
      return this.scope === 'rule' && !this.followingGlobal && Object.hasOwn(this.ruleOverrides, id)
        ? this.ruleOverrides[id] : this.globalRuleStates[id] !== false
    },
    setRuleState(id, enabled) {
      if (this.scope === 'rule') this.ruleOverrides[id] = enabled
      else this.globalRuleStates[id] = enabled
    },
    customRuleEnabled(id) { return !this.followingGlobal && this.customRuleStates[id] === true },
    setCustomRuleState(id, enabled) { this.customRuleStates[id] = enabled },
    startInlineAdd() {
      let id = 1000000
      const used = new Set(this.customRules.map(rule => rule.id))
      while (used.has(id)) id++
      this.inlineDraft = { suffix: String(id).slice(3), rule: '' }
    },
    saveInlineRule() {
      if (!this.inlineDraft.editingId && !/^\d{4}$/.test(this.inlineDraft.suffix)) return this.$message.error('规则 ID 后四位需要填写数字')
      const id = this.inlineDraft.editingId || Number(`100${this.inlineDraft.suffix}`)
      if (this.inlineDraft.editingId && !this.customRules.some(entry => entry.id === id)) return this.$message.error('待编辑规则已不存在')
      const rule = replaceRuleId(this.inlineDraft.rule.trim(), id)
      if (!rule) return this.$message.error('规则内容需要包含 id 动作')
      const item = { id, rule, enabled: false }
      const current = this.customRules.filter(entry => entry.id !== this.inlineDraft.editingId)
      const error = validateCustomRules([...current, item])
      if (error) return this.$message.error(error)
      this.customRules = this.inlineDraft.editingId
        ? this.customRules.map(entry => entry.id === id ? { ...entry, ...item } : entry)
        : [...this.customRules, item]
      this.inlineDraft = null
    },
    addCondition() {
      if (!this.visualForm.extraConditions) this.visualForm.extraConditions = []
      this.visualForm.extraConditions.push({ variable: '', operator: '', actions: '' })
    },
    nextRuleId() {
      const ids = [...this.globalRules, ...this.customRules].map(item => item.id)
      return Math.max(999999, ...ids.filter(id => Number.isSafeInteger(id))) + 1
    },
    resetEditor() {
      this.editingKey = ''
      this.visualForm = { id: this.nextRuleId(), type: 'pathExact', value: '', header: '', variable: '', operator: '', actions: 'phase:1,deny,status:403', extraConditions: [] }
    },
    editRule(record) {
      if (this.inlineDraft) return
      const form = parseVisualRule(record.rule)
      if (form) {
        this.editingKey = record.key
        this.visualForm = form
      } else {
        this.resetEditor()
        this.inlineDraft = { editingId: record.id, rule: record.rule }
      }
    },
    addRule() {
      let item
      try { item = buildVisualRule(this.visualForm) }
      catch (error) { return this.$message.error(error.message) }
      const current = this.customRules.filter(rule => `rule-${rule.id}` !== this.editingKey)
      const error = validateCustomRules([...current, item])
      if (error) return this.$message.error(error)
      this.customRules = [...current, { ...item, enabled: false }]
      this.resetEditor()
    },
    removeRule(key) {
      this.customRules = this.customRules.filter(item => `rule-${item.id}` !== key)
      if (this.editingKey === key) this.resetEditor()
    },
    async save() {
      if (this.inlineDraft) return this.$message.error('请先确认或取消新增规则')
      const error = validateCustomRules(this.customRules)
      if (error) return this.$message.error(error)
      this.saving = true
      try {
        await saveWafConfig(props(), this.scope === 'rule'
          ? { protectionMode: this.overrideProtectionMode, requestBodyAccess: this.requestBodyAccessOverride, categories: this.overrides, ruleStates: this.ruleOverrides, customRuleStates: this.customRuleStates, paranoiaLevel: this.ownParanoiaLevel }
          : { protectionMode: this.globalProtectionMode, requestBodyAccess: this.globalRequestBodyAccess, categories: this.globalCategories, ruleStates: this.globalRuleStates, customRules: this.customRules, paranoiaLevel: this.paranoiaLevel })
        this.$message.success('保存成功')
        await this.load()
      } catch (e) { this.$message.error(e?.message || '保存失败') }
      finally { this.saving = false }
    },
    async loadLogs() {
      this.checkingMetrics = true
      this.metricsError = ''
      this.hasMetrics = false
      try { this.hasMetrics = await trafficInstalled(props()) }
      catch (e) { this.metricsError = e?.message || '检查流量监测应用失败' }
      finally { this.checkingMetrics = false }
      if (!this.hasMetrics || this.metricsError) return
      this.loadingLogs = true
      try { this.logs = await fetchWafLogs(props(), this.scope === 'rule' ? this.domain : '') }
      catch (e) { this.$message.error(e?.message || '读取日志失败') }
      finally { this.loadingLogs = false }
    },
    async installTraffic() {
      try { await openTrafficInstall(props()) }
      catch (e) { this.$message.error(e?.message || '打开安装页面失败') }
    },
  },
}
</script>

<style>
* { box-sizing: border-box; }
body { margin: 0; color: #1d2129; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }
.waf-page { padding: 0; background: #fff; }
.page-title { margin: 0 0 16px; font-size: 18px; line-height: 1.4; overflow-wrap: anywhere; }
.scope-note { margin-bottom: 16px; }
.protection-summary { padding: 16px; margin-bottom: 16px; border: 1px solid #e5e6eb; border-radius: 8px; background: #f7f8fa; }
.setting-row { display: flex; align-items: center; flex-wrap: wrap; gap: 12px; padding: 14px 0; border-bottom: 1px solid #f2f3f5; }
.setting-heading { display: flex; flex: 1 1 220px; flex-direction: column; gap: 4px; }
.setting-heading span, .setting-note { color: #4e5969; font-size: 13px; line-height: 1.5; }
.mode-select { width: min(100%, 300px); margin-top: 10px; }
.strength-select { width: 150px; }
.effective-summary { display: flex; flex-wrap: wrap; gap: 8px 16px; margin-top: 12px; font-size: 13px; }
.effective-summary span { color: #4e5969; }
.setting-note { margin: 10px 0 0; }
.inactive-note { padding: 10px 12px; color: #4e5969; background: #f7f8fa; border-radius: 4px; }
.arco-table .arco-link { margin-left: 8px; }
.section-title { margin: 22px 0 10px; font-weight: 600; }
.rule-input, .log-table { margin: 16px 0; }
.id-entry { display: flex; align-items: center; gap: 4px; }
.id-entry .arco-input-wrapper { width: 76px; }
.visual-form { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; margin: 12px 0; }
.chained-condition { grid-column: 1 / -1; display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; padding: 12px; border: 1px solid #e5e6eb; border-radius: 4px; }
.rule-hint { color: #86909c; font-size: 12px; }
.actions { display: flex; justify-content: flex-end; margin-top: 20px; }
code { white-space: pre-wrap; overflow-wrap: anywhere; }
@media (max-width: 640px) { .visual-form { grid-template-columns: 1fr; } }
@media (max-width: 640px) { .chained-condition { grid-template-columns: 1fr; } }
</style>
