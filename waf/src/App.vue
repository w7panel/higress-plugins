<template>
  <main class="waf-page">
    <a-alert type="info" class="scope-note">
      {{ scope === 'rule' ? `当前域名：${domain}` : '全局 WAF 默认配置' }}。系统规则来自 OWASP CRS，可关闭但不能删除。
    </a-alert>
    <a-tabs v-model:active-key="tab">
      <a-tab-pane key="system" title="系统规则">
        <div class="crs-config">
          <a-switch :model-value="effectiveUseCRS" @change="setUseCRS" />
          <span>启用 OWASP CRS 系统规则</span>
          <a-link v-if="scope === 'rule' && useCRSOverride !== null" @click="useCRSOverride = null">恢复全局</a-link>
        </div>
        <p class="rule-hint">关闭后不加载整套 CRS，下面的类别和单条系统规则暂不生效；自定义 SecRule 仍然生效。开启 CRS 会增加网关内存占用。</p>
        <a-table :columns="systemColumns" :data="categories" :pagination="false" row-key="id">
          <template #enabled="{ record }">
            <a-switch :model-value="categoryEnabled(record.id)" :disabled="!effectiveUseCRS" @change="value => setCategory(record.id, value)" />
            <a-link v-if="scope === 'rule' && Object.hasOwn(overrides, record.id)" @click="clearCategory(record.id)">恢复全局</a-link>
          </template>
        </a-table>
        <h3 class="section-title">单条 CRS 规则</h3>
        <p class="rule-hint">类别关闭时，该类别内的单条设置不生效。“CRS 内部控制规则”会影响防护等级或规则执行流程。</p>
        <a-space>
          <a-select v-model="systemCategory" allow-clear placeholder="筛选类别" style="width: 220px">
            <a-option v-for="item in categories" :key="item.id" :value="item.id">{{ item.title }}</a-option>
          </a-select>
          <a-input v-model="systemQuery" allow-clear placeholder="搜索规则 ID 或说明" style="width: 260px" />
        </a-space>
        <a-table :columns="systemRuleColumns" :data="filteredSystemRules" :pagination="{ pageSize: 20 }" row-key="id">
          <template #systemEnabled="{ record }">
            <a-switch :model-value="systemRuleEnabled(record)" :disabled="!effectiveUseCRS || !categoryEnabled(record.category)" @change="value => setSystemRule(record.id, value)" />
            <a-link v-if="scope === 'rule' && Object.hasOwn(systemOverrides, record.id)" @click="clearSystemRule(record.id)">恢复全局</a-link>
          </template>
        </a-table>
      </a-tab-pane>
      <a-tab-pane key="custom" title="自定义规则">
        <a-table :columns="customColumns" :data="visibleRules" :pagination="false" row-key="key">
          <template #rule="{ record }"><code>{{ record.rule }}</code></template>
          <template #operation="{ record }">
            <a-link v-if="record.global && record.id" @click="toggleGlobalRule(record)">{{ disabledGlobalIds.includes(record.id) ? '恢复继承' : '当前域名禁用' }}</a-link>
            <template v-else-if="!record.global">
              <a-link v-if="!record.legacy" @click="editRule(record)">编辑</a-link>
              <a-link status="danger" @click="removeRule(record.key)">删除</a-link>
            </template>
          </template>
        </a-table>
        <a-tabs v-model:active-key="editorMode" class="rule-input">
          <a-tab-pane key="visual" title="可视化配置">
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
            <p class="rule-hint">快捷条件命中后返回 403。通用 SecRule 可填写 Coraza 支持的变量、操作符和动作；多个条件按 AND 链接，保存时由服务端编译校验。</p>
          </a-tab-pane>
          <a-tab-pane key="manual" title="手填 SecRule">
            <a-textarea v-model="newRule" placeholder='SecRule REQUEST_URI "@streq /admin" "id:1000001,phase:1,deny"' :auto-size="{ minRows: 3, maxRows: 8 }" />
          </a-tab-pane>
        </a-tabs>
        <a-space>
          <a-button @click="addRule">{{ editingKey ? '更新规则' : '添加自定义规则' }}</a-button>
          <a-button v-if="editingKey" @click="resetEditor">取消编辑</a-button>
        </a-space>
      </a-tab-pane>
      <a-tab-pane key="logs" title="防护日志">
        <a-alert type="info" class="scope-note">仅显示网关 Pod 保留的近期日志。</a-alert>
        <a-button :loading="loadingLogs" @click="loadLogs">刷新</a-button>
        <a-table :columns="logColumns" :data="logs" :loading="loadingLogs" row-key="key" class="log-table" />
      </a-tab-pane>
    </a-tabs>
    <div v-if="tab !== 'logs'" class="actions"><a-button type="primary" :loading="saving" @click="save">保存配置</a-button></div>
  </main>
</template>

<script>
import { buildVisualRule, categories, parseRuleId, parseVisualRule, validateCustomRules } from './rules.mjs'
import systemRules from './system-rules.json'

const clone = value => JSON.parse(JSON.stringify(value || {}))
const props = () => window.$wujie?.props || {}

export default {
  data() {
    return {
      categories, systemRules, methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'],
      tab: 'system', editorMode: 'visual', scope: 'global', domain: '',
      globalUseCRS: true, useCRSOverride: null, globalCategories: {}, overrides: {}, globalSystemRules: {}, systemOverrides: {}, systemCategory: '', systemQuery: '', globalRules: [], legacyRules: [], customRules: [], disabledGlobalIds: [],
      visualForm: { id: 1000000, type: 'pathExact', value: '', header: '', variable: '', operator: '', actions: 'phase:1,deny,status:403', extraConditions: [] },
      editingKey: '', newRule: '', saving: false, loadingLogs: false, logs: [],
      systemColumns: [{ title: 'OWASP CRS 类别', dataIndex: 'title' }, { title: '开启', slotName: 'enabled', width: 180 }],
      systemRuleColumns: [{ title: '规则 ID', dataIndex: 'id', width: 120 }, { title: '说明', dataIndex: 'title' }, { title: '开启', slotName: 'systemEnabled', width: 180 }],
      customColumns: [{ title: '规则 ID', dataIndex: 'id', width: 130 }, { title: 'SecRule', slotName: 'rule' }, { title: '操作', slotName: 'operation', width: 140 }],
      logColumns: [{ title: '时间', dataIndex: 'time' }, { title: '域名', dataIndex: 'domain' }, { title: '路径', dataIndex: 'path' }, { title: '规则 ID', dataIndex: 'ruleId' }, { title: '动作', dataIndex: 'action' }, { title: '来源 IP', dataIndex: 'clientIp' }],
    }
  },
  computed: {
    effectiveUseCRS() { return this.scope === 'rule' && this.useCRSOverride !== null ? this.useCRSOverride : this.globalUseCRS },
    filteredSystemRules() {
      const query = this.systemQuery.trim().toLowerCase()
      return this.systemRules.filter(rule => (!this.systemCategory || rule.category === this.systemCategory)
        && (!query || String(rule.id).includes(query) || rule.title.toLowerCase().includes(query)))
    },
    visibleRules() {
      return [
        ...this.legacyRules.map((rule, index) => ({ id: parseRuleId(rule), rule, global: this.scope === 'rule', legacy: true, key: `legacy-${index}` })),
        ...(this.scope === 'rule' ? this.globalRules.map(item => ({ ...item, global: true })) : []),
        ...this.customRules.map(item => ({ ...item, global: false })),
      ].map(item => ({ ...item, key: item.key || `${item.global ? 'global' : 'local'}-${item.id}` }))
    },
  },
  created() { this.load() },
  watch: { tab(value) { if (value === 'logs') this.loadLogs() } },
  methods: {
    setUseCRS(value) {
      if (this.scope === 'rule') this.useCRSOverride = value
      else this.globalUseCRS = value
    },
    async load() {
      const context = props()
      this.scope = context.configScope === 'rule' ? 'rule' : 'global'
      this.domain = context.domain || ''
      if (typeof context.loadWafConfig !== 'function') return this.$message.error('当前面板未提供 WAF 配置接口')
      try {
        const data = await context.loadWafConfig()
        this.globalUseCRS = data.global?.useCRS !== false
        this.useCRSOverride = typeof data.overrides?.useCRS === 'boolean' ? data.overrides.useCRS : null
        this.globalCategories = clone(data.global?.categories)
        this.globalSystemRules = clone(data.global?.systemRules)
        this.globalRules = Array.isArray(data.global?.customRules) ? clone(data.global.customRules) : []
        this.legacyRules = Array.isArray(data.global?.legacyRules) ? clone(data.global.legacyRules) : []
        this.overrides = clone(data.overrides?.categories)
        this.systemOverrides = clone(data.overrides?.systemRules)
        const currentRules = this.scope === 'rule' ? data.overrides?.customRules : data.global?.customRules
        this.customRules = Array.isArray(currentRules) ? clone(currentRules) : []
        this.disabledGlobalIds = [...(data.overrides?.disabledGlobalIds || [])]
        this.resetEditor()
      } catch (error) { this.$message.error(error?.message || '加载 WAF 配置失败') }
    },
    categoryEnabled(id) {
      return this.scope === 'rule' && Object.hasOwn(this.overrides, id)
        ? this.overrides[id] : this.globalCategories[id] !== false
    },
    setCategory(id, value) {
      if (this.scope === 'rule') this.overrides[id] = value
      else this.globalCategories[id] = value
    },
    clearCategory(id) { delete this.overrides[id] },
    systemRuleEnabled(rule) {
      if (!this.categoryEnabled(rule.category)) return false
      if (this.scope === 'rule' && Object.hasOwn(this.systemOverrides, rule.id)) return this.systemOverrides[rule.id]
      return this.globalSystemRules[rule.id] !== false
    },
    setSystemRule(id, value) {
      if (this.scope === 'rule') this.systemOverrides[id] = value
      else this.globalSystemRules[id] = value
    },
    clearSystemRule(id) { delete this.systemOverrides[id] },
    addCondition() {
      if (!this.visualForm.extraConditions) this.visualForm.extraConditions = []
      this.visualForm.extraConditions.push({ variable: '', operator: '', actions: '' })
    },
    nextRuleId() {
      const ids = [...this.globalRules, ...this.customRules].map(item => item.id)
      ids.push(...this.legacyRules.map(parseRuleId))
      return Math.max(999999, ...ids.filter(id => Number.isSafeInteger(id))) + 1
    },
    resetEditor() {
      this.editingKey = ''
      this.newRule = ''
      this.visualForm = { id: this.nextRuleId(), type: 'pathExact', value: '', header: '', variable: '', operator: '', actions: 'phase:1,deny,status:403', extraConditions: [] }
    },
    editRule(record) {
      this.editingKey = record.key
      this.newRule = record.rule
      const form = record.source === 'visual' ? parseVisualRule(record.rule) : null
      if (form) {
        this.visualForm = form
        this.editorMode = 'visual'
      } else {
        this.editorMode = 'manual'
      }
    },
    addRule() {
      let item
      if (this.editorMode === 'visual') {
        try { item = buildVisualRule(this.visualForm) }
        catch (error) { return this.$message.error(error.message) }
      } else {
        const rule = this.newRule.trim()
        item = { id: parseRuleId(rule), rule }
      }
      const inherited = this.scope === 'rule' ? this.globalRules : []
      if (this.legacyRules.some(rule => parseRuleId(rule) === item.id)) return this.$message.error('规则 ID 与旧版规则重复')
      const current = this.customRules.filter(rule => `local-${rule.id}` !== this.editingKey)
      const error = validateCustomRules([...inherited, ...current, item])
      if (error) return this.$message.error(error)
      this.customRules = [...current, item]
      this.resetEditor()
    },
    removeRule(key) {
      if (key.startsWith('legacy-')) this.legacyRules.splice(Number(key.slice(7)), 1)
      else this.customRules = this.customRules.filter(item => `local-${item.id}` !== key)
      if (this.editingKey === key) this.resetEditor()
    },
    toggleGlobalRule(item) {
      this.disabledGlobalIds = this.disabledGlobalIds.includes(item.id)
        ? this.disabledGlobalIds.filter(id => id !== item.id) : [...this.disabledGlobalIds, item.id]
    },
    async save() {
      const error = validateCustomRules(this.customRules)
      if (error) return this.$message.error(error)
      this.saving = true
      try {
        await props().saveWafConfig(this.scope === 'rule'
          ? { useCRS: this.useCRSOverride, categories: this.overrides, systemRules: this.systemOverrides, customRules: this.customRules, disabledGlobalIds: this.disabledGlobalIds }
          : { useCRS: this.globalUseCRS, categories: this.globalCategories, systemRules: this.globalSystemRules, customRules: this.customRules, legacyRules: this.legacyRules })
        this.$message.success('保存成功')
        await this.load()
      } catch (e) { this.$message.error(e?.message || '保存失败') }
      finally { this.saving = false }
    },
    async loadLogs() {
      if (typeof props().loadWafLogs !== 'function') return this.$message.error('当前面板未提供 WAF 日志接口')
      this.loadingLogs = true
      try { this.logs = await props().loadWafLogs() }
      catch (e) { this.$message.error(e?.message || '读取日志失败') }
      finally { this.loadingLogs = false }
    },
  },
}
</script>

<style>
* { box-sizing: border-box; }
body { margin: 0; color: #1d2129; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }
.waf-page { padding: 20px; background: #fff; }
.scope-note { margin-bottom: 16px; }
.crs-config { display: flex; align-items: center; gap: 10px; margin: 4px 0 8px; }
.section-title { margin: 22px 0 10px; font-weight: 600; }
.rule-input, .log-table { margin: 16px 0; }
.visual-form { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; margin: 12px 0; }
.chained-condition { grid-column: 1 / -1; display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; padding: 12px; border: 1px solid #e5e6eb; border-radius: 4px; }
.rule-hint { color: #86909c; font-size: 12px; }
.actions { display: flex; justify-content: flex-end; margin-top: 20px; }
code { white-space: pre-wrap; overflow-wrap: anywhere; }
@media (max-width: 640px) { .visual-form { grid-template-columns: 1fr; } }
@media (max-width: 640px) { .chained-condition { grid-template-columns: 1fr; } }
</style>
