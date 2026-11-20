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
        <p class="rule-hint">关闭后不加载整套 CRS，下面的类别设置暂不生效；自定义 SecRule 仍然生效。开启 CRS 会增加网关内存占用。</p>
        <div v-if="scope === 'global'" class="crs-config">
          <span>规则严格度</span>
          <a-select v-model="paranoiaLevel" style="width: 130px"><a-option v-for="level in [1, 2, 3, 4]" :key="level" :value="level">PL{{ level }}</a-option></a-select>
          <span>规则引擎</span>
          <a-select v-model="engineMode" style="width: 160px"><a-option value="On">阻断 On</a-option><a-option value="DetectionOnly">仅检测</a-option><a-option value="Off">关闭 Off</a-option></a-select>
        </div>
        <div class="crs-config">
          <a-switch :model-value="effectiveRequestBodyAccess" @change="setRequestBodyAccess" />
          <span>启用自定义规则的请求体检查</span>
          <a-link v-if="scope === 'rule' && requestBodyAccessOverride !== null" @click="requestBodyAccessOverride = null">恢复全局</a-link>
        </div>
        <p class="rule-hint">使用 REQUEST_BODY 或 POST 表单参数等请求体变量时开启；网关将读取请求体，可能增加内存占用。关闭不会改变 CRS 自身的请求体配置。</p>
        <a-table :columns="systemColumns" :data="categories" :pagination="false" row-key="name">
          <template #enabled="{ record }">
            <a-switch :model-value="categoryEnabled(record.name)" :disabled="!effectiveUseCRS" @change="value => setCategory(record.name, value)" />
            <a-link v-if="scope === 'rule' && Object.hasOwn(overrides, record.name)" @click="clearCategory(record.name)">恢复全局</a-link>
          </template>
        </a-table>
      </a-tab-pane>
      <a-tab-pane key="custom" title="自定义规则">
        <a-table :columns="customColumns" :data="visibleRules" :pagination="false" row-key="key">
          <template #rule="{ record }"><code>{{ record.rule }}</code></template>
          <template #operation="{ record }">
            <a-link v-if="scope === 'rule' && record.id" @click="toggleGlobalRule(record)">{{ disabledGlobalIds.includes(record.id) ? '恢复继承' : '当前域名禁用' }}</a-link>
            <template v-else-if="scope === 'global'">
              <a-link @click="editRule(record)">编辑</a-link>
              <a-link status="danger" @click="removeRule(record.key)">删除</a-link>
            </template>
          </template>
        </a-table>
        <a-tabs v-if="scope === 'global'" v-model:active-key="editorMode" class="rule-input">
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
            <a-input-number v-model="visualForm.id" :min="1000000" :precision="0" placeholder="规则 ID" />
            <a-textarea v-model="newRule" placeholder='SecRule REQUEST_URI "@streq /admin" "id:1000001,phase:1,deny"' :auto-size="{ minRows: 3, maxRows: 8 }" />
          </a-tab-pane>
        </a-tabs>
        <a-space v-if="scope === 'global'">
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
import { buildVisualRule, parseRuleId, parseVisualRule, validateCustomRules } from './rules.mjs'

const clone = value => JSON.parse(JSON.stringify(value || {}))
const props = () => window.$wujie?.props || {}

export default {
  data() {
    return {
      categories: [], paranoiaLevel: 1, engineMode: 'On', methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'],
      tab: 'system', editorMode: 'visual', scope: 'global', domain: '',
      globalUseCRS: true, useCRSOverride: null, globalRequestBodyAccess: false, requestBodyAccessOverride: null, globalCategories: {}, overrides: {}, globalRules: [], customRules: [], disabledGlobalIds: [],
      visualForm: { id: 1000000, type: 'pathExact', value: '', header: '', variable: '', operator: '', actions: 'phase:1,deny,status:403', extraConditions: [] },
      editingKey: '', newRule: '', saving: false, loadingLogs: false, logs: [],
      systemColumns: [{ title: 'OWASP CRS 类别', dataIndex: 'titleZh' }, { title: '开启', slotName: 'enabled', width: 180 }],
      customColumns: [{ title: '规则 ID', dataIndex: 'id', width: 130 }, { title: 'SecRule', slotName: 'rule' }, { title: '操作', slotName: 'operation', width: 140 }],
      logColumns: [{ title: '时间', dataIndex: 'time' }, { title: '域名', dataIndex: 'domain' }, { title: '路径', dataIndex: 'path' }, { title: '规则 ID', dataIndex: 'ruleId' }, { title: '动作', dataIndex: 'action' }, { title: '来源 IP', dataIndex: 'clientIp' }],
    }
  },
  computed: {
    effectiveUseCRS() { return this.scope === 'rule' && this.useCRSOverride !== null ? this.useCRSOverride : this.globalUseCRS },
    effectiveRequestBodyAccess() { return this.scope === 'rule' && this.requestBodyAccessOverride !== null ? this.requestBodyAccessOverride : this.globalRequestBodyAccess },
    visibleRules() {
      return (this.scope === 'rule' ? this.globalRules : this.customRules)
        .map(item => ({ ...item, key: `rule-${item.id}` }))
    },
  },
  created() { this.load() },
  watch: { tab(value) { if (value === 'logs') this.loadLogs() } },
  methods: {
    setUseCRS(value) {
      if (this.scope === 'rule') this.useCRSOverride = value
      else this.globalUseCRS = value
    },
    setRequestBodyAccess(value) {
      if (this.scope === 'rule') this.requestBodyAccessOverride = value
      else this.globalRequestBodyAccess = value
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
        this.globalRequestBodyAccess = data.global?.requestBodyAccess === true
        this.requestBodyAccessOverride = typeof data.overrides?.requestBodyAccess === 'boolean' ? data.overrides.requestBodyAccess : null
        this.categories = Array.isArray(data.catalog?.files) ? data.catalog.files : []
        this.paranoiaLevel = data.global?.paranoiaLevel || 1
        this.engineMode = data.global?.engineMode || 'On'
        this.globalCategories = clone(data.global?.categories)
        this.globalRules = Array.isArray(data.global?.customRules) ? clone(data.global.customRules) : []
        this.overrides = clone(data.overrides?.categories)
        this.customRules = this.scope === 'global' ? clone(this.globalRules) : []
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
        this.visualForm.id = record.id
        this.editorMode = 'manual'
      }
    },
    addRule() {
      let item
      if (this.editorMode === 'visual') {
        try { item = buildVisualRule(this.visualForm) }
        catch (error) { return this.$message.error(error.message) }
      } else {
        const id = Number(this.visualForm.id)
        if (!Number.isSafeInteger(id) || id < 1000000) return this.$message.error('规则 ID 必须从 1000000 开始')
        const rule = this.newRule.trim().replace(/\bid\s*:\s*\d+/i, `id:${id}`)
        if (parseRuleId(rule) !== id) return this.$message.error('手填 SecRule 首条规则需要包含 id 动作')
        item = { id, rule }
      }
      const current = this.customRules.filter(rule => `rule-${rule.id}` !== this.editingKey)
      const error = validateCustomRules([...current, item])
      if (error) return this.$message.error(error)
      this.customRules = [...current, item]
      this.resetEditor()
    },
    removeRule(key) {
      this.customRules = this.customRules.filter(item => `rule-${item.id}` !== key)
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
          ? { useCRS: this.useCRSOverride, requestBodyAccess: this.requestBodyAccessOverride, categories: this.overrides, disabledGlobalIds: this.disabledGlobalIds }
          : { useCRS: this.globalUseCRS, requestBodyAccess: this.globalRequestBodyAccess, categories: this.globalCategories, customRules: this.customRules, paranoiaLevel: this.paranoiaLevel, engineMode: this.engineMode })
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
