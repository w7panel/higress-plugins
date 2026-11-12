<template>
  <main class="waf-page">
    <a-alert type="info" class="scope-note">
      {{ scope === 'rule' ? `当前域名：${domain}` : '全局 WAF 默认配置' }}。系统规则来自 OWASP CRS，可关闭但不能删除。
    </a-alert>
    <a-tabs v-model:active-key="tab">
      <a-tab-pane key="rules" title="防护规则">
        <div class="section-title">系统规则</div>
        <a-table :columns="systemColumns" :data="categories" :pagination="false" row-key="id">
          <template #enabled="{ record }">
            <a-switch :model-value="categoryEnabled(record.id)" @change="value => setCategory(record.id, value)" />
            <a-link v-if="scope === 'rule' && Object.hasOwn(overrides, record.id)" @click="clearCategory(record.id)">恢复全局</a-link>
          </template>
        </a-table>
        <div class="section-title">自定义规则</div>
        <a-table :columns="customColumns" :data="visibleRules" :pagination="false" row-key="key">
          <template #rule="{ record }"><code>{{ record.rule }}</code></template>
          <template #operation="{ record }">
            <a-link v-if="record.global && record.id" @click="toggleGlobalRule(record)">{{ disabledGlobalIds.includes(record.id) ? '恢复继承' : '当前域名禁用' }}</a-link>
            <a-link v-else-if="!record.global" status="danger" @click="removeRule(record.key)">删除</a-link>
          </template>
        </a-table>
        <a-textarea v-model="newRule" placeholder='SecRule REQUEST_URI "@streq /admin" "id:1000001,phase:1,deny"' :auto-size="{ minRows: 3, maxRows: 8 }" class="rule-input" />
        <a-button @click="addRule">添加自定义规则</a-button>
        <div class="actions"><a-button type="primary" :loading="saving" @click="save">保存配置</a-button></div>
      </a-tab-pane>
      <a-tab-pane key="logs" title="防护日志">
        <a-alert type="info" class="scope-note">仅显示网关 Pod 保留的近期日志。</a-alert>
        <a-button :loading="loadingLogs" @click="loadLogs">刷新</a-button>
        <a-table :columns="logColumns" :data="logs" :loading="loadingLogs" row-key="key" class="log-table" />
      </a-tab-pane>
    </a-tabs>
  </main>
</template>

<script>
import { categories, parseRuleId, validateCustomRules } from './rules.mjs'

const clone = value => JSON.parse(JSON.stringify(value || {}))
const props = () => window.$wujie?.props || {}

export default {
  data() {
    return {
      categories, tab: 'rules', scope: 'global', domain: '',
      globalCategories: {}, overrides: {}, globalRules: [], legacyRules: [], customRules: [], disabledGlobalIds: [],
      newRule: '', saving: false, loadingLogs: false, logs: [],
      systemColumns: [{ title: 'OWASP CRS 类别', dataIndex: 'title' }, { title: '开启', slotName: 'enabled', width: 180 }],
      customColumns: [{ title: '规则 ID', dataIndex: 'id', width: 130 }, { title: 'SecRule', slotName: 'rule' }, { title: '操作', slotName: 'operation', width: 140 }],
      logColumns: [{ title: '时间', dataIndex: 'time' }, { title: '域名', dataIndex: 'domain' }, { title: '路径', dataIndex: 'path' }, { title: '规则 ID', dataIndex: 'ruleId' }, { title: '动作', dataIndex: 'action' }, { title: '来源 IP', dataIndex: 'clientIp' }],
    }
  },
  computed: {
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
    async load() {
      const context = props()
      this.scope = context.configScope === 'rule' ? 'rule' : 'global'
      this.domain = context.domain || ''
      if (typeof context.loadWafConfig !== 'function') return this.$message.error('当前面板未提供 WAF 配置接口')
      try {
        const data = await context.loadWafConfig()
        this.globalCategories = clone(data.global?.categories)
        this.globalRules = Array.isArray(data.global?.customRules) ? clone(data.global.customRules) : []
        this.legacyRules = Array.isArray(data.global?.legacyRules) ? clone(data.global.legacyRules) : []
        this.overrides = clone(data.overrides?.categories)
        const currentRules = this.scope === 'rule' ? data.overrides?.customRules : data.global?.customRules
        this.customRules = Array.isArray(currentRules) ? clone(currentRules) : []
        this.disabledGlobalIds = [...(data.overrides?.disabledGlobalIds || [])]
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
    addRule() {
      const rule = this.newRule.trim()
      const inherited = this.scope === 'rule' ? this.globalRules : []
      if (this.legacyRules.some(item => parseRuleId(item) === parseRuleId(rule))) return this.$message.error('规则 ID 与旧版规则重复')
      const error = validateCustomRules([...inherited, ...this.customRules, { rule }])
      if (error) return this.$message.error(error)
      this.customRules.push({ id: parseRuleId(rule), rule })
      this.newRule = ''
    },
    removeRule(key) {
      if (key.startsWith('legacy-')) this.legacyRules.splice(Number(key.slice(7)), 1)
      else this.customRules = this.customRules.filter(item => `local-${item.id}` !== key)
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
          ? { categories: this.overrides, customRules: this.customRules, disabledGlobalIds: this.disabledGlobalIds }
          : { categories: this.globalCategories, customRules: this.customRules, legacyRules: this.legacyRules })
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
.section-title { margin: 22px 0 10px; font-weight: 600; }
.rule-input, .log-table { margin: 16px 0; }
.actions { display: flex; justify-content: flex-end; margin-top: 20px; }
code { white-space: pre-wrap; overflow-wrap: anywhere; }
</style>
