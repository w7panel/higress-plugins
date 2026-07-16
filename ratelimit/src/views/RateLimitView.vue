<template>
  <section class="rate-page">
    <a-form ref="formRef" :model="form" auto-label-width class="rate-form">
      <a-form-item label="限流调试">
        <a-switch v-model="form.show_limit_quota_header" />
        <template #extra>开启后将在响应头中返回限流剩余额度，便于联调和排查。</template>
      </a-form-item>

      <a-form-item label="限流模式">
        <a-select v-model="form.mode" class="medium-control">
          <a-option value="global_threshold" label="全局限流模式" />
          <a-option value="rule_items" label="动态限流模式" />
        </a-select>
      </a-form-item>

      <div v-if="form.mode === 'global_threshold'" class="mode-box">
        <a-form-item label="限流策略">
          <div class="inline-controls">
            <a-select v-model="form.global_threshold.period" placeholder="选择周期" class="threshold-control">
              <a-option
                v-for="item in thresholdOptions"
                :key="item.value"
                :label="item.label"
                :value="item.value"
              />
            </a-select>
            <a-input-number
              v-model="form.global_threshold.value"
              :min="1"
              placeholder="输入阈值"
              class="threshold-control"
            />
          </div>
        </a-form-item>
      </div>

      <div v-else class="mode-box">
        <a-form-item label="限流策略">
          <div class="strategy-list">
            <a-button type="primary" class="create-button" @click="addRuleItem">新建策略</a-button>

            <article v-for="(item, index) in form.rule_items" :key="item.id" class="strategy-card">
              <div class="card-actions">
                <span class="strategy-title">设置块 {{ index + 1 }}</span>
                <a-button status="danger" type="text" @click="removeRuleItem(index)">删除设置块</a-button>
              </div>

              <a-form-item label="限流类型">
                <div class="limit-type-row">
                  <a-select
                    v-model="item.limitType"
                    placeholder="请选择限流类型"
                    class="medium-control"
                    @change="handleLimitTypeChange(item)"
                  >
                    <a-option
                      v-for="option in limitTypeOptions"
                      :key="option.value"
                      :label="option.label"
                      :value="option.value"
                    />
                  </a-select>
                  <a-checkbox
                    v-model="item.dynamicValue"
                    :disabled="isDynamicValueLocked(item)"
                    @change="handleDynamicValueChange(item)"
                  >
                    动态值
                  </a-checkbox>
                </div>
              </a-form-item>

              <a-form-item label="匹配名称">
                <a-select
                  v-if="isIpType(getActualLimitType(item))"
                  v-model="item.limitValue"
                  placeholder="请选择 IP 来源"
                  class="medium-control"
                >
                  <a-option v-for="option in ipSourceOptions" :key="option" :label="option" :value="option" />
                </a-select>
                <a-input
                  v-else
                  v-model="item.limitValue"
                  :disabled="isConsumerType(getActualLimitType(item))"
                  :placeholder="limitValuePlaceholder(getActualLimitType(item))"
                  class="medium-control"
                />
              </a-form-item>

              <div class="table-scroll">
                <table class="config-table">
                  <thead>
                    <tr>
                      <th class="key-column">Key</th>
                      <th>周期</th>
                      <th>阈值<span class="danger-text">（次）</span></th>
                      <th class="operation-column">操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="(limitKey, keyIndex) in item.limit_keys" :key="limitKey.id">
                      <td>
                        <div class="key-editor">
                          <a-select
                            v-model="limitKey.key_type"
                            placeholder="Key 类型"
                            class="key-type-control"
                            @change="value => value === 'full' && (limitKey.key = '')"
                          >
                            <a-option
                              v-for="option in getKeyTypeOptions(item)"
                              :key="option.value"
                              :label="option.label"
                              :value="option.value"
                            />
                          </a-select>
                          <a-input v-if="limitKey.key_type === 'full'" readonly model-value=".*" class="key-control">
                            <template #prepend>regexp:^</template>
                          </a-input>
                          <a-input
                            v-else
                            v-model="limitKey.key"
                            :spellcheck="false"
                            placeholder="请输入 Key"
                            class="key-control"
                          >
                            <template v-if="limitKey.key_type !== 'exact'" #prepend>regexp:^</template>
                            <template v-if="limitKey.key_type === 'prefix'" #append>.*</template>
                          </a-input>
                        </div>
                      </td>
                      <td>
                        <a-select v-model="limitKey.period" placeholder="周期">
                          <a-option
                            v-for="option in thresholdOptions"
                            :key="option.value"
                            :label="option.label"
                            :value="option.value"
                          />
                        </a-select>
                      </td>
                      <td>
                        <a-input-number v-model="limitKey.value" :min="1" placeholder="阈值" class="full-control" />
                      </td>
                      <td>
                        <a-button type="text" status="danger" @click="removeLimitKey(item, keyIndex)">删除</a-button>
                      </td>
                    </tr>
                    <tr>
                      <td colspan="4" class="add-row" @click="addLimitKey(item)">
                        <icon-plus :size="14" />
                        <span>新增子规则</span>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </article>
          </div>
        </a-form-item>
      </div>
    </a-form>

    <div class="page-actions">
      <a-button type="primary" :loading="saving" @click="submit">保存配置</a-button>
    </div>
  </section>
</template>

<script>
import { IconPlus } from '@arco-design/web-vue/es/icon'
import { clone, persistPluginConfig, pluginState } from '@/utils/plugin-config'

const thresholdOptions = [
  { label: '每秒', value: 'query_per_second' },
  { label: '每分钟', value: 'query_per_minute' },
  { label: '每小时', value: 'query_per_hour' },
  { label: '每天', value: 'query_per_day' },
]

const ipSourceOptions = ['from-header-x-forwarded-for', 'from-remote-addr']

const limitTypeOptions = [
  { label: '按请求 Header', value: 'header', fixedType: 'limit_by_header', dynamicType: 'limit_by_per_header', dynamicDefault: false, dynamicLocked: false },
  { label: '按请求 URL 参数名', value: 'param', fixedType: 'limit_by_param', dynamicType: 'limit_by_per_param', dynamicDefault: false, dynamicLocked: false },
  { label: '按请求 Cookie', value: 'cookie', fixedType: 'limit_by_cookie', dynamicType: 'limit_by_per_cookie', dynamicDefault: false, dynamicLocked: false },
  { label: '按请求 Consumer', value: 'consumer', fixedType: 'limit_by_consumer', dynamicType: 'limit_by_per_consumer', dynamicDefault: false, dynamicLocked: false },
  { label: '按请求 IP', value: 'ip', fixedType: '', dynamicType: 'limit_by_per_ip', dynamicDefault: true, dynamicLocked: true },
]

function createId() {
  return `${Date.now()}-${Math.random()}`
}

function createLimitKey() {
  return { id: createId(), key: '', key_type: 'prefix', period: 'query_per_second', value: 1 }
}

function createRuleItem() {
  return { id: createId(), limitType: 'header', dynamicValue: false, limitValue: '', limit_keys: [createLimitKey()] }
}

export default {
  components: { IconPlus },
  data() {
    return {
      saving: false,
      form: {},
      thresholdOptions,
      ipSourceOptions,
      limitTypeOptions,
    }
  },
  created() {
    this.dataToForm(clone(pluginState.config))
  },
  methods: {
    dataToForm(config = {}) {
      const hasRuleItems = Array.isArray(config.rule_items) && config.rule_items.length > 0
      this.form = {
        rule_name: config.rule_name || this.generateRuleName(),
        show_limit_quota_header: Boolean(config.show_limit_quota_header),
        mode: config.global_threshold || !hasRuleItems ? 'global_threshold' : 'rule_items',
        global_threshold: this.parseThreshold(config.global_threshold),
        rule_items: hasRuleItems
          ? config.rule_items.map(item => this.parseRuleItem(item))
          : [this.normalizeRuleItem(createRuleItem())],
      }
    },
    buildConfig() {
      const config = {
        ...clone(pluginState.config),
        rule_name: this.form.rule_name,
        show_limit_quota_header: Boolean(this.form.show_limit_quota_header),
      }
      delete config.global_threshold
      delete config.rule_items
      if (this.form.mode === 'global_threshold') {
        config.global_threshold = this.buildThreshold(this.form.global_threshold.period, this.form.global_threshold.value)
      } else {
        config.rule_items = this.form.rule_items.map(item => this.buildRuleItem(item))
      }
      return config
    },
    async submit() {
      if (!this.validate()) return
      this.saving = true
      try {
        await persistPluginConfig(this.buildConfig())
        this.$message.success('配置已保存')
      } catch (error) {
        this.$message.error(error?.message || '配置保存失败')
      } finally {
        this.saving = false
      }
    },
    isConsumerType(type) {
      return type === 'limit_by_consumer' || type === 'limit_by_per_consumer'
    },
    isIpType(type) {
      return type === 'limit_by_per_ip'
    },
    isDynamicValueLocked(item = {}) {
      return this.getLimitTypeOption(item.limitType).dynamicLocked
    },
    getKeyTypeOptions(item = {}) {
      if (!item.dynamicValue) return [{ label: '精准匹配', value: 'exact' }]
      return [
        { label: '前缀匹配', value: 'prefix' },
        { label: '正则匹配', value: 'regex' },
        { label: '全量匹配', value: 'full' },
        { label: '精准匹配', value: 'exact' },
      ]
    },
    limitValuePlaceholder(type) {
      if (type === 'limit_by_per_ip') return '请选择 IP 来源'
      if (this.isConsumerType(type)) return 'Consumer 类型无需填写'
      return '例如：Header 名、URL 参数名或 Cookie 名'
    },
    parseRuleItem(item = {}) {
      const option = limitTypeOptions.find(current =>
        (current.fixedType && Object.prototype.hasOwnProperty.call(item, current.fixedType)) ||
        (current.dynamicType && Object.prototype.hasOwnProperty.call(item, current.dynamicType))
      ) || limitTypeOptions[0]
      const actualType = option.fixedType && Object.prototype.hasOwnProperty.call(item, option.fixedType)
        ? option.fixedType
        : option.dynamicType
      return this.normalizeRuleItem({
        id: createId(),
        limitType: option.value,
        dynamicValue: actualType === option.dynamicType,
        limitValue: item[actualType] ?? '',
        limit_keys: (item.limit_keys || []).map(keyItem => ({
          id: createId(),
          ...this.parseLimitKey(keyItem.key || ''),
          ...this.parseThreshold(keyItem),
        })),
      })
    },
    parseLimitKey(rawKey = '') {
      const text = String(rawKey || '')
      if (text === '*' || text === 'regexp:^.*') return { key: '', key_type: 'full' }
      const prefixMatch = text.match(/^regexp:\^(.*)\.\*$/)
      if (prefixMatch) return { key: prefixMatch[1], key_type: 'prefix' }
      const regexMatch = text.match(/^regexp:\^(.*)$/)
      if (regexMatch) return { key: regexMatch[1], key_type: 'regex' }
      return { key: text, key_type: 'exact' }
    },
    getLimitTypeOption(type) {
      return limitTypeOptions.find(item => item.value === type) || limitTypeOptions[0]
    },
    getActualLimitType(item = {}) {
      const option = this.getLimitTypeOption(item.limitType)
      if (option.dynamicLocked) return option.dynamicType
      return item.dynamicValue ? option.dynamicType : option.fixedType
    },
    validate() {
      if (this.form.mode === 'global_threshold') {
        if (!this.form.global_threshold.period || !Number(this.form.global_threshold.value)) {
          this.$message.error('请补全全局限流阈值')
          return false
        }
        return true
      }
      if (!this.form.rule_items.length) {
        this.$message.error('请至少添加一个设置块')
        return false
      }
      for (let i = 0; i < this.form.rule_items.length; i += 1) {
        const item = this.form.rule_items[i]
        const actualType = this.getActualLimitType(item)
        if (!this.isConsumerType(actualType) && !item.limitValue) {
          this.$message.error(`设置块 ${i + 1} 缺少匹配名称`)
          return false
        }
        if (!item.limit_keys?.length) {
          this.$message.error(`设置块 ${i + 1} 缺少子规则`)
          return false
        }
        for (let j = 0; j < item.limit_keys.length; j += 1) {
          const keyItem = item.limit_keys[j]
          if (keyItem.key_type !== 'full' && !keyItem.key) {
            this.$message.error(`设置块 ${i + 1} 的第 ${j + 1} 条子规则缺少 Key`)
            return false
          }
          if (!keyItem.period || !Number(keyItem.value)) {
            this.$message.error(`设置块 ${i + 1} 的第 ${j + 1} 条子规则阈值不完整`)
            return false
          }
        }
      }
      return true
    },
    parseThreshold(obj = {}) {
      const found = thresholdOptions.find(item => Number(obj?.[item.value]) > 0)
      return { period: found?.value || 'query_per_second', value: found ? Number(obj[found.value]) : 1 }
    },
    buildThreshold(period, value) {
      return { [period]: Number(value) }
    },
    buildLimitKey(item = {}) {
      const key = String(item.key || '')
      if (item.key_type === 'full') return 'regexp:^.*'
      if (item.key_type === 'prefix') return `regexp:^${key}.*`
      if (item.key_type === 'regex') return `regexp:^${key}`
      return key
    },
    buildRuleItem(item) {
      const actualType = this.getActualLimitType(item)
      return {
        [actualType]: this.isConsumerType(actualType) ? '' : item.limitValue,
        limit_keys: item.limit_keys.map(keyItem => ({
          key: this.buildLimitKey(keyItem),
          ...this.buildThreshold(keyItem.period, keyItem.value),
        })),
      }
    },
    generateRuleName() {
      return `rate-limit-rule-${this.createName(10)}`
    },
    addRuleItem() {
      this.form.rule_items.push(this.normalizeRuleItem(createRuleItem()))
    },
    removeRuleItem(index) {
      if (this.form.rule_items.length === 1) {
        this.$message.warning('至少保留一个设置块')
        return
      }
      this.form.rule_items.splice(index, 1)
    },
    addLimitKey(item) {
      item.limit_keys.push(createLimitKey())
      this.normalizeRuleItem(item)
    },
    removeLimitKey(item, index) {
      if (item.limit_keys.length === 1) {
        this.$message.warning('至少保留一条子规则')
        return
      }
      item.limit_keys.splice(index, 1)
    },
    normalizeRuleItem(item = {}) {
      const option = this.getLimitTypeOption(item.limitType)
      if (option.dynamicLocked) item.dynamicValue = true
      else if (typeof item.dynamicValue !== 'boolean') item.dynamicValue = Boolean(option.dynamicDefault)
      const actualType = this.getActualLimitType(item)
      if (this.isIpType(actualType) && !ipSourceOptions.includes(item.limitValue)) item.limitValue = ipSourceOptions[0]
      if (this.isConsumerType(actualType)) item.limitValue = ''
      if (!item.limit_keys?.length) item.limit_keys = [createLimitKey()]
      if (!item.dynamicValue) item.limit_keys = item.limit_keys.map(keyItem => ({ ...keyItem, key_type: 'exact' }))
      return item
    },
    handleLimitTypeChange(item) {
      this.normalizeRuleItem(item)
    },
    handleDynamicValueChange(item) {
      this.normalizeRuleItem(item)
    },
    createName(length) {
      const chars = 'abcdefghijklmnopqrstuvwxyz'
      let value = ''
      for (let i = 0; i < length; i += 1) value += chars[parseInt(Math.random() * chars.length, 10)]
      return value
    },
  },
}
</script>

<style scoped>
.rate-page {
  width: 100%;
  max-width: 1080px;
  padding-top: 20px;
}

.rate-form,
.strategy-list {
  width: 100%;
}

.medium-control {
  width: 320px;
}

.mode-box {
  margin-top: 8px;
}

.inline-controls,
.limit-type-row,
.key-editor,
.add-row {
  display: flex;
  align-items: center;
  gap: 10px;
}

.threshold-control {
  width: 220px;
}

.create-button {
  margin-bottom: 4px;
}

.strategy-card {
  width: 100%;
  margin-top: 16px;
  padding: 20px;
  background: #f7f8fa;
  border: 1px solid #e5e6eb;
  border-radius: 4px;
}

.card-actions {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 12px;
}

.strategy-title {
  font-weight: 600;
}

.table-scroll {
  width: 100%;
  overflow-x: auto;
}

.config-table {
  width: 100%;
  min-width: 880px;
  border-collapse: collapse;
  background: #fff;
}

.config-table th,
.config-table td {
  padding: 12px;
  text-align: left;
  border: 1px solid #e5e6eb;
}

.config-table th {
  color: #4e5969;
  font-weight: 500;
  background: #f2f3f5;
}

.key-column {
  width: 52%;
}

.operation-column {
  width: 90px;
}

.key-type-control {
  width: 120px;
  flex: 0 0 120px;
}

.key-control {
  min-width: 280px;
}

.full-control {
  width: 100%;
}

.add-row {
  justify-content: center;
  color: #86909c;
  cursor: pointer;
}

.add-row:hover {
  color: rgb(var(--primary-6));
  background: var(--color-primary-light-1);
}

.danger-text {
  color: rgb(var(--danger-6));
}

.page-actions {
  display: flex;
  justify-content: flex-end;
  margin-top: 20px;
}

@media (max-width: 760px) {
  .medium-control,
  .threshold-control {
    width: 100%;
  }

  .inline-controls,
  .limit-type-row {
    align-items: flex-start;
    flex-direction: column;
    width: 100%;
  }
}
</style>
