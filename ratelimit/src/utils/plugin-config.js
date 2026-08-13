import { reactive } from 'vue'

export const pluginState = reactive({
  config: {},
  enabled: true,
  configScope: 'global',
  pluginId: '',
  namespace: '',
  ingressName: '',
  domain: '',
  path: '',
})

export function clone(value) {
  if (!value || typeof value !== 'object') return {}
  return JSON.parse(JSON.stringify(value))
}

export function getPluginProps() {
  return window.$wujie?.props || {}
}

function getGlobalRedisConfig(globalConfig = {}) {
  return clone(globalConfig.redis)
}

function createRuleName(length = 10) {
  const chars = 'abcdefghijklmnopqrstuvwxyz'
  let suffix = ''
  for (let i = 0; i < length; i += 1) {
    suffix += chars[parseInt(Math.random() * chars.length, 10)]
  }
  return `rate-limit-rule-${suffix}`
}

function normalizePluginConfig(value) {
  const config = clone(value)
  const normalized = {
    rule_name: config.rule_name || createRuleName(),
    show_limit_quota_header: Boolean(config.show_limit_quota_header),
    rejected_code: Number(config.rejected_code || 429),
    rejected_msg: config.rejected_msg || 'Too many requests',
    ...config,
    redis: {
      service_name: '',
      service_port: 6379,
      timeout: 1000,
      database: 0,
      ...(config.redis || {}),
    },
  }
  if (!normalized.global_threshold && !normalized.rule_items?.length) {
    normalized.global_threshold = { query_per_second: 1 }
  }
  return normalized
}

export function loadPluginState() {
  const props = getPluginProps()
  const pluginConfig = normalizePluginConfig(props.pluginConfig)
  const globalRedis = getGlobalRedisConfig(props.globalPluginConfig)
  pluginState.config = normalizePluginConfig({
    ...pluginConfig,
    redis: {
      ...pluginConfig.redis,
      ...globalRedis,
    },
  })
  pluginState.enabled = props.pluginEnabled ?? props.pluginConfigEnabled ?? props.enabled ?? true
  pluginState.configScope = props.configScope === 'rule' ? 'rule' : 'global'
  pluginState.pluginId = typeof props.pluginId === 'string' ? props.pluginId : ''
  pluginState.namespace = typeof props.namespace === 'string' ? props.namespace : ''
  pluginState.ingressName = typeof props.ingressName === 'string' ? props.ingressName : ''
  pluginState.domain = typeof props.domain === 'string' ? props.domain : ''
  pluginState.path = typeof props.path === 'string' ? props.path : ''
}

export async function persistPluginConfig(config) {
  const savePluginConfig = getPluginProps().savePluginConfig
  if (typeof savePluginConfig !== 'function') {
    throw new Error('当前运行环境未提供 savePluginConfig')
  }
  await Promise.resolve(savePluginConfig(config, pluginState.enabled))
  pluginState.config = clone(config)
  return pluginState.config
}
