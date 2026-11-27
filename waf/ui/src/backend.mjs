import catalog from '../system-rules.json' with { type: 'json' }
import { validateCustomRules } from './rules.mjs'

const pluginPath = '/apis/extensions.higress.io/v1alpha1/namespaces/higress-system/wasmplugins/w7panel-pluginwaf'
const files = new Set(catalog.files.map(file => file.name.replace(/\.conf$/, '')))
const detectionFiles = new Map(catalog.rules.filter(rule => !rule.internal && rule.message).map(rule => [rule.id, rule.file.replace(/\.conf$/, '')]))
const uiCatalog = { ...catalog, files: catalog.files.map(file => ({ ...file, name: file.name.replace(/\.conf$/, '') })), rules: catalog.rules.map(rule => ({ ...rule, file: rule.file.replace(/\.conf$/, '') })) }

function context(props) {
  const scope = props.configScope === 'rule' ? 'rule' : 'global'
  if (scope === 'rule' && (!props.namespace || !props.ingressName)) throw new Error('域名配置需要 namespace 和 ingressName')
  return { scope, target: `${props.namespace}/${props.ingressName}` }
}

async function k8s(props, path, init) {
  if (typeof props.k8sproxy !== 'function') throw new Error('当前面板未提供 Kubernetes 代理接口')
  const response = await props.k8sproxy(path, init)
  if (!response.ok) throw new Error(`Kubernetes 请求失败（${response.status}）：${await response.text()}`)
  return response.status === 204 ? null : response.json()
}

async function ingress(props) {
  const path = `/apis/networking.k8s.io/v1/namespaces/${encodeURIComponent(props.namespace)}/ingresses/${encodeURIComponent(props.ingressName)}`
  const item = await k8s(props, path)
  if (!item?.spec?.rules?.[0]?.host) throw new Error('无法读取当前域名')
}

const policy = value => ({ categories: {}, customRules: [], ...value })
function domainPolicy(value) {
  const overrides = policy(value)
  overrides.protectionMode ||= 'inherit'
  delete overrides.useCRS
  delete overrides.customRuleStates
  delete overrides.enabledGlobalIds
  if (overrides.policyVersion === 2) return overrides
  const inherit = overrides.protectionMode === 'inherit'
  return {
    ...overrides,
    policyVersion: 2,
    requestBodyAccess: inherit ? null : overrides.requestBodyAccess ?? null,
    paranoiaLevel: inherit ? null : overrides.paranoiaLevel ?? null,
    categories: inherit ? {} : overrides.categories,
    ruleStates: inherit ? {} : overrides.ruleStates || {},
  }
}
function globalConfig(plugin) {
  const config = plugin.spec?.defaultConfig || {}
  const global = policy(config.w7Policy)
  global.useCRS = true
  global.customRules = global.customRules.map(rule => ({ ...rule, enabled: true }))
  if (!global.protectionMode) global.protectionMode = 'disabled'
  return { config, global }
}
const findRule = (rules, target) => rules.findIndex(rule => rule.ingress?.includes(target))

export function compile(global, overrides) {
  for (const entry of [global, overrides].filter(Boolean)) {
    for (const name of Object.keys(entry.categories || {})) if (!files.has(name)) throw new Error(`未知 CRS 规则文件：${name}`)
    for (const id of Object.keys(entry.ruleStates || {})) if (!detectionFiles.has(Number(id))) throw new Error(`未知 CRS 规则 ID：${id}`)
  }
  if (!['disabled', 'custom', 'observe'].includes(global.protectionMode || 'disabled')) throw new Error('全局防护开关无效')
  if (overrides && !['disabled', 'custom', 'observe', 'inherit'].includes(overrides.protectionMode || 'inherit')) throw new Error('域名防护开关无效')
  if (global.paranoiaLevel && ![1, 2, 3, 4].includes(global.paranoiaLevel)) throw new Error('防护强度无效')
  if (overrides?.paranoiaLevel && ![1, 2, 3, 4].includes(overrides.paranoiaLevel)) throw new Error('域名防护强度无效')
  const ruleError = validateCustomRules(global.customRules || [])
  if (ruleError) throw new Error(ruleError)
  if (overrides?.customRules?.length) throw new Error('自定义规则只能在全局添加')
  const legacyInherit = overrides && overrides.policyVersion !== 2 && (!overrides.protectionMode || overrides.protectionMode === 'inherit')
  const own = overrides && !legacyInherit ? overrides : null
  const mode = overrides?.protectionMode && overrides.protectionMode !== 'inherit' ? overrides.protectionMode : global.protectionMode
  const categories = { ...global.categories, ...own?.categories }
  const ruleStates = { ...global.ruleStates, ...own?.ruleStates }
  const customRules = (global.customRules || []).map(rule => ({ id: rule.id, rule: rule.rule.trim(), enabled: true }))
  return { useCRS: true, categories, ruleStates, customRules, requestBodyAccess: own?.requestBodyAccess ?? global.requestBodyAccess ?? false, engineMode: mode === 'observe' ? 'DetectionOnly' : 'On', paranoiaLevel: own?.paranoiaLevel ?? global.paranoiaLevel ?? 1 }
}

export async function loadWafConfig(props) {
  const { scope, target } = context(props)
  if (scope === 'rule') await ingress(props)
  const plugin = await k8s(props, pluginPath)
  const { global } = globalConfig(plugin)
  const rules = plugin.spec?.matchRules || []
  const config = rules[findRule(rules, target)]?.config || {}
  const overrides = domainPolicy(config.w7Overrides)
  return { global, overrides, catalog: uiCatalog }
}

export async function saveWafConfig(props, input) {
  const { scope, target } = context(props)
  if (scope === 'rule') await ingress(props)
  const plugin = await k8s(props, pluginPath)
  const spec = plugin.spec || (plugin.spec = {})
  const { config, global: savedGlobal } = globalConfig(plugin)
  const rules = spec.matchRules || (spec.matchRules = [])
  if (scope === 'global') {
    const global = policy(input)
    global.useCRS = true
    global.customRules = global.customRules.map(rule => ({ ...rule, enabled: true }))
    Object.assign(config, compile(global), { w7Policy: global })
    for (const key of ['ruleFiles', 'secRules']) delete config[key]
    delete config.w7LegacyRules
    spec.defaultConfig = config
    spec.defaultConfigDisable = global.protectionMode === 'disabled'
    for (const rule of rules) {
      if (!rule.config?.w7Overrides) continue
      const overrides = policy(rule.config.w7Overrides)
      delete overrides.useCRS
      delete overrides.customRuleStates
      delete overrides.enabledGlobalIds
      if (!overrides.protectionMode) overrides.protectionMode = 'inherit'
      Object.assign(rule.config, compile(global, overrides), { w7Overrides: overrides })
      for (const key of ['ruleFiles', 'secRules']) delete rule.config[key]
      rule.configDisable = (overrides.protectionMode === 'inherit' ? global.protectionMode : overrides.protectionMode) === 'disabled'
    }
  } else {
    const overrides = domainPolicy(input)
    overrides.policyVersion = 2
    if (!overrides.protectionMode) overrides.protectionMode = 'inherit'
    const compiled = compile(savedGlobal, overrides)
    let index = findRule(rules, target)
    if (index < 0) {
      rules.push({ ingress: [target], config: {}, configDisable: false })
      index = rules.length - 1
    } else {
      const rule = rules[index]
      const remaining = (rule.ingress || []).filter(name => name !== target)
      const shared = remaining.length || Object.entries(rule).some(([key, value]) => !['ingress', 'config', 'configDisable'].includes(key) && Array.isArray(value) && value.length)
      if (shared) {
        const isolated = structuredClone(rule)
        isolated.ingress = [target]
        for (const [key, value] of Object.entries(isolated)) if (!['ingress', 'config', 'configDisable'].includes(key) && Array.isArray(value) && value.length) delete isolated[key]
        if (remaining.length) rule.ingress = remaining
        else delete rule.ingress
        rules.push(isolated)
        index = rules.length - 1
      }
    }
    const rule = rules[index]
    rule.config = { ...rule.config, ...compiled, w7Overrides: overrides }
    for (const key of ['ruleFiles', 'secRules']) delete rule.config[key]
    rule.configDisable = (overrides.protectionMode === 'inherit' ? savedGlobal.protectionMode : overrides.protectionMode) === 'disabled'
  }
  await k8s(props, pluginPath, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(plugin) })
  await props.refreshPluginConfig?.()
}
