import catalog from '../system-rules.json' with { type: 'json' }
import { validateCustomRules } from './rules.mjs'

const pluginPath = '/apis/extensions.higress.io/v1alpha1/namespaces/higress-system/wasmplugins/w7panel-pluginwaf'
const files = new Set(catalog.files.map(file => file.name))
const detectionFiles = new Map(catalog.rules.filter(rule => !rule.internal && rule.message).map(rule => [rule.id, rule.file]))

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
function globalConfig(plugin) {
  const config = plugin.spec?.defaultConfig || {}
  const global = policy(config.w7Policy)
  if (global.useCRS == null) global.useCRS = config.useCRS === true
  return { config, global }
}
const findRule = (rules, target) => rules.findIndex(rule => rule.ingress?.includes(target))

export function compile(global, overrides) {
  for (const entry of [global, overrides].filter(Boolean)) {
    for (const name of Object.keys(entry.categories || {})) if (!files.has(name)) throw new Error(`未知 CRS 规则文件：${name}`)
    for (const id of Object.keys(entry.ruleStates || {})) if (!detectionFiles.has(Number(id))) throw new Error(`未知 CRS 规则 ID：${id}`)
  }
  if (global.engineMode && !['On', 'Off', 'DetectionOnly'].includes(global.engineMode)) throw new Error('规则引擎模式无效')
  if (global.paranoiaLevel && ![1, 2, 3, 4].includes(global.paranoiaLevel)) throw new Error('规则严格度必须为 PL1–PL4')
  const ruleError = validateCustomRules(global.customRules || [])
  if (ruleError) throw new Error(ruleError)
  if (overrides) {
    if (overrides.customRules?.length || overrides.engineMode || overrides.paranoiaLevel) throw new Error('域名只能继承或禁用全局规则')
    const ids = new Set((global.customRules || []).map(rule => rule.id))
    for (const id of overrides.disabledGlobalIds || []) if (!ids.has(id)) throw new Error(`未知全局自定义规则 ID：${id}`)
  }
  const useCRS = overrides?.useCRS ?? global.useCRS ?? true
  const active = new Map(catalog.files.map(file => [file.name, global.categories?.[file.name] !== false]))
  for (const [name, enabled] of Object.entries(overrides?.categories || {})) active.set(name, enabled)
  const ruleFiles = [...active].filter(([, enabled]) => enabled).map(([name]) => name).sort()
  const states = { ...global.ruleStates, ...overrides?.ruleStates }
  const secRules = []
  if (overrides?.requestBodyAccess ?? global.requestBodyAccess ?? false) secRules.push('SecRequestBodyAccess On')
  if (useCRS) {
    for (const id of Object.keys(states).map(Number).filter(id => states[id] === false && active.get(detectionFiles.get(id))).sort((a, b) => a - b)) secRules.push(`SecRuleRemoveById ${id}`)
  }
  const disabled = new Set(overrides?.disabledGlobalIds || [])
  for (const rule of global.customRules || []) if (!disabled.has(rule.id)) secRules.push(rule.rule.trim())
  return { useCRS, ruleFiles, secRules, engineMode: global.engineMode || 'On', paranoiaLevel: global.paranoiaLevel || 1 }
}

export async function loadWafConfig(props) {
  const { scope, target } = context(props)
  if (scope === 'rule') await ingress(props)
  const plugin = await k8s(props, pluginPath)
  const { global } = globalConfig(plugin)
  const rules = plugin.spec?.matchRules || []
  const config = rules[findRule(rules, target)]?.config || {}
  const overrides = policy(config.w7Overrides)
  if (scope === 'rule' && !config.w7Overrides && typeof config.useCRS === 'boolean' && config.useCRS !== global.useCRS) overrides.useCRS = config.useCRS
  return { global, overrides, catalog }
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
    if (global.useCRS == null) global.useCRS = config.useCRS === true
    Object.assign(config, compile(global), { w7Policy: global })
    delete config.w7LegacyRules
    spec.defaultConfig = config
    for (const rule of rules) {
      if (!rule.config?.w7Overrides) continue
      const overrides = policy(rule.config.w7Overrides)
      const known = new Set((global.customRules || []).map(item => item.id))
      overrides.disabledGlobalIds = (overrides.disabledGlobalIds || []).filter(id => known.has(id))
      Object.assign(rule.config, compile(global, overrides), { w7Overrides: overrides })
    }
  } else {
    const overrides = policy(input)
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
    rule.configDisable = false
  }
  await k8s(props, pluginPath, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(plugin) })
  await props.refreshPluginConfig?.()
}
