import assert from 'node:assert/strict'
import { test } from 'node:test'
import { initLocalWaf } from '../src/local-dev.mjs'
import { loadWafConfig, saveWafConfig, compile } from '../src/backend.mjs'

const pluginPath = '/apis/extensions.higress.io/v1alpha1/namespaces/higress-system/wasmplugins/w7panel-pluginwaf'

test('standalone WAF reads and saves WasmPlugin through k8sproxy', async () => {
  const calls = []
  const plugin = { metadata: { resourceVersion: '1' }, spec: { defaultConfig: { useCRS: false }, matchRules: [
    { ingress: ['default/site', 'default/other'], config: { useCRS: false } },
  ] } }
  globalThis.window = {
    location: { search: '?scope=rule&namespace=default&ingressName=site&domain=site.example' },
    prompt: () => 'signed',
  }
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options })
    const body = url.includes('/ingresses/site')
      ? { spec: { rules: [{ host: 'site.example' }] } }
      : plugin
    if (options.method === 'PUT') Object.assign(plugin, JSON.parse(options.body))
    return { ok: true, status: 200, json: async () => structuredClone(body), text: async () => '' }
  }
  initLocalWaf()
  const props = window.$wujie.props
  const loaded = await loadWafConfig(props)
  assert.equal(loaded.global.useCRS, true)
  assert.ok(loaded.catalog.rules.length > 600)
  await saveWafConfig(props, { protectionMode: 'inherit', useCRS: false, categories: {}, ruleStates: {}, enabledGlobalIds: [] })
  assert.deepEqual(plugin.spec.matchRules.map(rule => rule.ingress), [['default/other'], ['default/site']])
  assert.equal(plugin.metadata.resourceVersion, '1')
  assert.equal(calls.at(-1).url, `/k8s-proxy${pluginPath}`)
  assert.equal(calls.at(-1).options.headers['X-W7Panel-Token'], 'signed')
  assert.equal(calls.at(-1).options.method, 'PUT')
})

test('global save compiles CRS and inherited domain rules', async () => {
  let plugin = { metadata: { resourceVersion: '3' }, spec: { defaultConfig: { useCRS: false, w7Policy: { protectionMode: 'observe' } }, matchRules: [
    { ingress: ['default/site'], config: { w7Policy: { protectionMode: 'observe' }, w7Overrides: { protectionMode: 'custom' } } },
  ] } }
  const props = { configScope: 'global', k8sproxy: async (_, init) => {
    if (init?.method === 'PUT') { plugin = JSON.parse(init.body); return { ok: true, status: 200, json: async () => plugin } }
    return { ok: true, status: 200, json: async () => structuredClone(plugin) }
  } }
  await saveWafConfig(props, { useCRS: true, categories: {}, ruleStates: { 942100: false }, customRules: [
    { id: 1000000, rule: 'SecRule REQUEST_URI "@streq /admin" "id:1000000,phase:1,deny"', enabled: true },
  ] })
  assert.equal(plugin.spec.defaultConfig.ruleStates[942100], false)
  assert.equal(plugin.spec.defaultConfig.secRules, undefined)
  assert.equal(plugin.spec.defaultConfig.ruleFiles, undefined)
  assert.equal(plugin.spec.defaultConfig.customRules[0].id, 1000000)
  assert.equal(plugin.spec.defaultConfig.customRules[0].enabled, false)
  assert.equal(plugin.spec.defaultConfig.policy.customRules[0].enabled, false)
  assert.equal(plugin.spec.defaultConfig.w7Policy, undefined)
  assert.equal(plugin.spec.matchRules[0].config.useCRS, true)
  assert.equal(plugin.spec.matchRules[0].config.overrides.protectionMode, 'inherit')
  assert.equal(plugin.spec.matchRules[0].config.w7Policy, undefined)
  assert.equal(plugin.spec.matchRules[0].config.w7Overrides, undefined)
  assert.equal(plugin.spec.matchRules[0].config.secRules, undefined)
  assert.equal(plugin.metadata.resourceVersion, '3')
})

test('custom rules are off by default and can be enabled per domain', () => {
  const global = { protectionMode: 'observe', useCRS: true, categories: { 'REQUEST-942-APPLICATION-ATTACK-SQLI': false }, customRules: [{ id: 1000000, rule: 'SecRule REQUEST_URI "@streq /admin" "id:1000000,phase:1,deny"', enabled: true }] }
  const own = compile(global, { protectionMode: 'custom', categories: {}, enabledGlobalIds: [] })
  assert.equal(own.customRules[0].enabled, false)
  assert.equal(own.categories['REQUEST-942-APPLICATION-ATTACK-SQLI'], false)
  assert.equal(compile(global, { protectionMode: 'custom', customRuleStates: { 1000000: true } }).customRules[0].enabled, true)
  assert.equal(compile(global, { protectionMode: 'inherit', customRuleStates: { 1000000: true } }).customRules[0].enabled, false)
  assert.equal(compile(global, { protectionMode: 'inherit' }).engineMode, 'DetectionOnly')
})

test('following global ignores domain settings and restores them in custom mode', () => {
  const global = { protectionMode: 'observe', useCRS: true, requestBodyAccess: false, paranoiaLevel: 1,
    categories: { 'REQUEST-942-APPLICATION-ATTACK-SQLI': false }, ruleStates: { 942100: false },
    customRules: [{ id: 1000000, rule: 'SecRule REQUEST_URI "@streq /admin" "id:1000000,phase:1,deny"', enabled: true }],
  }
  const own = { policyVersion: 2, protectionMode: 'inherit', useCRS: false, requestBodyAccess: true, paranoiaLevel: 2,
    categories: { 'REQUEST-942-APPLICATION-ATTACK-SQLI': true }, ruleStates: { 942100: true }, customRuleStates: { 1000000: false } }
  assert.deepEqual(compile(global, own), { useCRS: true, requestBodyAccess: false, paranoiaLevel: 1,
    categories: { 'REQUEST-942-APPLICATION-ATTACK-SQLI': false }, ruleStates: { 942100: false }, customRules: [{ ...global.customRules[0], enabled: false }], engineMode: 'DetectionOnly' })
  delete own.useCRS
  delete own.customRuleStates[1000000]
  assert.equal(compile(global, own).useCRS, true)
  assert.equal(compile(global, own).customRules.length, 1)
  own.protectionMode = 'custom'
  assert.equal(compile(global, own).engineMode, 'On')
  assert.equal(compile(global, own).requestBodyAccess, true)
  assert.equal(compile(global, own).paranoiaLevel, 2)
  assert.equal(compile(global, own).categories['REQUEST-942-APPLICATION-ATTACK-SQLI'], true)
  assert.equal(compile(global, own).ruleStates[942100], true)
  own.customRuleStates[1000000] = true
  assert.equal(compile(global, own).customRules[0].enabled, true)
  assert.equal(compile(global, { policyVersion: 2, customRuleStates: { 1000000: false } }).customRules.length, 1)
})

test('old CRS switch is removed and custom rule state is preserved on domain save', async () => {
  const global = { protectionMode: 'observe', useCRS: true, customRules: [
    { id: 1000000, rule: 'SecRule REQUEST_URI "@streq /admin" "id:1000000,phase:1,deny"', enabled: true },
  ] }
  let plugin = { spec: { defaultConfig: { policy: global }, matchRules: [
    { ingress: ['default/site'], config: { overrides: { protectionMode: 'inherit', useCRS: false, enabledGlobalIds: [] } } },
  ] } }
  const props = { configScope: 'rule', namespace: 'default', ingressName: 'site', k8sproxy: async (path, init) => {
    if (init?.method === 'PUT') { plugin = JSON.parse(init.body); return { ok: true, status: 200, json: async () => plugin } }
    return { ok: true, status: 200, json: async () => path.includes('/ingresses/') ? { spec: { rules: [{ host: 'site.example' }] } } : structuredClone(plugin) }
  } }
  let loaded = await loadWafConfig(props)
  assert.equal(loaded.overrides.useCRS, undefined)
  assert.deepEqual(loaded.overrides.customRuleStates, {})
  assert.equal(compile(loaded.global, loaded.overrides).customRules.length, 1)
  await saveWafConfig(props, loaded.overrides)
  assert.equal(plugin.spec.matchRules[0].config.useCRS, true)
  assert.equal(plugin.spec.matchRules[0].config.overrides.enabledGlobalIds, undefined)
  assert.deepEqual(plugin.spec.matchRules[0].config.overrides.customRuleStates, {})
  loaded.overrides.protectionMode = 'custom'
  loaded.overrides.customRuleStates[1000000] = true
  await saveWafConfig(props, loaded.overrides)
  assert.equal(plugin.spec.matchRules[0].config.customRules[0].enabled, true)
  loaded.overrides.protectionMode = 'inherit'
  await saveWafConfig(props, loaded.overrides)
  assert.equal(plugin.spec.matchRules[0].config.customRules[0].enabled, false)
  assert.equal(plugin.spec.matchRules[0].config.overrides.customRuleStates[1000000], true)
  loaded.overrides.protectionMode = 'custom'
  await saveWafConfig(props, loaded.overrides)
  assert.equal(plugin.spec.matchRules[0].config.customRules[0].enabled, true)
  plugin.spec.matchRules[0].config.overrides = { protectionMode: 'custom', useCRS: false, enabledGlobalIds: [] }
  loaded = await loadWafConfig(props)
  assert.equal(loaded.overrides.useCRS, undefined)
  assert.deepEqual(loaded.overrides.customRuleStates, {})
  assert.equal(compile(loaded.global, loaded.overrides).customRules.length, 1)
})

test('global save recompiles domains with independent overrides', async () => {
  let plugin = { spec: { defaultConfig: {}, matchRules: [{ ingress: ['default/site'], config: { overrides: {
    policyVersion: 2, protectionMode: 'inherit', useCRS: false, customRuleStates: { 1000000: false },
  } } }] } }
  const props = { configScope: 'global', k8sproxy: async (_, init) => {
    if (init?.method === 'PUT') { plugin = JSON.parse(init.body); return { ok: true, status: 200, json: async () => plugin } }
    return { ok: true, status: 200, json: async () => structuredClone(plugin) }
  } }
  const global = { protectionMode: 'observe', useCRS: true, categories: {}, ruleStates: {}, customRules: [
    { id: 1000000, rule: 'SecRule REQUEST_URI "@streq /admin" "id:1000000,phase:1,deny"', enabled: true },
  ] }
  await saveWafConfig(props, global)
  const rule = plugin.spec.matchRules[0]
  assert.equal(rule.configDisable, false)
  assert.equal(rule.config.engineMode, 'DetectionOnly')
  assert.equal(rule.config.useCRS, true)
  assert.equal(rule.config.customRules.length, 1)
  assert.equal(rule.config.customRules[0].enabled, false)
  assert.deepEqual(rule.config.overrides.customRuleStates, { 1000000: false })
  assert.equal(rule.config.overrides.enabledGlobalIds, undefined)
  global.protectionMode = 'disabled'
  await saveWafConfig(props, global)
  assert.equal(plugin.spec.matchRules[0].configDisable, true)
  assert.deepEqual(plugin.spec.matchRules[0].config.overrides.customRuleStates, { 1000000: false })
  global.customRules = []
  await saveWafConfig(props, global)
  assert.deepEqual(plugin.spec.matchRules[0].config.overrides.customRuleStates, {})
})

test('policy categories and domain selections load without a file suffix', async () => {
  const plugin = { spec: { defaultConfigDisable: false, defaultConfig: { useCRS: true, policy: {
    categories: { 'REQUEST-942-APPLICATION-ATTACK-SQLI': false }, customRules: [{ id: 1000000, rule: 'SecRule REQUEST_URI "@streq /admin" "id:1000000,phase:1,deny"', enabled: true }],
  } }, matchRules: [{ ingress: ['default/site'], config: { overrides: { protectionMode: 'custom', enabledGlobalIds: [], categories: { 'REQUEST-941-APPLICATION-ATTACK-XSS': false } } } }] } }
  const props = { configScope: 'rule', namespace: 'default', ingressName: 'site', k8sproxy: async path => ({ ok: true, status: 200, json: async () => path.includes('/ingresses/') ? { spec: { rules: [{ host: 'site.example' }] } } : plugin }) }
  const loaded = await loadWafConfig(props)
  assert.equal(loaded.global.categories['REQUEST-942-APPLICATION-ATTACK-SQLI'], false)
  assert.equal(loaded.overrides.categories['REQUEST-941-APPLICATION-ATTACK-XSS'], false)
  assert.equal(loaded.overrides.enabledGlobalIds, undefined)
  assert.equal(loaded.overrides.protectionMode, 'custom')
})

test('old policy field names are ignored and removed on domain save', async () => {
  let plugin = { spec: { defaultConfig: { w7Policy: { protectionMode: 'observe' } }, matchRules: [
    { ingress: ['default/site'], config: { w7Policy: { protectionMode: 'observe' }, w7Overrides: { protectionMode: 'custom' } } },
  ] } }
  const props = { configScope: 'rule', namespace: 'default', ingressName: 'site', k8sproxy: async (path, init) => {
    if (init?.method === 'PUT') { plugin = JSON.parse(init.body); return { ok: true, status: 200, json: async () => plugin } }
    return { ok: true, status: 200, json: async () => path.includes('/ingresses/') ? { spec: { rules: [{ host: 'site.example' }] } } : structuredClone(plugin) }
  } }
  const loaded = await loadWafConfig(props)
  assert.equal(loaded.global.protectionMode, 'disabled')
  assert.equal(loaded.overrides.protectionMode, 'inherit')
  await saveWafConfig(props, { protectionMode: 'custom' })
  assert.equal(plugin.spec.defaultConfig.w7Policy, undefined)
  assert.equal(plugin.spec.matchRules[0].config.w7Policy, undefined)
  assert.equal(plugin.spec.matchRules[0].config.w7Overrides, undefined)
  assert.equal(plugin.spec.matchRules[0].config.overrides.protectionMode, 'custom')
})

test('invalid rules and Kubernetes conflicts stop save', async () => {
  assert.throws(() => compile({ categories: { '../bad.conf': true }, customRules: [] }), /未知 CRS/)
  const props = { configScope: 'global', k8sproxy: async (_, init) => init?.method === 'PUT'
    ? { ok: false, status: 409, text: async () => 'resourceVersion conflict' }
    : { ok: true, status: 200, json: async () => ({ metadata: { resourceVersion: '1' }, spec: { defaultConfig: {} } }) } }
  await assert.rejects(saveWafConfig(props, { useCRS: false }), /409.*resourceVersion conflict/)
  await assert.rejects(loadWafConfig({ configScope: 'rule' }), /namespace 和 ingressName/)
})
