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
  assert.equal(loaded.global.useCRS, false)
  assert.ok(loaded.catalog.rules.length > 600)
  await saveWafConfig(props, { protectionMode: 'inherit', useCRS: false, categories: {}, ruleStates: {}, enabledGlobalIds: [] })
  assert.deepEqual(plugin.spec.matchRules.map(rule => rule.ingress), [['default/other'], ['default/site']])
  assert.equal(plugin.metadata.resourceVersion, '1')
  assert.equal(calls.at(-1).url, `/k8s-proxy${pluginPath}`)
  assert.equal(calls.at(-1).options.headers['X-W7Panel-Token'], 'signed')
  assert.equal(calls.at(-1).options.method, 'PUT')
})

test('global save compiles CRS and inherited domain rules', async () => {
  let plugin = { metadata: { resourceVersion: '3' }, spec: { defaultConfig: { useCRS: false }, matchRules: [
    { ingress: ['default/site'], config: { w7Overrides: { protectionMode: 'custom', useCRS: false, enabledGlobalIds: [] } } },
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
  assert.equal(plugin.spec.defaultConfig.customRules[0].enabled, true)
  assert.equal(plugin.spec.matchRules[0].config.useCRS, false)
  assert.equal(plugin.spec.matchRules[0].config.secRules, undefined)
  assert.equal(plugin.metadata.resourceVersion, '3')
})

test('custom rules start disabled for domains and inherited mode follows global', () => {
  const global = { protectionMode: 'observe', useCRS: true, categories: { 'REQUEST-942-APPLICATION-ATTACK-SQLI': false }, customRules: [{ id: 1000000, rule: 'SecRule REQUEST_URI "@streq /admin" "id:1000000,phase:1,deny"', enabled: true }] }
  const own = compile(global, { protectionMode: 'custom', categories: {}, enabledGlobalIds: [] })
  assert.deepEqual(own.customRules, [])
  assert.equal(own.categories['REQUEST-942-APPLICATION-ATTACK-SQLI'], false)
  assert.equal(compile(global, { protectionMode: 'inherit', enabledGlobalIds: [] }).customRules.length, 1)
  assert.equal(compile(global, { protectionMode: 'inherit' }).engineMode, 'DetectionOnly')
})

test('domain policy overrides each setting independently of protection mode', () => {
  const global = { protectionMode: 'observe', useCRS: true, requestBodyAccess: false, paranoiaLevel: 1,
    categories: { 'REQUEST-942-APPLICATION-ATTACK-SQLI': false }, ruleStates: { 942100: false },
    customRules: [{ id: 1000000, rule: 'SecRule REQUEST_URI "@streq /admin" "id:1000000,phase:1,deny"', enabled: true }],
  }
  const own = { policyVersion: 2, protectionMode: 'inherit', useCRS: false, requestBodyAccess: true, paranoiaLevel: 2,
    categories: { 'REQUEST-942-APPLICATION-ATTACK-SQLI': true }, ruleStates: { 942100: true }, customRuleStates: { 1000000: false } }
  assert.deepEqual(compile(global, own), { useCRS: false, requestBodyAccess: true, paranoiaLevel: 2,
    categories: { 'REQUEST-942-APPLICATION-ATTACK-SQLI': true }, ruleStates: { 942100: true }, customRules: [], engineMode: 'DetectionOnly' })
  delete own.useCRS
  delete own.customRuleStates[1000000]
  assert.equal(compile(global, own).useCRS, true)
  assert.equal(compile(global, own).customRules.length, 1)
  own.protectionMode = 'custom'
  assert.equal(compile(global, own).engineMode, 'On')
  assert.throws(() => compile(global, { policyVersion: 2, customRuleStates: { 1000000: 'false' } }), /无效的自定义规则覆盖/)
})

test('existing domain policies load with the same effective selections', async () => {
  const global = { protectionMode: 'observe', useCRS: true, customRules: [
    { id: 1000000, rule: 'SecRule REQUEST_URI "@streq /admin" "id:1000000,phase:1,deny"', enabled: true },
  ] }
  let plugin = { spec: { defaultConfig: { w7Policy: global }, matchRules: [
    { ingress: ['default/site'], config: { w7Overrides: { protectionMode: 'inherit', useCRS: false, enabledGlobalIds: [] } } },
  ] } }
  const props = { configScope: 'rule', namespace: 'default', ingressName: 'site', k8sproxy: async (path, init) => {
    if (init?.method === 'PUT') { plugin = JSON.parse(init.body); return { ok: true, status: 200, json: async () => plugin } }
    return { ok: true, status: 200, json: async () => path.includes('/ingresses/') ? { spec: { rules: [{ host: 'site.example' }] } } : structuredClone(plugin) }
  } }
  let loaded = await loadWafConfig(props)
  assert.equal(loaded.overrides.useCRS, null)
  assert.deepEqual(loaded.overrides.customRuleStates, {})
  assert.equal(compile(loaded.global, loaded.overrides).customRules.length, 1)
  await saveWafConfig(props, loaded.overrides)
  assert.equal(plugin.spec.matchRules[0].config.useCRS, true)
  assert.equal(plugin.spec.matchRules[0].config.w7Overrides.enabledGlobalIds, undefined)
  plugin.spec.matchRules[0].config.w7Overrides = { protectionMode: 'custom', useCRS: false, enabledGlobalIds: [] }
  loaded = await loadWafConfig(props)
  assert.equal(loaded.overrides.useCRS, false)
  assert.equal(loaded.overrides.customRuleStates[1000000], false)
  assert.equal(compile(loaded.global, loaded.overrides).customRules.length, 0)
})

test('global save recompiles domains with independent overrides', async () => {
  let plugin = { spec: { defaultConfig: {}, matchRules: [{ ingress: ['default/site'], config: { w7Overrides: {
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
  assert.equal(rule.config.useCRS, false)
  assert.deepEqual(rule.config.customRules, [])
  assert.equal(rule.config.w7Overrides.enabledGlobalIds, undefined)
  global.protectionMode = 'disabled'
  await saveWafConfig(props, global)
  assert.equal(plugin.spec.matchRules[0].configDisable, true)
})

test('policy categories and domain selections load without a file suffix', async () => {
  const plugin = { spec: { defaultConfigDisable: false, defaultConfig: { useCRS: true, w7Policy: {
    categories: { 'REQUEST-942-APPLICATION-ATTACK-SQLI': false }, customRules: [{ id: 1000000, rule: 'SecRule REQUEST_URI "@streq /admin" "id:1000000,phase:1,deny"', enabled: true }],
  } }, matchRules: [{ ingress: ['default/site'], config: { w7Overrides: { protectionMode: 'custom', enabledGlobalIds: [], categories: { 'REQUEST-941-APPLICATION-ATTACK-XSS': false } } } }] } }
  const props = { configScope: 'rule', namespace: 'default', ingressName: 'site', k8sproxy: async path => ({ ok: true, status: 200, json: async () => path.includes('/ingresses/') ? { spec: { rules: [{ host: 'site.example' }] } } : plugin }) }
  const loaded = await loadWafConfig(props)
  assert.equal(loaded.global.categories['REQUEST-942-APPLICATION-ATTACK-SQLI'], false)
  assert.equal(loaded.overrides.categories['REQUEST-941-APPLICATION-ATTACK-XSS'], false)
  assert.deepEqual(loaded.overrides.enabledGlobalIds, [])
  assert.equal(loaded.overrides.protectionMode, 'custom')
})

test('invalid rules and Kubernetes conflicts stop save', async () => {
  assert.throws(() => compile({ categories: { '../bad.conf': true }, customRules: [] }), /未知 CRS/)
  const props = { configScope: 'global', k8sproxy: async (_, init) => init?.method === 'PUT'
    ? { ok: false, status: 409, text: async () => 'resourceVersion conflict' }
    : { ok: true, status: 200, json: async () => ({ metadata: { resourceVersion: '1' }, spec: { defaultConfig: {} } }) } }
  await assert.rejects(saveWafConfig(props, { useCRS: false }), /409.*resourceVersion conflict/)
  await assert.rejects(loadWafConfig({ configScope: 'rule' }), /namespace 和 ingressName/)
})
