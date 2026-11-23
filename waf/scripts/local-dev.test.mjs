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
  await saveWafConfig(props, { useCRS: false, categories: {}, ruleStates: {}, disabledGlobalIds: [] })
  assert.deepEqual(plugin.spec.matchRules.map(rule => rule.ingress), [['default/other'], ['default/site']])
  assert.equal(plugin.metadata.resourceVersion, '1')
  assert.equal(calls.at(-1).url, `/k8s-proxy${pluginPath}`)
  assert.equal(calls.at(-1).options.headers['X-W7Panel-Token'], 'signed')
  assert.equal(calls.at(-1).options.method, 'PUT')
})

test('global save compiles CRS and inherited domain rules', async () => {
  let plugin = { metadata: { resourceVersion: '3' }, spec: { defaultConfig: { useCRS: false }, matchRules: [
    { ingress: ['default/site'], config: { w7Overrides: { useCRS: false, disabledGlobalIds: [1000000] } } },
  ] } }
  const props = { configScope: 'global', k8sproxy: async (_, init) => {
    if (init?.method === 'PUT') { plugin = JSON.parse(init.body); return { ok: true, status: 200, json: async () => plugin } }
    return { ok: true, status: 200, json: async () => structuredClone(plugin) }
  } }
  await saveWafConfig(props, { useCRS: true, categories: {}, ruleStates: { 942100: false }, customRules: [
    { id: 1000000, rule: 'SecRule REQUEST_URI "@streq /admin" "id:1000000,phase:1,deny"' },
  ] })
  assert.ok(plugin.spec.defaultConfig.secRules.includes('SecRuleRemoveById 942100'))
  assert.equal(plugin.spec.matchRules[0].config.useCRS, false)
  assert.deepEqual(plugin.spec.matchRules[0].config.secRules, [])
  assert.equal(plugin.metadata.resourceVersion, '3')
})

test('invalid rules and Kubernetes conflicts stop save', async () => {
  assert.throws(() => compile({ categories: { '../bad.conf': true }, customRules: [] }), /未知 CRS/)
  const props = { configScope: 'global', k8sproxy: async (_, init) => init?.method === 'PUT'
    ? { ok: false, status: 409, text: async () => 'resourceVersion conflict' }
    : { ok: true, status: 200, json: async () => ({ metadata: { resourceVersion: '1' }, spec: { defaultConfig: {} } }) } }
  await assert.rejects(saveWafConfig(props, { useCRS: false }), /409.*resourceVersion conflict/)
  await assert.rejects(loadWafConfig({ configScope: 'rule' }), /namespace 和 ingressName/)
})
