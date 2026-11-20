import assert from 'node:assert/strict'
import { test } from 'node:test'
import { initLocalWaf } from '../src/local-dev.mjs'

test('standalone WAF uses the panel API for config and host proxies for logs', async () => {
  const calls = []
  globalThis.window = {
    location: { search: '?scope=rule&namespace=default&ingressName=nginx-test&domain=nginx-test.example' },
    prompt: () => 'test-token',
  }
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options })
    return { ok: true, json: async () => ({ code: 0, data: { global: {}, overrides: {} } }) }
  }
  initLocalWaf()
  const props = window.$wujie.props
  assert.equal(props.configScope, 'rule')
  assert.equal(props.domain, 'nginx-test.example')
  await props.loadWafConfig()
  await props.saveWafConfig({ useCRS: false })
  await props.k8sproxy('/apis/w7panel.w7.com/v1alpha1/namespaces/default/appgroups/w7panel-metrics')
  await props.panelProxy('traffic/waf-logs?domain=nginx-test.example')
  assert.equal(calls.length, 4)
  assert.match(calls[0].url, /^\/panel-api\/v1\/waf\/config\?scope=rule&namespace=default&ingressName=nginx-test$/)
  assert.equal(calls[1].options.method, 'PUT')
  assert.deepEqual(JSON.parse(calls[1].options.body), { scope: 'rule', namespace: 'default', ingressName: 'nginx-test', policy: { useCRS: false } })
  assert.match(calls[2].url, /^\/k8s-proxy\/apis\/w7panel.w7.com\/v1alpha1\/namespaces\/default\/appgroups\/w7panel-metrics$/)
  assert.equal(calls[3].url, '/panel-api/v1/traffic/waf-logs?domain=nginx-test.example')
  assert.equal(calls[3].options.headers['X-W7Panel-Token'], 'test-token')
})

test('domain mode requires a complete ingress context', async () => {
  globalThis.window = { location: { search: '?scope=rule' } }
  initLocalWaf()
  await assert.rejects(window.$wujie.props.loadWafConfig(), /namespace 和 ingressName/)
})
