import assert from 'node:assert/strict'
import { test } from 'node:test'
import { fetchWafLogs, openTrafficInstall, trafficInstalled } from '../src/logs.mjs'

test('traffic plugin presence follows the installed AppGroups', async () => {
  const path = '/apis/w7panel.w7.com/v1alpha1/namespaces/default/appgroups'
  const group = { metadata: { name: 'metrics-traffic-wijvhtpk' }, spec: { identifie: 'metrics_traffic' } }
  assert.equal(await trafficInstalled({ k8sproxy: async value => {
    assert.equal(value, path)
    return { ok: true, json: async () => ({ items: [{ metadata: { name: 'w7panel-metrics' } }, group] }) }
  } }), true)
  assert.equal(await trafficInstalled({ k8sproxy: async () => ({ ok: true, json: async () => ({ items: [{ metadata: { name: 'w7panel-metrics' } }] }) }) }), false)
  await assert.rejects(trafficInstalled({ k8sproxy: async () => ({ ok: false, status: 403 }) }), /403/)
})

test('missing traffic plugin opens its market install page', async () => {
  const originalFetch = globalThis.fetch
  const urls = []
  globalThis.fetch = async (url, options) => {
    assert.equal(url, 'https://zm.w7.com/zpk-market/formula/list')
    assert.equal(JSON.parse(options.body).tag, '监控插件')
    return { ok: true, json: async () => ({ data: { list: [
      { identify: 'metrics-audit', formula_url: 'https://example.test/audit' },
      { identify: 'metrics_traffic', formula_url: 'https://example.test/traffic' },
    ] } }) }
  }
  try {
    await openTrafficInstall({ handles: { toStoreInstall: url => urls.push(url) } })
    assert.deepEqual(urls, ['https://example.test/traffic'])
  } finally { globalThis.fetch = originalFetch }
})

test('WAF log query is scoped to the current domain', async () => {
  const calls = []
  const props = { panelProxy: async path => {
    calls.push(path)
    return { ok: true, json: async () => ({ data: [{ time: '2026-11-20T00:00:00Z', path: '/blocked' }] }) }
  } }
  const rows = await fetchWafLogs(props, 'example.com')
  assert.equal(calls[0], 'namespaces/default/services/metrics-traffic:8080/proxy/api/v1/traffic/waf-logs?domain=example.com')
  assert.equal(rows[0].key, '2026-11-20T00:00:00Z-0')
  await fetchWafLogs(props, '')
  assert.equal(calls[1], 'namespaces/default/services/metrics-traffic:8080/proxy/api/v1/traffic/waf-logs')
})
