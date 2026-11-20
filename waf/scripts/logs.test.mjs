import assert from 'node:assert/strict'
import { test } from 'node:test'
import { fetchWafLogs, metricsInstalled } from '../src/logs.mjs'

test('metrics presence follows the panel AppGroup check', async () => {
  const path = '/apis/w7panel.w7.com/v1alpha1/namespaces/default/appgroups/w7panel-metrics'
  assert.equal(await metricsInstalled({ k8sproxy: async value => {
    assert.equal(value, path)
    return { ok: true, json: async () => ({ metadata: { name: 'w7panel-metrics' } }) }
  } }), true)
  assert.equal(await metricsInstalled({ k8sproxy: async () => ({ status: 404 }) }), false)
  await assert.rejects(metricsInstalled({ k8sproxy: async () => ({ status: 403 }) }), /403/)
})

test('WAF log query is scoped to the current domain', async () => {
  const calls = []
  const props = { panelProxy: async path => {
    calls.push(path)
    return { ok: true, json: async () => ({ data: [{ time: '2026-11-20T00:00:00Z', path: '/blocked' }] }) }
  } }
  const rows = await fetchWafLogs(props, 'example.com')
  assert.equal(calls[0], 'traffic/waf-logs?domain=example.com')
  assert.equal(rows[0].key, '2026-11-20T00:00:00Z-0')
  await fetchWafLogs(props, '')
  assert.equal(calls[1], 'traffic/waf-logs')
})
