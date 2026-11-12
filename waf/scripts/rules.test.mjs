import test from 'node:test'
import assert from 'node:assert/strict'
import { buildVisualRule, categories, parseRuleId, parseVisualRule, validateCustomRules } from '../src/rules.mjs'

test('CRS categories have unique names and disjoint ID ranges', () => {
  assert.equal(new Set(categories.map(item => item.id)).size, categories.length)
  const ranges = categories.map(item => item.range.split('-').map(Number))
  for (let i = 1; i < ranges.length; i += 1) assert.ok(ranges[i - 1][1] < ranges[i][0])
})

test('custom rules require a unique ID outside the CRS range', () => {
  const rule = 'SecRule REQUEST_URI "@streq /admin" "id:1000001,phase:1,deny"'
  assert.equal(parseRuleId(rule), 1000001)
  assert.equal(validateCustomRules([{ rule }]), '')
  assert.match(validateCustomRules([{ rule }, { rule }]), /重复/)
  assert.match(validateCustomRules([{ rule: rule.replace('1000001', '942001') }]), /大于等于/)
})

test('visual rules round-trip through SecRule text', () => {
  for (const [type, value, header] of [
    ['pathExact', '/admin', ''], ['pathContains', '/private', ''],
    ['method', 'POST', ''], ['ip', '192.0.2.0/24', ''],
    ['header', 'badbot', 'User-Agent'],
  ]) {
    const form = { id: 1000001, type, value, header }
    const item = buildVisualRule(form)
    assert.equal(item.source, 'visual')
    assert.deepEqual(parseVisualRule(item.rule), form)
    assert.equal(validateCustomRules([item]), '')
  }
})

test('visual form rejects unsafe values and leaves arbitrary manual rules untouched', () => {
  assert.throws(() => buildVisualRule({ id: 1000001, type: 'pathExact', value: '/a"b' }), /匹配值/)
  assert.throws(() => buildVisualRule({ id: 1000001, type: 'header', header: 'Bad Name', value: 'x' }), /请求头/)
  assert.equal(parseVisualRule('SecRule REQUEST_URI "@rx /admin" "id:1000001,phase:1,deny"'), null)
})
