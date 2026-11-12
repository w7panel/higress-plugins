import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { buildVisualRule, categories, parseRuleId, parseVisualRule, validateCustomRules } from '../src/rules.mjs'

test('CRS categories have unique names and disjoint ID ranges', () => {
  assert.equal(new Set(categories.map(item => item.id)).size, categories.length)
  const ranges = categories.map(item => item.range.split('-').map(Number))
  for (let i = 1; i < ranges.length; i += 1) assert.ok(ranges[i - 1][1] < ranges[i][0])
})

test('CRS 3.3.2 catalog contains every known ID in its category', () => {
  const rules = JSON.parse(readFileSync(new URL('../src/system-rules.json', import.meta.url)))
  assert.equal(rules.length, 371)
  assert.equal(new Set(rules.map(rule => rule.id)).size, rules.length)
  for (const rule of rules) {
    const category = categories.find(item => item.id === rule.category)
    assert.ok(category, `unknown category for ${rule.id}`)
    const [start, end] = category.range.split('-').map(Number)
    assert.ok(rule.id >= start && rule.id <= end, `ID ${rule.id} outside ${rule.category}`)
  }
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

test('visual form rejects unsafe values and parses generic single-line rules', () => {
  assert.throws(() => buildVisualRule({ id: 1000001, type: 'pathExact', value: '/a"b' }), /匹配值/)
  assert.throws(() => buildVisualRule({ id: 1000001, type: 'header', header: 'Bad Name', value: 'x' }), /请求头/)
  assert.deepEqual(parseVisualRule('SecRule REQUEST_URI "@rx /admin" "id:1000001,phase:1,deny"'), {
    id: 1000001, type: 'advanced', variable: 'REQUEST_URI', operator: '@rx /admin', actions: 'phase:1,deny', extraConditions: [],
  })
})

test('advanced visual rules preserve Coraza variables, operators and actions', () => {
  const form = { id: 1000002, type: 'advanced', variable: 'ARGS|REQUEST_COOKIES', operator: '@rx (?i)attack', actions: 'phase:2,deny,status:406,log', extraConditions: [] }
  const item = buildVisualRule(form)
  assert.equal(item.rule, 'SecRule ARGS|REQUEST_COOKIES "@rx (?i)attack" "id:1000002,phase:2,deny,status:406,log"')
  assert.deepEqual(parseVisualRule(item.rule), form)
  assert.equal(validateCustomRules([item]), '')
  assert.throws(() => buildVisualRule({ ...form, actions: 'phase:2,id:3,deny' }), /规则 ID/)
  assert.throws(() => buildVisualRule({ ...form, operator: '@rx "attack"' }), /操作符/)
})

test('advanced visual rules generate an editable AND chain', () => {
  const form = {
    id: 1000003, type: 'advanced', variable: 'REQUEST_METHOD', operator: '@streq POST', actions: 'phase:2,deny,status:403',
    extraConditions: [{ variable: 'ARGS', operator: '@contains attack', actions: 't:none' }],
  }
  const item = buildVisualRule(form)
  assert.equal(item.rule, 'SecRule REQUEST_METHOD "@streq POST" "id:1000003,phase:2,deny,status:403,chain"\nSecRule ARGS "@contains attack" "t:none"')
  assert.deepEqual(parseVisualRule(item.rule), form)
  assert.equal(validateCustomRules([item]), '')
  assert.match(validateCustomRules([{ ...item, rule: `${item.rule}\nSecRuleEngine Off` }]), /只能包含/)
})
