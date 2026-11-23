import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { buildVisualRule, parseRuleId, parseVisualRule, replaceRuleId, validateCustomRules } from '../src/rules.mjs'

test('CRS catalog files match generated rule inventory', () => {
  const catalog = JSON.parse(readFileSync(new URL('../system-rules.json', import.meta.url)))
  assert.equal(catalog.crsVersion, 'v4.30.0')
  assert.equal(catalog.files.length, 21)
  assert.equal(catalog.rules.find(item => item.id === 933100).nameZh, 'PHP 起始标签检测')
  assert.equal(new Set(catalog.files.map(item => item.name)).size, catalog.files.length)
  assert.equal(new Set(catalog.rules.map(item => item.id)).size, catalog.rules.length)
  const files = new Set(catalog.files.map(item => item.name))
  for (const rule of catalog.rules.filter(item => !item.internal)) assert.ok(files.has(rule.file))
})

test('custom rules require a unique ID outside the CRS range', () => {
  const rule = 'SecRule REQUEST_URI "@streq /admin" "id:1000001,phase:1,deny"'
  assert.equal(parseRuleId(rule), 1000001)
  assert.equal(validateCustomRules([{ id: 1000001, rule }]), '')
  assert.match(validateCustomRules([{ id: 1000001, rule }, { id: 1000001, rule }]), /重复/)
  assert.match(validateCustomRules([{ id: 942001, rule: rule.replace('1000001', '942001') }]), /大于等于/)
  assert.match(validateCustomRules([{ id: 1000002, rule }]), /不一致/)
  assert.match(validateCustomRules([{ id: '1000001', rule }]), /不一致/)
})

test('rule IDs come from actions, not operator or message text', () => {
  const fakeOperatorId = 'SecRule REQUEST_URI "@contains id:1000001" "phase:1,deny"'
  const fakeMessageId = 'SecRule REQUEST_URI "@streq /admin" "msg:\'blocked,id:1000001\',phase:1,deny"'
  assert.equal(parseRuleId(fakeOperatorId), null)
  assert.equal(parseRuleId(fakeMessageId), null)
  assert.match(validateCustomRules([{ id: 1000001, rule: fakeOperatorId }]), /只能有一个规则 ID/)
  assert.match(validateCustomRules([{ id: 1000001, rule: fakeMessageId }]), /只能有一个规则 ID/)
  const valid = 'SecRule REQUEST_URI "@streq /admin" "msg:\'blocked,id:9999999\',id:1000001,phase:1,deny"'
  assert.equal(parseRuleId(valid), 1000001)
  assert.equal(validateCustomRules([{ id: 1000001, rule: valid }]), '')
})

test('rule IDs must be safe integers', () => {
  const rule = 'SecRule REQUEST_URI "@streq /admin" "id:9007199254740993,phase:1,deny"'
  assert.equal(parseRuleId(rule), null)
  assert.match(validateCustomRules([{ id: 9007199254740992, rule }]), /安全整数/)
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

test('inline editor replaces only the action ID', () => {
  const rule = 'SecRule REQUEST_URI "@contains id:77" "msg:\'seen id:77\',phase:1,id:77,deny"'
  const replaced = replaceRuleId(rule, 1000000)
  assert.equal(replaced, 'SecRule REQUEST_URI "@contains id:77" "msg:\'seen id:77\',phase:1,id:1000000,deny"')
  assert.equal(parseRuleId(replaced), 1000000)
  assert.equal(replaceRuleId('SecRule REQUEST_URI "@streq /" "phase:1,deny"', 1000000), null)
})
