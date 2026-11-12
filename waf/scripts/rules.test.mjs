import test from 'node:test'
import assert from 'node:assert/strict'
import { categories, parseRuleId, validateCustomRules } from '../src/rules.mjs'

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
