export const categories = [
  { id: 'method', title: '请求方法', range: '911000-911999' },
  { id: 'scanner', title: '扫描器识别', range: '913000-913999' },
  { id: 'protocol', title: '协议与请求格式', range: '920000-922999' },
  { id: 'lfi', title: '本地文件包含', range: '930000-930999' },
  { id: 'rfi', title: '远程文件包含', range: '931000-931999' },
  { id: 'rce', title: '远程命令执行', range: '932000-932999' },
  { id: 'php', title: 'PHP 攻击', range: '933000-933999' },
  { id: 'generic', title: '通用应用攻击', range: '934000-934999' },
  { id: 'xss', title: '跨站脚本', range: '941000-941999' },
  { id: 'sqli', title: 'SQL 注入', range: '942000-942999' },
  { id: 'session', title: '会话固定', range: '943000-943999' },
  { id: 'java', title: 'Java 攻击', range: '944000-944999' },
  { id: 'leak', title: '响应数据泄露', range: '950000-955999' },
]

export function parseRuleId(rule) {
  const match = String(rule || '').match(/\bid\s*:\s*(\d+)/i)
  return match ? Number(match[1]) : null
}

export function validateCustomRules(rules) {
  const ids = new Set()
  for (const item of rules) {
    if (!item.rule?.trim().startsWith('SecRule ')) return '自定义规则必须以 SecRule 开头'
    const id = parseRuleId(item.rule)
    if (!id || id < 1000000) return '自定义规则需要大于等于 1000000 的唯一 ID'
    if (ids.has(id)) return `规则 ID ${id} 重复`
    ids.add(id)
  }
  return ''
}
