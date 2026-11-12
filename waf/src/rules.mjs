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

const visualTypes = {
  pathExact: ['REQUEST_URI', 'streq'],
  pathContains: ['REQUEST_URI', 'contains'],
  method: ['REQUEST_METHOD', 'streq'],
  ip: ['REMOTE_ADDR', 'ipMatch'],
  header: ['REQUEST_HEADERS', 'contains'],
}

export function buildVisualRule(form) {
  const id = Number(form.id)
  const value = String(form.value || '').trim()
  const type = visualTypes[form.type]
  if (!Number.isSafeInteger(id) || id < 1000000) throw new Error('规则 ID 必须是大于等于 1000000 的整数')
  if (!type) throw new Error('请选择匹配条件')
  if (!value || value.length > 512 || /["\\\r\n]/.test(value)) throw new Error('匹配值不能为空，且不能包含引号、反斜杠或换行')
  if (form.type === 'header' && !/^[A-Za-z0-9-]+$/.test(form.header || '')) throw new Error('请输入合法的请求头名称')
  const variable = form.type === 'header' ? `${type[0]}:${form.header}` : type[0]
  return { id, rule: `SecRule ${variable} "@${type[1]} ${value}" "id:${id},phase:1,deny,status:403"`, source: 'visual' }
}

export function parseVisualRule(rule) {
  const match = String(rule || '').match(/^SecRule (REQUEST_URI|REQUEST_METHOD|REMOTE_ADDR|REQUEST_HEADERS:([A-Za-z0-9-]+)) "@(streq|contains|ipMatch) ([^"\\\r\n]+)" "id:(\d+),phase:1,deny,status:403"$/)
  if (!match) return null
  const type = Object.keys(visualTypes).find(key => {
    const [variable, operator] = visualTypes[key]
    return (match[2] ? variable === 'REQUEST_HEADERS' : variable === match[1]) && operator === match[3]
  })
  return type ? { id: Number(match[5]), type, value: match[4], header: match[2] || '' } : null
}
