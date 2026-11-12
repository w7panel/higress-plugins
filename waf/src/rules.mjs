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
  if (rules.length > 100) return '全局和域名自定义规则合计最多 100 条'
  const ids = new Set()
  for (const item of rules) {
    const text = item.rule?.trim() || ''
    if (text.split('\n').some(line => !line.trim().startsWith('SecRule '))) return '自定义规则只能包含 SecRule 指令'
    if (new TextEncoder().encode(text).length > 8192) return '单条自定义规则不能超过 8192 字节'
    const matches = [...text.matchAll(/\bid\s*:\s*(\d+)/gi)]
    if (matches.length !== 1) return '每条自定义规则需要且只能有一个规则 ID'
    const id = Number(matches[0][1])
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
  if (!Number.isSafeInteger(id) || id < 1000000) throw new Error('规则 ID 必须是大于等于 1000000 的整数')
  if (form.type === 'advanced') {
    const variable = String(form.variable || '').trim()
    const operator = String(form.operator || '').trim()
    const actions = String(form.actions || '').trim()
    const extraConditions = form.extraConditions || []
    if (!variable || /["\r\n]/.test(variable)) throw new Error('请输入合法的匹配变量')
    if (!operator || /["\r\n]/.test(operator)) throw new Error('请输入合法的匹配操作符')
    if (!actions || /["\r\n]/.test(actions) || /(?:^|,)\s*(?:id\s*:|chain\s*(?:,|$))/i.test(actions)) throw new Error('请输入动作，规则 ID 和链式连接由表单生成')
    if (!Array.isArray(extraConditions)) throw new Error('匹配条件格式无效')
    const lines = [`SecRule ${variable} "${operator}" "id:${id},${actions}${extraConditions.length ? ',chain' : ''}"`]
    for (const [index, condition] of extraConditions.entries()) {
      const nextVariable = String(condition.variable || '').trim()
      const nextOperator = String(condition.operator || '').trim()
      const nextActions = String(condition.actions || '').trim() || 't:none'
      if (!nextVariable || /["\r\n]/.test(nextVariable) || !nextOperator || /["\r\n]/.test(nextOperator)) throw new Error(`第 ${index + 2} 个匹配条件无效`)
      if (/["\r\n]/.test(nextActions) || /(?:^|,)\s*(?:id\s*:|chain\s*(?:,|$))/i.test(nextActions)) throw new Error(`第 ${index + 2} 个条件的动作无效`)
      lines.push(`SecRule ${nextVariable} "${nextOperator}" "${nextActions}${index < extraConditions.length - 1 ? ',chain' : ''}"`)
    }
    const rule = lines.join('\n')
    if (new TextEncoder().encode(rule).length > 8192) throw new Error('规则不能超过 8192 字节')
    return { id, rule, source: 'visual' }
  }
  const value = String(form.value || '').trim()
  const type = visualTypes[form.type]
  if (!type) throw new Error('请选择匹配条件')
  if (!value || value.length > 512 || /["\\\r\n]/.test(value)) throw new Error('匹配值不能为空，且不能包含引号、反斜杠或换行')
  if (form.type === 'header' && !/^[A-Za-z0-9-]+$/.test(form.header || '')) throw new Error('请输入合法的请求头名称')
  const variable = form.type === 'header' ? `${type[0]}:${form.header}` : type[0]
  return { id, rule: `SecRule ${variable} "@${type[1]} ${value}" "id:${id},phase:1,deny,status:403"`, source: 'visual' }
}

export function parseVisualRule(rule) {
  const lines = String(rule || '').split('\n')
  const advanced = lines[0].match(/^SecRule ([^"\r\n]+) "([^"\r\n]+)" "id:(\d+),([^"\r\n]+)"$/)
  if (advanced && !/(?:^|,)\s*id\s*:/i.test(advanced[4])) {
    const extraConditions = []
    for (const [index, line] of lines.slice(1).entries()) {
      const match = line.match(/^SecRule ([^"\r\n]+) "([^"\r\n]+)" "([^"\r\n]+)"$/)
      if (!match || /(?:^|,)\s*id\s*:/i.test(match[3])) return null
      if (match[3].endsWith(',chain') !== (index < lines.length - 2)) return null
      extraConditions.push({ variable: match[1].trim(), operator: match[2], actions: match[3].replace(/,chain$/, '') })
    }
    if ((extraConditions.length > 0) !== advanced[4].endsWith(',chain')) return null
    const preset = parsePresetRule(rule)
    return preset || { id: Number(advanced[3]), type: 'advanced', variable: advanced[1].trim(), operator: advanced[2], actions: advanced[4].replace(/,chain$/, ''), extraConditions }
  }
  return null
}

function parsePresetRule(rule) {
  const match = String(rule || '').match(/^SecRule (REQUEST_URI|REQUEST_METHOD|REMOTE_ADDR|REQUEST_HEADERS:([A-Za-z0-9-]+)) "@(streq|contains|ipMatch) ([^"\\\r\n]+)" "id:(\d+),phase:1,deny,status:403"$/)
  if (!match) return null
  const type = Object.keys(visualTypes).find(key => {
    const [variable, operator] = visualTypes[key]
    return (match[2] ? variable === 'REQUEST_HEADERS' : variable === match[1]) && operator === match[3]
  })
  return type ? { id: Number(match[5]), type, value: match[4], header: match[2] || '' } : null
}
