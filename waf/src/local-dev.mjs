// Standalone development uses the same WAF API as the panel host.
export function initLocalWaf() {
  const query = new URLSearchParams(window.location.search)
  const scope = query.get('scope') === 'rule' ? 'rule' : 'global'
  const namespace = query.get('namespace') || ''
  const ingressName = query.get('ingressName') || ''
  let token = ''

  async function request(path, options = {}) {
    if (scope === 'rule' && (!namespace || !ingressName)) throw new Error('域名测试需要 namespace 和 ingressName 参数')
    if (!token) token = window.prompt('输入 W7Panel 面板令牌（仅保存在当前页面内存中）')?.trim() || ''
    if (!token) throw new Error('未输入 W7Panel 面板令牌')
    const params = new URLSearchParams({ scope, ...(scope === 'rule' ? { namespace, ingressName } : {}) })
    const response = await fetch(`/panel-api/v1/waf/${path}?${params}`, {
      ...options,
      headers: { 'X-W7Panel-Token': token, ...(options.body ? { 'Content-Type': 'application/json' } : {}) },
    })
    const payload = await response.json()
    if (!response.ok || (payload.code && payload.code !== 200)) throw new Error(payload.msg || `WAF 请求失败（${response.status}）`)
    return payload.data
  }

  window.$wujie = { props: {
    configScope: scope,
    domain: query.get('domain') || ingressName,
    loadWafConfig: () => request('config'),
    saveWafConfig: policy => request('config', { method: 'PUT', body: JSON.stringify({ scope, namespace, ingressName, policy }) }),
    loadWafLogs: () => request('logs'),
  } }
}
