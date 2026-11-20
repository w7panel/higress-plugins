// Standalone development uses the same WAF API as the panel host.
export function initLocalWaf() {
  const query = new URLSearchParams(window.location.search)
  const scope = query.get('scope') === 'rule' ? 'rule' : 'global'
  const namespace = query.get('namespace') || ''
  const ingressName = query.get('ingressName') || ''
  let token = ''

  async function send(path, options = {}) {
    if (!token) token = window.prompt('输入 W7Panel 面板令牌（仅保存在当前页面内存中）')?.trim() || ''
    if (!token) throw new Error('未输入 W7Panel 面板令牌')
    return fetch(path, {
      ...options,
      headers: { 'X-W7Panel-Token': token, ...(options.body ? { 'Content-Type': 'application/json' } : {}) },
    })
  }

  async function request(path, options = {}) {
    if (scope === 'rule' && (!namespace || !ingressName)) throw new Error('域名测试需要 namespace 和 ingressName 参数')
    const params = new URLSearchParams({ scope, ...(scope === 'rule' ? { namespace, ingressName } : {}) })
    const response = await send(`/panel-api/v1/waf/${path}?${params}`, options)
    const payload = await response.json()
    if (!response.ok || (payload.code && payload.code !== 200)) throw new Error(payload.msg || `WAF 请求失败（${response.status}）`)
    return payload.data
  }

  window.$wujie = { props: {
    configScope: scope,
    domain: query.get('domain') || ingressName,
    loadWafConfig: () => request('config'),
    saveWafConfig: policy => request('config', { method: 'PUT', body: JSON.stringify({ scope, namespace, ingressName, policy }) }),
    k8sproxy: path => send(`/k8s-proxy${path}`),
    panelProxy: path => send(`/panel-api/v1/${path}`),
  } }
}
