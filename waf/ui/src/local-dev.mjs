// Standalone development uses the same Kubernetes proxy as the panel host.
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
      headers: { ...options.headers, 'X-W7Panel-Token': token },
    })
  }

  window.$wujie = { props: {
    configScope: scope,
    namespace,
    ingressName,
    domain: query.get('domain') || ingressName,
    k8sproxy: (path, options) => send(`/k8s-proxy${path}`, options),
    panelProxy: (path, options) => send(`/panel-api/v1/${path}`, options),
  } }
}
