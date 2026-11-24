const trafficApps = '/apis/w7panel.w7.com/v1alpha1/namespaces/default/appgroups'
const trafficId = value => String(value || '').trim().toLowerCase().replaceAll('_', '-') === 'metrics-traffic'

export async function trafficInstalled(props) {
  if (typeof props.k8sproxy !== 'function') throw new Error('当前面板未提供 Kubernetes 代理接口')
  const response = await props.k8sproxy(trafficApps)
  if (!response.ok) throw new Error(`检查流量监测应用失败（${response.status}）`)
  const groups = (await response.json())?.items
  if (!Array.isArray(groups)) throw new Error('流量监测应用列表格式无效')
  return groups.some(group => trafficId(group?.spec?.identifie || group?.metadata?.annotations?.['w7.cc/identifie'] || group?.metadata?.name))
}

export async function openTrafficInstall(props) {
  if (typeof props.handles?.toStoreInstall !== 'function') throw new Error('当前面板未提供应用安装入口')
  const response = await fetch('https://zm.w7.com/zpk-market/formula/list', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ page: 1, limit: 500, tag: '监控插件' }),
  })
  if (!response.ok) throw new Error(`查询流量监测应用失败（${response.status}）`)
  const body = await response.json()
  const rows = body?.data?.list ?? body?.list
  const url = Array.isArray(rows) && rows.find(row => trafficId(row.identify))?.formula_url
  if (!url) throw new Error('应用市场中未找到流量监测应用')
  await props.handles.toStoreInstall(url)
}

export async function fetchWafLogs(props, domain) {
  if (typeof props.panelProxy !== 'function') throw new Error('当前面板未提供监控查询代理接口')
  const query = domain ? `?domain=${encodeURIComponent(domain)}` : ''
  const response = await props.panelProxy(`namespaces/default/services/metrics-traffic:8080/proxy/api/v1/traffic/waf-logs${query}`)
  const payload = await response.json().catch(() => null)
  if (!response.ok) throw new Error(payload?.msg || `读取防护日志失败（${response.status}）`)
  return (payload?.data || []).map((row, index) => ({ ...row, key: `${row.time}-${index}` }))
}
