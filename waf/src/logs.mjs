const metricsApp = '/apis/w7panel.w7.com/v1alpha1/namespaces/default/appgroups/w7panel-metrics'

export async function metricsInstalled(props) {
  if (typeof props.k8sproxy !== 'function') throw new Error('当前面板未提供 Kubernetes 代理接口')
  const response = await props.k8sproxy(metricsApp)
  if (response.status === 404) return false
  if (!response.ok) throw new Error(`检查面板监控失败（${response.status}）`)
  return Boolean((await response.json())?.metadata?.name)
}

export async function fetchWafLogs(props, domain) {
  if (typeof props.panelProxy !== 'function') throw new Error('当前面板未提供监控查询代理接口')
  const query = domain ? `?domain=${encodeURIComponent(domain)}` : ''
  const response = await props.panelProxy(`traffic/waf-logs${query}`)
  const payload = await response.json().catch(() => null)
  if (!response.ok) throw new Error(payload?.msg || `读取防护日志失败（${response.status}）`)
  return (payload?.data || []).map((row, index) => ({ ...row, key: `${row.time}-${index}` }))
}
