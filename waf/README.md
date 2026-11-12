# WAF 插件前端

基于现有 Higress WAF (`useCRS`、`secRules`) 的独立 MicroApp。系统规则按 OWASP CRS 3.3.2 类别开关，自定义规则使用 ModSecurity `SecRule` 语法。

宿主通过 `window.$wujie.props` 提供 `configScope`、`domain`、`loadWafConfig()`、`saveWafConfig(config)` 和 `loadWafLogs()`。配置的校验、继承与编译由 w7panel-server 完成，前端不直接修改 WasmPlugin。

运行 `make ui` 构建并生成 `dist/frontend.zip`。域名入口显示当前域名的日志；日志来自网关 Pod，受 Pod 日志保留时间限制。
