# WAF 插件前端

基于现有 Higress WAF (`useCRS`、`secRules`) 的独立 MicroApp。系统规则按 OWASP CRS 3.3.2 类别开关，自定义规则使用 ModSecurity `SecRule` 语法。

“启用 OWASP CRS 系统规则”对应 `useCRS`：开启时加载整套 CRS，关闭时不加载 CRS，但仍执行自定义 `SecRule`。全局开关是域名规则的默认值；域名可覆盖，也可恢复继承。关闭 CRS 会让类别和单条系统规则设置暂不生效，可降低网关内存占用。

宿主通过 `window.$wujie.props` 提供 `configScope`、`domain`、`loadWafConfig()`、`saveWafConfig(config)` 和 `loadWafLogs()`。配置的校验、继承与编译由 w7panel-server 完成，前端不直接修改 WasmPlugin。

运行 `make ui` 构建并生成 `dist/frontend.zip`。域名入口显示当前域名的日志；日志来自网关 Pod，受 Pod 日志保留时间限制。

设置环境变量 `VERSION=1.0.0` 和 `ZPK_IDC_PASSWORD` 后，运行 `make full` 将前端包发布到 ZPK 制品 `w7panel-pluginwaf`。本项目不打包 Helm Chart，也不升级集群中的 Helm release。

## 218 集群 Envoy 内存异常（2026-11-12）

218 集群的 Higress 2.2.3 网关在启用 WAF `waf:2.0.0`、域名配置 `useCRS: true` 时，Envoy RSS 达到约 34 GiB，CPU 一度约 25 核，Pod 曾失去就绪状态。该网关未设置内存上限，Envoy 启动参数为 `--concurrency 72`。

短时对照测试只切换了 `w7panel-pluginwaf` 唯一域名规则的 `configDisable`：同一个 Envoy 进程的 RSS 在停用约 45 秒后从约 33.7 GiB 降至 1.7 GiB；恢复规则后又升至约 32.7 GiB。期间该容器的重启次数未增加。随后 WAF 资源被移除，新网关 Pod 就绪，RSS 约 1.7 GiB。**这证明高内存与启用该 WAF 配置强相关，但没有堆分析证据证明是持续泄漏。**

[Higress WAF 2.0.0 源码](https://github.com/alibaba/higress/blob/76605194e6fc/plugins/wasm-go/extensions/waf/wasmplugin/plugin.go)在 `useCRS: true` 时加载 `@owasp_crs/*.conf` 并创建 Coraza WAF。结合 72 个 Envoy 工作线程，启停差值折合约 450 MiB/线程，推测是每个工作线程持有规则引擎造成的内存放大；具体分配仍需 Wasm/进程堆分析确认。类别开关使用的 `SecRuleRemoveById` 在 CRS 加载之后执行，不能代替关闭 `useCRS` 来避免整套 CRS 的加载。WAF 2.0.3 的这段加载代码与 2.0.0 相同，不能把单纯升级视为修复。

### 推荐处理

1. 在完成验证前保持 WAF 资源停用。若只需要自定义规则，重新启用时设置 `useCRS: false`：不加载系统 CRS，自定义 `SecRule` 仍可执行。全局及域名设置可在本插件的“系统规则”页配置；重新安装插件前应确认生效配置，避免以 `useCRS: true` 在 72 线程网关上启动。
2. 若必须使用 CRS，先在测试环境降低 Envoy 工作线程数，例如从 72 试到 8，再测网关 RSS、CPU、吞吐和延迟。按此次差值粗估，8 线程可能占用约 5–6 GiB；这只是容量估算。根据实测结果调整线程数，并在确定稳定峰值后设置合理的内存 request/limit。当前网关只有 1 个副本，生产变更应安排可回滚的滚动更新。
3. 长期方案是让 CRS 规则引擎减少工作线程间的重复内存，或选用经过容量验证的其他 WAF 实现。修改前需通过堆分析确认实际分配位置。

218 集群 Helm release 为 `higress`，Chart 版本为 `2.2.3`。限制工作线程的配置入口是 `higress-core.gateway.podAnnotations`，覆盖文件内容如下；这里**只记录方法，未修改集群**：

```yaml
higress-core:
  gateway:
    podAnnotations:
      proxy.istio.io/config: |
        concurrency: 8
```

升级时保留现有 Helm values，并把该文件传给 `helm upgrade`；升级前先用 `helm get values higress -n higress-system -o yaml` 备份现有 values，并用同版本 Chart 的 `helm upgrade --dry-run=client` 检查网关 Pod 注解。升级后确认新 Pod Ready、Envoy 参数出现 `--concurrency 8`，再按实际流量观察 RSS、CPU 和延迟；异常时用 `helm history` 查上一个 revision 并 `helm rollback`。此注解会触发网关 Pod 滚动重启，不能只修改 Deployment 顶层注解。

在上面的 YAML 保存为 `/tmp/higress-waf-concurrency-8.yaml` 后，可用以下命令预览；确认后移除 `--dry-run=client` 才会实际升级：

```sh
curl -fL https://higress.io/helm-charts/higress-2.2.3.tgz -o /tmp/higress-2.2.3.tgz
helm --kubeconfig ~/.kube/218.config -n higress-system get values higress -o yaml > /tmp/higress-values-before.yaml
helm --kubeconfig ~/.kube/218.config -n higress-system upgrade higress /tmp/higress-2.2.3.tgz --reuse-values -f /tmp/higress-waf-concurrency-8.yaml --dry-run=client
```

## 系统规则 ID 与来源

本目录的“协议与请求格式”类别使用 `920000-922999` 作为关闭范围。前端映射见 `src/rules.mjs`，服务端映射见 `w7panel-server/common/service/waf/config.go`。关闭类别时生成的 `SecRuleRemoveById 920000-922999` 会停用该范围内已加载的 CRS 规则；这些 ID 属于系统规则，不是用户自定义规则。

以下清单以 [OWASP CRS 3.3.2 的 920 规则文件](https://github.com/coreruleset/coreruleset/blob/v3.3.2/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf)和[921 规则文件](https://github.com/coreruleset/coreruleset/blob/v3.3.2/rules/REQUEST-921-PROTOCOL-ATTACK.conf)中的 `id:` 为准。完整文件列表见 [CRS 3.3.2 rules 目录](https://github.com/coreruleset/coreruleset/tree/v3.3.2/rules)；该版本没有 `REQUEST-922` 文件或 922xxx 规则。

| 作用 | 实际存在的规则 ID |
| --- | --- |
| 请求行与 multipart 格式 | 920100、920120、920121 |
| 请求体长度与传输方式 | 920160、920170、920171、920180、920181 |
| Range 与 Connection 头 | 920190、920200、920201、920202、920210 |
| 编码与非法字符 | 920220、920230、920240、920250、920260、920270、920271、920272、920273、920274、920275、920460 |
| Host、Accept、User-Agent、Content-Type 等请求头 | 920280、920290、920300、920310、920311、920320、920330、920340、920341、920350、920470、920480、920490、920510 |
| 参数与上传大小限制 | 920360、920370、920380、920390、920400、920410 |
| 内容类型、协议版本、扩展名、受限头及备份文件 | 920420、920430、920440、920450、920500 |
| 请求走私 | 921110 |
| 响应拆分、请求头注入与 CR/LF 注入 | 921120、921130、921140、921150、921151、921160、921190 |
| 重复参数检测 | 921170、921180（前者计数，后者检测） |
| LDAP 注入 | 921200 |

`920011`～`920018` 和 `921011`～`921018` 也是文件中的规则 ID，用于按 CRS 防护等级跳过规则段，不是攻击检测签名。实际执行哪些检测规则还取决于所配置的 CRS 防护等级。
