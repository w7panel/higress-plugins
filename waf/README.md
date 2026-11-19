# WAF 插件前端

基于现有 Higress WAF (`useCRS`、`secRules`) 的独立 MicroApp。系统规则按类别开关，自定义规则使用 ModSecurity `SecRule` 语法。具体 CRS 规则版本取决于网关加载的 WAF 插件。

“启用 OWASP CRS 系统规则”对应 `useCRS`：开启时加载整套 CRS，关闭时不加载 CRS，但仍执行自定义 `SecRule`。全局开关是域名规则的默认值；域名可覆盖，也可恢复继承。关闭 CRS 会让类别设置暂不生效，可降低网关内存占用。

使用 `REQUEST_BODY` 或 POST 表单参数等请求体变量时，打开“启用自定义规则的请求体检查”。服务端会在自定义规则前下发 `SecRequestBodyAccess On`；域名可覆盖全局设置。此开关默认关闭，开启会让网关读取请求体，可能增加内存占用。仅添加 phase 2 `SecRule` 不会自动启用请求体读取；`useCRS: false` 不影响这个开关。更新服务端和前端后，需重新保存对应配置才会改写已下发的 WasmPlugin。

宿主通过 `window.$wujie.props` 提供 `configScope`、`domain`、`loadWafConfig()`、`saveWafConfig(config)` 和 `loadWafLogs()`。配置的校验、继承与编译由 w7panel-server 完成，前端不直接修改 WasmPlugin。

## 本地联调

参考 `w7panel-kilo` 的独立页面方式，在本机启动开发服务器，直接打开 WAF 页面。开发服务器只代理 `/panel-api/v1/waf/*` 到 W7Panel；页面使用现有 WAF 配置与日志 API，首次请求时会提示输入面板令牌，令牌仅保存在当前页面内存中，刷新后需重新输入。需要使用已包含 WAF API 的 `w7panel-server` 版本。

```sh
cd waf
npm ci
npm run dev
```

打开 `http://127.0.0.1:8082/` 测试全局配置。测试域名配置时，打开 `http://127.0.0.1:8082/?scope=rule&namespace=default&ingressName=实际Ingress名称&domain=实际域名`。`namespace` 和 `ingressName` 必须与集群中的 Ingress 一致；`domain` 只用于页面显示，服务端会从 Ingress 读取真实域名。局域网测试可使用本机 IP 代替 `127.0.0.1`。面板地址不同可在启动前设置 `WAF_PANEL_ORIGIN`，默认是 `http://218.23.2.48:9090`。也可运行 `make local-test`。

**本地保存会立即修改目标集群的 WAF 配置**，日志也来自真实网关。218 集群的 72 线程网关即使只启用无 CRS 的空规则，也曾迅速接近 8 GiB 内存上限；联调时不要直接启用 WAF。结束测试后停止开发服务器。生产构建仍通过宿主注入接口工作。

运行 `make ui` 构建并生成 `dist/frontend.zip`。域名入口显示当前域名的日志；日志来自网关 Pod，受 Pod 日志保留时间限制。

设置环境变量 `VERSION=1.0.0` 和 `ZPK_IDC_PASSWORD` 后，运行 `make full` 将前端包发布到 ZPK 制品 `w7panel-pluginwaf`。本项目不打包 Helm Chart，也不升级集群中的 Helm release。

## 218 集群 Envoy 内存异常（2026-11-12）

218 集群的 Higress 2.2.3 网关在启用 WAF `waf:2.0.0`、域名配置 `useCRS: true` 时，Envoy RSS 达到约 34 GiB，CPU 一度约 25 核，Pod 曾失去就绪状态。该网关未设置内存上限，Envoy 启动参数为 `--concurrency 72`。

短时对照测试只切换了 `w7panel-pluginwaf` 唯一域名规则的 `configDisable`：同一个 Envoy 进程的 RSS 在停用约 45 秒后从约 33.7 GiB 降至 1.7 GiB；恢复规则后又升至约 32.7 GiB。期间该容器的重启次数未增加。随后 WAF 资源被移除，新网关 Pod 就绪，RSS 约 1.7 GiB。**这证明高内存与启用该 WAF 配置强相关，但没有堆分析证据证明是持续泄漏。**

[Higress WAF 2.0.0 源码](https://github.com/alibaba/higress/blob/76605194e6fc/plugins/wasm-go/extensions/waf/wasmplugin/plugin.go)在 `useCRS: true` 时加载 `@owasp_crs/*.conf` 并创建 Coraza WAF。结合 72 个 Envoy 工作线程，启停差值折合约 450 MiB/线程，推测是每个工作线程持有规则引擎造成的内存放大；具体分配仍需 Wasm/进程堆分析确认。类别开关使用的 `SecRuleRemoveById` 在 CRS 加载之后执行，不能代替关闭 `useCRS` 来避免整套 CRS 的加载。WAF 2.0.3 的这段加载代码与 2.0.0 相同，不能把单纯升级视为修复。

### 单条 CRS 规则排查记录（2026-11-13）

检查事故时的生效配置：`secRules` 含 4 条类别范围 `SecRuleRemoveById` 和 5 条自定义规则，**没有单条 ID 的 `SecRuleRemoveById`**。相关 WAF 配置摘录如下；自定义规则未在此复制：

```yaml
useCRS: true
secRules:
  - SecRuleRemoveById 934000-934999
  - SecRuleRemoveById 944000-944999
  - SecRuleRemoveById 913000-913999
  - SecRuleRemoveById 942000-942999
  # 另有 5 条自定义 SecRule
```

因此这次约 34 GiB 的现场内存不能归因于界面中的单条规则开关。类别关闭指令同样是在加载 CRS 后执行，不能避免加载峰值。

用 WAF 2.0.0 对应的 Coraza 版本和内嵌的 55 个 CRS 文件，在本地原生 Go 进程中重复 3 次创建规则引擎；下表为每次测试约值：

| 配置 | 创建期间总分配 | GC 后堆占用 |
| --- | ---: | ---: |
| 仅自定义规则 | 约 0 MiB | 0.8 MiB |
| 加载整套 CRS | 67.4 MiB | 18.8 MiB |
| CRS + 关闭单条 920100 | 67.4 MiB | 18.8 MiB |
| CRS + 关闭 920–922 类别 | 67.8 MiB | 18.2 MiB |

测试证明单条关闭指令不能减少 CRS 的加载分配；它不等同于 Envoy Wasm 的 72 线程内存测试，不能据此推算生产 RSS 或断定具体分配源。要查清约 34 GiB 的构成，还需对 Wasm/Envoy 做堆分析和不同线程数的实测。

原界面单条规则清单按 CRS 3.3.2 编写，而 WAF 2.0.0 内嵌 CRS 标记为 `4.0.0-rc1`；核对发现清单中有 5 个 ID 不存在于内嵌规则，类别范围内另有 106 个实际 ID 未列出。该清单不能准确代表当前网关实际规则，现暂时移除单条 CRS 规则界面，保留类别与自定义规则功能。

配套服务端已停止读取和编译 `systemRules`，再次保存全局配置时会清除旧的全局和域名覆盖字段，并重编译对应的 `secRules`；单独保存域名配置也会清除该域名的旧字段。部署新代码本身不会改写已下发的 WAF 资源，若曾用单条开关生成 `SecRuleRemoveById <ID>`，需重新保存配置才会从生效配置移除。当前生产 WAF 资源保持停用，未为本次排查重新启用。

### 无 CRS 的空规则复测（2026-11-18）

218 集群的网关仍为 Higress 2.2.3、WAF `waf:2.0.0`、Envoy `--concurrency 72`、单副本、容器内存上限 8 GiB。测试前 `defaultConfigDisable: true`、`matchRules: []`，Pod Ready，重启次数 2；容器 cgroup `memory.current` 连续 12 秒稳定在 2327–2329 MiB。

只给测试域名 `whotest1.fan.b2.sz.w7.com` 的 Ingress 增加一条匹配规则，规则配置为 `useCRS: false`、`secRules: ["SecRuleEngine On"]`，**没有自定义 `SecRule`，也没有单条 CRS 关闭指令**。激活后约 7 秒，`memory.current` 从 2366、2383、2676 MiB 升至 7041 MiB，超过预设的 6500 MiB 停止阈值，脚本立即将 `matchRules` 恢复为空；因此没有继续测试单条自定义规则。cgroup 记录的 `memory.peak` 为 7120 MiB，`memory.events` 中 `oom` 与 `oom_kill` 均为 0，Pod 没有重启；恢复后约 1 分钟稳定在 2435 MiB 左右，测试域名返回 HTTP 200。

这次测试表明，**即使下发的域名规则指定 `useCRS: false` 且没有自定义检测规则，启用 WAF 匹配规则也能让 72 工作线程的网关迅速接近 8 GiB 上限**。WAF 2.0.0 源码在 `useCRS: false` 时不主动加入 CRS 文件，但仅凭这次 cgroup 总量还无法定位分配；后续的线程数与 Wasm 指标对照见下文。不要把关闭 CRS 视为这个 72 线程网关上的内存安全保证。

### 8 线程对照与 CRS 长时观察（2026-11-18）

在同一台 218 网关上临时给 `pilot-agent proxy` 增加 `--concurrency 8`，确认新 Pod 的 Envoy 进程也显示 `--concurrency 8` 后，仍只给测试域名的 Ingress 启用 WAF 匹配规则。测试按阶段恢复 `matchRules: []`，容器内存达到 6500 MiB 或域名请求失败就立即停止；结束时移除启动参数并确认 72 线程 Pod Ready、WAF 关闭。该网关为单副本，测试期间发生了 Pod 滚动更新。

| 阶段 | 配置 | `memory.current` 采样结果 | 域名访问 |
| --- | --- | --- | --- |
| 基线 | WAF 关闭 | 约 465–498 MiB | HTTP 200 |
| 空规则，30 秒 | `useCRS: false`，仅 `SecRuleEngine On` | 峰值 1284 MiB，后约 1078 MiB | HTTP 200 |
| 一条自定义规则，30 秒 | `useCRS: false`，增加一条不会命中的 URI 规则 | 峰值 1183 MiB，后约 1086 MiB | HTTP 200 |
| CRS，30 秒 | `useCRS: true`，仅 `SecRuleEngine On` | 从 1133 MiB 持续升至 1387 MiB | HTTP 200 |
| CRS，较长复测 | 从关闭状态重新启用相同 CRS 配置 | 从约 503 MiB 升至 1360 MiB；约 70 秒时 HTTP 探针超时，提前停止 | 先为 HTTP 200，后一次 5 秒超时 |

较长复测时，网关日志出现 Envoy metrics 抓取 504/超时，Kubernetes 记录该 8 线程 Pod 就绪探针 503 和超时；这些现象与 WAF/CRS 启用同时发生，但尚无堆栈证明超时的具体原因。该 Pod 在测试期间没有重启，未观察到 8 GiB 内存上限触发；删除后无法再读取其 cgroup OOM 计数。**8 线程显著降低了短时内存占用，但本次没有证明 CRS 稳定，也不能把 8 线程直接作为生产配置。** 最终 WAF 恢复为 `defaultConfigDisable: true`、`matchRules: []`，网关恢复 72 线程、单副本、Ready，测试域名返回 HTTP 200；新 Pod 的 `memory.events` 中 `oom` 和 `oom_kill` 均为 0。

还试过给网关 Pod 模板增加 `proxy.istio.io/config: "concurrency: 8\n"` 注解：新 Pod 含该注解，但 Envoy 仍以 72 线程启动，因此下面不能把该注解视为已验证的降线程方法。后续的逐线程 Wasm 指标对照见下文；CRS 加载期间的 CPU、就绪与延迟仍需另行验证。

### 空规则与请求体检查的内存归因（2026-11-19）

在 218 测试环境临时调整 Envoy 工作线程数，仅给 `default/ing-xuivtxkw` 启用 `useCRS: false` 的 WAF 匹配规则，连续采样容器 `memory.current`、Envoy RSS 和 `/memory` 分配器指标。各组启用前均使用新 Pod；测试达到 6500 MiB、请求失败或 Pod 失去就绪时停止并恢复配置。

| 工作线程 | WAF 关闭 | 空规则启用 20 秒 | 增量 | Envoy 分配器 `allocated` 增量 |
| ---: | ---: | ---: | ---: | ---: |
| 8 | 472 MiB | 1086 MiB | 614 MiB | 约 106 MiB |
| 16 | 645 MiB | 1615 MiB | 970 MiB | 约 117 MiB |
| 32 | 956 MiB | 2661 MiB | 1705 MiB | 约 141 MiB |

增量随工作线程数上升，而 Envoy `/memory` 的 `allocated` 只记录其中一小部分。另一次 8 线程实验将匹配规则设为 `secRules: []`，不发送测试请求：WAF 关闭时为 493 MiB，启用后约 10 秒达到 1092 MiB，随后 20 秒维持在 1091–1095 MiB。Envoy Wasm 指标同时出现 WAF 主线程及 8 个工作线程的 `memory_size`，**每个都是 48 MiB，合计 432 MiB**；这项指标与容器总量不能直接相加，剩余增量包含 Wasm 实例及运行时的其他内存。再加入 `SecRuleEngine On` 后，内存与逐线程指标基本不变。由此确认，本次无 CRS 空规则的主要固定开销来自 WAF 激活时按工作线程创建的 Wasm 实例；它不需要自定义 `SecRule`、请求体检查或实际请求触发。72 线程测试的 7041 MiB 未同步抓到逐线程指标，不能把全部峰值精确归因于这 48 MiB/实例。

将已停用的默认配置从 `useCRS: true` 临时改为 `false`，保持匹配规则 `useCRS: false` 不变，8 线程启用 20 秒后的内存分别为 1086 和 1081 MiB。默认 CRS 被暗中合并加载不能解释空规则的内存暴涨。

请求体开关的命中验证中，同一条 `ARGS_POST:probe` 的 phase 2 规则在 `SecRequestBodyAccess Off` 时返回 HTTP 200，在 `On` 时返回 HTTP 403，说明开关生效。内存对照中，8 线程下每组发送 32 个 1 MiB POST、并发数 8，两组均返回 HTTP 200：`Off` 的请求期峰值比组前高 99 MiB，`On` 高 108 MiB。两组顺序运行，缓存可能保留，9 MiB 差值只表示该负载下的量级；请求体大小与并发数继续增加时仍可能带来更高峰值。这次观察到的约 7 GiB 暴涨不以请求体检查为前提。

原始采样保存在测试机 `/tmp/waf-memory-matrix-20261119.jsonl`、`/tmp/waf-wasm-stats-20261119.jsonl` 和 `/tmp/waf-body-load-20261119.jsonl`。测试结束已恢复 `defaultConfigDisable: true`、`matchRules: []`、默认 `useCRS: true` 和 Envoy 72 线程；Pod Ready、重启 0 次，`oom` 与 `oom_kill` 均为 0。

### 推荐处理

1. 在完成隔离环境容量验证前，保持 218 集群的 WAF 资源停用。只需要自定义规则时，应设置 `useCRS: false`，但 72 工作线程下空规则测试也曾迅速达到 7 GiB，不能直接在当前网关启用。全局及域名设置可在本插件的“系统规则”页配置；重新安装插件前应确认生效配置。
2. 若必须使用 CRS，先在隔离环境测网关 RSS、CPU、吞吐、延迟和就绪状态。8 线程短时内存较低，但较长复测出现超时，不能仅按内存选择线程数；根据稳定峰值及可用性结果再设置内存 request/limit。当前网关只有 1 个副本，生产变更应安排可回滚的滚动更新。
3. 长期方案是降低 WAF Wasm 实例和 CRS 规则引擎在各工作线程上的重复内存，或选用经过容量验证的其他 WAF 实现。修改前仍需通过堆分析确认完整分配位置。

218 集群 Helm release 为 `higress`，Chart 版本为 `2.2.3`。本次测试确认，临时给网关 Deployment 的容器 `args` 增加 `--concurrency 8` 能使 Envoy 按 8 线程启动；测试后已移除该参数。直接改 Deployment 会与 Helm 管理的模板产生差异，后续 Helm 升级可能覆盖它。持久配置应先查明该 Chart 的对应 values 入口并在隔离环境验证，不能沿用上面已证实无效的 Pod 注解示例。

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
