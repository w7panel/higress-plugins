# WAF 插件

独立维护的 WAF Wasm 与 MicroApp，内置 OWASP CRS v4.30.0。系统规则按实际 conf 文件加载；自定义规则使用 ModSecurity `SecRule` 语法。

## 自维护版本（2026-11-20）

- Wasm 源码和固定版本 CRS 在 `wasm/`；CRS 上游提交 `e03a4f6dabc7a30ebd8c52c97d28a154f590a48f`，原许可证保留于 `wasm/CRS-LICENSE`。Higress 原插件代码许可证见 `wasm/HIGRESS-LICENSE`。
- `python3 ui/scripts/generate_catalog.py --check` 核对 627 条规则、21 个检测 conf 的清单与中文名称映射；映射缺 ID、缺中文名称、重复 ID 或清单过期时失败。中文名称按 CRS 检测消息逐条整理，原始英文 `message` 保留供逐条核对；界面按 conf 折叠显示检测规则，可逐条开关。
- 全局策略可设置 CRS 总开关、PL1–PL4、防护模式（关闭、拦截、仅记录）、请求体检查和自定义规则。域名默认逐项跟随全局，可分别覆盖防护模式、CRS、强度、类别、单条规则、请求体检查及全局自定义规则；每项可恢复跟随。关闭防护时仍可编辑配置，重新开启后生效。自定义规则 ID 从 1000000 起。
- `VERSION=0.1.0-crs4.30.0-verified make build-image` 构建 `ccr.ccs.tencentyun.com/afan-public/w7panel-waf:<版本>`；`make push-image` 推送。构建固定使用 Higress Go 1.24.4、Coraza 3.3.3、`no_fs_access` 标签和 `https://goproxy.cn,direct` 模块镜像。`make build-rust-image` 使用 mise Rust 1.99.1 构建实验版 `ccr.ccs.tencentyun.com/afan-public/w7panel-wafrust:<版本>`，`make push-rust-image` 推送；先按 `wasm-rust/README.md` 安装 Rust WASM target。`make build-helm` 生成默认停用的 WasmPlugin Chart。新资源默认 PL1、On，旧策略不迁移。升级已有 Helm release 前，先核对 Chart 中包含的全部资源。
- 发布顺序：先构建并推送 Wasm，备份原 WasmPlugin YAML，保持 `defaultConfigDisable: true` 与 `matchRules: []` 切换 OCI 地址和清空旧配置；再发布 WAF 前端，最后发布移除旧 WAF 路由的面板。仅在受控测试窗口启用规则，资源或请求异常时立即回滚，结束后恢复原配置。

防护开关支持禁用、开启防护、仅观察；域名额外支持跟随全局。域名跟随全局时，只执行和显示全局设置；切回其他防护模式时，原有域名设置恢复。全局添加的自定义规则默认不执行，由各域名逐条开启。删除全局自定义规则时会清理域名对应的开关状态。

使用 `REQUEST_BODY` 或 POST 表单参数等请求体变量时，在“自定义规则”页打开“读取请求体”。MicroApp 会在自定义规则前写入 `SecRequestBodyAccess On`；域名自定义配置可覆盖全局设置。此开关默认关闭，开启会让网关读取请求体，可能增加内存占用。仅添加 phase 2 `SecRule` 不会自动启用请求体读取。更新前端后，需重新保存对应配置才会改写已下发的 WasmPlugin。

宿主通过 `window.$wujie.props` 提供 `configScope`、`domain`、`namespace`、`ingressName`、`k8sproxy`、`panelProxy`、`handles.toStoreInstall` 和 `refreshPluginConfig()`。MicroApp 在浏览器内校验、继承、编译策略，通过宿主 `k8sproxy` 以当前用户权限直接读写 WasmPlugin JSON（Kubernetes YAML 资源）。保存时保留 `metadata.resourceVersion`，并发修改由 Kubernetes 拒绝。域名配置还需能读取相应 Ingress。自定义 SecRule 由前端检查格式和 ID，完整语法仍由网关加载时检验。防护日志检查 `default` 下是否已安装 `metrics-traffic` AppGroup；未安装时可从应用市场跳转安装。已安装时经面板通用 Service 代理访问 `default/metrics-traffic:8080` 的 `/api/v1/traffic/waf-logs`，查询 metrics-traffic 保存于 VictoriaLogs 的最近一小时拦截记录。

## 本地联调

### 整套 CRS 加载性能（2026-11-26）

Wasm 曾在 `main.go` 注册 `coraza-wasilibs` 的 RX、PM、SQLi、XSS 算子。当前 Higress Envoy 的 V8 Wasm 环境中，这些算子会引入额外的 Wasm 运行开销；慢点在 `coraza.NewWAF()` 初始化规则，尤其是 `go-re2` 的嵌套 wazero 调用。现改用 Coraza 自带的 Go 算子，保留同一套 CRS 规则与配置。

本地用 Higress Gateway 2.2.3、2 核、8 GiB、2 个工作线程、`useCRS: true` 对比：

| 版本 | Envoy 启动到就绪 | 单次 `coraza.NewWAF()` | 容器内存 |
| --- | ---: | ---: | ---: |
| 注册 wasilibs 的原镜像 | 约 84 秒 | 未单独测量 | 约 1.9 GiB |
| 移除 wasilibs 的本地 Wasm | 约 6.4 秒 | 约 0.21 秒 | 约 0.53 GiB |

`NewWAF()` 的 0.21 秒来自临时分段计时构建；Envoy 整体冷启动仍约 6 秒，不能算作 1 秒内就绪。两版均通过本地自定义规则、SQLi、XSS 拦截和正常请求探针。复测方法见 `skills/waf-envoy-test/SKILL.md`；生产资源和不同并发数下的耗时需另测。独立 Rust WASM 内存对照见 `wasm-rust/README.md`。

### 规则更新时的内存累积（2026-11-26）

连续修改完整 CRS 的单条规则开关时，网关内多个 Wasm 实例的内存逐次升高。排查 SDK 的插件上下文删除流程和 Coraza 3.3.3 后，未发现旧 WAF 被全局缓存持有；诊断构建中，每轮更新前 GC 后存活堆约 22 MiB，编译新规则后约 43 MiB，下一轮又回到约 22 MiB。主要问题是规则编译产生大量短期对象，而 GC 不够及时，Wasm 线性内存随高水位扩张后不会立即缩回。

`parseConfig` 现在在解析前和编译后执行 GC，及时回收旧规则及解析临时对象；同一插件上下文中，有效 directives 未变化时复用已编译的 WAF，仅规则实际变化才重新编译。相同规则复用和不同规则重编译由单元测试覆盖。

在同一测试网关连续切换完整 CRS 的规则 20 次：修复前第 20 次三个 Wasm 实例约 256/260/288 MiB，修复后约 136/156/136 MiB，后 7 次基本稳定；容器内存约从 1.48 GiB 降至 1.21 GiB。测试结束后恢复了原镜像和配置。本地 Envoy 验证正常请求返回 200，自定义规则、SQLi、XSS 均返回 403。该测试证明这 20 次更新中未持续累积，不能据此保证无限次数更新后内存绝不增长；Wasm 内存页也不会原地缩小。

### 请求体与非请求体逐条压测（2026-11-27）

本机 Higress Gateway 2.2.3、2 核、2 个 worker、真实 HTTP 上游的结果见 [逐条压测报告](wasm-rust/benchmarks/README.md)。此前 `/test` 只是附加自定义规则，完整 CRS 也已测试。515 条可配置官方检测规则分别加载后，16 KiB 表单体各 8 次：Go 单规则 p50 中位数 2.15 ms、60 条超过 10 ms；Rust 为 1.02 ms、1 条超过 10 ms。完整 CRS PL1 下，16 KiB 表单体 100 次、并发 8：Go 6.5 RPS / p95 1553 ms，Rust 221.7 RPS / p95 41.84 ms。

无请求体 GET 的逐条复测也覆盖了 URL、请求头与真实上游 HTML 响应：515 条两版均加载成功，514 条对应正常请求返回 200；PL4 的 920274 在两边都返回 403。单规则 p50 中位数 Go 1.56 ms、Rust 1.04 ms；Go 有 10 条超过 10 ms，Rust 没有。8 次样本只能定位明显慢点；响应规则的正常流量耗时也不等于命中攻击时的耗时。性能不能单独证明两版拦截语义等价，不能只因某条规则较慢就默认关闭。

超出 128 KiB 内存缓冲上限时，旧版 Go 会放行未经完整检查的 256 KiB 表单体，旧版 Rust 会在 WASI 临时文件路径上崩溃并返回 503。当前源码让两版在完整 CRS 下对该请求返回 413；Go 其他写入错误返回 500，避免静默放行。真实上游探针还验证了正常 GET 为 200，URL SQLi、XSS 和请求头扫描器为 403；响应泄漏特征命中时，两版均将响应体替换为相同长度的零字节，保持客户端可完整读取。2026-11-27 已将提交 `131b885` 的修复版发布到 218：Go 为 `w7panel-waf:0.1.3-crs4.30.0-131b885`，Rust 为 `w7panel-waf:rust-0.1.3-crs4.30.0-131b885`。两个现有对比域名均验证正常 GET 200，自定义规则、URL SQLi/XSS、请求头扫描器和表单 SQLi 403，256 KiB 表单体 413。Rust 镜像最初推送到 `w7panel-wafrust` 仓库时，网关拉取返回 401 且 `FAIL_OPEN` 放行；改用网关可读取的 `w7panel-waf` 仓库后，重新测试得到 413。Rust 对超过内存缓冲上限的上传也会返回 413，支持大文件上传需要另行设计 WASI 存储路径。

218 的两个现有对比域名已完成 515 条 CRS 规则逐条加载和压测：每条分别测无 body GET、16 KiB POST，Go/Rust 的状态码分布一致。耗时、40 次复测和控制面短暂不可用的记录见 [218 逐条压测报告](wasm-rust/benchmarks/README.md#218-集群逐条压测2026-11-27)。

218 上的 Rust 攻击样本逐条筛查证实 238 条请求规则由目标规则拦截，另有 28 条返回 200、5 条返回与目标规则无关的 400；详细覆盖范围和原始 CSV 见 [Rust 攻击样本报告](wasm-rust/benchmarks/README.md#218-rust-攻击特征请求2026-11-27)。2026-11-27 已将 218 的现有 `w7panel-pluginwaf` WasmPlugin 镜像切为 Rust `rust-0.1.3-crs4.30.0-131b885`，保留原配置；正常、攻击和超限请求探针通过。独立测试插件 `w7panel-wafrust` 仍在 218。

### Registry 鉴权参数误报（2026-11-27）

218 上请求 `GET https://zpk.fan.b2.sz.w7.com/zpk/v2/registry/auth?scope=repository%3Aapp%2Fr_tet1%3Apull&service=docker-registry` 返回 403；将 `service` 改为 `test` 返回 200。Gateway 访问日志的 `response_code_details` 为 `via_wasm::higress-system.w7panel-pluginwaf`，且无上游地址，确认由 WAF 拦截。用 218 当前配置及同版本 Rust/CRS 4.30.0 离线重放后，PL1 规则 **932260**（`REQUEST-932-APPLICATION-ATTACK-RCE.conf`，直接执行 Unix 命令检测）在 `ARGS:service=docker-registry` 中匹配 `docker-`，随后 **949110** 因入站异常分达到阈值返回 403。这是正常业务参数的误报；去掉 `service` 或改为 `test` 时未命中 932260。

如需放行，应仅对该鉴权路由的 `ARGS:service` 排除 932260，保留此规则对其他参数和路由的检测。当前仅记录原因，未改动线上 WAF 配置。Rust 插件目前不在 Gateway 访问日志中输出命中规则 ID，定位时需结合请求差异与相同配置的 Coraza 重放。

参考 `w7panel-kilo` 的独立页面方式，在本机启动开发服务器，直接打开 WAF 页面。开发服务器代理 `/k8s-proxy/*` 和日志使用的 `/panel-api/v1/*` 到 W7Panel；首次请求时会提示输入面板令牌，令牌仅保存在当前页面内存中，刷新后需重新输入。当前用户需有读取和更新 WAF WasmPlugin 的 Kubernetes 权限。

```sh
cd waf/ui
npm ci
npm run dev
```

打开 `http://127.0.0.1:8082/` 测试全局配置。测试域名配置时，打开 `http://127.0.0.1:8082/?scope=rule&namespace=default&ingressName=实际Ingress名称&domain=实际域名`。`namespace` 和 `ingressName` 必须与集群中的 Ingress 一致；`domain` 只用于页面显示，MicroApp 会从 Ingress 读取真实域名。局域网测试可使用本机 IP 代替 `127.0.0.1`。通过 `WAF_PANEL_ORIGIN` 指定面板地址；默认代理到本机 `http://127.0.0.1:9090`。也可运行 `make local-test`。

**本地保存会立即修改目标集群的 WAF 配置**，日志也来自真实网关。联调前核对目标环境与网关资源限制；结束测试后停止开发服务器。生产构建仍通过宿主注入接口工作。

在 `waf/` 运行 `make ui` 构建并生成 `ui/dist/frontend.zip`。域名入口只查询当前域名的日志；日志保留时间由 VictoriaLogs 配置决定。

设置环境变量 `VERSION=1.0.0` 和 `ZPK_IDC_PASSWORD` 后，运行 `make full` 构建、推送 Go 与 Rust Wasm 镜像和前端 ZPK，并打包 Helm Chart。先切换插件前端并验证直接读写 WasmPlugin，再发布移除旧 `/waf/config` 路由的面板版本。该命令不自动升级集群中的 Helm release。

## 系统规则 ID 与来源

旧版 WAF 的“协议与请求格式”类别使用 `920000-922999` 作为关闭范围。以下为旧版规则 ID 的历史记录；当前自维护版本的规则清单见 `ui/system-rules.json`，编译逻辑见 `config.go`。

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
