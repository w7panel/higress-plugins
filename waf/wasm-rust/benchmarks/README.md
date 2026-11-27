# WAF 请求体与 CRS 逐条压测（2026-11-27）

在本机 Higress Gateway 2.2.3 中复用同一个 Envoy 进程，通过 LDS 切换配置；请求发往临时的真实 HTTP 上游。网关限制为 2 核、8 GiB、2 个 worker。Go 镜像为 `w7panel-waf:0.1.3-crs4.30.0-20261126-memtest`，Rust 镜像为 `w7panel-waf:rust-route-20261126a`。用 `../bench-rules.py` 复现：

```sh
python3 waf/wasm-rust/bench-rules.py body <镜像> --requests 100 --concurrency 8 --sizes 1024,16384
python3 waf/wasm-rust/bench-rules.py rules <镜像> --requests 8 --concurrency 4
python3 waf/wasm-rust/bench-rules.py rules <镜像> --ids 921110,932232,934100,942340,944120 --requests 40 --concurrency 4
python3 waf/wasm-rust/bench-rules.py nonbody <镜像> --requests 8 --concurrency 4
python3 waf/wasm-rust/bench-rules.py smoke <镜像或本地.wasm文件>
```

`body` 模式分别测关闭 CRS 且关闭请求体、关闭 CRS 但打开请求体、完整 CRS PL1 三种配置；表单体是 `data=` 加重复字母 `a`。`--payload alnum` 可改为固定种子的随机字母数字。每个 body 场景还会将 SQLi 放在请求体开头和结尾探测拦截。`rules` 模式从 `ui/system-rules.json` 选取 **515 条用户可配置检测规则**：保留所选规则所在文件，关闭其他检测文件和同文件的其他检测 ID；CRS 必需的 112 条初始化、拦截和关联规则仍保留。396 条是请求规则，119 条是响应规则；响应规则的 POST body 时间主要反映基础路径。每轮等待 LDS 更新成功，再预热 3 次。CSV 中的 `errors` 是与预期 200 不符的请求数。

原始结果：[Go body](2026-11-27-go-body.csv)、[Rust body](2026-11-27-rust-body.csv)、[Go 逐条规则](2026-11-27-go-rules.csv)、[Rust 逐条规则](2026-11-27-rust-rules.csv)、[Go 40 次复测](2026-11-27-go-top40.csv)、[Rust 40 次复测](2026-11-27-rust-top40.csv)。逐条筛查每条只有 8 次请求，适合找明显慢点，不适合按微小延迟差给全部规则排序。绝对 RPS 包含 Python 客户端和上游服务的开销。

## 请求体结果

| 配置、body 大小 | Go RPS / p95 | Rust RPS / p95 |
| --- | ---: | ---: |
| 关闭 CRS、请求体检查，1 KiB | 3,882 / 3.07 ms | 5,382 / 2.47 ms |
| 关闭 CRS、打开请求体检查，1 KiB | 4,886 / 2.29 ms | 5,221 / 2.45 ms |
| 完整 CRS PL1，1 KiB | 86.0 / 118.85 ms | 1,268 / 10.27 ms |
| 关闭 CRS、打开请求体检查，16 KiB | 2,248 / 5.15 ms | 4,828 / 2.48 ms |
| 完整 CRS PL1，16 KiB | 6.5 / 1,552.81 ms | 221.7 / 41.84 ms |

以上每格 100 次请求、并发 8、均为 200 且无请求错误。16 KiB 换成随机字母数字后，完整 CRS 的 Go 慢点仍可复现，说明并非只由重复字符造成。Go 与 Rust 的规则语义不同，速度差不能作为拦截效果等价的证据。

## 逐条筛查

515 条 Go、Rust 配置均成功加载，16 KiB 表单体各 8 次请求均为 200。Go 的单规则 p50 中位数为 2.15 ms，Rust 为 1.02 ms；Go 有 60 条的 p50 超过 10 ms，Rust 有 1 条。对筛查中较慢的规则增加到 40 次请求后：

| CRS ID | 规则 | Go p50 | Rust p50 |
| ---: | --- | ---: | ---: |
| 921110 | HTTP 请求走私 | 38.55 ms | 1.55 ms |
| 932232 | Unix 命令注入（严格命令集） | 29.90 ms | 1.22 ms |
| 934100 | Node.js 动态代码执行注入 | 174.09 ms | 1.82 ms |
| 942340 | SQL 认证绕过（3/3） | 42.49 ms | 1.05 ms |
| 944120 | Java 反序列化：危险类与 Runtime 链式调用 | 23.96 ms | 1.45 ms |

这些是无攻击特征的长表单值扫描成本。完整 CRS 的耗时会叠加多条规则的扫描；不能用单规则 RPS 相加估算完整配置。较慢规则不宜只因性能而默认关闭，应先核对站点流量、命中情况和防护需求。

## 超出请求体限制时的行为（修复前）

`wasm/wasmplugin/rules/coraza-demo.conf` 设置 `SecRequestBodyNoFilesLimit 131072` 和 `SecRequestBodyLimitAction Reject`。真实上游下，完整 CRS 的 128 KiB 表单体，首尾含 SQLi 都返回 403；256 KiB 时：

| 插件 | 无攻击的 256 KiB body | 首部 SQLi | 尾部 SQLi |
| --- | ---: | ---: | ---: |
| Go | 200 | 200 | 200 |
| Rust | 503 | 503 | 503 |

Go 插件在 `WriteRequestBody` 返回错误时直接继续转发，导致超出非文件限制的表单体绕过检查。Rust 插件在请求体回调中触发 WASM panic；Envoy 日志指向 WASI 不支持的系统路径操作并返回 503，具体调用链仍需定位。这两个行为都需要单独修复：超限请求应按明确策略拒绝或受控处理，不能静默放行或让 VM 崩溃。体积上限及处理策略适合在域名配置中明确呈现；在修复和验证前，不应依据本次性能数字将 Rust 插件视为可直接替换 Go 插件。

## 非请求体规则与修复复测

同一脚本的 `nonbody` 模式在每条规则单独加载后发送无请求体 GET：URL 含 1 KiB 普通查询值，请求头 `X-Bench` 含 1 KiB 普通值，真实上游返回 16 KiB HTML。每条 8 次、并发 4。原始结果：[Go 非 body](2026-11-27-go-nonbody.csv)、[Rust 非 body](2026-11-27-rust-nonbody.csv)。两边 515 条均加载成功；514 条对应正常请求均为 200，PL4 规则 920274 在两边均返回 403。单规则 p50 中位数 Go 1.56 ms、Rust 1.04 ms；Go 有 10 条超过 10 ms，Rust 为 0 条。8 次样本只用于筛查，不作为细小性能差异的排名。

修复版的完整 CRS 真实上游探针结果如下；镜像以本地源码构建，未发布到 218 集群：

| 场景 | Go | Rust |
| --- | ---: | ---: |
| 256 KiB 表单体，无攻击或首尾 SQLi | 413 | 413 |
| 无请求体正常 GET | 200 | 200 |
| URL SQLi、URL XSS、请求头扫描器 | 403 | 403 |
| 响应含目录列表特征 | 200，同长度零字节覆盖 | 200，同长度零字节覆盖 |

Go 的请求体写入错误现在停止转发；已知的 WASI 内存缓冲上限错误返回 413，其他写入错误返回 500。Rust 在进入不受支持的临时文件路径前按已编译的内存缓冲上限返回 413。两版的响应体命中现在保持原长度并覆盖为零字节，避免先发送响应头后改短 body 导致客户端等待或读取不完整。超过内存缓冲上限的请求体会整体拒绝，包含较大的文件上传；即使配置为 `DetectionOnly`，该运行环境也无法安全处理超限 body。支持大文件上传需要先为 WASI 临时文件路径设计和验证可用的存储方案。


## 218 集群逐条压测（2026-11-27）

对比 Ingress `wafgo218.fan.b2.sz.w7.com`、`wafrust218.fan.b2.sz.w7.com` 分别绑定修复版 Go、Rust 插件，共用同一个 2 核、8 GiB 的 Higress Gateway 和现有 whoami 上游。使用 [`bench-218.py`](../bench-218.py) 从 `ui/system-rules.json` 选出 515 条可配置检测规则；每轮启用目标规则所在文件、禁用该文件的其他检测 ID，保留 CRS 内部规则。唯一的临时自定义规则用于确认新配置已生效。每轮预热 3 次，然后以并发 4 各请求 8 次：无 body GET 带 1 KiB 查询值和 1 KiB 请求头；POST 带 16 KiB 表单体。请求通过 `kubectl port-forward`，以下耗时包含隧道、Python 客户端和 whoami，适合筛查明显慢点，不代表插件自身耗时或直接吞吐量。

原始数据：[Go 515 条](2026-11-27-218-go-rules.csv)、[Rust 515 条](2026-11-27-218-rust-rules.csv)、[Go 40 次复测](2026-11-27-218-go-recheck.csv)、[Rust 40 次复测](2026-11-27-218-rust-recheck.csv)。Go 和 Rust 的规则 ID、顺序完全一致，每条都有 GET、POST 两行且每行 8 次。两边 GET 都是 514 条返回 200，PL4 规则 `920274` 返回 403；POST 515 条都返回 200。此处只测无攻击特征的流量，不验证每条规则的攻击命中语义。

| 指标，515 条的中位数 | Go | Rust |
| --- | ---: | ---: |
| 规则加载至探针生效 | 4.30 s | 0.95 s |
| 无 body GET p50 / p95 | 64.88 / 95.68 ms | 62.03 / 91.87 ms |
| 16 KiB POST p50 / p95 | 72.67 / 107.80 ms | 66.59 / 97.74 ms |
| 无 body GET RPS | 58.9 | 62.7 |
| 16 KiB POST RPS | 51.5 | 57.0 |

8 次样本的离群值另用每条 40 次复测。以下是 16 KiB POST 的 p50；相同规则的 GET 复测结果见 CSV。

| CRS ID | Go | Rust |
| ---: | ---: | ---: |
| 921110 | 161.06 ms | 39.76 ms |
| 932232 | 129.33 ms | 38.48 ms |
| 934100 | 259.97 ms | 41.37 ms |
| 942340 | 146.28 ms | 42.19 ms |
| 944120 | 108.94 ms | 47.57 ms |
| 931130 | 233.47 ms | 34.82 ms |
| 934120 | 264.85 ms | 34.07 ms |

Go 的上述 POST 慢点仍可复现；筛查时 Go `920420`、`932290` 及 Rust `942460` 的高值在 40 次复测中消失。绝对延迟随测试时段明显变化，不能把两版几毫秒的中位差归因于规则引擎。Go 逐条测试期间 Kubernetes API 两次短暂返回 `ServiceUnavailable`/连接拒绝，脚本从断点续跑；同时观察到控制面其他 Pod 重建，无法据此判定与压测的因果关系。Gateway Pod 始终 Running、重启数 0，最终两个插件均恢复原测试规则和镜像。`kubectl top` 网关内存从开始的约 965 MiB、Go 第 383 条时约 1053 MiB，到全部结束并恢复配置后约 1017 MiB；两插件同驻，不能据此拆分各自内存。

复现时运行 `python3 waf/wasm-rust/bench-218.py go --output go.csv`，再运行相同命令并将 `go` 改为 `rust`。脚本只修改两个对比 Ingress 对应的 WasmPlugin `matchRules[].config`，结束时按原值恢复；运行前确认 218 kubeconfig、网关 Pod 名、测试域名和目标配置仍与脚本一致。

## 218 Rust 攻击特征请求（2026-11-27）

使用与内置规则完全相同的 [CRS v4.30.0 回归样本](https://github.com/coreruleset/coreruleset/tree/v4.30.0/tests/regression/tests)（提交 `e03a4f6dabc7a30ebd8c52c97d28a154f590a48f`）。[`bench-218-attacks.py`](../bench-218-attacks.py) 复用上面的逐条配置和生效探针：每次只启用一个请求阶段规则，最多尝试 3 个明确写有该 ID `expect_ids` 的官方样本。Rust 不输出逐条命中 ID，因此对返回 403 的样本再单独关闭目标 ID；同一请求随后返回 200 才计为**目标规则导致的拦截**。对证实拦截的样本做并发 4、共 8 次重复请求。原始记录：[Rust 攻击样本 CSV](2026-11-27-218-rust-attacks.csv)。

| 请求阶段目录 ID | 数量 |
| --- | ---: |
| 总计 | 396 |
| 无法在当前 HTTP 客户端准确重放，或上游未给出该 ID 的命中样本 | 125 |
| 可重放样本 | 271 |
| 目标规则导致 403，关闭目标规则后为 200 | 238 |
| 样本返回 200，当前无逐条命中日志，无法证明是否计分 | 28 |
| 样本返回 400，关闭目标规则后仍为 400 | 5 |

238 条已证实规则中，85 条使用了非空请求体，153 条使用无请求体请求；8 次重复请求全部是 403。它们的单规则 p50 中位数为 73.84 ms，p95 中位数为 111.89 ms，RPS 中位数为 45.7。耗时包含 `kubectl port-forward`、Python 客户端、配置切换后的测试窗口及网关链路，不代表 Rust 规则自身耗时。400 的 5 个样本是 `920100`、`920120`、`920121`、`920410`、`933111`；关闭目标规则后仍为 400，不能据此判定规则命中。200 的 28 条也不能判定漏检：有些 CRS 规则只增加异常分值，单独加载不会跨过拦截阈值。当前 Rust 插件缺少逐条命中日志，需要补充可观测性后才能验证这些规则的检测语义。响应阶段的 119 个目录 ID 需要可控上游响应，本轮没有重放；本测试也不等同于运行上游完整回归套件。

一条样本包含未渲染模板和固定 `Content-Length`，直接重放会等待额外请求体；脚本跳过模板、显式长度、非 HTTP/1.1、编码原始报文和超出 128 KiB 的样本。运行前用 `python3 -m pip install PyYAML` 安装 YAML 解析器，再经 GitHub 代理检出上游样本：

```sh
git clone --depth 1 --branch v4.30.0 --single-branch 'https://gh-proxy.org/https://github.com/coreruleset/coreruleset.git' /tmp/crs-v4.30.0
python3 waf/wasm-rust/bench-218-attacks.py rust --tests-dir /tmp/crs-v4.30.0/tests/regression/tests --output rust-attacks.csv
```

测试结束后已核对两个测试 WasmPlugin 的配置恢复，Gateway Pod 为 Running、重启 0。Rust 测试期间 `kubectl top` 观测到网关约 1015 MiB；这是 Go 和 Rust 两个插件同驻的 Pod 总量，不能拆分归因。2026-11-27 按部署要求将现有 `higress-system/w7panel-pluginwaf` 的 `spec.url` 从 Go 镜像 `0.1.3-crs4.30.0-131b885` 改为已在 218 测试入口验证的 Rust 镜像 `rust-0.1.3-crs4.30.0-131b885`；其他 `spec` 字段与切换前完全一致，Rust 源码自 `131b885` 后无变化。该插件绑定的对比入口验证正常 GET 200，自定义规则、URL SQLi/XSS、扫描器、表单 SQLi 403，256 KiB 表单体 413；Gateway 仍为 Running、重启 0。此时 `w7panel-pluginwaf` 和独立测试资源 `w7panel-wafrust` 均指向 Rust 镜像。
