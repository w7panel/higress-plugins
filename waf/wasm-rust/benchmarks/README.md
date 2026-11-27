# WAF 请求体与 CRS 逐条压测（2026-11-27）

在本机 Higress Gateway 2.2.3 中复用同一个 Envoy 进程，通过 LDS 切换配置；请求发往临时的真实 HTTP 上游。网关限制为 2 核、8 GiB、2 个 worker。Go 镜像为 `w7panel-waf:0.1.3-crs4.30.0-20261126-memtest`，Rust 镜像为 `w7panel-waf:rust-route-20261126a`。用 `../bench-rules.py` 复现：

```sh
python3 waf/wasm-rust/bench-rules.py body <镜像> --requests 100 --concurrency 8 --sizes 1024,16384
python3 waf/wasm-rust/bench-rules.py rules <镜像> --requests 8 --concurrency 4
python3 waf/wasm-rust/bench-rules.py rules <镜像> --ids 921110,932232,934100,942340,944120 --requests 40 --concurrency 4
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

## 超出请求体限制时的行为

`wasm/wasmplugin/rules/coraza-demo.conf` 设置 `SecRequestBodyNoFilesLimit 131072` 和 `SecRequestBodyLimitAction Reject`。真实上游下，完整 CRS 的 128 KiB 表单体，首尾含 SQLi 都返回 403；256 KiB 时：

| 插件 | 无攻击的 256 KiB body | 首部 SQLi | 尾部 SQLi |
| --- | ---: | ---: | ---: |
| Go | 200 | 200 | 200 |
| Rust | 503 | 503 | 503 |

Go 插件在 `WriteRequestBody` 返回错误时直接继续转发，导致超出非文件限制的表单体绕过检查。Rust 插件在请求体回调中触发 WASM panic；Envoy 日志指向 WASI 不支持的系统路径操作并返回 503，具体调用链仍需定位。这两个行为都需要单独修复：超限请求应按明确策略拒绝或受控处理，不能静默放行或让 VM 崩溃。体积上限及处理策略适合在域名配置中明确呈现；在修复和验证前，不应依据本次性能数字将 Rust 插件视为可直接替换 Go 插件。
