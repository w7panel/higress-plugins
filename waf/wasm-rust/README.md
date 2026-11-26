# Rust WAF WASM 内存实验

这是独立的对照插件，不接入 WAF Chart；`make full` 会将它作为独立镜像推送。它使用 `coraza-rs` 的固定提交、同一个 `waf/wasm/wasmplugin/rules/` CRS 目录和现有 WAF JSON 配置。上游 Rust 引擎与 Go Coraza 的规则语义不能视为完全等价。

```sh
mise install rust@1.99.1
mise exec rust@1.99.1 -- rustup target add wasm32-wasip1
cd waf/wasm-rust
mise exec rust@1.99.1 -- cargo test --locked
mise exec rust@1.99.1 -- cargo build --locked --release --target wasm32-wasip1
cd ../..
bash waf/skills/waf-envoy-test/scripts/test.sh waf/wasm-rust/target/wasm32-wasip1/release/waf_rust_experiment.wasm
```

在仓库根目录运行 `python3 waf/wasm-rust/measure-build.py rust` 或 `... go`，可在临时目录做冷构建并采样编译进程组的 RSS 总量峰值。该数字包含并行子进程，不包含操作系统文件缓存。Go 测量使用本机 Go；发布镜像仍使用 Dockerfile 中的 Go 1.24.4。

## 本地对照（2026-11-26）

基线为 Go 提交 `41ff41f`，Rust 构建来自本目录。Higress Gateway 2.2.3、2 核、8 GiB、2 个工作线程，`useCRS:true`、PL1。每次运行都通过自定义规则、SQLi、XSS 和正常请求四个探针。

| 指标，三次顺序测试 | Go | Rust |
| --- | ---: | ---: |
| Envoy 启动到就绪 | 6、7、6 秒 | 2、2、2 秒 |
| 容器 cgroup 内存峰值 | 538.9、535.8、538.7 MiB | 210.3、223.6、222.4 MiB |
| 冷构建进程组 RSS 峰值 | 462.0、509.1、484.5 MiB | 1943.4、1904.0、1937.4 MiB |

构建内存用本机 Go 1.26.8 和通过 `mise` 安装的 Rust 1.99.1 测得，属于工具链对照；运行内存包含 Envoy 与插件。Rust 插件保留了 Go 版 `@demo-conf` 对请求体的实际设置；当前 Go 版在 `useCRS:true` 时即使未设置 `requestBodyAccess`，该文件也会打开请求体访问。请求体大小上限、响应阶段拦截和全部 CRS 规则行为仍有实现差异，因此这些数字仅说明本地实验配置的资源占用，不能作为生产替换依据。

## 连续修改规则

用 `python3 waf/wasm-rust/measure-reload.py <wasm 文件或镜像>` 在**同一 Envoy 容器**中，通过文件式 LDS 连续更新监听器 20 次，交替禁用、启用自定义规则。每轮请求均验证 `/waf-local-probe` 在 200 和 403 之间按配置切换；每轮生效后等待 1 秒读取容器 cgroup 的 `memory.current` 和 `memory.peak`。本地结果：

| cgroup 内存 | Go | Rust |
| --- | ---: | ---: |
| 初次加载 `memory.current` | 539.9 MiB | 215.6 MiB |
| 首次更新后 `memory.current` | 654.0 MiB | 305.2 MiB |
| 第 20 次更新后 `memory.current` | 652.2 MiB | 304.8 MiB |
| 20 次更新期间 `memory.peak` | 658.1 MiB | 309.7 MiB |

**结论：**这 20 次规则更新没有观察到逐轮累积；两版都在首次更新后跃升，随后形成稳定高水位。`memory.current` 包含 Envoy、WASM 运行时和 cgroup 文件缓存，不能据此断言旧规则对象完全释放，也不能把首次跃升归因于 Rust 引擎。长时间运行、高并发请求和生产配置仍需另测。

## 218 集群对照（2026-11-26）

Higress Gateway 的两个独立 Ingress 分别绑定 `w7panel-pluginwaf`（Go）和 `w7panel-wafrust`（Rust），两边均启用 CRS PL1。通过 `kubectl port-forward` 发请求，复用 HTTP 连接；以下 RPS 受隧道和测试客户端影响，仅用于同环境对照。正常请求应返回 200，SQLi、XSS 和 POST 表单 SQLi 应返回 403；全部请求均无状态码错误。

| 场景 | Go RPS / p95 | Rust RPS / p95 |
| --- | ---: | ---: |
| 正常，500 次、并发 1 | 21.4 / 55.9 ms | 27.5 / 38.6 ms |
| 正常，1000 次、并发 20 | 192.8 / 134.2 ms | 307.9 / 70.9 ms |
| 正常，1000 次、并发 50 | 188.1 / 338.4 ms | 453.7 / 153.2 ms |
| SQLi，500 次、并发 20 | 164.3 / 177.6 ms | 336.6 / 59.8 ms |
| XSS，500 次、并发 20 | 140.3 / 168.3 ms | 326.9 / 68.6 ms |
| POST 表单 SQLi，500 次、并发 20 | 158.0 / 161.4 ms | 334.9 / 132.4 ms |

Envoy `wasm.envoy.wasm.runtime.v8.plugin.*.memory_size` 的主线程加两个 worker：压测前 Go 312.0 MiB、Rust 103.5 MiB；全部请求压测后 Go 344.0 MiB、Rust 107.1 MiB。连续替换自定义规则且逐轮验证新规则生效后，Go 第 20 次为 396.0 MiB，期间在 308–436 MiB 波动；Rust首次更新后 196.1 MiB，第 20 次 220.8 MiB，第 40 次 223.1 MiB。Rust 的首次重编译有约 89 MiB 跃升，随后趋缓。该指标是 WASM 线性内存大小，不是插件 RSS；它能显示高水位增长，不能单独证明对象泄漏或回收。两插件同驻一个网关，容器总内存不能按插件拆分。
