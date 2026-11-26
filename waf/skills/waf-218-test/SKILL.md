---
name: waf-218-test
description: Test the WAF Wasm plugin on the shared 218 Higress gateway, including scoped CRS and custom-rule probes, resource monitoring, and reliable rollback. Use when a WAF change needs validation on 218; do not invoke for local-only tests.
---

# 218 WAF 测试

218 是共享测试集群，网关为单副本。测试地址为 `218.23.2.48`，W7Panel 为 `http://218.23.2.48:9090/`。WAF 资源是 `higress-system/w7panel-pluginwaf`，网关 Deployment 是 `higress-system/higress-gateway`。历史测试域名 `whotest1.fan.b2.sz.w7.com` 对应 Ingress `default/ing-xuivtxkw`；每次测试前重新核对，不要假定它们仍相同。

## 开始前

1. 确认当前 `kubectl` context 指向 218 集群、网关只有一个 Ready 副本，并读回 Deployment、WasmPlugin、Ingress 的当前配置。保存原始 JSON 到 `/tmp`，记录 Wasm 镜像 URL、`defaultConfigDisable`、`matchRules`、容器 `args`、CPU/内存 limit 和 Pod 重启次数。若当前已有其他 WAF 测试或网关异常，停止，不覆盖他人的配置。
2. 先运行 `python3 ui/scripts/generate_catalog.py --check`、`cd ui && npm test && npm run build` 和 `cd wasm && go test ./...` 中与改动有关的本地检查。构建的 Wasm 镜像必须明确对应本次源码；不要只凭 tag 推断版本。
3. 先用测试域名的正常请求记录 HTTP 状态和耗时，再确认 SQLi 样例和自定义精确路径探针在 WAF 关闭时返回 200。探针只访问测试域名。

## 网关验证

- 只给已核对的测试 Ingress 增加 `matchRules`。优先从 `useCRS: false` 的精确路径 `SecRule` 开始，确认返回 403，验证镜像、域名匹配和基本拦截链路。再测试需要的 CRS 配置；完整 CRS 要单独记录冷加载时间，不把配置已下发等同于 WAF 已生效。
- 当前 72 线程网关曾在启用空 WAF 时接近 8 GiB 内存上限。完整 CRS 测试先将网关临时降到 2 个 Envoy 工作线程，等待新 Pod Ready 且旧 Pod 退出，再下发 WAF；这会滚动更新共享网关。不要在 72 线程下直接打开完整 CRS。仅修改 WasmPlugin 和 Deployment，不能用精简 Chart 升级现有 Higress Helm release。
- 每 2–3 秒采集网关 Pod 的 `/sys/fs/cgroup/memory.current`、`memory.events`、`cpu.stat`、重启次数和正常 HTTP 探针；每 10–15 秒检查 SQLi 与自定义规则是否返回预期 403，并记录从配置下发到首次生效的时间。需要定位慢点时抓取网关日志和 Envoy Wasm 指标，同时区分镜像拉取、指令生成与 `coraza.NewWAF()` 阶段。
- 内存达到 6500 MiB、正常请求失败或 5 秒超时、Pod 失去 Ready、出现 OOM/重启时立即停止并回滚。完整 CRS 的短时观察最长 90 秒；期间规则持续返回 200 应判定为未通过。管理接口或 Prometheus 抓取超时是初始化阻塞的线索，不代替业务探针结论。

## 回滚与报告

用 `finally` 或同等可靠的清理流程恢复保存的 WasmPlugin 镜像 URL、`defaultConfigDisable`、`matchRules` 和 Deployment `args`/资源限制；异常或手动中断也要执行。等待滚动更新完成，读回确认配置与测试前一致，再检查单个 Pod Ready、重启/OOM 计数及测试域名正常请求。若回滚未完成，立即报告当前实际状态，不声称环境已恢复。

报告写明镜像 digest、Ingress/域名、线程数、CPU/内存限制、规则实际首次 403 时间、正常请求情况、内存峰值、OOM/重启以及回滚核验。区分“已下发”“已加载”“已拦截”；没有完成 72 线程容量验证时，不宣称可以上线。历史实测与失败背景见 `../../README.md`。
