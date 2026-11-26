---
name: waf-envoy-test
description: 在本机 Higress Envoy 中加载 WAF Wasm 镜像或 wasm 文件，测量整套 CRS 冷启动并验证拦截。用于 WAF Wasm 性能或规则回归测试；不操作 Kubernetes 集群。
---

# WAF Envoy 本地测试

使用 `scripts/test.sh` 运行隔离测试。脚本固定使用 Higress Gateway 2.2.3、2 核、8 GiB、2 个工作线程，配置 `useCRS:true`，等待监听就绪后验证自定义规则、SQLi、XSS 与正常请求。Docker 端口动态分配到本机回环地址；退出时停止容器。

```bash
bash waf/skills/waf-envoy-test/scripts/test.sh ccr.ccs.tencentyun.com/afan-public/w7panel-waf:<tag>
```

也可传入本地 `.wasm` 文件。验证当前源码时先构建镜像，例如 `docker build -t waf-local:test waf/wasm`，再把 `waf-local:test` 传给脚本。需要 Docker、curl，首次运行会拉取 Gateway 镜像。

报告启动到就绪时间、每次 `plugin start successfully` 的时间、探针后的内存、可读取时的容器 cgroup 内存峰值和四个探针结果。区分 Envoy 冷启动与 `coraza.NewWAF()` 耗时：普通镜像日志不能单独量出后者；若镜像带分段计时日志，再引用该日志。测试超时或规则不符时保留脚本输出以定位，不把本地结果当作线上耗时。
