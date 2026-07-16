# 集群限流插件配置前端

从面板限流配置组件拆分出的独立 MicroApp，使用 Vue 3 和 Arco Design Vue，提供限流策略、响应内容和 Redis 配置。

插件同时支持两种配置范围：

- 全局配置（`global`）：配置作用于整个集群的网关请求。
- 规则配置（`rule`）：配置只作用于当前域名/Ingress 规则。

## 页面路由

项目使用 `vue-router` 的 `createWebHashHistory`，路由配置位于 `src/router/index.js`。制品 MicroApp 菜单配置两个页面：

- `#/rate-limit`：限流管理。
- `#/response-redis`：响应内容与 Redis 配置。

两个页面读取并保存同一份 `pluginConfig`。限流管理页面只校验限流策略；响应内容与 Redis 页面统一校验返回码和 Redis 服务地址。

## 宿主协议

页面从 `window.$wujie.props` 读取：

- `pluginConfig`：当前限流插件配置。
- `pluginEnabled`：当前配置是否启用；兼容旧字段 `pluginConfigEnabled` 和 `enabled`。
- `configScope`：`global` 或 `rule`。
- `pluginId`：插件资源名称。
- `namespace`、`ingressName`、`domain`、`path`：规则配置上下文；全局配置时为空。
- `savePluginConfig(config, enabled)`：保存配置及启用状态。

页面不直接请求 Kubernetes API，也不自行定位 WasmPlugin 或 Ingress。

## 开发与构建

```bash
npm install
npm run serve

# 构建并将前端代码打包到 dist/frontend.zip
make ui
```

开发服务默认监听 `8082`。`make ui` 会先生成 `dist/` 生产文件，再将其中的代码直接打包为 `dist/frontend.zip`；压缩包本身不会被重复打入。

也可以单独执行：

```bash
make build-ui   # 只构建 dist
make publish    # 打包 dist/frontend.zip；dist 不存在时自动先构建
make clean      # 清理 dist
```
