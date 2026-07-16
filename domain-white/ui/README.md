# ui-domain-plugin

域名网关插件的独立配置前端。项目使用 Vue 3 和 Arco Design Vue，构建产物可作为网关插件制品的静态前端包。

## 接入约定

页面从 `window.$wujie.props` 读取以下字段：

- `pluginConfig`：当前插件配置，结构为
  `{ white_domains, response_code, response_content }`；页面仍兼容读取旧的
  `{ list, errpage }` 结构，保存时统一转换为插件实际使用的字段。
- `pluginEnabled`：当前启用状态；兼容读取 `enabled`，未提供时默认为 `true`。
- `configScope`：配置范围，值为 `global` 或 `rule`，仅用于页面提示。
- `savePluginConfig(config, enabled)`：保存当前配置和启用状态。

页面不读取或修改具体网关、路由和规则目标，这些信息由上层网关适配器处理。

## 开发与构建

```bash
npm install
npm run serve
npm run build
```

生产构建结果位于 `dist/`，发布前端包时以其中的 `index.html` 作为入口。
