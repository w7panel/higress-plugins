# WAF 系统规则分类

雷池参考链接介绍的是部署方法，没有公开可迁移的规则定义。雷池的语义检测也无法逐条等同于 OWASP CRS。本插件使用 Higress WAF 内置的 OWASP CRS，并按常见防护能力整理类别；规则内容和版本以实际加载的 WAF 插件为准。已核对的 WAF 2.0.0 内嵌 CRS 标记为 `4.0.0-rc1`。

| 防护能力 | CRS 规则 ID 范围 |
| --- | --- |
| 请求方法限制 | 911000–911999 |
| 扫描器识别 | 913000–913999 |
| 协议和请求格式攻击 | 920000–922999 |
| 本地文件包含、远程文件包含 | 930000–931999 |
| 远程命令执行 | 932000–932999 |
| PHP 和通用应用攻击 | 933000–934999 |
| 跨站脚本 | 941000–941999 |
| SQL 注入 | 942000–942999 |
| 会话固定和 Java 攻击 | 943000–944999 |
| 响应数据泄露 | 950000–955999 |

类别关闭时向 Higress WAF 的 `secRules` 追加 `SecRuleRemoveById` 指令。CRS 开启时，初始化和阻断评估规则始终保留。自定义规则使用独立 ID（从 1000000 开始），避免与 CRS 及已有规则冲突。

`useCRS` 是整套 CRS 的总开关。关闭后不加载 CRS，类别开关暂不生效；自定义 SecRule 仍可执行。域名开关默认继承全局，也可单独覆盖。

单条 CRS 规则功能暂时移除。原 371 条清单按 CRS 3.3.2 编写，与 WAF 2.0.0 内嵌规则不一致；详情见 [排查记录](README.md#单条-crs-规则排查记录2026-11-13)。现仍可按类别关闭，`SecRuleRemoveById` 在加载 CRS 后执行，不能代替 `useCRS: false` 来降低加载峰值。

“自定义规则”页的快捷条件生成固定的 403 拦截规则；“通用 SecRule”可填写 Coraza 匹配变量、操作符、动作，并通过添加 AND 条件生成链式规则。手填入口保留，服务端仅允许 SecRule 指令、单条配置最多 8192 字节、总数最多 100 条，保存时由 Coraza 编译校验。

请求体规则需在“系统规则”页开启“启用自定义规则的请求体检查”。该设置由服务端编译为 `SecRequestBodyAccess On`，可在域名上覆盖或恢复全局；无需在手填规则中写非 SecRule 指令。开启后才会读取 POST 表单参数和 `REQUEST_BODY`，会增加网关请求体处理开销。

参考：[Higress WAF 配置](https://github.com/alibaba/higress/blob/main/plugins/wasm-go/extensions/waf/README.md)、[OWASP CRS 3.3.2](https://github.com/coreruleset/coreruleset/tree/v3.3.2)、[雷池帮助文档](https://help.waf-ce.chaitin.cn/node/01973fc6-e12f-789f-a8ff-e81d383c80bc)。
