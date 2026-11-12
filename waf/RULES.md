# WAF 系统规则分类

雷池参考链接介绍的是部署方法，没有公开可迁移的规则定义。雷池的语义检测也无法逐条等同于 OWASP CRS。本插件使用 Higress WAF 内置的 OWASP CRS 3.3.2 规则，并按常见防护能力整理类别；规则内容仍以 CRS 原版为准。

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

类别关闭时向 Higress WAF 的 `secRules` 追加 `SecRuleRemoveById` 指令。CRS 初始化和阻断评估规则始终保留。自定义规则使用独立 ID（从 1000000 开始），避免与 CRS 及已有规则冲突。

“系统规则”页列出上述类别的 371 个 CRS 3.3.2 规则 ID，支持按单条规则禁用。类别关闭优先，类别内的单条开关此时不生效；域名设置可覆盖全局单条设置。清单来自 CRS 3.3.2 对应的 `REQUEST-*`、`RESPONSE-*` 规则文件；标为“CRS 内部控制规则”的条目参与防护等级和规则执行流程，调整时需了解其作用。

“自定义规则”页的快捷条件生成固定的 403 拦截规则；“通用 SecRule”可填写 Coraza 匹配变量、操作符、动作，并通过添加 AND 条件生成链式规则。手填入口保留，服务端仅允许 SecRule 指令、单条配置最多 8192 字节、总数最多 100 条，保存时由 Coraza 编译校验。

参考：[Higress WAF 配置](https://github.com/alibaba/higress/blob/main/plugins/wasm-go/extensions/waf/README.md)、[OWASP CRS 3.3.2](https://github.com/coreruleset/coreruleset/tree/v3.3.2)、[雷池帮助文档](https://help.waf-ce.chaitin.cn/node/01973fc6-e12f-789f-a8ff-e81d383c80bc)。
