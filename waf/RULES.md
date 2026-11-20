# WAF 系统规则

自维护 Wasm 固定内置 OWASP CRS v4.30.0（上游提交 `e03a4f6dabc7a30ebd8c52c97d28a154f590a48f`）。`system-rules.json` 从内嵌的 conf 生成，包含 627 个规则 ID 和 21 个可选择的检测文件；`rule-names.zh.json` 为对应的中文名称映射。运行 `python3 generate_catalog.py --check` 验证文件、规则 ID 和名称一致。

系统规则界面只显示 conf 类别，不显示单条规则开关。关闭某一类别时，服务端从 `ruleFiles` 中移除该 conf，Wasm 不编译其中的检测规则。CRS 初始化、异常评分和阻断评估文件始终加载。全局可以选择 PL1–PL4 和 `SecRuleEngine On`、`DetectionOnly`、`Off`；域名只能继承这些全局设置。

自定义规则仅在全局创建，ID 从 1000000 起。域名可禁用或恢复继承的全局规则，也可覆盖 CRS 总开关、conf 类别与请求体检查开关。保存时服务端再次校验文件名、ID 和 Coraza 语法。旧版策略及旧的 `SecRuleRemoveById` 指令不迁移。

CRS 来源：[OWASP Core Rule Set v4.30.0](https://github.com/coreruleset/coreruleset/tree/v4.30.0)。
