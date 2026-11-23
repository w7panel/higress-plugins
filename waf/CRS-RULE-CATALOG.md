# OWASP CRS 4.30.0 规则名称整理

本表对应 `wasm/wasmplugin/rules/crs/` 内置的 OWASP CRS v4.30.0（上游提交 `e03a4f6dabc7a30ebd8c52c97d28a154f590a48f`）。以实际 conf 中的规则 ID、`msg` 和 `paranoia-level` 标签为准；中文名称用于人工审核，尚未写入运行配置或前端。

范围：21 个检测 conf、515 个 ID，其中 345 条带检测消息，170 条是没有检测消息的跳转/辅助规则。另有 112 个初始化、异常评分和阻断评估等内部 ID，不作为可单独开关的攻击检测规则。

PL 栏的“—”表示规则没有 `paranoia-level` 标签，主要是辅助规则；它不等于“默认执行”。TAPD 示例把 933120、933130 写作无等级，但内置 CRS 4.30.0 中两者均带 `paranoia-level/1`，这里列为 PL1。

## 检测规则

| conf | 分类 | 检测规则 | 辅助 ID |
| --- | --- | ---: | ---: |
| `REQUEST-911-METHOD-ENFORCEMENT.conf` | 请求方法 | 1 | 8 |
| `REQUEST-913-SCANNER-DETECTION.conf` | 扫描器识别 | 1 | 8 |
| `REQUEST-920-PROTOCOL-ENFORCEMENT.conf` | 协议与请求格式 | 59 | 9 |
| `REQUEST-921-PROTOCOL-ATTACK.conf` | 协议攻击 | 17 | 9 |
| `REQUEST-922-MULTIPART-ATTACK.conf` | Multipart 攻击 | 4 | 3 |
| `REQUEST-930-APPLICATION-ATTACK-LFI.conf` | 本地文件包含 | 6 | 8 |
| `REQUEST-931-APPLICATION-ATTACK-RFI.conf` | 远程文件包含 | 5 | 8 |
| `REQUEST-932-APPLICATION-ATTACK-RCE.conf` | 远程命令执行 | 48 | 8 |
| `REQUEST-933-APPLICATION-ATTACK-PHP.conf` | PHP 注入 | 21 | 8 |
| `REQUEST-934-APPLICATION-ATTACK-GENERIC.conf` | 通用应用攻击 | 14 | 8 |
| `REQUEST-941-APPLICATION-ATTACK-XSS.conf` | 跨站脚本 | 33 | 9 |
| `REQUEST-942-APPLICATION-ATTACK-SQLI.conf` | SQL 注入 | 60 | 8 |
| `REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf` | 会话固定 | 3 | 8 |
| `REQUEST-944-APPLICATION-ATTACK-JAVA.conf` | Java 攻击 | 14 | 8 |
| `RESPONSE-950-DATA-LEAKAGES.conf` | 响应数据泄露 | 4 | 11 |
| `RESPONSE-951-DATA-LEAKAGES-SQL.conf` | SQL 信息泄露 | 16 | 9 |
| `RESPONSE-952-DATA-LEAKAGES-JAVA.conf` | Java 信息泄露 | 1 | 8 |
| `RESPONSE-953-DATA-LEAKAGES-PHP.conf` | PHP 信息泄露 | 4 | 8 |
| `RESPONSE-954-DATA-LEAKAGES-IIS.conf` | IIS 信息泄露 | 5 | 8 |
| `RESPONSE-955-WEB-SHELLS.conf` | Web Shell | 27 | 8 |
| `RESPONSE-956-DATA-LEAKAGES-RUBY.conf` | Ruby 信息泄露 | 2 | 8 |

### 请求方法 · `REQUEST-911-METHOD-ENFORCEMENT.conf`

| ID | 中文防护名称 | 严格程度 |
| ---: | --- | --- |
| 911100 | 禁用的 HTTP 请求方法 | PL1 |

### 扫描器识别 · `REQUEST-913-SCANNER-DETECTION.conf`

| ID | 中文防护名称 | 严格程度 |
| ---: | --- | --- |
| 913100 | 安全扫描器 User-Agent | PL1 |

### 协议与请求格式 · `REQUEST-920-PROTOCOL-ENFORCEMENT.conf`

| ID | 中文防护名称 | 严格程度 |
| ---: | --- | --- |
| 920100 | 无效的 HTTP 请求行 | PL1 |
| 920120 | multipart/form-data 格式绕过 | PL1 |
| 920160 | Content-Length 不是数字 | PL1 |
| 920170 | GET/HEAD 请求携带请求体 | PL1 |
| 920171 | GET/HEAD 请求携带 Transfer-Encoding | PL1 |
| 920180 | POST 缺少 Content-Length 和 Transfer-Encoding | PL1 |
| 920181 | 同时存在 Content-Length 和 Transfer-Encoding | PL1 |
| 920190 | Range 结束字节无效 | PL1 |
| 920660 | 使用已废弃的 Request-Range 请求头 | PL1 |
| 920210 | Connection 请求头重复或冲突 | PL1 |
| 920250 | UTF-8 编码滥用 | PL1 |
| 920260 | Unicode 全角/半角编码滥用 | PL1 |
| 920270 | 请求包含空字符 | PL1 |
| 920280 | 缺少 Host 请求头 | PL1 |
| 920290 | Host 请求头为空 | PL1 |
| 920310 | Accept 请求头为空 | PL1 |
| 920311 | Accept 请求头为空 | PL1 |
| 920330 | User-Agent 请求头为空 | PL1 |
| 920340 | 有请求体长度但缺少 Content-Type | PL1 |
| 920350 | Host 请求头使用数字 IP | PL1 |
| 920380 | 请求参数数量过多 | PL1 |
| 920360 | 参数名过长 | PL1 |
| 920370 | 参数值过长 | PL1 |
| 920390 | 参数总大小超限 | PL1 |
| 920400 | 单个上传文件过大 | PL1 |
| 920410 | 上传文件总大小超限 | PL1 |
| 920470 | 非法 Content-Type 请求头 | PL1 |
| 920420 | 请求内容类型不在允许范围 | PL1 |
| 920480 | 内容类型字符集不在允许范围 | PL1 |
| 920530 | Content-Type 声明多个字符集 | PL1 |
| 920640 | 携带请求体但缺少 Content-Type | PL1 |
| 920430 | HTTP 协议版本不在允许范围 | PL1 |
| 920440 | URL 文件扩展名受限 | PL1 |
| 920500 | 访问备份文件或工作文件 | PL1 |
| 920450 | 使用受限 HTTP 请求头 | PL1 |
| 920520 | Accept-Encoding 请求头过长 | PL1 |
| 920600 | Accept 请求头含非法 charset 参数 | PL1 |
| 920540 | Unicode 字符绕过 | PL1 |
| 920610 | 请求 URI 含未编码的片段符 | PL1 |
| 920620 | 存在多个 Content-Type 请求头 | PL1 |
| 920200 | Range 范围段过多（至少 6 段） | PL2 |
| 920201 | PDF 请求的 Range 范围段过多（至少 63 段） | PL2 |
| 920230 | 重复 URL 编码 | PL2 |
| 920271 | 请求包含不可打印字符 | PL2 |
| 920320 | 缺少 User-Agent 请求头 | PL2 |
| 920121 | multipart/form-data 格式绕过 | PL2 |
| 920451 | 使用受限 HTTP 请求头 | PL2 |
| 920240 | URL 编码滥用 | PL2 |
| 920650 | 通过 _method 参数覆盖 HTTP 方法 | PL2 |
| 920272 | 请求包含 ASCII 127 以下的非打印字符 | PL3 |
| 920300 | 缺少 Accept 请求头 | PL3 |
| 920490 | x-up-devcap-post-charset 请求头异常组合 | PL3 |
| 920510 | 无效的 Cache-Control 请求头 | PL3 |
| 920521 | 非法 Accept-Encoding 请求头 | PL3 |
| 920202 | PDF 请求的 Range 范围段过多（至少 6 段） | PL4 |
| 920273 | 请求包含严格字符集外的字符 | PL4 |
| 920274 | 请求头包含严格字符集外的字符 | PL4 |
| 920275 | 请求头包含严格字符集外的字符 | PL4 |
| 920460 | 请求中存在异常字符转义 | PL4 |

### 协议攻击 · `REQUEST-921-PROTOCOL-ATTACK.conf`

| ID | 中文防护名称 | 严格程度 |
| ---: | --- | --- |
| 921110 | HTTP 请求走私 | PL1 |
| 921120 | HTTP 响应拆分 | PL1 |
| 921130 | HTTP 响应拆分 | PL1 |
| 921140 | 通过请求头注入 HTTP 头 | PL1 |
| 921150 | 请求载荷中的 CR/LF 头注入 | PL1 |
| 921160 | 请求载荷中的 CR/LF 与头名称注入 | PL1 |
| 921190 | 文件名中的 CR/LF 引发 HTTP 拆分 | PL1 |
| 921200 | LDAP 注入 | PL1 |
| 921421 | MIME 声明外的危险 Content-Type | PL1 |
| 921240 | mod_proxy 攻击尝试 | PL1 |
| 921250 | 旧版 Cookie V1 格式滥用 | PL1 |
| 921151 | 请求载荷中的 CR/LF 头注入 | PL2 |
| 921422 | MIME 声明外的危险 Content-Type | PL2 |
| 921230 | HTTP Range 请求头攻击 | PL3 |
| 921180 | HTTP 参数污染 | PL3 |
| 921210 | 参数数组后的异常字符造成参数污染 | PL3 |
| 921220 | 数组记法造成 HTTP 参数污染 | PL4 |

### Multipart 攻击 · `REQUEST-922-MULTIPART-ATTACK.conf`

| ID | 中文防护名称 | 严格程度 |
| ---: | --- | --- |
| 922100 | multipart 全局 _charset_ 声明不允许 | PL1 |
| 922110 | multipart 头含非法 charset 参数 | PL1 |
| 922120 | 使用已废弃的 Content-Transfer-Encoding | PL1 |
| 922130 | multipart 请求头包含非法字符 | PL1 |

### 本地文件包含 · `REQUEST-930-APPLICATION-ATTACK-LFI.conf`

| ID | 中文防护名称 | 严格程度 |
| ---: | --- | --- |
| 930100 | 路径穿越（/../ 或 /.../） | PL1 |
| 930110 | 路径穿越（/../ 或 /.../） | PL1 |
| 930120 | 访问操作系统文件 | PL1 |
| 930130 | 访问受限文件 | PL1 |
| 930140 | 访问 AI 编码助手产物文件 | PL1 |
| 930121 | 在请求头中访问操作系统文件 | PL2 |

### 远程文件包含 · `REQUEST-931-APPLICATION-ATTACK-RFI.conf`

| ID | 中文防护名称 | 严格程度 |
| ---: | --- | --- |
| 931100 | 使用 IP 地址的 URL 参数尝试远程文件包含 | PL1 |
| 931110 | 常见 RFI 参数名携带 URL 载荷 | PL1 |
| 931120 | URL 载荷末尾带问号的远程文件包含 | PL1 |
| 931130 | 指向站外地址的远程文件包含 | PL2 |
| 931131 | 远程文件包含 | PL2 |

### 远程命令执行 · `REQUEST-932-APPLICATION-ATTACK-RCE.conf`

| ID | 中文防护名称 | 严格程度 |
| ---: | --- | --- |
| 932230 | 短 Unix 命令注入（2–3 字符） | PL1 |
| 932235 | 未混淆的 Unix 命令注入 | PL1 |
| 932120 | Windows PowerShell 命令注入 | PL1 |
| 932125 | PowerShell 别名命令注入 | PL1 |
| 932130 | Unix Shell 表达式注入 | PL1 |
| 932140 | Windows FOR/IF 命令注入 | PL1 |
| 932270 | Unix Shell 表达式注入 | PL1 |
| 932280 | Shell 花括号展开注入 | PL1 |
| 932250 | 直接执行 Unix 命令 | PL1 |
| 932260 | 直接执行 Unix 命令 | PL1 |
| 932340 | 无参数的 Unix 命令执行 | PL1 |
| 932330 | Unix Shell 历史命令调用 | PL1 |
| 932160 | Unix Shell 代码注入 | PL1 |
| 932170 | Shellshock（CVE-2014-6271） | PL1 |
| 932171 | Shellshock（CVE-2014-6271） | PL1 |
| 932175 | Unix Shell 别名调用 | PL1 |
| 932180 | 上传受限文件 | PL1 |
| 932370 | Windows 命令注入 | PL1 |
| 932380 | Windows 命令注入 | PL1 |
| 932371 | Windows 命令注入 | PL2 |
| 932231 | Unix 命令注入 | PL2 |
| 932131 | Unix Shell 表达式注入 | PL2 |
| 932200 | 远程命令执行绕过手法 | PL2 |
| 932205 | 远程命令执行绕过手法 | PL2 |
| 932206 | 远程命令执行绕过手法 | PL2 |
| 932207 | 远程命令执行绕过手法 | PL2 |
| 932220 | 通过管道的 Unix 命令注入 | PL2 |
| 932240 | Unix 命令注入规避检测 | PL2 |
| 932281 | Shell 花括号展开注入 | PL2 |
| 932210 | SQLite 系统命令执行 | PL2 |
| 932271 | Unix Shell 表达式注入 | PL2 |
| 932300 | SMTP 命令执行 | PL2 |
| 932310 | IMAP 命令执行 | PL2 |
| 932320 | POP3 命令执行 | PL2 |
| 932236 | 未混淆的 Unix 命令注入 | PL2 |
| 932239 | User-Agent 或 Referer 中的 Unix 命令注入 | PL2 |
| 932161 | 请求头中的 Unix Shell 代码 | PL2 |
| 932390 | Shell fork bomb | PL2 |
| 932232 | Unix 命令注入 | PL3 |
| 932237 | 请求头中的 Unix Shell 代码 | PL3 |
| 932238 | 请求头中的 Unix Shell 代码 | PL3 |
| 932290 | 引号规避检测 | PL3 |
| 932190 | Shell 通配符绕过 | PL3 |
| 932350 | 无参数的 Unix 命令执行 | PL3 |
| 932301 | SMTP 命令执行 | PL3 |
| 932311 | IMAP 命令执行 | PL3 |
| 932321 | POP3 命令执行 | PL3 |
| 932331 | Unix Shell 历史命令调用 | PL3 |

### PHP 注入 · `REQUEST-933-APPLICATION-ATTACK-PHP.conf`

| ID | 中文防护名称 | 严格程度 |
| ---: | --- | --- |
| 933100 | PHP 起始标签检测 | PL1 |
| 933110 | 上传 PHP 脚本文件 | PL1 |
| 933120 | PHP 配置指令检测 | PL1 |
| 933130 | PHP 变量声明检测 | PL1 |
| 933135 | PHP 变量访问检测 | PL1 |
| 933140 | PHP 输入输出流检测 | PL1 |
| 933200 | PHP wrapper 协议检测 | PL1 |
| 933150 | 高风险 PHP 函数名称 | PL1 |
| 933160 | 高风险 PHP 函数调用 | PL1 |
| 933170 | PHP 序列化对象注入 | PL1 |
| 933180 | PHP 可变函数调用 | PL1 |
| 933210 | PHP 可变函数调用 | PL1 |
| 933220 | PHP 会话文件上传 | PL1 |
| 933151 | 中风险 PHP 函数名称 | PL2 |
| 933152 | 中风险 PHP 函数名称 | PL2 |
| 933153 | 中风险 PHP 函数名称 | PL2 |
| 933131 | PHP 变量声明检测 | PL3 |
| 933161 | 低风险 PHP 函数调用 | PL3 |
| 933111 | 上传 PHP 脚本文件 | PL3 |
| 933190 | PHP 结束标签检测 | PL3 |
| 933211 | PHP 可变函数调用 | PL3 |

### 通用应用攻击 · `REQUEST-934-APPLICATION-ATTACK-GENERIC.conf`

| ID | 中文防护名称 | 严格程度 |
| ---: | --- | --- |
| 934100 | Node.js 注入（规则 1/2） | PL1 |
| 934110 | 访问云服务元数据地址的 SSRF | PL1 |
| 934190 | 无协议的本机或内网主机名 SSRF | PL1 |
| 934130 | JavaScript 原型污染 | PL1 |
| 934150 | Ruby 代码注入 | PL1 |
| 934160 | Node.js 拒绝服务攻击 | PL1 |
| 934170 | PHP data 协议载荷 | PL1 |
| 934200 | 服务端模板注入 | PL1 |
| 934101 | Node.js 注入（规则 2/2） | PL2 |
| 934120 | 使用 IP 地址的 URL 参数 SSRF | PL2 |
| 934140 | Perl 代码注入 | PL2 |
| 934180 | 服务端模板注入 | PL2 |
| 934220 | 嵌套属性遍历的 ORM 查询操作符注入 | PL2 |
| 934210 | ORM 查询操作符注入 | PL3 |

### 跨站脚本 · `REQUEST-941-APPLICATION-ATTACK-XSS.conf`

| ID | 中文防护名称 | 严格程度 |
| ---: | --- | --- |
| 941100 | libinjection 识别的 XSS | PL1 |
| 941110 | script 标签型 XSS | PL1 |
| 941120 | 事件处理器型 XSS | PL1 |
| 941130 | HTML 属性型 XSS | PL1 |
| 941140 | JavaScript URI 型 XSS | PL1 |
| 941160 | NoScript HTML 注入 | PL1 |
| 941170 | NoScript HTML 属性注入 | PL1 |
| 941180 | Node Validator 拒绝列表关键字 | PL1 |
| 941190 | IE XSS 过滤器识别的攻击 | PL1 |
| 941200 | IE XSS 过滤器识别的攻击 | PL1 |
| 941210 | 可疑 JavaScript 关键字 | PL1 |
| 941220 | IE XSS 过滤器识别的攻击 | PL1 |
| 941230 | IE XSS 过滤器识别的攻击 | PL1 |
| 941240 | IE XSS 过滤器识别的攻击 | PL1 |
| 941250 | IE XSS 过滤器识别的攻击 | PL1 |
| 941260 | IE XSS 过滤器识别的攻击 | PL1 |
| 941270 | IE XSS 过滤器识别的攻击 | PL1 |
| 941280 | IE XSS 过滤器识别的攻击 | PL1 |
| 941290 | IE XSS 过滤器识别的攻击 | PL1 |
| 941300 | IE XSS 过滤器识别的攻击 | PL1 |
| 941310 | US-ASCII 异常编码 XSS | PL1 |
| 941350 | UTF-7 编码的 IE XSS | PL1 |
| 941360 | JSFuck / Hieroglyphy 混淆 | PL1 |
| 941370 | JavaScript 全局变量注入 | PL1 |
| 941390 | JavaScript 方法注入 | PL1 |
| 941400 | 无括号的 JavaScript 函数调用 XSS | PL1 |
| 941101 | libinjection 识别的 XSS | PL2 |
| 941150 | 非法 HTML 属性型 XSS | PL2 |
| 941181 | Node Validator 拒绝列表关键字 | PL2 |
| 941320 | HTML 标签事件处理器型 XSS | PL2 |
| 941330 | IE XSS 过滤器识别的攻击 | PL2 |
| 941340 | IE XSS 过滤器识别的攻击 | PL2 |
| 941380 | AngularJS 客户端模板注入 | PL2 |

### SQL 注入 · `REQUEST-942-APPLICATION-ATTACK-SQLI.conf`

| ID | 中文防护名称 | 严格程度 |
| ---: | --- | --- |
| 942100 | libinjection 识别的 SQL 注入 | PL1 |
| 942140 | 常见数据库名称注入 | PL1 |
| 942151 | SQL 函数名称注入 | PL1 |
| 942160 | 使用 sleep()/benchmark() 的盲注 | PL1 |
| 942170 | 条件查询中的延时函数盲注 | PL1 |
| 942190 | SQL 代码执行或信息探测 | PL1 |
| 942220 | 整数溢出攻击载荷 | PL1 |
| 942230 | 条件式 SQL 注入 | PL1 |
| 942240 | MySQL 字符集切换或 MSSQL 拒绝服务 | PL1 |
| 942250 | MATCH AGAINST / MERGE / EXECUTE IMMEDIATE 注入 | PL1 |
| 942270 | 常见 SQL 语句注入 | PL1 |
| 942280 | PostgreSQL pg_sleep / WAITFOR 延时或关库 | PL1 |
| 942290 | MongoDB 查询注入 | PL1 |
| 942320 | MySQL/PostgreSQL 存储过程或函数注入 | PL1 |
| 942350 | MySQL UDF 与数据结构操作注入 | PL1 |
| 942360 | 拼接式 SQL 注入或 SQL 本地文件包含 | PL1 |
| 942500 | MySQL 行内注释注入 | PL1 |
| 942540 | 拆分查询的 SQL 认证绕过 | PL1 |
| 942560 | MySQL 科学计数法载荷 | PL1 |
| 942550 | 基于 JSON 的 SQL 注入 | PL1 |
| 942120 | SQL 操作符注入 | PL2 |
| 942130 | 布尔条件 SQL 注入 | PL2 |
| 942131 | 布尔条件 SQL 注入 | PL2 |
| 942150 | SQL 函数名称注入 | PL2 |
| 942180 | SQL 认证绕过（1/3） | PL2 |
| 942200 | MySQL 注释/空格混淆及反引号终止 | PL2 |
| 942210 | 链式 SQL 注入（1/2） | PL2 |
| 942260 | SQL 认证绕过（2/3） | PL2 |
| 942300 | MySQL 注释、条件和 char 函数注入 | PL2 |
| 942310 | 链式 SQL 注入（2/2） | PL2 |
| 942330 | 典型 SQL 注入探测（1/3） | PL2 |
| 942340 | SQL 认证绕过（3/3） | PL2 |
| 942361 | ALTER/UNION 关键字 SQL 注入 | PL2 |
| 942362 | 拼接式 SQL 注入或 SQL 本地文件包含 | PL2 |
| 942370 | 典型 SQL 注入探测（2/3） | PL2 |
| 942380 | SQL 注入 | PL2 |
| 942390 | XOR/OR 条件 SQL 注入 | PL2 |
| 942400 | SQL 注入 | PL2 |
| 942410 | SQL 注入 | PL2 |
| 942470 | SQL 注入 | PL2 |
| 942480 | SQL 注入 | PL2 |
| 942430 | 请求参数 SQL 特殊字符超过 12 个 | PL2 |
| 942440 | SQL 注释序列 | PL2 |
| 942450 | SQL 二进制或十六进制编码 | PL2 |
| 942510 | 引号或反引号绕过 SQL 注入检测 | PL2 |
| 942520 | SQL 认证绕过（4.0/4） | PL2 |
| 942521 | SQL 认证绕过（4.1/4） | PL2 |
| 942522 | SQL 认证绕过（4.1/4） | PL2 |
| 942101 | libinjection 识别的 SQL 注入 | PL2 |
| 942152 | SQL 函数名称注入 | PL2 |
| 942321 | MySQL/PostgreSQL 存储过程或函数注入 | PL2 |
| 942251 | HAVING 子句注入 | PL3 |
| 942490 | 典型 SQL 注入探测（3/3） | PL3 |
| 942420 | Cookie SQL 特殊字符超过 8 个 | PL3 |
| 942431 | 请求参数 SQL 特殊字符超过 6 个 | PL3 |
| 942460 | 重复非字母数字元字符异常 | PL3 |
| 942511 | 引号绕过 SQL 注入检测 | PL3 |
| 942530 | SQL 查询终止符注入 | PL3 |
| 942421 | Cookie SQL 特殊字符超过 3 个 | PL4 |
| 942432 | 请求参数 SQL 特殊字符超过 2 个 | PL4 |

### 会话固定 · `REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf`

| ID | 中文防护名称 | 严格程度 |
| ---: | --- | --- |
| 943100 | HTML 中设置 Cookie 值的会话固定 | PL1 |
| 943110 | SessionID 参数与站外 Referer 组合 | PL1 |
| 943120 | SessionID 参数缺少 Referer | PL1 |

### Java 攻击 · `REQUEST-944-APPLICATION-ATTACK-JAVA.conf`

| ID | 中文防护名称 | 严格程度 |
| ---: | --- | --- |
| 944100 | 可疑 Java 类触发远程命令执行 | PL1 |
| 944110 | Java 进程创建（CVE-2017-9805） | PL1 |
| 944120 | Java 反序列化命令执行（CVE-2015-4852） | PL1 |
| 944130 | 可疑 Java 类 | PL1 |
| 944140 | 上传 Java 脚本文件 | PL1 |
| 944150 | Log4Shell 命令执行载荷 | PL1 |
| 944151 | Log4Shell 命令执行载荷 | PL2 |
| 944200 | Java 序列化魔数 | PL2 |
| 944210 | Base64 编码的 Java 序列化魔数 | PL2 |
| 944240 | Java 反序列化命令执行（CVE-2015-4852） | PL2 |
| 944250 | 可疑 Java 方法触发命令执行 | PL2 |
| 944260 | 恶意 Java 类加载载荷 | PL2 |
| 944300 | Base64 编码的可疑关键字 | PL3 |
| 944152 | Log4Shell 命令执行载荷 | PL4 |

### 响应数据泄露 · `RESPONSE-950-DATA-LEAKAGES.conf`

| ID | 中文防护名称 | 严格程度 |
| ---: | --- | --- |
| 950130 | 目录列表暴露 | PL1 |
| 950140 | CGI 源码泄露 | PL1 |
| 950150 | ASP.NET 异常信息泄露 | PL1 |
| 950100 | 应用返回 HTTP 5xx 状态 | PL2 |

### SQL 信息泄露 · `RESPONSE-951-DATA-LEAKAGES-SQL.conf`

| ID | 中文防护名称 | 严格程度 |
| ---: | --- | --- |
| 951110 | Microsoft Access SQL 错误信息泄露 | PL1 |
| 951120 | Oracle SQL 错误信息泄露 | PL1 |
| 951130 | DB2 SQL 错误信息泄露 | PL1 |
| 951140 | EMC SQL 错误信息泄露 | PL1 |
| 951150 | Firebird SQL 错误信息泄露 | PL1 |
| 951160 | FrontBase SQL 错误信息泄露 | PL1 |
| 951170 | HSQLDB SQL 错误信息泄露 | PL1 |
| 951180 | Informix SQL 错误信息泄露 | PL1 |
| 951190 | Ingres SQL 错误信息泄露 | PL1 |
| 951200 | InterBase SQL 错误信息泄露 | PL1 |
| 951210 | MaxDB SQL 错误信息泄露 | PL1 |
| 951220 | MSSQL SQL 错误信息泄露 | PL1 |
| 951230 | MySQL SQL 错误信息泄露 | PL1 |
| 951240 | PostgreSQL SQL 错误信息泄露 | PL1 |
| 951250 | SQLite SQL 错误信息泄露 | PL1 |
| 951260 | Sybase SQL 错误信息泄露 | PL1 |

### Java 信息泄露 · `RESPONSE-952-DATA-LEAKAGES-JAVA.conf`

| ID | 中文防护名称 | 严格程度 |
| ---: | --- | --- |
| 952110 | Java 错误信息泄露 | PL1 |

### PHP 信息泄露 · `RESPONSE-953-DATA-LEAKAGES-PHP.conf`

| ID | 中文防护名称 | 严格程度 |
| ---: | --- | --- |
| 953100 | PHP 信息泄露 | PL1 |
| 953110 | PHP 源码泄露 | PL1 |
| 953120 | PHP 源码泄露 | PL1 |
| 953101 | PHP 信息泄露 | PL2 |

### IIS 信息泄露 · `RESPONSE-954-DATA-LEAKAGES-IIS.conf`

| ID | 中文防护名称 | 严格程度 |
| ---: | --- | --- |
| 954100 | IIS 安装路径泄露 | PL1 |
| 954110 | IIS 应用可用性错误 | PL1 |
| 954120 | IIS 信息泄露 | PL1 |
| 954130 | IIS 信息泄露 | PL1 |
| 954101 | IIS 安装路径泄露 | PL2 |

### Web Shell · `RESPONSE-955-WEB-SHELLS.conf`

| ID | 中文防护名称 | 严格程度 |
| ---: | --- | --- |
| 955100 | PHP WebShell 后门 | PL1 |
| 955110 | r57 WebShell 后门 | PL1 |
| 955120 | WSO WebShell 后门 | PL1 |
| 955130 | b4tm4n WebShell 后门 | PL1 |
| 955140 | Mini Shell WebShell 后门 | PL1 |
| 955150 | Ashiyane WebShell 后门 | PL1 |
| 955160 | Symlink_Sa WebShell 后门 | PL1 |
| 955170 | CasuS WebShell 后门 | PL1 |
| 955180 | GRP WebShell 后门 | PL1 |
| 955190 | NGHshell WebShell 后门 | PL1 |
| 955200 | SimAttacker WebShell 后门 | PL1 |
| 955210 | 未知 WebShell 后门 | PL1 |
| 955220 | lama WebShell 后门 | PL1 |
| 955230 | lostDC WebShell 后门 | PL1 |
| 955240 | 未知 WebShell 后门 | PL1 |
| 955250 | 未知 WebShell 后门 | PL1 |
| 955260 | Ru24PostWebShell 后门 | PL1 |
| 955270 | s72 Shell WebShell 后门 | PL1 |
| 955280 | PhpSpy WebShell 后门 | PL1 |
| 955290 | g00nshell WebShell 后门 | PL1 |
| 955300 | PuNkHoLic Shell WebShell 后门 | PL1 |
| 955310 | azrail WebShell 后门 | PL1 |
| 955320 | SmEvK_PaThAn WebShell 后门 | PL1 |
| 955330 | Shell I WebShell 后门 | PL1 |
| 955340 | b374k m1n1 WebShell 后门 | PL1 |
| 955400 | ASP WebShell 后门 | PL1 |
| 955350 | webadmin.php 文件管理器后门 | PL2 |

### Ruby 信息泄露 · `RESPONSE-956-DATA-LEAKAGES-RUBY.conf`

| ID | 中文防护名称 | 严格程度 |
| ---: | --- | --- |
| 956100 | Ruby 信息泄露 | PL1 |
| 956110 | Ruby 源码泄露 | PL2 |

## 辅助与内部 ID

以下 ID 在 conf 中用于 PL 跳转、状态设置等处理，没有攻击检测 `msg`，因此不为它们编造防护名称。具体行为应直接查看相应 conf。

- `REQUEST-911-METHOD-ENFORCEMENT.conf`：911011、911012、911013、911014、911015、911016、911017、911018
- `REQUEST-913-SCANNER-DETECTION.conf`：913011、913012、913013、913014、913015、913016、913017、913018
- `REQUEST-920-PROTOCOL-ENFORCEMENT.conf`：920011、920012、920539、920013、920014、920015、920016、920017、920018
- `REQUEST-921-PROTOCOL-ATTACK.conf`：921011、921012、921013、921014、921015、921016、921170、921017、921018
- `REQUEST-922-MULTIPART-ATTACK.conf`：922160、922140、922150
- `REQUEST-930-APPLICATION-ATTACK-LFI.conf`：930011、930012、930013、930014、930015、930016、930017、930018
- `REQUEST-931-APPLICATION-ATTACK-RFI.conf`：931011、931012、931013、931014、931015、931016、931017、931018
- `REQUEST-932-APPLICATION-ATTACK-RCE.conf`：932011、932012、932013、932014、932015、932016、932017、932018
- `REQUEST-933-APPLICATION-ATTACK-PHP.conf`：933011、933012、933013、933014、933015、933016、933017、933018
- `REQUEST-934-APPLICATION-ATTACK-GENERIC.conf`：934011、934012、934013、934014、934015、934016、934017、934018
- `REQUEST-941-APPLICATION-ATTACK-XSS.conf`：941011、941012、941010、941013、941014、941015、941016、941017、941018
- `REQUEST-942-APPLICATION-ATTACK-SQLI.conf`：942011、942012、942013、942014、942015、942016、942017、942018
- `REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf`：943011、943012、943013、943014、943015、943016、943017、943018
- `REQUEST-944-APPLICATION-ATTACK-JAVA.conf`：944011、944012、944013、944014、944015、944016、944017、944018
- `RESPONSE-950-DATA-LEAKAGES.conf`：950020、950021、950022、950011、950012、950013、950014、950015、950016、950017、950018
- `RESPONSE-951-DATA-LEAKAGES-SQL.conf`：951011、951012、951100、951013、951014、951015、951016、951017、951018
- `RESPONSE-952-DATA-LEAKAGES-JAVA.conf`：952011、952012、952013、952014、952015、952016、952017、952018
- `RESPONSE-953-DATA-LEAKAGES-PHP.conf`：953011、953012、953013、953014、953015、953016、953017、953018
- `RESPONSE-954-DATA-LEAKAGES-IIS.conf`：954011、954012、954013、954014、954015、954016、954017、954018
- `RESPONSE-955-WEB-SHELLS.conf`：955011、955012、955013、955014、955015、955016、955017、955018
- `RESPONSE-956-DATA-LEAKAGES-RUBY.conf`：956011、956012、956013、956014、956015、956016、956017、956018

内部 conf（初始化、异常评分和阻断评估等）中的 112 个 ID 未列入上方可选检测规则。完整 ID 与源文件对应关系见 `system-rules.json`。

## 维护方式

升级 CRS 时，先运行 `python3 generate_catalog.py` 更新 `system-rules.json`，再对照新增、删除或变更的 ID 更新本表及 `rule-names.zh.json`；运行 `python3 generate_catalog.py --check` 核对清单。中文名称描述规则的检测对象或特征，不代表规则一定阻断；是否执行还取决于 PL、类别开关、引擎模式和异常评分。
