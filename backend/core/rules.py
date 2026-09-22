"""内置规则引擎。

两个用途（两条链路**相互独立**，见 backend/worker.py）：
1. 未配置 LLM API Key 时，作为兜底扫描器，保证系统开箱即用；
2. 配置了 LLM 时，与 AI 语义分析**并行**跑，结果在报告里合并去重
   （同一处 AI 命中优先）。规则命中**不会**作为上下文喂给模型——
   早期文档曾这么描述，与实现不符，此处更正。

正则规则最大的敌人是误报：一条 `\\$\\{[^}]*\\}` 就能把 pom.xml 的 `${version}`、
Spring 的 `@Value("${x}")` 全报成 SQL 注入。所以规则支持四个可选的上下文约束
字段（file_patterns / file_exclude_patterns / file_contains / line_require /
line_exclude / skip_tests），并在默认
情况下跳过「整行注释」（凭证类规则例外，见 SCAN_COMMENT_RULES）。
"""
from __future__ import annotations

import re

# 误报治理三原则（2026-09-22 一次大范围治理后固化，改规则前请先读）：
#
# 1. 「出现某字符串」≠「有漏洞」。判定必须还原到攻击路径本身：
#    路径穿越 = 外部输入进入文件系统 API，不是「源码里有 ../」；
#    SSRF = HTTP 客户端真的发出请求，不是「出现了 HttpClient 这个词」。
#    反面教材：`\.\.[/\\]` 一条分支在 Angular 仓库里刷出 805 条误报（占报告 90%）。
#
# 2. 黑名单之外必须有反例排除（line_exclude / file_exclude_patterns / skip_tests）。
#    校验与防护代码（`contains("../")`、`ssl_ciphers !MD5`）是防线不是漏洞，
#    报出来是负价值；单元测试里的夹具数据同理。
#
# 3. 每条规则都要配**正例 + 反例**回归测试，见 backend/tests/test_rules.py。
#    只做收紧没有回归，很容易顺手把真漏洞一起干掉，而且没人会发现。
#    另外：放宽和收紧都要双向验证 —— 反例归零要有证据，正例仍命中也要有证据。

# 「外部输入入口」特征 —— 用于**文件级**判断：这个文件到底接不接触外部输入。
#
# 为什么需要它：正则是逐行的，看不到跨行的数据流。`ioutil.ReadFile(filePath)`
# 到底是「读自己的配置文件」还是「读用户传来的路径」，单看这一行永远分不清，
# 只有整个文件能回答（里面有没有处理 HTTP 请求 / 命令行参数）。
# 2026-09-22 实测：repo4 的 39 条路径穿越里 36 条来自完全不接触外部输入的文件
# （工具类 / 库函数 / 解析器 / 单测），repo3 的 SSRF 15 条里 13 条来自不接请求的
# 统一 HTTP 封装类 —— 这正是「变量名当污点源」造成的系统性噪声。
#
# 用法：把它放进规则的 file_contains，表示「只在这个文件真的会收到外部输入时
# 才评判该规则」。注意它只是**降低噪声**，不能替代行级判据。
# 刻意写得宽松（宁可多放进来，也不要因为漏判一个框架而丢掉真漏洞）。
#
# 刻意**不**收：命令行参数（os.Args / argv / stdin）。CLI 的参数由调用者自己控制，
# 调用者本来就能直接读那个文件，不构成信任边界；把它算进来只会让「工具程序读自己的
# 参数路径」变成路径穿越（实测 repo4 的 xmltest.go、repo5 的 themeCssBuild.js 都是这么中的）。
EXTERNAL_INPUT_HINTS = [
    r"(?i)(?:request\.|req\.(?:query|params|body|url|headers)"
    r"|r\.URL\b|\w*FormValue\s*\(|\w*PostForm\w*\s*\("
    r"|\.(?:query|param)\w*\s*\(|ctx\.\w*(?:query|param|body)\w*"
    r"|getParameter\s*\(|get_argument\s*\(|@RequestParam|@PathVariable"
    r"|@RequestBody|@RequestHeader|@(?:\w+)?Mapping\b|@RestController\b|@Controller\b"
    r"|MultipartFile|\bmultipart\b"
    r"|\$_(?:GET|POST|REQUEST|COOKIE|FILES)|formData|\.uploads?\b"
    r"|router\.(?:get|post|put|delete|patch|use)\s*\(|app\.(?:get|post|put|delete|use)\s*\("
    r"|@app\.route\b)"
]

SEVERITY_ORDER = ["critical", "high", "medium", "low"]

# severity_downgrade 用：命中「危险性更低的子类」时降一级
_DOWNGRADE = {"critical": "high", "high": "medium", "medium": "low", "low": "low"}

# severity: critical / high / medium / low
RULES: list[dict] = [
    # ---------- 凭证泄漏 ----------
    {
        "id": "hardcoded-password",
        "name": "硬编码密码",
        "severity": "high",
        "category": "凭证泄漏",
        "pattern": r"(?i)\b(password|passwd|pwd|secret|token|apikey|api_key|access_key)\b\s*[:=]\s*[\"'][^\"'\s]{6,}[\"']",
        "line_exclude": [
            # 值就是字段名本身的「占位符 / 默认值」，不是泄漏的凭据：
            #   Password = "password"、secret: "changeme"、token = "xxx"
            # 判据要求「键与值是同一个词」，所以 `password = "RealSecret123"` 照样报。
            r"(?i)\b(?:password|passwd|pwd|secret|token|api_?key|access_?key|credential)\b"
            r"\s*[:=]\s*[\"'](?:password|passwd|pwd|secret|token|changeme|placeholder"
            r"|none|null|undefined|\*{3,}|x{3,}|<[^>]{0,20}>)['\"]",
        ],
        "advice": "凭证不应硬编码在源码中，请改用环境变量或密钥管理服务，并立即轮换已泄漏的凭据。",
    },
    {
        "id": "private-key-block",
        "name": "私钥文件内容",
        "severity": "critical",
        "category": "凭证泄漏",
        "confidence": "high",
        "pattern": r"-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
        # 本规则刻意连注释一起扫（注释里残留真实密钥确实是事故），但「解释密钥格式」
        # 的文档注释不是泄漏，例如：
        #   // 嘗試以 PKCS#1 格式解析 (通常以 -----BEGIN RSA PRIVATE KEY----- 開頭)
        # 真正的 PEM 密钥块，标记行之后必然紧跟很长一段 base64 材料。
        # context_require 把「本行 + 下一行」当成一个窗口来匹配，正好覆盖两种真实形态：
        #   · .pem/.key 文件：标记独占一行，base64 在下一行
        #   · 代码常量：'-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADAN…' 同行的转义字符串
        # 文档注释两行都凑不出 40 个连续 base64 字符，自然被排除。
        "context_require": [r"PRIVATE KEY-----[\s\S]{0,120}?[A-Za-z0-9+/]{40,}={0,2}"],
        "advice": "私钥绝不可入库，请从代码库移除、轮换密钥，并通过配置文件注入。",
    },
    {
        "id": "cloud-access-key",
        "name": "云厂商 AccessKey",
        "severity": "critical",
        "category": "凭证泄漏",
        "confidence": "high",
        "pattern": r"\b(AKIA[0-9A-Z]{16}|LTAI[0-9A-Za-z]{12,})\b",
        "advice": "疑似云平台长期密钥泄漏，请立即在控制台禁用并轮换，改用 RAM 角色/STS 临时凭证。",
    },
    {
        "id": "jdbc-credential",
        "name": "数据库连接串内嵌凭证",
        "severity": "high",
        "category": "凭证泄漏",
        "confidence": "high",
        "pattern": r"(?i)jdbc:[a-z0-9]+://[^\s\"']*[:@][^\s\"']*[:@][^\s\"']+",
        "advice": "连接串中不要内嵌账号密码，请外置到配置中心并加密存储。",
    },
    # ---------- 注入 ----------
    {
        "id": "sql-string-concat",
        "name": "SQL 语句字符串拼接",
        "severity": "critical",
        "category": "SQL 注入",
        # 旧写法 `(select|insert into|update|delete from)\b.{0,80}(...)` 里 update/delete
        # 是裸词，于是 `"update runner " + configName`、`errors.New("[step1][update/escli]" + e)`
        # 全被报成 SQL 注入。现在要求关键字后必须是真正的 SQL 结构（update t set / select … from）。
        "pattern": (
            r"(?i)(?:\bselect\b[^\n;]{0,120}\bfrom\b"
            r"|\binsert\s+into\s+\w"
            r"|\bupdate\s+\w+\s+set\b"
            r"|\bdelete\s+from\s+\w"
            r")[^\n;]{0,150}?"
            r"(?:\+\s*[a-z_][\w\.\[\]]*|\$\{[^}]+\}|%s\"?\s*%|\.format\s*\(|\bf\"|\bf')"
        ),
        # 单测里的 `"mysql_sql": "select * from " + tablename` 是夹具数据
        "skip_tests": True,
        # 拼的是**表名/列名**（`"Select * From " + tableName`）：SQL 结构确实存在，
        # 但表名无法用占位符绑定，且通常来自内部配置而不是用户输入 ——
        # 保留这条线索（值得看一眼），但不该占 critical。
        "severity_downgrade": [
            r"(?i)\b(?:from|join|into|update)\s+[`\"']{1,2}\s*\+",
        ],
        "line_exclude": [
            # WMI 查询（WQL）走的是 QueryWmiByNamespace 这类接口，不是 SQL 注入。
            # 形如：QueryWmiByNamespace("\\root\\wmi", "Select * from XXX Where Name='"+v+"'")
            r"(?i)\bWmi\w*\s*\(|\bWQL\b|Win32_\w+|MSStorageDriver_\w+",
        ],
        "advice": "使用参数化查询（PreparedStatement / 占位符绑定），禁止拼接 SQL 字符串。",
    },
    {
        "id": "command-exec",
        "name": "命令执行危险调用",
        "severity": "critical",
        "category": "命令注入",
        "pattern": r"(Runtime\.getRuntime\(\)\.exec|ProcessBuilder\s*\(|os\.system\s*\(|os\.popen\s*\(|subprocess\.(run|call|Popen|check_output)\s*\([^)]*shell\s*=\s*True|child_process\.exec\s*\()",
        "line_exclude": [
            # 参数是「单个字符串字面量且没有任何插值」时是纯静态命令 ——
            # 打包/构建脚本里的 os.popen('go build -o app app.go') 不是命令注入。
            # 只要出现 f-string / % / + / { 拼接，就不满足这个形态，照旧报告。
            r"(?i)^[^\n]*\b(?:os\.(?:popen|system)|subprocess\.\w+"
            r"|child_process\.exec|Runtime\.getRuntime\(\)\.exec)"
            r"\s*\(\s*[rfbu]{0,2}[\"'][^\"'{}$%+]*[\"']\s*\)\s*;?\s*$",
        ],
        "advice": "避免拼接用户输入执行系统命令；如需执行，改用参数数组形式并做白名单校验。",
    },
    {
        "id": "deserialization",
        "name": "不安全的反序列化",
        "severity": "critical",
        "category": "反序列化",
        "pattern": r"(pickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*Loader)|ObjectInputStream|readObject\s*\(|JSON\.parse\s*\([^)]*reviver|unserialize\s*\(|Marshal\.load\s*\()",
        "advice": "不要反序列化不可信数据；改用 JSON 等安全格式，或强制使用 SafeLoader / 白名单类型。",
    },
    {
        "id": "expression-injection",
        "name": "表达式注入 (SpEL/OGNL)",
        "severity": "critical",
        "category": "表达式注入",
        # `Function\s*\(` 无边界，会把 Go 的 `NewExponentialDecayFunction()`、
        # Java 的 `xxxFunction(` 全报成动态代码执行。这里要求 Function 是独立标识符
        # （前面不能是字母/点），即 JS 的 `Function(...)` / `new Function(...)`。
        # `parseExpression(` 同理：olivere/elastic 的 URI 模板解析器里也有一个同名
        # 本地函数 `parseExpression(expression)`，与 SpEL/OGNL 毫无关系 —— 要求它
        # 必须带接收者（`parser.parseExpression(`），因为 SpEL 一定是在解析器实例上调用的。
        "pattern": (
            r"(SpelExpressionParser|ExpressionParser"
            r"|[A-Za-z_]\w*\.\s*parseExpression\s*\(|Ognl\.getValue"
            r"|ScriptEngine.*eval|eval\s*\("
            r"|(?<![\w.])Function\s*\(|setTimeout\s*\(\s*[\"'])"
        ),
        "line_exclude": [
            # 函数/方法**定义**不是调用：Go 的 `func parseExpression(...) {`、
            # Java 的 `public Object eval(String s) {` 只是声明，没有执行任何东西。
            r"^\s*(?:func|def|function|async\s+function|public|private|protected"
            r"|static|final|internal)\b[^\n]*\b(?:parseExpression|eval|Function)\s*\("
            r"[^\n]*[\{;:]\s*$",
        ],
        "advice": "禁止将用户输入作为表达式或脚本执行，改为枚举映射或规则引擎白名单。",
    },
    {
        "id": "xxe",
        "name": "XML 外部实体 (XXE)",
        "severity": "high",
        "category": "XXE",
        "pattern": r"(DocumentBuilderFactory\.newInstance|SAXParserFactory\.newInstance|XMLReaderFactory\.createXMLReader|xml\.etree|XMLParser\s*\(|libxml_disable_entity_loader)",
        "advice": "解析 XML 前禁用外部实体（disallow-doctype-decl、external-general-entities=false）。",
    },
    {
        "id": "path-traversal",
        "name": "路径穿越风险",
        "severity": "high",
        "category": "路径穿越",
        # 曾经的写法是 `\.\.[/\\][\w\.\-/\\]*`——「行内出现 ../ 就报」。这是错的：
        # 路径穿越的成立条件是「外部可控输入进入文件系统 API」，而不是「源码里有 ../」。
        # 相对路径在 TS/Node 工程里遍地都是（import '../environments/env'、tsconfig 的
        # extends、构建脚本的 mv ../、__dirname 拼接），实测在一个 Angular 仓库里
        # 刷出 805 条误报，占整份报告 90%，把真问题全淹了。
        # 现在只认「文件系统 API 调用 + 同行出现外部输入」，并排除校验/防护代码。
        "pattern": (
            r"(?i)(?:new\s+File\s*\(|\bPaths\.get\s*\("
            r"|Files\.(?:read|write|new|copy|move|delete|lines|create|exists)\w*\s*\("
            r"|\bFile(?:Input|Output)Stream\s*\(|\bFileReader\s*\(|\bRandomAccessFile\s*\("
            r"|os\.path\.join\s*\(|\bpath\.(?:join|resolve)\s*\("
            r"|\breadFile(?:Sync)?\s*\(|\bcreateReadStream\s*\("
            r"|\bsend_?file\s*\(|\bsendFile\s*\(|\bres\.download\s*\(|\bFileResponse\s*\("
            r"|\bZipFile\s*\(|(?<![\w.])open\s*\(|\bfopen\s*\(|\binclude\s*\()"
        ),
        "line_require": [
            # 同行必须出现「外部输入」——否则只是服务端自己的静态路径拼接（如 __dirname）。
            # ⚠️ 这里**刻意不接受** `query` / `param` / `params` / `body` / `filePath` 这类
            # 纯变量名当证据：Go 的 `func (q *Query) Open()`（类型名撞车）、
            # `ioutil.ReadFile(filePath)`（工具函数）都会因此整片误报。
            # 变量名不是污点来源，见本文件顶部「误报治理三原则」第 1 条。
            r"(?i)(?:request\.|req\.(?:query|params|body|url|path|headers)|"
            r"getParameter\s*\(|getOriginalFilename|@RequestParam|@PathVariable|@RequestBody|"
            r"MultipartFile|\bmultipart\b|"
            r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)|"
            r"\.query\b|\.params?\b|\.files?\b|"
            r"\bfile_?name\b|\bargv\b|\buser_?input\b|\buntrusted\b|"
            r"\.\./|\.\.\\\\|%2e|%2f)"
        ],
        "file_contains": EXTERNAL_INPUT_HINTS,
        # 单测里的 os.OpenFile(path.Join(tmpDir, fileName), ...) 是夹具
        "skip_tests": True,
        "line_exclude": [
            # 校验 / 防护 / 规范化代码是「防线」而不是「漏洞」：
            # path.contains("../")、indexOf("..")、replace("..","")、白名单判断
            r"(?i)(contains|indexOf|includes|startsWith|endsWith|replace(?:All)?|"
            r"sanitiz|normali[sz]e|isValid|validate|verify|whitelist|allowlist|denylist)",
            # 服务端自己的固定根目录拼接（path.join(__dirname, '../x')）是静态路径，
            # 攻击者不可控；Angular schematics / 构建脚本里满屏都是这种写法。
            r"(__dirname|__filename|process\.cwd\s*\(|import\.meta\.url)"
        ],
        # 只剩「文件 API + 同行外部输入」这一条线索，跨行数据流看不到，标 low
        "confidence": "low",
        "advice": "对文件路径做规范化校验，限定在允许的根目录内，拒绝包含 .. 的输入。",
    },
    {
        "id": "ssrf",
        "name": "SSRF 服务端请求伪造",
        "severity": "high",
        "category": "SSRF",
        # 旧写法把类名 `HttpClient` / `RestTemplate` / `okhttp` 直接当命中条件，
        # 于是 `log.info("[HttpClient] POST {} - headers: {}", url, ...)` 这类日志行
        # 也报 SSRF。现在只认「客户端真正发起请求」的调用形态，并排除日志语句。
        # 另注两条边界：
        #   · 刻意不收 `axios.` / `fetch(` —— 那是浏览器 API，前端发请求不构成 SSRF
        #     （Angular 的 `this.http.post('showcase/x', params)` 一次刷出 64 条误报）；
        #   · `https?.get(` 必须用 (?<![\w.]) 排除 `this.http.` 形态，只留 Go/Node
        #     里真正的 `http.Get(` / `https.get(`。
        "pattern": (
            r"(?i)(?:requests\.(?:get|post|put|head|request)\s*\("
            r"|urllib\.request\.urlopen\s*\(|\burlopen\s*\("
            r"|httpx\.(?:get|post|put|stream)\s*\("
            r"|(?:restTemplate|webClient|httpClient|okHttpClient)"
            r"\.(?:getForObject|getForEntity|postForObject|postForEntity|exchange|execute|send|newCall|get|post|put|delete)\s*\("
            r"|HttpRequest\.newBuilder\s*\(|\bHttpURLConnection\b"
            r"|(?<![\w.])https?\.(?:get|post|request)\s*\()"
        ),
        "line_require": [
            r"(?i)(request|req\.|params?|\bquery\b|\bbody\b|\binput\b|\burl\b|\buri\b|\btarget\b|callback|redirect|\bhost\b|\bdomain\b)"
        ],
        # 统一 HTTP 封装类（HttpClient.java）里 `postForObject(url, ...)` 的 url 是
        # **方法参数**，谁都能叫 url —— 这种命中一次刷 5 条，实测 repo3 的 15 条里 13 条
        # 来自不接触请求的封装类。文件级过滤：只有真的会收到外部输入的文件才评判。
        # （真正决定可达性的是调用方，封装类本身不是漏洞点。）
        "file_contains": EXTERNAL_INPUT_HINTS,
        "line_exclude": [
            # 日志/注释里的 URL 不是请求
            r"(?i)\.(?:info|warn|error|debug|trace)\s*\(|console\.(?:log|warn|error)\s*\(|System\.out\.print"
        ],
        "confidence": "low",
        "advice": "对外发请求前校验目标地址，禁止访问内网段与元数据地址，必要时走统一出口代理。",
    },
    {
        "id": "log-injection",
        "name": "日志注入 / 日志伪造",
        "severity": "medium",
        "category": "日志注入",
        # 只有「字符串拼接进日志」才是 CRLF 注入的经典形态；SLF4J 的
        # log.info("x={}", v) 占位符写法不算，否则每个过滤器都会中一条。
        "pattern": r"(log(ger)?\.(info|warn|error|debug|trace)|System\.out\.print(ln)?|console\.log|\bprint)\s*\([^)]*\+",
        "line_require": [
            r"(?i)(request|req\.|params?\b|input|user|header|token|uri|url|body|cookie|session|filename|message|\bmsg\b|content|data)"
        ],
        "advice": "记录日志前对用户输入做换行与转义处理，避免日志伪造与 CRLF 注入；尽量使用参数化占位符并过滤 \\r\\n。",
    },
    # ---------- Web 安全 ----------
    {
        "id": "xss-innerhtml",
        "name": "XSS 危险 DOM 写入",
        "severity": "high",
        "category": "XSS",
        "pattern": r"(innerHTML\s*=|outerHTML\s*=|document\.write\s*\(|v-html|dangerouslySetInnerHTML|\.html\s*\(\s*[a-z_])",
        # 单元测试里的 document.write('<div>Hello</div>') 是构造测试夹具，不是漏洞
        "skip_tests": True,
        "advice": "避免直接把不可信内容写入 DOM，使用 textContent 或前端框架的转义插值。",
    },
    {
        "id": "sql-mybatis-dollar-xml",
        "name": "MyBatis mapper 中 ${} 拼接",
        "severity": "high",
        "category": "SQL 注入",
        # 只认真正的 MyBatis mapper XML：pom.xml、Spring 配置里的 ${} 是配置
        # 占位符不是 SQL 注入，必须靠 DTD 或 <mapper namespace= 区分开。
        "file_patterns": [r"(?i)\.xml$"],
        "file_contains": [r"(?i)mybatis-3-mapper\.dtd", r"<mapper\s+namespace\s*="],
        "pattern": r"\$\{[^}]+\}",
        "advice": "MyBatis 中 ${} 是字符串直接拼接，请改用 #{} 预编译占位符；排序字段、表名等确实需要动态拼接的场景必须做白名单校验。",
    },
    {
        "id": "sql-mybatis-dollar-annotation",
        "name": "MyBatis 注解 SQL 中 ${} 拼接",
        "severity": "high",
        "category": "SQL 注入",
        # Java 里的 ${} 绝大多数是 @Value("${...}") 配置注入，只有出现在
        # @Select/@Update 这类注解 SQL 里才有风险，所以逐行排除配置注解。
        "file_patterns": [r"(?i)\.java$"],
        "file_contains": [r"@(Select|Update|Insert|Delete)\s*\("],
        "line_exclude": [
            r"@(Value|ConfigurationProperties|PropertySource|ConditionalOnProperty|Scheduled|KafkaListener|RabbitListener|FeignClient|RequestMapping|GetMapping|PostMapping|RequestParam|PathVariable|Qualifier|Cacheable|Transactional|EventListener)\b"
        ],
        "pattern": r"\$\{[^}]+\}",
        "advice": "注解 SQL 中的 ${} 同样是字符串直接拼接，请改用 #{} 预编译占位符。",
    },
    {
        "id": "cors-wildcard",
        "name": "CORS 通配放开",
        "severity": "medium",
        "category": "不安全配置",
        "pattern": r"(?i)(allow_?origin(s)?\s*[:=]\s*[\"']\*|Access-Control-Allow-Origin[\"']?\s*[:=]\s*[\"']\*|cors\(\s*\{\s*origin\s*:\s*\*|addAllowedOrigin\s*\(\s*[\"']\*)",
        "advice": "跨域来源应使用白名单，并配合凭证校验，避免 * 与 allowCredentials 同时出现。",
    },
    {
        "id": "debug-enabled",
        "name": "调试模式开启",
        "severity": "medium",
        "category": "不安全配置",
        "pattern": r"(?i)(debug\s*[:=]\s*(true|1|True)|DEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True)",
        "line_exclude": [
            # URL 查询串里的 debug=1 是 pprof / 调试链接的参数，不是「应用 debug 模式开启」：
            #   link := &url.URL{Path: profile.Href, RawQuery: "debug=1"}
            r"(?i)(RawQuery|url\.Values|QueryParam|query_?string|\.Query\s*\(\s*\)"
            r"|[?&][^\s\"']*debug=)",
        ],
        "confidence": "low",
        "advice": "生产环境必须关闭 debug，否则会暴露堆栈与源码。",
    },
    {
        "id": "weak-crypto",
        "name": "弱加密算法",
        "severity": "medium",
        "category": "加密安全",
        # 旧写法 `\b(md5|sha1|des|rc4|ecb)\b` 只要出现这几个词就报，于是把
        # 「import "crypto/des"」「SnmpReaderAuthProtocolMd5 = "MD5"」
        # 「下拉选项 []interface{}{"SHA1", "SHA256", …}」全报成弱加密 ——
        # 导入一个包、声明一个协议名常量，都不等于代码真的在用弱算法。
        # 现在只认三种「真的在用」的形态：
        #   ① 以包/构造/方法形态调用：md5.Sum( / hashlib.md5( / des.NewCipher( / new DES(
        #   ② 在加解密 API 的参数里指名算法：getInstance("MD5") / createHash('md5')
        #   ③ 显式 ECB 模式：Mode.ECB / MODE_ECB（AES-ECB 本身就是弱用法）
        # 刻意保留的反面：`"crypto/des"` 这类**整行就是一个字符串/import 路径**的
        # 写法自然落选，因为它后面既没有 `.` 也没有 `(`。
        # 另一处刻意的取舍：`\bmd5\s*[.(]` 后面**不**允许再接字母数字 —— 否则
        # `md5util.GetMd5(groupKey)`（项目自封装的哈希工具，用来算分组 key）
        # 会整片命中，而那不是「在用弱算法做安全计算」。
        "pattern": (
            r"(?i)(?:\b(?:md5|sha-?1)\s*[.(]"
            r"|\b(?:rc4|des)\s*[.(]"
            r"|(?:getInstance|createHash|createHmac|createCipher\w*|NewCipher|NewHash|hashlib\.new)"
            r"\s*\([^)\n]*\b(?:md5|sha-?1|des|rc4|ecb)\b"
            r"|\.(?:MODE_)?ECB\b|\bMODE_ECB\b)"
        ),
        "line_exclude": [
            # `ssl_ciphers HIGH:!aNULL:!MD5:!DES` 是**禁用**弱算法（! 前缀），属于正确配置；
            # 带 - 前缀的 openssl 写法同理（-SHA1 表示关闭）。
            r"(?i)[!\-]\s*(md5|sha1|des|rc4|ecb)\b"
        ],
        "advice": "MD5/SHA1/DES/ECB 已不安全，请改用 SHA-256 以上或 AES-GCM 等强算法。",
    },
    {
        "id": "insecure-random",
        "name": "不安全随机数",
        "severity": "medium",
        "category": "加密安全",
        "pattern": r"(Math\.random\s*\(\)|random\.randint\s*\(|new\s+Random\s*\(|\bjava\.util\.Random\b|\brand\s*\(\)|\bmt_rand\s*\()",
        # 只有「随机数用于安全语义」才成立：令牌 / 会话 / 密码 / 验证码 / 主键。
        # UI 里的 `Math.random() < 0.5 ? -1 : 1`（随机排序、随机演示数据）不是漏洞。
        "line_require": [
            r"(?i)(token|session|secret|salt|nonce|password|passwd|otp|captcha|verif|auth|csrf"
            r"|primarykey|primary_key|uuid|guid|serial|order_?id|account|唯一|标识|编号)"
        ],
        "skip_tests": True,
        "advice": "涉及令牌、验证码、密钥时请使用密码学安全随机源（SecureRandom / secrets / crypto）。",
    },
    # ---------- 文件相关 ----------
    {
        "id": "file-upload-unsafe",
        "name": "文件上传缺少校验",
        "severity": "high",
        "category": "文件上传",
        "pattern": r"(MultipartFile|multipart/form-data|request\.files|formidable|multer\s*\()[^\n]{0,80}",
        "advice": "上传需校验扩展名/内容类型/大小，落盘使用随机文件名并存放于非 Web 根目录。",
    },
    {
        "id": "file-download-path",
        "name": "文件下载路径可控",
        "severity": "high",
        "category": "文件下载",
        # 旧写法的第二段 `(filename|path|file|name)` 没有词边界，于是
        # `d.name,`、`fname,`、`readFileNum` 全算命中，日志行一报一大片。
        # 现在三处收紧：
        #   · 第一段必须是**调用形态**（`download(`/`res.download(`/`readFile(`），
        #     否则 URL 串里的 "downloadUrl"、`-download-test` 也会中；
        #   · `readFile` 刻意**区分大小写**（Node 的 fs.readFile 才是下载/读取入口），
        #     否则 Go 的 `os.ReadFile(filePath)` / `ioutil.ReadFile(fileName)` 会整片误报
        #     —— 那是读文件，不是「下载路径可控」；
        #   · 第二段分两支：复合名 filename/file_path… 允许前面有点
        #     （req.query.filename），短名 name/path/file 要求前面不是「词字符或点」
        #     （排除 d.name / readFileNum）。
        "pattern": (
            r"(?:readFile\s*\(|(?<!\w)[Dd]ownload\s*\(|send_?[Ff]ile\s*\(|res\.download\s*\("
            r"|FileInputStream\s*\()"
            r"[^\n]{0,80}?(?:"
            r"(?<!\w)(?:filename|file_?name|file_?path|filepath|save_?path|target_?path)\b"
            r"|(?<![\w.])(?:name|path|file)\b"
            r")\s*[\"']?\s*[=,\)]"
        ),
        "line_exclude": [
            r"(?i)\b(?:log|logger|logging|console|print|printf|slog|fmt)\s*[.\(]",
        ],
        "skip_tests": True,
        "confidence": "low",
        "advice": "下载文件名与路径必须做白名单映射，禁止由用户直接指定磁盘路径。",
    },
    {
        "id": "sensitive-data-expose",
        "name": "敏感信息输出",
        "severity": "medium",
        "category": "敏感数据暴露",
        # 必须带词边界：旧写法 `mobile|phone` 会命中 `mobilephone:`、`telephone:`
        # 这类字段名（甚至是注释里的字段说明），把正常表单配置报成敏感数据泄漏。
        # 右侧再加负向断言：赋字面量（`telephone: '11111111111'`、`MOBILE = 'mobile'`）
        # 是常量/测试夹具，不是「把敏感数据返回出去」。
        # 键名可能带引号（JSON/字典：`"mobile": user.mobile`），所以 `[:=]` 前允许一个收尾引号。
        "pattern": r"(?i)\b(idcard|id_card|id_no|identity_?card|身份证|银行卡|bank_?card|credit_?card|mobile|telephone|phone_?number|card_?number)\b['\"]?\s*[:=]\s*(?!['\"]|\d)\S",
        "line_exclude": [
            # 表单读值、属性比较、case 分支标签都不是「对外输出敏感字段」
            r"(?i)^\s*case\s+['\"]|hasOwnProperty|===|!==|\.get\s*\(",
            # 全大写的 key 是常量/枚举定义（ua-parser 的 `MOBILE : MOBILE`），不是数据输出
            r"^\s*[A-Z][A-Z_]{2,}\s*:"
        ],
        "skip_tests": True,
        "advice": "敏感字段返回前端前需脱敏（掩码），并限制访问权限。",
    },
    # ---------- Java 特有 ----------
    {
        "id": "unsafe-reflection",
        "name": "反射调用风险",
        "severity": "medium",
        "category": "不安全反射",
        "pattern": r"(Class\.forName\s*\(|getDeclaredMethod\s*\(|getDeclaredField\s*\(|getDeclaredConstructor\s*\(|Method\.invoke\s*\(|\.invoke\s*\(|URLClassLoader|defineClass\s*\(|getMethod\s*\(\s*[\"'])",
        "advice": "反射加载的类名/方法名不可来自用户输入，需做白名单校验。",
    },
]

# 这四条规则要连注释一起扫：注释里残留的密码同样是泄漏。
# 其余规则默认跳过「整行都是注释」的行 —— `// request.getMethod()` 这类被注释掉
# 的代码报出来只会稀释报告，把真正要看的问题淹掉。
SCAN_COMMENT_RULES = {
    "hardcoded-password",
    "private-key-block",
    "cloud-access-key",
    "jdbc-credential",
}

_COMMENT_RE = re.compile(r"^\s*(//|#(?!!)|/\*|\*|<!--|--)")

# 测试代码路径。标了 skip_tests 的规则会跳过这些文件——测试里的
# `document.write('<div>Hello</div>')`、`telephone: '11111111111'` 是夹具数据，
# 不是漏洞。凭证类规则刻意**不**跳过：测试里硬编码真实密钥恰恰是常见事故。
_TEST_PATH_RE = re.compile(
    r"(?i)(?:^|/)(?:tests?|__tests__|testing|specs?|__mocks__|mocks?|fixtures?|e2e)(?:/|$)"
    r"|\.(?:spec|test)\.[a-z0-9]+$"
    # Angular 老版本用 `xxx_spec.ts` 而不是 `xxx.spec.ts`，两种都要认
    r"|_spec\.[a-z0-9]+$"
    r"|_test\.(?:go|py|rb|js|ts)$"
    r"|(?:^|/)test_[^/]+\.py$"
)


def _compile_all() -> list[dict]:
    """编译全部规则（含上下文约束）；单条写错不影响整体启动。

    可选的上下文约束字段：
    - file_patterns：路径匹配才生效（如只对 .xml / .java）
    - file_exclude_patterns：路径命中任一条就整条规则不参与本文件
    - file_contains：整个文件含该特征才生效（如真是 MyBatis mapper 才跑 ${} 规则、
      或见 EXTERNAL_INPUT_HINTS「这个文件接不接外部输入」）
    - line_require：本行还要再命中其中之一
    - line_exclude：本行命中任何一条就放过
    - severity_downgrade：本行命中任何一条就把严重度**降一级**（critical→high→medium），
      置信度同时降一级。用于「形态是真的、但危险性明显更低」的子类，
      比如拼接的是表名而不是查询条件 —— 保留线索，但明确标成「需要确认的线索」
    - context_require：把「本行 + 下一行」拼成窗口再匹配 —— 给 PEM 私钥块这种
      「标记在上一行、正文在下一行」的跨行结构用，行级规则的正则表达不了
    - skip_tests：跳过测试文件（见 _TEST_PATH_RE）
    - confidence：本条命中的可信度（high/medium/low），缺省 medium。写进报告，
      让人知道哪些是「直接证据」、哪些只是「值得看一眼的线索」
    """
    compiled: list[dict] = []
    for rule in RULES:
        try:
            compiled.append({
                "rule": rule,
                "pattern": re.compile(rule["pattern"]),
                "file_patterns": [re.compile(p) for p in rule.get("file_patterns", [])],
                "file_exclude": [re.compile(p) for p in rule.get("file_exclude_patterns", [])],
                "file_contains": [re.compile(p, re.MULTILINE) for p in rule.get("file_contains", [])],
                "line_require": [re.compile(p) for p in rule.get("line_require", [])],
                "line_exclude": [re.compile(p) for p in rule.get("line_exclude", [])],
                "severity_downgrade": [re.compile(p) for p in rule.get("severity_downgrade", [])],
                "context_require": [re.compile(p) for p in rule.get("context_require", [])],
                "skip_tests": bool(rule.get("skip_tests")),
            })
        except re.error as exc:  # 规则写错时跳过，并在启动日志里暴露
            print(f"[rules] 规则 {rule['id']} 正则编译失败，已跳过：{exc}")
    return compiled


_COMPILED = _compile_all()


def _any_match(patterns: list[re.Pattern], text: str) -> bool:
    return any(p.search(text) for p in patterns)


# 参与扫描的源码后缀
CODE_EXTS = {
    ".java", ".kt", ".scala", ".py", ".js", ".jsx", ".ts", ".tsx", ".vue",
    ".go", ".rs", ".c", ".cpp", ".h", ".hpp", ".cs", ".php", ".rb", ".swift",
    ".sql", ".sh", ".bash", ".zsh", ".yml", ".yaml", ".xml", ".properties",
    ".ini", ".conf", ".toml", ".json", ".jsp", ".ftl", ".html", ".htm",
    ".gradle", ".tf", ".env", ".pem", ".key",
}

SKIP_DIRS = {
    ".git", "node_modules", "dist", "build", "target", "out", ".venv", "venv",
    "__pycache__", ".idea", ".vscode", ".next", ".nuxt", "vendor", "coverage",
    ".pytest_cache", ".mypy_cache", "logs", "log", ".gradle", "bin", "obj",
}

MAX_FILE_BYTES = 512 * 1024

MAX_LINE_LEN = 400


def scan_text(path: str, text: str, rule_ids: set[str] | None = None) -> list[dict]:
    """对单段文本跑规则，返回命中列表。

    rule_ids=None 跑全部；传空集合则一条都不跑（调用方明确说「没有参与扫描的
    规则」时不能被当成「跑全部」）。
    """
    findings: list[dict] = []
    lines = text.splitlines()
    for item in _COMPILED:
        rule = item["rule"]
        if rule_ids is not None and rule["id"] not in rule_ids:
            continue
        # 文件级上下文：路径不符 / 命中排除项 / 是测试文件 / 文件里没有该特征，
        # 整条规则都不参与本文件
        if item["file_patterns"] and not _any_match(item["file_patterns"], path):
            continue
        if item["file_exclude"] and _any_match(item["file_exclude"], path):
            continue
        if item["skip_tests"] and _TEST_PATH_RE.search(path):
            continue
        if item["file_contains"] and not _any_match(item["file_contains"], text):
            continue
        scan_comments = rule["id"] in SCAN_COMMENT_RULES
        for idx, line in enumerate(lines, start=1):
            s = line.strip()
            if not s or len(s) > MAX_LINE_LEN:
                continue
            if not scan_comments and _COMMENT_RE.match(s):
                continue
            if item["line_exclude"] and _any_match(item["line_exclude"], s):
                continue
            if item["line_require"] and not _any_match(item["line_require"], s):
                continue
            # 跨行窗口：本行 + 下一行（给 PEM 私钥块这类「标记与正文分行」的结构用）
            if item["context_require"]:
                nxt = lines[idx].strip() if idx < len(lines) else ""
                if not _any_match(item["context_require"], s + "\n" + nxt):
                    continue
            m = item["pattern"].search(s)
            if not m:
                continue
            severity = rule["severity"]
            confidence = rule.get("confidence", "medium")
            if item["severity_downgrade"] and _any_match(item["severity_downgrade"], s):
                # 降级连带置信度一起降：既然判定它危险性更低，就不该再标成中置信。
                # 报告里一眼能看出「这条只是线索，不是结论」。
                severity = _DOWNGRADE.get(severity, severity)
                confidence = _DOWNGRADE.get(confidence, confidence)
            findings.append({
                "rule_id": rule["id"],
                "title": rule["name"],
                "severity": severity,
                "category": rule["category"],
                "file": path,
                "line": idx,
                "snippet": s[:240],
                "advice": rule["advice"],
                "source": "rule",
                "confidence": confidence,
                "matched": m.group(0)[:120],
            })
    return findings
