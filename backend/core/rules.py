"""内置规则引擎。

两个用途：
1. 未配置 LLM API Key 时，作为兜底扫描器，保证系统开箱即用；
2. 配置了 LLM 时，先用规则做一轮快速预筛，把命中片段作为上下文喂给模型，
   减少 token 消耗、提高命中率。

正则规则最大的敌人是误报：一条 `\\$\\{[^}]*\\}` 就能把 pom.xml 的 `${version}`、
Spring 的 `@Value("${x}")` 全报成 SQL 注入。所以规则支持四个可选的上下文约束
字段（file_patterns / file_contains / line_require / line_exclude），并在默认
情况下跳过「整行注释」（凭证类规则例外，见 SCAN_COMMENT_RULES）。
"""
from __future__ import annotations

import re

SEVERITY_ORDER = ["critical", "high", "medium", "low"]

# severity: critical / high / medium / low
RULES: list[dict] = [
    # ---------- 凭证泄漏 ----------
    {
        "id": "hardcoded-password",
        "name": "硬编码密码",
        "severity": "high",
        "category": "凭证泄漏",
        "pattern": r"(?i)\b(password|passwd|pwd|secret|token|apikey|api_key|access_key)\b\s*[:=]\s*[\"'][^\"'\s]{6,}[\"']",
        "advice": "凭证不应硬编码在源码中，请改用环境变量或密钥管理服务，并立即轮换已泄漏的凭据。",
    },
    {
        "id": "private-key-block",
        "name": "私钥文件内容",
        "severity": "critical",
        "category": "凭证泄漏",
        "pattern": r"-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
        "advice": "私钥绝不可入库，请从代码库移除、轮换密钥，并通过配置文件注入。",
    },
    {
        "id": "cloud-access-key",
        "name": "云厂商 AccessKey",
        "severity": "critical",
        "category": "凭证泄漏",
        "pattern": r"\b(AKIA[0-9A-Z]{16}|LTAI[0-9A-Za-z]{12,})\b",
        "advice": "疑似云平台长期密钥泄漏，请立即在控制台禁用并轮换，改用 RAM 角色/STS 临时凭证。",
    },
    {
        "id": "jdbc-credential",
        "name": "数据库连接串内嵌凭证",
        "severity": "high",
        "category": "凭证泄漏",
        "pattern": r"(?i)jdbc:[a-z0-9]+://[^\s\"']*[:@][^\s\"']*[:@][^\s\"']+",
        "advice": "连接串中不要内嵌账号密码，请外置到配置中心并加密存储。",
    },
    # ---------- 注入 ----------
    {
        "id": "sql-string-concat",
        "name": "SQL 语句字符串拼接",
        "severity": "critical",
        "category": "SQL 注入",
        "pattern": r"(?i)(select|insert\s+into|update|delete\s+from)\b[^\n;]{0,80}(\+\s*[a-z_][\w\.\[\]\"']*|\$\{[^}]+\}|%s\"?\s*%|\.format\()",
        "advice": "使用参数化查询（PreparedStatement / 占位符绑定），禁止拼接 SQL 字符串。",
    },
    {
        "id": "command-exec",
        "name": "命令执行危险调用",
        "severity": "critical",
        "category": "命令注入",
        "pattern": r"(Runtime\.getRuntime\(\)\.exec|ProcessBuilder\s*\(|os\.system\s*\(|os\.popen\s*\(|subprocess\.(run|call|Popen|check_output)\s*\([^)]*shell\s*=\s*True|child_process\.exec\s*\()",
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
        "pattern": r"(SpelExpressionParser|ExpressionParser|parseExpression\s*\(|Ognl\.getValue|ScriptEngine.*eval|eval\s*\(|Function\s*\(|setTimeout\s*\(\s*[\"'])",
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
        "pattern": r"(?i)\.\.[/\\][\w\.\-/\\]*|new\s+File\s*\(\s*[a-z_][\w\.]*\s*\+|os\.path\.join\s*\([^)]*(request|param|input|user|filename)",
        "advice": "对文件路径做规范化校验，限定在允许的根目录内，拒绝包含 .. 的输入。",
    },
    {
        "id": "ssrf",
        "name": "SSRF 服务端请求伪造",
        "severity": "high",
        "category": "SSRF",
        "pattern": r"(requests\.(get|post|put)\s*\(|urllib\.request\.urlopen\s*\(|HttpClient|RestTemplate|okhttp|axios\.(get|post)\s*\(|fetch\s*\()[^)]*(request|param|url|uri|target|callback|redirect)",
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
        "advice": "生产环境必须关闭 debug，否则会暴露堆栈与源码。",
    },
    {
        "id": "weak-crypto",
        "name": "弱加密算法",
        "severity": "medium",
        "category": "加密安全",
        "pattern": r"(?i)\b(md5|sha1|des|rc4|ecb)\b",
        "advice": "MD5/SHA1/DES/ECB 已不安全，请改用 SHA-256 以上或 AES-GCM 等强算法。",
    },
    {
        "id": "insecure-random",
        "name": "不安全随机数",
        "severity": "medium",
        "category": "加密安全",
        "pattern": r"(Math\.random\s*\(\)|random\.randint|new\s+Random\s*\(|\bjava\.util\.Random\b)",
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
        "pattern": r"(download|readFile|FileInputStream|send_file|sendFile|res\.download)[^\n]{0,80}(filename|path|file|name)\s*[=,\)]",
        "advice": "下载文件名与路径必须做白名单映射，禁止由用户直接指定磁盘路径。",
    },
    {
        "id": "sensitive-data-expose",
        "name": "敏感信息输出",
        "severity": "medium",
        "category": "敏感数据暴露",
        "pattern": r"(?i)(idcard|id_card|身份证|银行卡|bankcard|mobile|phone)\s*[:=]\s*",
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


def _compile_all() -> list[dict]:
    """编译全部规则（含上下文约束）；单条写错不影响整体启动。

    可选的上下文约束字段：
    - file_patterns：路径匹配才生效（如只对 .xml / .java）
    - file_contains：整个文件含该特征才生效（如真是 MyBatis mapper 才跑 ${} 规则）
    - line_require：本行还要再命中其中之一
    - line_exclude：本行命中任何一条就放过
    """
    compiled: list[dict] = []
    for rule in RULES:
        try:
            compiled.append({
                "rule": rule,
                "pattern": re.compile(rule["pattern"]),
                "file_patterns": [re.compile(p) for p in rule.get("file_patterns", [])],
                "file_contains": [re.compile(p, re.MULTILINE) for p in rule.get("file_contains", [])],
                "line_require": [re.compile(p) for p in rule.get("line_require", [])],
                "line_exclude": [re.compile(p) for p in rule.get("line_exclude", [])],
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
        # 文件级上下文：路径不符 / 文件里没有该特征，整条规则不参与本文件
        if item["file_patterns"] and not _any_match(item["file_patterns"], path):
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
            m = item["pattern"].search(s)
            if not m:
                continue
            findings.append({
                "rule_id": rule["id"],
                "title": rule["name"],
                "severity": rule["severity"],
                "category": rule["category"],
                "file": path,
                "line": idx,
                "snippet": s[:240],
                "advice": rule["advice"],
                "source": "rule",
                "matched": m.group(0)[:120],
            })
    return findings
