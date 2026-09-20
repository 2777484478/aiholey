"""内置安全审计技能库。

技能名与参考系统（代码审计服务器）保持一致，便于对照。提示词里使用占位符，
运行时由引擎替换：
    ${scanPath}        本次扫描的代码根目录（已拉取到本地）
    ${reportPath}      本次运行的报告输出根目录
    ${skillName}       当前技能名
    ${scanReportPath}  复扫场景下的「上一份报告」路径
    ${projectProfile}  项目适配画像（JSON 字符串），由第一阶段分析产出
"""
from __future__ import annotations

# 六步扫描总纲 + 两次运行时调用各技能都要求先做技术栈识别，
# 这是参考系统提示词里的固定结构，此处保持一致的措辞。
_TEMPLATE = (
    "使用 security-scan-base 和 ${skillName} 对 ${scanPath} 执行标准六步安全扫描。"
    "先识别技术栈，再进行 __TOPIC__ 漏洞审计，做完攻击路径确认后再生成报告。"
    "扫描时忽略 ${scanPath}/.git/ 以及 ${scanPath}/.gitignore 下列出的文件。"
    "把结果放在 ${reportPath}/${skillName}/report/ 中；"
    "将原本生成在 ${scanPath}/.security-scan/ 下的中间文件改放到 ${reportPath}/${skillName}/log/，"
    "${scanPath}/.security-scan/ 下不要再产生文件。不要用 subagent。"
    "注意：skill 报告要放在对应的 ${skillName} 文件夹下，不要放错。"
    "其中 scanPath、reportPath 和 skillName 会由系统自动替换。"
)

# (技能名, 中文说明, 审计主题, 分类)
_CATALOG: list[tuple[str, str, str | None, str]] = [
    ("project-adapt", "项目适配分析（技术栈识别 + 审计规则增强）", None, "流程"),
    ("security-scan-base", "标准六步安全扫描总纲", None, "流程"),
    ("summarize_report", "扫描结果汇总（生成总报告 + 误报排除）", None, "流程"),
    ("credential-exposure-scanner", "凭证泄漏（硬编码密钥/口令/Token）", "凭证泄漏（硬编码密钥、口令、Token、认证头）", "敏感信息"),
    ("sensitive-data-exposure-scanner", "敏感数据暴露", "敏感数据暴露（返回体、日志、配置、构建产物）", "敏感信息"),
    ("sql-injection-scanner", "SQL 注入", "SQL 注入", "注入类"),
    ("os-command-injection-scanner", "OS 命令注入", "OS 命令注入 / 命令拼接执行", "注入类"),
    ("expression-injection-scanner", "表达式注入 (SpEL/OGNL/Aviator)", "表达式注入 (SpEL/OGNL/Aviator)", "注入类"),
    ("jndi-injection-scanner", "JNDI 注入", "JNDI 注入", "注入类"),
    ("ldap-injection-scanner", "LDAP 注入", "LDAP 注入", "注入类"),
    ("nosql-injection-scanner", "NoSQL 注入", "NoSQL 注入", "注入类"),
    ("ssti-scanner", "服务端模板注入 SSTI", "服务端模板注入 (SSTI)", "注入类"),
    ("log-injection-crlf-scanner", "日志注入 (CRLF)", "日志注入（CRLF 换行注入、伪造日志条目）", "注入类"),
    ("xss-reflected-scanner", "反射型 XSS", "反射型跨站脚本 (XSS)", "前端安全"),
    ("xss-stored-scanner", "存储型 XSS", "存储型跨站脚本 (XSS)", "前端安全"),
    ("ssrf-scanner", "SSRF 服务端请求伪造", "SSRF 服务端请求伪造", "请求伪造"),
    ("xxe-scanner", "XXE 外部实体注入", "XXE XML 外部实体注入", "注入类"),
    ("path-traversal-scanner", "路径穿越 / 任意文件读取", "路径穿越与任意文件读取", "文件相关"),
    ("insecure-file-upload-scanner", "不安全文件上传", "不安全文件上传", "文件相关"),
    ("insecure-file-download-scanner", "不安全文件下载", "不安全文件下载", "文件相关"),
    ("idor-scanner", "IDOR 越权访问", "IDOR 越权访问（对象级授权缺失）", "访问控制"),
    ("unauth-api-scanner", "未授权接口访问", "未授权 API 访问 / 鉴权缺失", "访问控制"),
    ("insecure-configuration-scanner", "不安全配置", "不安全配置（调试开关、默认口令、危险中间件配置）", "配置类"),
    ("fastjson-deserialization-scanner", "反序列化 (FastJSON)", "反序列化 (FastJSON)", "反序列化"),
    ("gson-deserialization-scanner", "反序列化 (Gson)", "反序列化 (Gson)", "反序列化"),
    ("lombok-deserialization-scanner", "反序列化 (Lombok)", "反序列化 (Lombok)", "反序列化"),
    ("java-deserialization-scanner", "反序列化 (Java 原生)", "Java 原生反序列化", "反序列化"),
    ("orgjson-deserialization-scanner", "反序列化 (org.json)", "反序列化 (org.json)", "反序列化"),
    ("mongodb-deserialization-scanner", "反序列化 (MongoDB)", "反序列化 (MongoDB)", "反序列化"),
]

_PROJECT_ADAPT_PROMPT = (
    "对 ${scanPath} 执行**项目适配分析**，为后续各专项扫描技能提供增强上下文。"
    "先识别技术栈（语言、框架及版本、构建工具、安全机制、模块划分），"
    "再归纳本项目特有的审计适配规则：框架特定的常量/依赖注入追踪路径、"
    "安全相关的代码模式（正则）、需要跨服务追踪的引用。"
    "最后给出扫描增强参数（文件编码、方法体分析深度、前置注释行数）。"
    "只输出 JSON，不要解释文字。结构：\n"
    '{"project_name":"","tech_stack":{"language":"","framework":"","framework_version":"",'
    '"security_mechanism":"","build_tool":"","modules":[]},'
    '"adaptations":[{"id":"adapt-001","type":"framework_specific|security_pattern","name":"",'
    '"description":"","script_ref":null,"applies_to":[]}],'
    '"project_patterns":[{"name":"","description":"","file_pattern":"","code_pattern":"","applies_to":[]}],'
    '"scan_enhancements":{"encoding":["UTF-8"],"method_body_depth":3,"preceding_comment_lines":10,"impl_lookup":true}}'
)

_SUMMARY_PROMPT = (
    "汇总本次多技能扫描的结果：读取 ${reportPath} 下各技能产出的报告，"
    "按技能维度统计漏洞数量与等级分布，合并重复项，"
    "核对每条漏洞的攻击路径可达性，剔除误报并单列「已排除的误报」附录，"
    "最终生成一份汇总审计报告到 ${reportPath}/summary/report/。"
)


def _prompt(name: str, topic: str | None) -> str:
    if name == "project-adapt":
        return _PROJECT_ADAPT_PROMPT
    if name == "summarize_report":
        return _SUMMARY_PROMPT
    if name == "security-scan-base":
        return (
            "对 ${scanPath} 执行标准六步安全扫描：1) 识别技术栈与框架版本；2) 枚举入口点与数据流；"
            "3) 逐项匹配漏洞模式；4) 攻击路径可达性确认；5) 排除误报；6) 生成报告。"
            "扫描时忽略 ${scanPath}/.git/ 以及 ${scanPath}/.gitignore 下列出的文件。"
            "报告输出到 ${reportPath}/${skillName}/report/，中间文件放到 ${reportPath}/${skillName}/log/。"
        )
    return _TEMPLATE.replace("__TOPIC__", topic or "通用")


def SEED_SKILLS() -> list[dict]:
    out = []
    for i, (name, desc, topic, category) in enumerate(_CATALOG, start=1):
        out.append({
            "name": name,
            "description": desc,
            "prompt": _prompt(name, topic),
            "category": category,
            "builtin": 1,
            "enabled": 1 if name not in ("project-adapt", "summarize_report") else 1,
            "sort_order": i * 10,
        })
    return out


# 流程型技能：不作为「检测项」在报告里统计
FLOW_SKILLS = {"project-adapt", "security-scan-base", "summarize_report"}

# 默认参与扫描的检测技能（覆盖高频风险，避免一次跑满 26 项）
DEFAULT_SKILL_SET = [
    "credential-exposure-scanner",
    "sql-injection-scanner",
    "os-command-injection-scanner",
    "expression-injection-scanner",
    "path-traversal-scanner",
    "ssrf-scanner",
    "xxe-scanner",
    "unauth-api-scanner",
    "sensitive-data-exposure-scanner",
    "insecure-configuration-scanner",
    "xss-reflected-scanner",
    "java-deserialization-scanner",
]
