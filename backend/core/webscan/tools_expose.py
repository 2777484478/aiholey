"""Web 扫描暴露面与攻击面工具集（二）—— 组件漏洞 / 文件包含 / 认证攻击面 / API 审计 / WAF 识别。

这一组回答的问题不是「这个页面有没有洞」，而是
**「这台机器上跑着什么、它的哪些面是敞开的、我的扫描结论有多可信」**：

- 组件版本 → 已知 CVE：把「用了 jQuery 1.8」变成「可用 CVE-2020-11022 打」
- 文件包含：`php://filter` / `data://` / `expect://` 这一层包装器无法被
  「目录遍历」覆盖，必须单独测
- 认证攻击面：用户枚举、Basic Auth 明文传输、速率限制缺失
- API 审计：GraphQL introspection、OpenAPI 文档、端点的 HTTP 方法面
- WAF 识别：**这一项决定前面所有「未发现」结论的可信度**

安全边界
--------
全部只读或近似只读：
- 只发 GET / HEAD / OPTIONS，以及**不带真实凭据**的登录失败探测（用于用户枚举）；
- 弱口令尝试默认**关闭**（`weak_creds=False`）——它与注入探测有本质区别：
  失败的口令尝试可能触发账号锁定，从而影响真实用户，属于有副作用的动作；
- 文件包含载荷只用于触发内容回显或报错，不做写入。
"""
from __future__ import annotations

import base64
import json
import re
from urllib.parse import parse_qsl, quote, urlparse

from backend.core.webscan.tools import (
    BudgetExceeded,
    DISCOVERED_LANDING_CAP,
    FallbackBaseline,
    ScanSession,
    _issue,
    _snippet,
    origin_of,
    soft404_note,
    tool,
    uniq,
)
from backend.core.webscan.tools_vuln import (
    _iter_scripts,
    _looks_blocked,
    _page_text,
    _raw_query_with,
    _same_origin_params,
)

# ============================================================ 组件版本 → 已知漏洞


def _ver(s: str) -> tuple:
    """把版本串变成可比较的元组；段数不足补零，避免 `1.2` 与 `1.2.0` 比不出结果。"""
    nums = re.findall(r"\d+", s or "")[:4]
    return tuple(int(x) for x in nums) + (0,) * (4 - len(nums))


def _in_range(v: str, lo: str, hi: str) -> bool:
    try:
        return _ver(lo) <= _ver(v) < _ver(hi)
    except Exception:
        return False


# 服务端产品：从 Server / X-Powered-By / Via 等响应头里抠产品名与版本
_BANNER_RE = re.compile(
    r"(?i)\b(nginx|openresty|apache|httpd|tomcat|catalina|jetty|iis|lighttpd|"
    r"gunicorn|uvicorn|werkzeug|kestrel|undertow|wildfly|jboss|weblogic|websphere|"
    r"php|asp\.net|express|node\.js|nodejs|python|ruby|openresty)\s*[/ ]\s*v?(\d[\w.]*)")

_ALIAS = {"httpd": "apache", "catalina": "tomcat", "openresty": "nginx",
          "node.js": "nodejs", "node": "nodejs"}

# (产品, 版本下界（含）, 版本上界（不含）, 严重度, 标题, CVE, 说明, 建议)
_CVE_RULES: list[tuple[str, str, str, str, str, str, str, str]] = [
    ("apache", "2.4.49", "2.4.51", "critical",
     "Apache HTTP Server 路径穿越与远程代码执行", "CVE-2021-41773 / CVE-2021-42013",
     "该版本对路径归一化的处理存在缺陷，可用 `/.%2e/` 一类编码穿越出文档根目录读取任意文件；"
     "若启用了 CGI，可进一步直接执行系统命令。该漏洞 2021 年被大规模自动化利用，"
     "暴露在网络上通常数小时内就会被打。",
     "升级到 2.4.51 及以上；无法立即升级时确认根目录有 `Require all denied`，并关闭不必要的 CGI。"),
    ("apache", "2.4.51", "2.4.54", "medium",
     "Apache HTTP Server mod_proxy 客户端 IP 伪造", "CVE-2022-31813",
     "mod_proxy 转发时未清除原始 `X-Forwarded-For`，后端基于该头做的访问控制可被绕过。",
     "升级到 2.4.54 以上，或在反向代理层显式覆盖该头。"),
    ("nginx", "1.3.0", "1.20.1", "high",
     "nginx DNS 解析器堆缓冲区溢出", "CVE-2021-23017",
     "启用 `resolver` 指令时，来自 DNS 响应的畸形包可造成 1 字节堆溢出，"
     "存在被利用实现远程代码执行的可能。",
     "升级到 1.20.1 / 1.21.0 以上。"),
    ("tomcat", "9.0.0", "9.0.62", "medium",
     "Apache Tomcat 会话信息泄漏", "CVE-2021-25122 / CVE-2021-25329 / CVE-2022-23181",
     "该版本区间内的 Tomcat 存在多个会话与请求处理缺陷，可导致响应内容错发或本地提权。",
     "升级到 9.0.62 以上；同时检查 `server.xml` 中是否保留了默认示例应用。"),
    ("php", "0", "7.4.33", "high",
     "PHP 版本已停止安全支持", "多个（版本已 EOL）",
     "该 PHP 分支已结束安全支持，此后发现的漏洞不会再获得官方修复。"
     "国内大量遗留系统仍停留在 PHP 5.x/7.x，是 Webshell 与反序列化攻击的主要目标。",
     "升级到仍在支持的 PHP 版本（8.1+）；短期内至少禁用 `allow_url_include`、"
     "收紧 `disable_functions`，并确认没有暴露 phpinfo 与调试页面。"),
    ("weblogic", "0", "12.2.1.4", "critical",
     "WebLogic 版本过旧，存在多个反序列化 RCE", "CVE-2017-10271 / CVE-2019-2725 / CVE-2020-14882",
     "WebLogic 的多个历史版本存在可未授权利用的反序列化与 console 绕过漏洞，"
     "是内网渗透中使用最广泛的一类入口。",
     "升级到最新补丁版本；无法升级时限制 `/console`、`/wls-wsat` 等路径的访问来源，"
     "并在前置设备上拦截 T3/IIOP 协议。"),
]

# 前端库版本：从文件内容与文件名里提取
_JS_LIBS: list[tuple[str, list[str]]] = [
    ("jQuery", [r"jQuery\s+(?:JavaScript\s+Library\s+)?v?(\d+\.\d+(?:\.\d+)?)",
                r"jQuery\.fn\.jquery\s*=\s*[\"'](\d+\.\d+(?:\.\d+)?)",
                r"jquery[-.]v?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js",
                r"jquery[@/](\d+\.\d+(?:\.\d+)?)"]),
    ("lodash", [r"lodash\s+v?(\d+\.\d+\.\d+)",
                r"lodash[-.]v?(\d+\.\d+\.\d+)(?:\.min)?\.js",
                r"lodash@(\d+\.\d+\.\d+)"]),
    ("Bootstrap", [r"Bootstrap\s+v?(\d+\.\d+\.\d+)",
                   r"bootstrap[-.]v?(\d+\.\d+\.\d+)(?:\.min)?\.(?:js|css)"]),
    ("axios", [r"axios[/@](\d+\.\d+\.\d+)", r"axios[-.]v?(\d+\.\d+\.\d+)"]),
    ("moment.js", [r"moment(?:\.js)?\s+v?(\d+\.\d+\.\d+)",
                   r"moment[-.]v?(\d+\.\d+\.\d+)(?:\.min)?\.js"]),
    ("Vue.js", [r"Vue\.js\s+v?(\d+\.\d+\.\d+)",
                r"vue[@.-]v?(\d+\.\d+\.\d+)(?:\.min)?\.js"]),
    ("React", [r"react[@.-]v?(\d+\.\d+\.\d+)(?:\.min)?\.js"]),
]

# (库, 下界, 上界, 严重度, 标题, CVE, 说明, 建议)
_JS_CVE_RULES: list[tuple[str, str, str, str, str, str, str, str]] = [
    ("jQuery", "0", "1.9.0", "high",
     "jQuery 版本早已停止维护且存在多个跨站脚本缺陷", "CVE-2015-9251 等",
     "jQuery 1.x/2.x 已结束维护，其 `$.html()`、`$(location.hash)` 等接口在"
     "接收不可信输入时会执行 HTML，构成 DOM 型 XSS。旧版本还普遍存在"
     "`htmlPrefilter` 相关的 XSS（CVE-2020-11022/11023）。",
     "升级到 jQuery 3.5.0 以上；如无法升级，至少收敛所有把外部输入交给 "
     "`html()`/`append()` 的调用点。"),
    ("jQuery", "1.9.0", "3.5.0", "medium",
     "jQuery 存在 htmlPrefilter 跨站脚本缺陷", "CVE-2020-11022 / CVE-2020-11023",
     "在 `htmlPrefilter` 处理路径上，攻击者可控的 HTML 字符串可绕过清洗逻辑执行脚本。"
     "该问题影响面极广，因为几乎所有 3.5.0 之前的 jQuery 都在这个区间。",
     "升级到 jQuery 3.5.0 以上。"),
    ("lodash", "0", "4.17.21", "high",
     "lodash 存在命令注入与原型污染缺陷", "CVE-2021-23337 / CVE-2020-8203",
     "`template()` 存在命令注入面，`zipObjectDeep` 等接口存在原型污染，"
     "可导致上游业务逻辑被篡改甚至远程代码执行。",
     "升级到 lodash 4.17.21 以上；避免把外部输入交给 `template()`。"),
    ("Bootstrap", "0", "3.4.1", "medium",
     "Bootstrap 存在跨站脚本缺陷", "CVE-2019-8331",
     "`data-template`、`data-content` 等属性在渲染 tooltip/popover 时未做充分转义，"
     "可在受害者页面上执行脚本。",
     "升级到 Bootstrap 3.4.1 / 4.3.1 以上。"),
    ("axios", "0", "0.21.2", "medium",
     "axios 存在服务端请求伪造与 ReDoS 缺陷", "CVE-2021-3749",
     "该版本区间存在正则拒绝服务，部分版本还存在 SSRF 面。",
     "升级到 axios 0.21.2 以上。"),
    ("moment.js", "0", "2.29.4", "medium",
     "moment.js 存在正则拒绝服务缺陷", "CVE-2022-31129",
     "构造的超长日期字符串可让解析过程消耗大量 CPU，造成接口不可用。",
     "升级到 2.29.4 以上，或迁移到 dayjs / date-fns 等仍在维护的库。"),
]

# 组件存在性指纹（不需要版本号，识别到即提示该类组件的高危历史）
_FRAMEWORK_RISKS: list[tuple[str, str, str, str, str, str]] = [
    ("Apache Shiro", r"rememberMe\s*=\s*deleteMe", "high",
     "识别到 Apache Shiro 会话特征（`rememberMe` Cookie）。Shiro 的 rememberMe "
     "反序列化（CVE-2016-4437）是内网渗透最常被利用的入口之一：密钥若为默认值，"
     "攻击者可构造恶意序列化对象直接获得服务器权限。",
     "确认 Shiro 版本不低于 1.7.1；不要使用默认 AES 密钥，避免硬编码；"
     "升级后仍需验证 rememberMe 已启用序列化白名单。"),
    ("Struts2", r"struts|\.action[\"'?]|jakarta\.struts", "high",
     "识别到 Struts2 技术栈。Struts2 的 OGNL 表达式注入（S2-045、S2-057 等）"
     "历史上多次造成未授权远程代码执行。",
     "升级到最新 Struts 版本并移除未使用的插件；在边界设备上拦截 OGNL 特征。"),
    ("泛微 e-cology", r"weaver|ecology|e-cology|泛微", "high",
     "识别到泛微 OA 特征。该类系统历史上存在大量未授权文件上传与 SQL 注入漏洞，"
     "是内网渗透的高价值目标，且补丁覆盖率普遍偏低。",
     "核对当前版本与官方最新补丁；把 OA 系统限制在内网并单独隔离，"
     "在网关层对文件上传与 `bsh.servlet` 类路径做拦截。"),
    ("致远 OA", r"seeyon|致远", "high",
     "识别到致远 OA 特征。该类系统历史上存在多个未授权文件上传与远程代码执行漏洞。",
     "核对版本与补丁；限制外网可达性；在网关层拦截异常的文件上传与 `htmlofficeservlet` 类路径。"),
    ("通达 OA", r"ispirit|通达oa|tongda", "high",
     "识别到通达 OA 特征。该类系统历史上存在未授权访问与文件包含漏洞。",
     "核对版本与补丁；限制外网可达性。"),
    ("若依 RuoYi", r"ruoyi|若依", "medium",
     "识别到若依（RuoYi）脚手架特征。该框架历史上存在多个未授权访问与"
     "代码生成器相关的远程代码执行面，且默认口令与默认密钥常在部署时被保留。",
     "确认已修改默认账号口令与 JWT 密钥；关闭生产环境中的代码生成模块；"
     "核对 `prod-api` 前缀下的接口是否都经过鉴权。"),
    ("Spring Boot", r"Whitelabel Error Page|spring-boot|springframework", "medium",
     "识别到 Spring Boot 特征。若 Actuator 端点未做收敛，`/actuator/env`、"
     "`/actuator/heapdump` 可直接泄漏环境变量（含数据库口令）与内存中的凭据。",
     "生产环境关闭或收敛 Actuator 端点，并限制管理端口仅内网可达。"),
]


@tool("component_vuln",
      "组件版本与已知漏洞比对：从响应头、页面特征与 JS bundle 中提取服务端产品"
      "（nginx/Apache/Tomcat/PHP/WebLogic 等）与前端库（jQuery/lodash/Bootstrap/axios 等）"
      "的版本，比对明确的已知高危 CVE；同时识别 Shiro/Struts2/国产 OA 等"
      "历史高危组件特征。仅报告版本区间与 CVE 能明确对应的结论。",
      {"url": "str，站点入口 URL（通常是首页）"},
      phase="recon", category="组件漏洞")
def component_vuln(sess: ScanSession, url: str) -> dict:
    origin = origin_of(url)
    issues: list[dict] = []
    notes: list[str] = []
    products: dict[str, str] = {}
    libs: dict[str, str] = {}

    html, _status, _ct = _page_text(sess, url)
    blobs: list[str] = [html]
    headers_blob = ""

    try:
        resp, _e = sess.request("GET", url)
    except (BudgetExceeded, OSError):
        resp = None
    if resp is not None:
        headers_blob = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        cookies = (resp.headers.get_list("set-cookie")
                   if hasattr(resp.headers, "get_list") else [])
        blobs.append(headers_blob)
        blobs.append("\n".join(cookies))

    # ---- 服务端产品与版本 ----
    for blob in blobs:
        for m in _BANNER_RE.finditer(blob or ""):
            name = _ALIAS.get(m.group(1).lower(), m.group(1).lower())
            v = m.group(2).strip(".")
            if name and v and name not in products:
                products[name] = v

    for name, v in products.items():
        for prod, lo, hi, sev, title, cve, detail, advice in _CVE_RULES:
            if prod != name or not _in_range(v, lo, hi):
                continue
            issues.append(_issue(
                "component-vuln", sev, "组件漏洞", f"{title}（{name} {v}）", url,
                f"目标响应头声明了 `{name}` 版本 `{v}`。{detail}",
                advice, cwe="CWE-1104",
                evidence=f"产品 {name} 版本 {v}；命中区间 [{lo}, {hi})；{cve}",
                confidence="high"))

    # 响应头暴露精确版本本身就是一个独立问题：攻击者据此可以直接挑选利用代码
    versioned = [f"{k} {v}" for k, v in products.items()
                 if re.match(r"^\d+\.\d+", v)]
    if versioned:
        issues.append(_issue(
            "component-vuln", "low", "信息泄漏", "响应头暴露组件精确版本", url,
            f"响应头中直接给出了组件及其完整版本号：{'、'.join(versioned)}。"
            "这让攻击者无需任何额外探测就能确定可用的漏洞利用代码，"
            "相当于把扫描阶段的工作直接省略掉。",
            "在 Web 服务器配置中关闭或模糊化版本号（nginx `server_tokens off`；"
            "Apache `ServerTokens Prod`；Tomcat 自定义 `server.info`）。",
            cwe="CWE-200", evidence="、".join(versioned), confidence="high"))

    # ---- 前端库版本 ----
    bundles = _iter_scripts(sess, origin, html, {"quick": 5, "standard": 12, "deep": 20}
                            .get(sess.depth, 12))
    texts = [("首页 HTML", html)]
    for src in bundles:
        t, _e = sess.fetch_text(src)
        if t:
            texts.append((src.rsplit("/", 1)[-1], t))
    # 文件名里也常带版本（`jquery-1.8.3.min.js?v=1.8.3`）
    texts.append(("脚本引用", "\n".join(bundles)))

    for lib, pats in _JS_LIBS:
        for label, text in texts:
            found = ""
            for pat in pats:
                m = re.search(pat, text or "", re.I)
                if m:
                    found = m.group(1)
                    break
            if found and lib not in libs:
                libs[lib] = found
                break

    for lib, v in libs.items():
        for name, lo, hi, sev, title, cve, detail, advice in _JS_CVE_RULES:
            if name != lib or not _in_range(v, lo, hi):
                continue
            issues.append(_issue(
                "component-vuln", sev, "组件漏洞", f"{title}（{lib} {v}）", url,
                f"前端资源中识别到 `{lib}` 版本 `{v}`。{detail}",
                advice, cwe="CWE-1104",
                evidence=f"库 {lib} 版本 {v}；命中区间 [{lo}, {hi})；{cve}",
                confidence="high"))

    m = re.search(r'ng-version=["\']([\d.]+)', html or "")
    if m:
        libs["Angular"] = m.group(1)

    # ---- 组件存在性指纹 ----
    hay = "\n".join(blobs)
    for name, pat, sev, detail, advice in _FRAMEWORK_RISKS:
        if not re.search(pat, hay, re.I):
            continue
        issues.append(_issue(
            "component-vuln", sev, "组件漏洞", f"识别到高危技术栈：{name}", url,
            detail, advice, cwe="CWE-1104",
            evidence=f"页面/响应头特征匹配 {pat}", confidence="medium"))
        notes.append(f"技术栈指纹命中 {name}，建议按该类系统的历史漏洞清单单独复核")

    if not products and not libs:
        notes.append("未能从响应头与前端资源中识别出可定版的组件，版本比对未生效")

    summary = (f"识别服务端组件 {len(products)} 个"
               f"{'（' + '、'.join(f'{k} {v}' for k, v in list(products.items())[:5]) + '）' if products else ''}，"
               f"前端库 {len(libs)} 个"
               f"{'（' + '、'.join(f'{k} {v}' for k, v in list(libs.items())[:5]) + '）' if libs else ''}，"
               f"命中 {len(issues)} 项版本风险")
    return {"ok": True, "summary": summary,
            "data": {"url": url, "server_products": products, "frontend_libs": libs,
                     "bundles": bundles[:12], "findings": len(issues)},
            "issues": issues, "notes": notes}


# ============================================================ 文件包含（LFI / RFI）

# 为什么不能交给 traversal_probe：包装器协议（php://、data://、expect://）
# 走的不是「路径拼接」而是「流协议解析」，判据也完全不同
# （base64 解码、进程信息格式、include 报错），
# 目录遍历的「读到了 /etc/passwd 内容」在这里一条都不适用。
_LFI_TAG = "aih0leyrfi"

# (族, 名称, 载荷, 判据类型, 严重度, 说明)
#
# 「族」这一层不能省。第一版按参数命中即 break，结果一个参数上
# `php://filter` 先命中之后，`data://`、`expect://`、`/proc/self/environ`
# 与远程包含这四类**一次都没被投递过**——它们的根因完全不同
# （包装器解析 vs 流协议执行 vs 本地文件读取 vs allow_url_include），
# 报告却只会写一条「文件包含」，看起来测过其实只测了一种。
# 现在按族去重：同一族命中一次就收手，不同族各自测到底。
_LFI_WRAPPERS: list[tuple[str, str, str, str, str, str]] = [
    ("php-wrapper", "php://filter base64 读取源码",
     "php://filter/convert.base64-encode/resource=index.php", "b64",
     "high", "`php://filter` 包装器被服务端解析并执行，说明参数直接进入了 include/require。"
             "攻击者可借此读取任意 PHP 源码、配置文件的**明文内容**（base64 只是编码不是加密），"
             "从中提取数据库口令、密钥与业务逻辑。"),
    ("php-wrapper", "php://filter 直接读取文件",
     "php://filter/resource=/etc/passwd", "passwd",
     "high", "`php://filter` 被解析，且成功读到了系统文件内容。"
             "与上一条同源，但连编码层都没有，危害等价而利用更直接。"),
    ("data-wrapper", "data:// 包装器",
     "data://text/plain;base64,PD9waHAgZWNobyAiYWloMGxleXJmaSI7Pz4=", "data",
     "critical", "`data://` 包装器被解析，服务端把我们提供的文本当成了被包含的文件内容。"
                 "真实场景下这意味着可以执行任意 PHP 代码，等同于远程代码执行。"),
    ("expect-wrapper", "expect:// 命令执行",
     "expect://id", "uid",
     "critical", "`expect://` 包装器可用，传入的参数被当作系统命令执行。"
                 "这是文件包含类漏洞中最严重的一种，直接等价于命令注入。"),
    ("proc-file", "/proc/self/environ 环境变量",
     "/proc/self/environ", "environ",
     "high", "读取到了进程的环境变量。生产环境的环境变量里通常包含数据库连接串、"
             "云凭据与第三方服务的密钥。"),
    ("proc-file", "/proc/self/cmdline 启动参数",
     "/proc/self/cmdline", "cmdline",
     "medium", "读取到了进程的启动命令行，可据此推断部署路径与所用中间件版本。"),
    ("sys-file", "/etc/hosts 主机解析",
     "/etc/hosts", "hosts",
     "medium", "读取到了系统 hosts 文件，泄漏内部主机名与网络拓扑，为横向移动提供线索。"),
    ("sys-file", "Windows hosts 文件",
     "C:\\Windows\\System32\\drivers\\etc\\hosts", "hosts",
     "medium", "在 Windows 目标上读到了 hosts 文件，同样泄漏内部网络拓扑。"),
    ("rfi", "远程文件包含（不可达地址触发）",
     "http://127.0.0.1:1/aih0ley_rfi.txt", "include_err",
     "high", "服务端响应中出现了 PHP 的 include 失败报错，"
             "证明参数被当作文件路径传给了 include 且支持 URL 形式的包装器。"
             "生产环境开启 `allow_url_include` 时，攻击者可直接包含外部服务器上的代码，"
             "构成远程代码执行。"),
]

_LFI_BUDGET = {"quick": 36, "standard": 110, "deep": 200}

# 族的探测顺序：危害从高到低，预算不足时优先测最严重的
_LFI_FAMILY_ORDER = ["php-wrapper", "data-wrapper", "expect-wrapper",
                     "proc-file", "sys-file", "rfi"]

# 每个族最多换几个参数试。族多了以后必须限：不限的话
# 「6 族 × 12 参数 × 2 载荷」会把一次扫描的预算全吃在这一个工具上，
# 反而让后面的检查项没预算跑——漏掉的比多测到的更多。
_LFI_PARAM_CAP = {"quick": 2, "standard": 4, "deep": 6}


_LFI_PARAMS = ["file", "path", "page", "template", "tpl", "include", "inc", "doc",
               "document", "view", "load", "src", "source", "content", "dir", "folder",
               "filename", "filepath", "resource", "open", "read", "cat", "target",
               "module", "mod", "lang", "skin", "theme", "url", "uri"]


def _lfi_verdict(kind: str, body: bytes) -> tuple[int, str]:
    """检查响应体是否构成该类包装器的命中证据，返回 (命中强度, 证据片段)。"""
    text = body[:200000].decode("utf-8", "replace")
    low = text.lower()

    if kind == "b64":
        # 判据不能只是「看起来像 base64」——普通页面里也常有长 base64 串。
        # 必须真的解出可识别的内容（PHP 标签 / 常见源码关键字）。
        # 阈值给到 24：`<?php // file not found ?>` 这种短源码 base64 后
        # 只有 40 个字符，门槛设成 60 会把「读到了但文件很短」这种真实命中漏掉。
        for m in re.finditer(r"[A-Za-z0-9+/]{24,}={0,2}", text):
            try:
                dec = base64.b64decode(m.group(0) + "=" * (-len(m.group(0)) % 4))
            except Exception:
                continue
            dt = dec.decode("utf-8", "replace")
            if not dt or sum(c.isprintable() or c in "\r\n\t" for c in dt) < len(dt) * 0.9:
                continue
            if re.search(r"<\?php|<\?=|function\s+\w+\s*\(|class\s+\w+|<!DOCTYPE|<html",
                         dt, re.I):
                return 3, _snippet(dt, needle="php" if "<?php" in dt else "", width=200)
        return 0, ""
    if kind == "passwd":
        if re.search(r"root:[^:\s]{0,4}:\d+:\d+:[^:\r\n]*:", text):
            return 3, _snippet(text, needle="root:", width=200)
        return 0, ""
    if kind == "data":
        if _LFI_TAG in text:
            return 3, _snippet(text, needle=_LFI_TAG, width=160)
        return 0, ""
    if kind == "uid":
        if re.search(r"uid=\d+\([\w\-]+\)\s+gid=\d+\(", text):
            return 3, _snippet(text, needle="uid=", width=160)
        return 0, ""
    if kind == "environ":
        # 环境变量文件是多行 KEY=VALUE，至少要有 3 个像样的键才算命中
        pairs = re.findall(r"(?m)^([A-Z][A-Z0-9_]{2,30})=", text)
        if len(set(pairs)) >= 3:
            return 3, _snippet(text, needle=pairs[0] + "=", width=200)
        return 0, ""
    if kind == "cmdline":
        if re.search(r"(?i)(php-fpm|/usr/sbin/|/usr/bin/|python|java|node|apache2|nginx)", text) \
                and "\x00" in text[:400]:
            return 2, _snippet(text, needle="usr", width=160)
        return 0, ""
    if kind == "hosts":
        if re.search(r"(?mi)^\s*(?:127\.0\.0\.1|::1|10\.\d|192\.168)\s+\S+", text) \
                and len(text) < 8000:
            return 3, _snippet(text, needle="127.0.0.1", width=180)
        return 0, ""
    if kind == "include_err":
        if re.search(r"(?i)(include|require)(_once)?\s*\(\s*\)\s*[:.]?.*"
                     r"(failed to open stream|Failed opening|No such file)", text) \
                or re.search(r"(?i)failed to open stream:.{0,80}in <b>", text):
            return 3, _snippet(text, needle="Failed opening"
                               if "Failed opening" in text else "failed to open stream", width=220)
        return 0, ""
    return 0, ""


@tool("lfi_probe",
      "本地/远程文件包含检测（**只读**）：向文件类参数投递 `php://filter`、`data://`、"
      "`expect://`、`/proc/self/environ`、`/etc/hosts`、Windows hosts 等包装器与系统文件路径，"
      "并用 include 失败报错确认远程包含能力。"
      "普通路径穿越请用 `traversal_probe`，两者判据与载荷完全不重叠。",
      {"url": "str，目标 URL（可自带查询串）",
       "params": "list[str]，可选，指定要检测的参数名"},
      phase="scan", category="注入与参数")
def lfi_probe(sess: ScanSession, url: str, params: list | None = None) -> dict:
    parsed = urlparse(url)
    base_path = parsed.path or "/"
    base_q = parsed.query
    origin = origin_of(url)
    budget = _LFI_BUDGET.get(sess.depth, 100)

    given = _same_origin_params(url)
    extra = [p for p in (params or []) if isinstance(p, str) and p.strip()]
    js_params = ((sess.discovered.get("js_params") or {}).get(origin) or [])
    # 文件类参数名排前面：命中率与这些名字强相关，预算要花在它们身上
    ordered = uniq([p for p in (given + extra + js_params) if p])
    ordered += [p for p in _LFI_PARAMS if p not in ordered]
    names = ordered[:12]

    # 落点：入口路径 + api_surface 采集到的带参 URL。
    # 文件包含的落点几乎从来不是首页——它长在「下载/预览/导出」这类功能页上，
    # 参数名往往是 `file` / `path` / `doc`。只测入口路径等于把整类漏洞漏掉。
    landings: list[tuple[str, str, list[str]]] = [(base_path, base_q, names)]
    seen_paths = {base_path}
    disc_cap = DISCOVERED_LANDING_CAP.get(sess.depth, 10)
    disc_added = 0
    for du in ((sess.discovered.get("param_urls") or {}).get(origin) or []):
        if disc_added >= disc_cap:
            break
        dp = urlparse(du)
        if dp.path in seen_paths or not dp.query:
            continue
        own = [k for k, _v in parse_qsl(dp.query, keep_blank_values=True) if k]
        if not own:
            continue
        seen_paths.add(dp.path)
        # 次要落点：它自己的参数名排前面，再补文件类候选名
        landings.append((dp.path or "/", dp.query,
                         own[:4] + [p for p in _LFI_PARAMS if p not in own][:4]))
        disc_added += 1

    fb = FallbackBaseline(sess, origin)
    issues: list[dict] = []
    notes: list[str] = []
    # (参数, 名称, 严重度, 说明, 证据, 载荷)
    hits: list[tuple[str, str, str, str, str, str]] = []
    tried = 0
    family_hit: set[str] = set()
    param_cap = _LFI_PARAM_CAP.get(sess.depth, 4)

    by_family: dict[str, list[tuple]] = {}
    for w in _LFI_WRAPPERS:
        by_family.setdefault(w[0], []).append(w)

    for family in _LFI_FAMILY_ORDER:
        if family in family_hit:
            continue
        for lpath, lq, lnames in landings:
            if family in family_hit or tried >= budget:
                break
            for name in lnames[:param_cap]:
                if family in family_hit or tried >= budget:
                    break
                for _fam, label, payload, kind, sev, why in by_family.get(family, []):
                    if tried >= budget:
                        break
                    tried += 1
                    # 走裸通道手工拼查询串：包装器里的 `://`、`;`、`,`、`=`
                    # 经 urllib 编码后语义可能被改变，且部分中间件不做解码。
                    raw = f"{lpath}?{_raw_query_with(lq, name, payload)}"
                    try:
                        r = sess.request_raw(url, raw)
                    except (BudgetExceeded, OSError):
                        break
                    if r.error or not r.body:
                        continue
                    if fb.matches(r.status, r.body, r.ctype):
                        continue                   # 兜底页，判据不成立
                    strength, evidence = _lfi_verdict(kind, r.body)
                    if strength:
                        landing_url = f"{origin}{lpath}" + (f"?{lq}" if lq else "")
                        hits.append((name, label, sev, why, evidence, payload,
                                     landing_url))
                        family_hit.add(family)
                        break                      # 该族已确认，换下一族

    for name, label, sev, why, evidence, payload, landing_url in hits:
        issues.append(_issue(
            "lfi-probe", sev, "注入与参数", f"文件包含：{label}（参数 `{name}`）",
            landing_url,
            f"参数 `{name}` 的取值被服务端当作文件路径处理，且成功命中了「{label}」的判定特征。"
            f"{why}",
            "不要使用用户可控的文件路径拼接 include；改为白名单映射"
            "（只允许 `page=about` 这类枚举值）；确需动态读取时用固定前缀 + "
            "`basename()` 且禁止包装器协议；生产环境关闭 `allow_url_include`。",
            cwe="CWE-98", method="GET", param=name, payload=payload,
            evidence=evidence, confidence="high"))

    if not hits:
        notes.append(f"测试 {len(landings)} 个落点共 {tried} 次包装器载荷，未发现文件包含")
    else:
        notes.append(f"命中 {len(family_hit)} 个包装器族"
                     + ("（各族利用条件不同，修复时需分别验证）" if len(family_hit) >= 2 else ""))
    if len(landings) > 1:
        notes.append(f"除入口路径外，还在该站 {len(landings) - 1} 个带参数的落点上"
                     f"（如 `{landings[1][0]}?{landings[1][1]}`）做了文件包含测试")
    n = soft404_note(fb, origin)
    if n:
        notes.append(n)

    summary = (f"覆盖 {len(_LFI_FAMILY_ORDER)} 个包装器族，"
               f"测试前 {len(names[:param_cap])} 个参数共 {tried} 次载荷，"
               f"命中 {len(hits)} 类文件包含"
               + (f"（{len(family_hit)} 族）" if family_hit else ""))
    return {"ok": True, "summary": summary,
            "data": {"url": url, "params": names, "attempts": tried,
                     "hits": [{"param": h[0], "kind": h[1], "payload": h[4]} for h in hits]},
            "issues": issues, "notes": notes}


# ============================================================ 认证攻击面

_BASIC_RE = re.compile(r"(?i)\bbasic\s+realm")

_LOGIN_PATHS = ["/login", "/admin/login", "/api/login", "/auth/login", "/user/login",
                "/signin", "/api/auth/login", "/manage/login", "/system/login",
                "/admin", "/api/token", "/oauth/token", "/wp-login.php", "/console/login"]

# 哨兵用户名：一个几乎不可能存在的账号。它的响应代表「用户不存在」的基线，
# 所有枚举判定都是拿其它用户名与它对比得出来的。
_SENTINEL_USER = "aih0ley_nouser_9x7zq"
_BAD_PASSWORD = "aih0ley_WrongPw_123!"

_ENUM_USERS = ["admin", "administrator", "root", "test", "guest", "user"]

_PW_FIELD_RE = re.compile(r"(?i)^(pass|passwd|password|pwd|passw|userpass)$")
_USER_FIELD_RE = re.compile(r"(?i)^(user|username|userid|user_name|login|loginname|"
                            r"account|email|uname|uid|name)$")


def _login_sig(resp) -> tuple:
    """把一次登录响应压成可比较的签名：(状态码, 长度, 文案特征)。"""
    body = resp.text or ""
    text = re.sub(r"<script.*?</script>", " ", body, flags=re.S | re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip().lower()
    return (resp.status_code, len(resp.content or b""), text[:200])


def _sig_differs(a: tuple, b: tuple) -> bool:
    """两次登录响应是否有「说明用户名是否存在」的实质差异。

    判据要严：只有状态码变化、文案不同、或长度差异超过 15%（且绝对值超过 30 字节）
    才算差异。只看长度很容易把随机时间戳/trace id 造成的抖动当成用户存在。
    """
    if a[0] != b[0]:
        return True
    if a[2] != b[2]:
        return True
    base = max(a[1], b[1])
    return abs(a[1] - b[1]) > max(30, int(0.15 * base))


def _find_login(sess: ScanSession, url: str) -> tuple[str, str, dict]:
    """找登录端点，返回 (端点 URL, 提交方法, 参数名映射)。"""
    origin = origin_of(url)
    html, _s, _c = _page_text(sess, url)

    # 1) 页面上的密码表单优先 —— 它一定是真的登录入口
    for fm in re.finditer(r"<form\b([^>]*)>(.*?)</form>", html or "", re.I | re.S):
        attrs = fm.group(1)
        inner = fm.group(2)
        if not re.search(r"(?i)type\s*=\s*[\"']password", inner):
            continue
        action_m = re.search(r"""(?i)action\s*=\s*["']([^"']*)["']""", attrs)
        method_m = re.search(r"""(?i)method\s*=\s*["']([^"']*)["']""", attrs)
        action = action_m.group(1) if action_m else url
        if action.startswith(("http://", "https://")):
            full = action
        elif action.startswith("/"):
            full = origin + action
        else:
            full = f"{url.rsplit('/', 1)[0]}/{action}"
        method = (method_m.group(1) if method_m else "post").lower()
        names = re.findall(r"""(?i)name\s*=\s*["']([^"']+)["']""", inner)
        uf = next((n for n in names if _USER_FIELD_RE.match(n)), "username")
        pf = next((n for n in names if _PW_FIELD_RE.match(n)), "password")
        return full, method, {"user": uf, "pass": pf}

    # 2) 常见路径兜底
    for path in _LOGIN_PATHS:
        try:
            r, _e = sess.request("GET", origin + path)
        except (BudgetExceeded, OSError):
            break
        if r is None:
            continue
        if r.status_code in (404, 410) or r.status_code >= 500:
            continue
        body = r.text or ""
        if r.status_code == 401 or re.search(r"(?i)type\s*=\s*[\"']password", body) \
                or (r.status_code < 400 and "json" in (r.headers.get("content-type") or "")):
            return origin + path, "post", {"user": "username", "pass": "password"}
    return "", "", {}


@tool("auth_audit",
      "认证攻击面检测：识别 Basic Auth 及其是否运行在明文 HTTP 上、定位登录端点、"
      "通过**响应差异**判断是否存在用户名枚举（含哨兵基线与二次确认）、"
      "并观察登录接口是否缺少速率限制。"
      "弱口令尝试默认关闭，需显式开启 `weak_creds` —— 失败的口令尝试可能触发账号锁定，"
      "属于有副作用的动作。",
      {"url": "str，站点入口 URL",
       "weak_creds": "bool，默认 false。是否尝试极少量（6 组）常见弱口令"},
      phase="scan", category="认证与会话")
def auth_audit(sess: ScanSession, url: str, weak_creds: bool = False) -> dict:
    origin = origin_of(url)
    issues: list[dict] = []
    notes: list[str] = []
    is_plain = urlparse(url).scheme != "https"

    # ---- Basic Auth ----
    basic = False
    try:
        r, _e = sess.request("GET", url)
    except (BudgetExceeded, OSError):
        r = None
    if r is not None and r.status_code == 401:
        wa = r.headers.get("www-authenticate", "")
        if _BASIC_RE.search(wa):
            basic = True
            issues.append(_issue(
                "auth-audit", "high" if is_plain else "low", "认证与会话",
                "使用 HTTP Basic 认证" + ("（且运行在明文 HTTP 上）" if is_plain else ""),
                url,
                "服务端使用 HTTP Basic 认证。Basic 认证只是把 `用户名:口令` 做 base64，"
                "**不是加密**；" + ("当前站点走明文 HTTP，任何能旁路流量的人都能直接还原出口令。"
                                    if is_plain else
                                    "虽然走 HTTPS，但凭据仍会随每个请求重复发送，"
                                    "一旦 TLS 被降级或证书被伪造就会直接泄漏。"),
                "改用基于会话或令牌的认证；必须用 Basic 时强制 HTTPS 并配合"
                "短期凭据与多因素认证。", cwe="CWE-522",
                evidence=f"WWW-Authenticate: {wa[:120]}", confidence="high"))

    # ---- 登录端点 ----
    login_url, login_method, fields = _find_login(sess, url)
    enum_users: list[str] = []
    lockout_observed = False

    if login_url:
        notes.append(f"定位到登录端点 {login_url}（{login_method.upper()}，"
                     f"用户字段 `{fields['user']}`、口令字段 `{fields['pass']}`）")

        def attempt(user: str, pw: str):
            try:
                if login_method == "get":
                    return sess.request("GET", login_url,
                                        params={fields["user"]: user, fields["pass"]: pw})[0]
                return sess.request("POST", login_url,
                                    data={fields["user"]: user, fields["pass"]: pw})[0]
            except (BudgetExceeded, OSError):
                return None

        base1 = attempt(_SENTINEL_USER, _BAD_PASSWORD)
        base2 = attempt(_SENTINEL_USER, _BAD_PASSWORD)
        if base1 is None or base2 is None:
            notes.append("登录端点无法稳定访问，用户枚举未执行")
        else:
            s1, s2 = _login_sig(base1), _login_sig(base2)
            if _sig_differs(s1, s2):
                notes.append("同一用户名两次登录的响应不一致（疑似含随机内容），"
                             "用户枚举结论可信度下降")
            # 确认阶段很关键：一次差异可能只是抖动。只有「与哨兵基线不同」
            # **且重复一次仍然不同**的用户名才算可枚举。
            for u in _ENUM_USERS:
                resp = attempt(u, _BAD_PASSWORD)
                if resp is None:
                    continue
                sig = _login_sig(resp)
                if not _sig_differs(sig, s1):
                    continue
                confirm = attempt(u, _BAD_PASSWORD)
                if confirm is not None and _sig_differs(_login_sig(confirm), s1):
                    enum_users.append(u)
            if _looks_blocked(base1.status_code, base1.text or ""):
                notes.append("登录响应疑似被 WAF 拦截，用户枚举结论不可信")

        # ---- 速率限制观察 ----
        rapid = []
        for _ in range(6):
            rr = attempt(_SENTINEL_USER, _BAD_PASSWORD)
            if rr is None:
                break
            rapid.append(rr)
        if rapid:
            locked = [x for x in rapid
                      if x.status_code in (429, 423) or
                      re.search(r"(?i)(too many|rate limit|locked|锁定|频繁|尝试次数)",
                                x.text or "")]
            lockout_observed = bool(locked)
            if not lockout_observed:
                issues.append(_issue(
                    "auth-audit", "low", "认证与会话", "登录接口未观察到速率限制", login_url,
                    f"连续 {len(rapid)} 次登录失败后，服务端未返回 429/423，"
                    "响应中也没有出现锁定或频率限制的提示。这**不等于**没有限制"
                    "（可能由前置网关按 IP 计数、或阈值更高），但在本阈值下未见拦截，"
                    "攻击者可以按此速率持续猜解口令。",
                    "为登录接口加入按账号与按来源 IP 的双维度限速、失败次数累积锁定、"
                    "以及验证码/多因素等抗自动化手段。", cwe="CWE-307",
                    evidence=f"连续 {len(rapid)} 次失败登录，状态码 "
                             f"{[x.status_code for x in rapid]}", confidence="medium"))

        if enum_users:
            issues.append(_issue(
                "auth-audit", "medium", "认证与会话", "登录接口存在用户名枚举", login_url,
                f"对同一批错误口令，用户名 `{'、'.join(enum_users)}` 的响应与不存在用户"
                f"（哨兵 `{_SENTINEL_USER}`）存在稳定差异（状态码/文案/长度），"
                "且重复请求仍然复现。攻击者可借此先筛出一批有效账号，"
                "再对少量账号集中做口令猜解，大幅降低被限速发现的概率。",
                "登录失败一律返回统一文案与统一状态码，且响应时间也应保持一致；"
                "口令找回流程同理，不要在响应中区分「账号不存在」与「口令错误」。",
                cwe="CWE-204", method=login_method.upper(),
                evidence=f"哨兵基线：status={s1[0]} len={s1[1]}；"
                         f"可区分用户：{'、'.join(enum_users)}",
                confidence="high"))
    else:
        notes.append("未定位到登录端点，用户枚举与速率限制检查未执行")

    # ---- 弱口令（默认关闭）----
    weak_hit = None
    if weak_creds and login_url:
        pairs = [("admin", "admin"), ("admin", "123456"), ("admin", "admin123"),
                 ("test", "test"), ("root", "root"), ("user", "user")]
        for u, p in pairs:
            try:
                if login_method == "get":
                    rr = sess.request("GET", login_url,
                                      params={fields["user"]: u, fields["pass"]: p})[0]
                else:
                    rr = sess.request("POST", login_url,
                                      data={fields["user"]: u, fields["pass"]: p})[0]
            except (BudgetExceeded, OSError):
                break
            if rr is None:
                continue
            success = (rr.status_code in (301, 302, 303) and
                       "login" not in (rr.headers.get("location") or "").lower()) or \
                      (rr.status_code == 200 and any(
                          k in (rr.text or "").lower()
                          for k in ("welcome", "dashboard", "logout", "欢迎", "退出")))
            if success and not _looks_blocked(rr.status_code, rr.text or ""):
                weak_hit = (u, p)
                break
        if weak_hit:
            issues.append(_issue(
                "auth-audit", "critical", "认证与会话", "登录接口存在弱口令", login_url,
                f"使用默认口令组合 `{weak_hit[0]}/{weak_hit[1]}` 即可成功登录。"
                "默认口令是最容易被自动化工具批量扫中的入口，一旦命中通常直接导致系统失陷。",
                "修改所有默认口令并强制复杂度策略；启用多因素认证；"
                "对来自内网的登录同样保持警惕，不要依赖网络边界。",
                cwe="CWE-521", method=login_method.upper(),
                evidence=f"口令组合 {weak_hit[0]}/{weak_hit[1]} 登录成功",
                confidence="high"))

    summary = (f"{'Basic 认证启用；' if basic else ''}"
               f"{'登录端点 ' + login_url + '；' if login_url else '未找到登录端点；'}"
               f"可枚举用户 {len(enum_users)} 个；"
               f"速率限制{'未见' if login_url and not lockout_observed else '（未检查/已见）'}"
               + (f"；弱口令命中 {weak_hit[0]}/{weak_hit[1]}" if weak_hit else ""))
    return {"ok": True, "summary": summary,
            "data": {"url": url, "basic_auth": basic, "plaintext_transport": is_plain,
                     "login_endpoint": login_url, "login_method": login_method,
                     "enumerable_users": enum_users,
                     "rate_limit_observed": (True if lockout_observed else
                                             (False if login_url else None)),
                     "weak_credentials_found": bool(weak_hit),
                     "weak_creds_enabled": bool(weak_creds)},
            "issues": issues, "notes": notes}


# ============================================================ API 深度审计

_GQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphql/", "/gql",
              "/api/gql", "/query", "/graphiql", "/v2/graphql"]

_OPENAPI_PATHS = ["/swagger.json", "/openapi.json", "/v3/api-docs", "/v2/api-docs",
                  "/api-docs", "/swagger/v1/swagger.json", "/api/openapi.json",
                  "/openapi.yaml", "/swagger.yaml", "/doc.html", "/swagger-resources",
                  "/.well-known/openapi.json"]

_INTROSPECTION_Q = "query IntrospectionQuery { __schema { queryType { name } types { name } } }"


@tool("api_audit",
      "API 深度审计（**只读**）：探测 GraphQL 端点并判断 introspection 是否开启、"
      "发现并解析 OpenAPI/Swagger 文档（统计接口数、是否声明鉴权方案）、"
      "对已发现的接口用 OPTIONS 审计其声明的 HTTP 方法面（是否暴露 PUT/DELETE 等写方法）。",
      {"url": "str，站点根地址或首页 URL"},
      phase="scan", category="API 安全")
def api_audit(sess: ScanSession, url: str) -> dict:
    origin = origin_of(url)
    issues: list[dict] = []
    notes: list[str] = []

    # ---- GraphQL ----
    gql_found: list[str] = []
    gql_introspection: list[str] = []
    for path in _GQL_PATHS:
        full = origin + path
        try:
            r, _e = sess.request("GET", full, params={"query": "{__typename}"})
        except (BudgetExceeded, OSError):
            break
        if r is None or r.status_code >= 500:
            continue
        ct = (r.headers.get("content-type") or "").lower()
        if "json" not in ct:
            continue
        try:
            data = r.json()
        except Exception:
            continue
        if not isinstance(data, dict) or "data" not in data:
            continue
        # `/graphql` 与 `/graphql/` 是同一个端点，框架通常两者都路由。
        # 不归一化就会把同一个缺陷报成两条，看起来像两个独立问题。
        norm = path.rstrip("/") or "/"
        if norm in {p.rstrip("/") or "/" for p in gql_found}:
            continue
        gql_found.append(path)
        # introspection 用一个最小的 schema 查询单独确认
        try:
            r2, _e2 = sess.request("POST", full, json={"query": _INTROSPECTION_Q},
                                   headers={"Content-Type": "application/json"})
        except (BudgetExceeded, OSError):
            r2 = None
        if r2 is not None and "__schema" in (r2.text or ""):
            gql_introspection.append(path)
        if len(gql_found) >= 3:
            break

    for path in gql_introspection:
        issues.append(_issue(
            "api-audit", "medium", "API 安全",
            f"GraphQL introspection 处于开启状态（`{path}`）",
            origin + path,
            "该 GraphQL 端点未凭据即可执行内省查询并返回完整 schema。"
            "攻击者据此可以直接拿到全部类型、字段、参数与关联关系，"
            "把「盲测」变成「照单测试」，同时也能发现本不该暴露的内部字段"
            "（如内部状态、调试字段、被废弃但仍可调用的接口）。",
            "生产环境关闭 introspection（Apollo Server `introspection: false`；"
            "GraphQL Java `graphql.servlet.disable-introspection=true`）；"
            "对所有查询启用深度/复杂度限制与查询白名单。",
            cwe="CWE-200", method="POST",
            evidence=f"POST {origin}{path} 返回体包含 `__schema`",
            confidence="high"))
    if gql_found and not gql_introspection:
        notes.append(f"发现 GraphQL 端点 {'、'.join(gql_found)}，introspection 已关闭（正确实现）")

    # ---- OpenAPI / Swagger 文档 ----
    docs: list[dict] = []
    for path in _OPENAPI_PATHS:
        full = origin + path
        try:
            r, _e = sess.request("GET", full)
        except (BudgetExceeded, OSError):
            break
        if r is None or not (200 <= r.status_code < 300):
            continue
        body = r.text or ""
        ct = (r.headers.get("content-type") or "").lower()
        if "json" in ct or body.lstrip().startswith("{"):
            try:
                spec = r.json()
            except Exception:
                continue
            if not isinstance(spec, dict) or "paths" not in spec:
                continue
            paths = spec.get("paths") or {}
            ops = sum(len([k for k in v if k in ("get", "post", "put", "delete",
                                                 "patch", "head", "options")])
                      for v in paths.values() if isinstance(v, dict))
            schemes = list((spec.get("components", {}).get("securitySchemes") or
                            spec.get("securityDefinitions") or {}).keys())
            unsecured = [p for p, v in paths.items()
                         if isinstance(v, dict) and not v.get("security")]
            docs.append({"path": path, "title": str((spec.get("info") or {}).get("title", "")),
                         "version": str((spec.get("info") or {}).get("version", "")),
                         "path_count": len(paths), "operations": ops,
                         "security_schemes": schemes,
                         "no_security_declared": len(unsecured)})
            if len(docs) >= 3:
                break
        elif "html" in ct and re.search(r"(?i)swagger-ui|knife4j|openapi|redoc", body):
            docs.append({"path": path, "title": "接口文档页面", "version": "",
                         "path_count": 0, "operations": 0,
                         "security_schemes": [], "no_security_declared": 0})

    for d in docs:
        if d["path_count"]:
            issues.append(_issue(
                "api-audit", "medium", "API 安全",
                f"接口文档对外暴露且可直接解析（`{d['path']}`）",
                origin + d["path"],
                f"`{origin}{d['path']}` 无需凭据即可访问，且是结构化的接口描述文件："
                f"标题「{d['title']}」版本 {d['version'] or '未知'}，共 {d['path_count']} 个路径、"
                f"{d['operations']} 个操作。"
                + (f"声明的鉴权方案：{'、'.join(d['security_schemes'])}；"
                   if d["security_schemes"] else "文档中**没有声明任何鉴权方案**；")
                + f"其中 {d['no_security_declared']} 个路径未标注 security 字段。"
                  "这份文档等于把接口清单一并交给攻击者，配合参数结构可直接构造请求，"
                  "并优先挑选未声明鉴权的接口试探未授权访问。",
                "生产环境关闭接口文档（`springdoc.api-docs.enabled=false`、"
                "`knife4j.production=true`）；确需保留时加鉴权并限制来源 IP；"
                "同时在文档中如实标注每个接口的鉴权要求。",
                cwe="CWE-200", evidence=f"GET {origin}{d['path']} → 200，"
                                       f"paths={d['path_count']} ops={d['operations']}",
                confidence="high"))
        else:
            notes.append(f"{origin}{d['path']} 是接口文档页面，建议确认是否需要鉴权")

    # ---- 端点方法面 ----
    endpoints = ((sess.discovered.get("endpoints") or {}).get(origin) or [])
    limit = {"quick": 6, "standard": 20, "deep": 40}.get(sess.depth, 20)
    writable: list[tuple[str, str]] = []
    for path in endpoints[:limit]:
        try:
            r, _e = sess.request("OPTIONS", origin + path)
        except (BudgetExceeded, OSError):
            break
        if r is None:
            continue
        allow = r.headers.get("allow", "")
        risky = [m for m in ("PUT", "DELETE", "PATCH") if m in allow.upper()]
        if risky:
            writable.append((path, allow))

    if writable:
        listed = "、".join(f"`{p}`（{a}）" for p, a in writable[:6])
        issues.append(_issue(
            "api-audit", "medium", "API 安全",
            f"{len(writable)} 个接口声明支持写方法", origin,
            f"以下接口在 OPTIONS 响应中声明支持 PUT/DELETE/PATCH：{listed}。"
            "本次只读取了 Allow 头，**没有实际发送写请求**，因此无法确认这些方法是否有鉴权。"
            "若确实缺失鉴权，攻击者可直接改写或删除业务数据。",
            "确认这些写方法在服务端有独立鉴权（不要依赖前端不提供入口）；"
            "不需要的方法直接在网关层拒绝；对批量删除类接口加入二次确认与操作审计。",
            cwe="CWE-650", method="OPTIONS",
            evidence="；".join(f"OPTIONS {origin}{p} → Allow: {a}" for p, a in writable[:6]),
            confidence="medium"))

    summary = (f"GraphQL 端点 {len(gql_found)} 个"
               f"{'（introspection 开启 ' + str(len(gql_introspection)) + ' 个）' if gql_introspection else ''}，"
               f"接口文档 {len(docs)} 份，声明写方法的接口 {len(writable)} 个")
    return {"ok": True, "summary": summary,
            "data": {"url": url, "graphql_endpoints": gql_found,
                     "graphql_introspection": gql_introspection,
                     "api_docs": docs,
                     "write_method_endpoints": [{"path": p, "allow": a} for p, a in writable]},
            "issues": issues, "notes": notes}


# ============================================================ WAF 识别

# 被动特征：CDN/WAF 厂商会在响应头或 Cookie 里留下自己的标记
_WAF_SIGNS: list[tuple[str, str]] = [
    ("Cloudflare", r"cf-ray|__cfduid|cf-cache-status|cloudflare"),
    ("Akamai", r"akamai|x-akamai|akamai-grn"),
    ("AWS CloudFront / WAF", r"x-amz-cf-id|x-amzn-requestid|awselb"),
    ("Imperva / Incapsula", r"x-iinfo|incap_ses|visid_incap|incapsula"),
    ("F5 BIG-IP ASM", r"bigipserver|ts[0-9a-f]{4,}|x-wa-info|f5-"),
    ("Sucuri", r"x-sucuri-id|x-sucuri-cache|sucuri"),
    ("Barracuda", r"barra_counter_session|barracuda"),
    ("ModSecurity", r"mod_security|modsecurity|nosniff-from-modsecurity"),
    ("安全狗 SafeDog", r"safedog|safedog-flow-item"),
    ("阿里云 WAF", r"aliyungf_tc|acw_tc|yundun"),
    ("腾讯云 WAF / 大禹", r"tencent|dayu|stgw"),
    ("华为云 WAF", r"hwwafsesid|hw-waf"),
    ("宝塔 WAF", r"btwaf|bt_waf"),
    ("360 网站卫士", r"360wzws|360waf|qianxin-360"),
    ("长亭雷池", r"chaitin|safeline|sl-session"),
    ("知道创宇 创宇盾", r"yunsuo_session|knownsec|创宇"),
    ("网宿 / 白山", r"wscdn|wangsu|baishancloud"),
]

# 主动触发：这几类载荷覆盖了最常被拦截的攻击特征
_WAF_PAYLOADS: list[tuple[str, str]] = [
    ("XSS", "<script>alert(1)</script>"),
    ("SQL 注入", "1' UNION SELECT NULL,NULL-- -"),
    ("路径穿越", "../../../../etc/passwd"),
    ("表达式注入", "${7*7}"),
    ("命令注入", ";cat /etc/passwd"),
]


@tool("waf_detect",
      "WAF / 防护设备识别：先按响应头与 Cookie 特征被动识别厂商，"
      "再投递 5 类典型攻击载荷观察是否被拦截，用于判断防护是否生效。"
      "**这一项的结论直接影响其它所有检测项的可信度** —— "
      "存在 WAF 时，多数「未发现」的真实含义是「被拦住了，没测到」。",
      {"url": "str，站点入口 URL"},
      phase="recon", category="扫描上下文")
def waf_detect(sess: ScanSession, url: str) -> dict:
    origin = origin_of(url)
    issues: list[dict] = []
    notes: list[str] = []

    # ---- 被动识别 ----
    vendors: list[str] = []
    header_blob = ""
    try:
        r, _e = sess.request("GET", url)
    except (BudgetExceeded, OSError):
        r = None
    if r is not None:
        cookies = r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else []
        header_blob = "\n".join(f"{k}: {v}" for k, v in r.headers.items()) + "\n" + "\n".join(cookies)
        for name, pat in _WAF_SIGNS:
            if re.search(pat, header_blob, re.I):
                vendors.append(name)

    # ---- 主动触发 ----
    baseline_status = r.status_code if r is not None else 0
    blocked_by: list[tuple[str, str, int]] = []
    for kind, payload in _WAF_PAYLOADS:
        probe = f"{origin}/aih0ley-waf-{abs(hash(kind)) % 10000}?x={quote(payload, safe='')}"
        try:
            rr, _e = sess.request("GET", probe)
        except (BudgetExceeded, OSError):
            break
        if rr is None:
            continue
        if _looks_blocked(rr.status_code, rr.text or "") and baseline_status < 400:
            blocked_by.append((kind, payload, rr.status_code))
        elif rr.status_code in (403, 406, 412, 429, 501) and baseline_status < 400:
            # 状态码被拦但页面不带拦截特征 —— 可能是 WAF 静默返回，也可能是
            # 应用自身的访问控制。单凭这一条不下结论，只记录。
            blocked_by.append((kind, payload + "（无拦截页特征）", rr.status_code))

    strong_blocks = [b for b in blocked_by if "无拦截页特征" not in b[1]]
    is_waf = bool(vendors) or len(strong_blocks) >= 2 or \
        len([b for b in blocked_by]) >= 3

    if is_waf:
        src = []
        if vendors:
            src.append(f"响应特征命中：{'、'.join(vendors)}")
        if blocked_by:
            src.append(f"{len(blocked_by)} 类攻击载荷被拦截（"
                       + "、".join(f"{k}→{s}" for k, _p, s in blocked_by[:4]) + "）")
        issues.append(_issue(
            "waf-detect", "info", "扫描上下文", "目标部署了 WAF / 防护设备", url,
            "检测到目标前存在 Web 应用防火墙或同类防护设备：" + "；".join(src) + "。"
            "**这不是一个漏洞，但它会显著改变本次扫描结论的解读方式**："
            "很多攻击载荷在到达应用之前就被拦掉了，因此「未发现某类漏洞」"
            "的真实含义可能是「该类载荷被拦截、应用本身并未被真正测到」，"
            "而不是「应用不存在该类漏洞」。",
            "在防护设备上确认拦截策略与放行白名单；"
            "对本次扫描报出的「未发现」项，建议在临时放行扫描源 IP 后复测一次，"
            "以区分「应用安全」与「WAF 挡住了」。",
            cwe="", evidence="；".join(src)[:600], confidence="high"))
        notes.append("存在 WAF：本轮所有「未发现」类结论的可信度下降，建议放行扫描源后复测")
    else:
        notes.append("未识别到 WAF 特征，攻击载荷可直接到达应用，"
                     "因此本轮「未发现」类结论可信度较高")
    if blocked_by and not is_waf:
        notes.append(f"{len(blocked_by)} 次探测返回拦截类状态码但无 WAF 特征，"
                     "疑似应用自身访问控制，未判定为 WAF")

    summary = (f"{'识别到 WAF：' + '、'.join(vendors) if vendors else '未识别到 WAF 厂商特征'}；"
               f"载荷拦截 {len(blocked_by)}/{len(_WAF_PAYLOADS)}")
    return {"ok": True, "summary": summary,
            "data": {"url": url, "vendors": vendors, "waf_detected": is_waf,
                     "blocked": [{"kind": k, "status": s} for k, _p, s in blocked_by],
                     "payloads_tested": len(_WAF_PAYLOADS)},
            "issues": issues, "notes": notes}
