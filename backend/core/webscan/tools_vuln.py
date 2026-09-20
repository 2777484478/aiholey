"""Web 扫描应用层漏洞工具集（一）—— XSS / CSRF / 凭据泄漏 / CRLF 注入。

与其它模块的分工
----------------
tools.py        对 HTTP 端点做常规配置与内容检查（响应头、Cookie、目录、信息泄漏）
tools_deep.py   端口与服务识别，以及参数型注入、目录遍历、前端接口面
tools_vuln.py   本模块：**需要理解上下文语义**才能判定的应用层缺陷
tools_expose.py 暴露面与攻击面测绘（凭据、组件版本、认证、API、WAF）

为什么这四类必须单独成组
------------------------
它们的共同点是「响应里出现过某个字符串」完全不足以定性，
判定必须带上**上下文**：

- XSS：同样的载荷，落在 HTML 文本里是可执行的，落在被引号包住的属性里
  只是一段普通文字。只做「载荷是否被回显」会把两者混为一谈。
- CSRF：不存在「响应里有什么」这回事，要综合表单有无 token、Cookie 有无
  SameSite、是否用 GET 承载状态变更三项才能定性。
- 凭据泄漏：`AKIAIOSFODNN7EXAMPLE` 是 AWS 官方文档里的示例串，
  把它报成「AWS 密钥泄漏」会让报告立刻失去可信度。
- CRLF：唯一可靠判据是**响应头里凭空多出的那个头**，
  只看响应体永远测不出来。

安全边界
--------
- XSS / CSRF / CRLF 全部只发 GET，不改动任何服务端状态；
- CSRF **不提交表单**，只做静态判定（缺 token、缺 SameSite、GET 改状态）；
- 凭据扫描只读已抓取到的文本，不额外构造探测。
"""
from __future__ import annotations

import base64
import json
import re
from urllib.parse import parse_qsl, urlparse

from backend.core.webscan.tools import (
    BudgetExceeded,
    DISCOVERED_LANDING_CAP,
    ScanSession,
    _issue,
    _snippet,
    dedup_issues,
    origin_of,
    sanitize_text,
    tool,
    uniq,
)

# ============================================================ 共用小工具

_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.I)

# 反射型 XSS 的唯一标记：既够独特（不会撞上页面原有内容），
# 又全是字母数字（不会被服务端或 WAF 当成攻击特征直接拦掉，
# 否则「载荷被 WAF 拦了」会被误读成「没有反射」）。
XSS_MARKER = "aih0leyzq7"

# WAF 拦截页特征：拦截页常常把原始请求回显出来，
# 不排除掉的话，每一次被拦截都会被判成一次「成功的反射型 XSS」。
_WAF_BLOCK_RE = re.compile(
    r"(?i)(request blocked|access denied|has been blocked|security policy|"
    r"网站防火墙|安全狗|云锁|拦截|拒绝访问|forbidden by|attention required|"
    r"incident id|ray id|waf)")
_WAF_STATUS = {400, 403, 405, 406, 412, 418, 429, 501}


def _iter_scripts(sess: ScanSession, origin: str, html: str,
                  limit: int) -> list[str]:
    """从 HTML 里列出要抓的 JS bundle 绝对地址，按档位截断。

    排序复用 tools_deep 的经验：`-es5` 是 `-es2015` 的降级副本，只抓一个；
    带 main/app/chunk/vendor 的才是业务代码。
    """
    seen: list[str] = []
    for m in _SCRIPT_SRC_RE.finditer(html or ""):
        src = m.group(1).strip()
        if not src or src.startswith(("data:", "blob:", "javascript:")):
            continue
        full = src if src.startswith("http") else f"{origin}/{src.lstrip('/')}"
        if not full.startswith(("http://", "https://")):
            continue
        if full not in seen:
            seen.append(full)

    def rank(u: str) -> tuple:
        name = u.rsplit("/", 1)[-1].lower()
        return (1 if "-es5" in name or ".es5." in name else 0,
                0 if any(k in name for k in ("main", "app", "chunk", "vendor",
                                             "index", "common", "config")) else 1,
                -len(name))
    return sorted(seen, key=rank)[:limit]


def _looks_blocked(status: int, body: str) -> bool:
    """响应像不像 WAF 拦截页。"""
    return status in _WAF_STATUS and bool(_WAF_BLOCK_RE.search(body or ""))


def _page_text(sess: ScanSession, url: str) -> tuple[str, int, str]:
    """取首页文本，返回 (HTML, 状态码, Content-Type)。"""
    try:
        resp, _err = sess.request("GET", url)
    except (BudgetExceeded, OSError):
        return "", 0, ""
    if resp is None:
        return "", 0, ""
    ctype = (resp.headers.get("content-type") or "").split(";")[0].strip().lower()
    raw = resp.content or b""
    return raw[:400000].decode(resp.encoding or "utf-8", "replace"), resp.status_code, ctype


def _same_origin_params(url: str) -> list[str]:
    out: list[str] = []
    for k, _v in parse_qsl(urlparse(url).query, keep_blank_values=True):
        if k and k not in out:
            out.append(k)
    return out


def _raw_query_with(base_q: str, name: str, value: str) -> str:
    """把查询串里同名参数**替换**掉，而不是追加。

    这是一个必须踩过一次才会记住的坑：追加会得到 `file=home&file=<载荷>`，
    而 `parse_qs` / `$_GET` / 绝大多数框架取的都是**第一个**值，
    于是精心构造的载荷从头到尾没生效，扫描器却报告「试过了、没问题」。
    这种静默失效比直接报错难查得多——它看起来是一次成功的阴性结论。
    """
    kept: list[str] = []
    for part in (base_q or "").split("&"):
        if not part:
            continue
        if part.split("=", 1)[0] == name:
            continue
        kept.append(part)
    kept.append(f"{name}={value}")
    return "&".join(kept)


# ============================================================ 反射型 XSS 上下文判定

# 无损可用的探测串务必带标记前缀：判据里要用「标记之后的那一段」当作
# 真正的注入片段，这样属性闭合分析才不会把标记本身算进去。
XSS_PROBES: list[tuple[str, str]] = [
    ("无引号标签注入", f"{XSS_MARKER}<svg/onload=alert(1)>"),
    ("双引号闭合标签注入", f'{XSS_MARKER}"><svg/onload=alert(1)>'),
    ("单引号闭合标签注入", f"{XSS_MARKER}'><svg/onload=alert(1)>"),
]


def _reflect_context(html: str, idx: int) -> tuple[str, str]:
    """判断反射点落在什么 HTML 上下文里，返回 (上下文, 未闭合的引号)。

    上下文取值：
      ``text``    —— 标签之间，注入的 ``<x>`` 会被浏览器当标签解析
      ``tag``     —— 标签内部但不在引号里（属性名区域）
      ``attr``    —— 标签内部且处于引号包住的属性值中
      ``script`` / ``style`` —— raw-text 元素内部，``<`` 不具备标记语义
      ``comment`` —— HTML 注释内

    为什么要区分到这个粒度：载荷 `aih0leyzq7<svg/onload=alert(1)>` 在
    `text` 里是一个能执行的标签，在 `value="…"` 里却只是一串普通字符。
    只判「载荷被原样回显」的实现会把这两种情况一起报成高危。
    """
    s = html[:idx]
    n = len(s)
    pos = 0
    raw = ""                      # 当前所在的 raw-text 元素名
    while pos < n:
        lt = s.find("<", pos)
        if lt < 0:
            break
        if raw:
            m = re.compile(r"</" + raw + r"\s*>", re.I).search(s, lt)
            if not m:
                return (raw, "")
            raw, pos = "", m.end()
            continue
        if s.startswith("<!--", lt):
            end = s.find("-->", lt + 4)
            if end < 0:
                return ("comment", "")
            pos = end + 3
            continue
        if s.startswith(("<!", "<?"), lt):
            gt = s.find(">", lt)
            if gt < 0:
                return ("tag", "")
            pos = gt + 1
            continue
        m = re.match(r"</?\s*([a-zA-Z][a-zA-Z0-9:._-]*)", s[lt:])
        if not m:
            pos = lt + 1              # 孤立的 `<`，当作普通文本
            continue
        tag = m.group(1).lower()
        # 找这个标签的 `>`，跳过属性引号里的内容
        quote, j = "", lt + 1
        while j < n:
            c = s[j]
            if quote:
                if c == quote:
                    quote = ""
            elif c in "\"'":
                quote = c
            elif c == ">":
                break
            j += 1
        if j >= n:
            # 标签尚未闭合 —— 反射点就落在这个开标签内部
            return ("attr" if quote else "tag", quote)
        if not s.startswith("</", lt) and tag in ("script", "style"):
            raw = tag
        pos = j + 1
    return ("text", "")


def _attr_escape(payload: str, quote: str) -> bool:
    """载荷能不能从引号包住的属性值里逃出来并另开一个标签。

    条件：载荷里出现了相同的引号 → 属性值提前结束；引号之后有 `>` → 标签结束；
    `>` 之后还有 `<` → 开了一个新标签。三者缺一，`<svg…>` 都只是属性里的普通字符。
    """
    if not quote:
        return False
    k = payload.find(quote)
    if k < 0:
        return False
    rest = payload[k + 1:]
    gt = rest.find(">")
    if gt < 0:
        return False
    return "<" in rest[gt + 1:]


def _judge_reflection(body: str, probe: str) -> tuple[str, str, str]:
    """判定一条反射能到什么程度。

    返回 ``("confirmed"|"likely"|"", 上下文说明, 依据)``。
    空字符串表示「反射存在但不可利用」，调用方不该为它出报告——
    这类噪声（被编码的反射、注释内反射）会让报告淹没在无效条目里。
    """
    idx = body.find(probe)
    if idx < 0:
        return "", "", ""
    ctx, quote = _reflect_context(body, idx)
    payload = probe[len(XSS_MARKER):]

    if ctx == "comment":
        return "", "", ""
    if ctx in ("script", "style"):
        # 脚本/样式块内的上下文取决于引号闭合与语句位置，
        # 静态判不出「一定能执行」，但也不能放过——交人工复核。
        return "likely", f"{'脚本' if ctx == 'script' else '样式'}块内部（{ctx} 上下文）", \
            "载荷被原样回显在脚本区域内，能否执行取决于外层引号与语句结构，需人工复核"
    if ctx == "tag":
        if ">" in payload:
            return "likely", "标签内部（未引号包裹）", \
                "载荷落在标签内部，可注入新的属性或提前结束标签"
        return "", "", ""
    if ctx == "attr":
        if _attr_escape(payload, quote):
            return "confirmed", f"引号包裹的属性值内，且可用 {quote} 闭合逃逸", \
                f"载荷中的 {quote} 提前结束了属性值，随后的 `>` 结束标签并新建了可执行标签"
        return "", "", ""
    # ctx == "text"
    if "<" in payload and ">" in payload:
        return "confirmed", "标签之间的文本位置", \
            "载荷中的 `<svg/onload=…>` 被原样输出到标签之间，浏览器会把它解析成真实元素并触发 onload"
    return "", "", ""


@tool("xss_check",
      "跨站脚本检测（**只读**）：反射型 XSS 走**上下文判定**——先判断反射点落在 "
      "HTML 文本 / 引号属性 / 脚本块 / 注释的哪一处，再判断载荷能否真的逃逸并新建标签，"
      "把「被编码的无效回显」与「可执行注入」区分开；"
      "同时静态分析页面 JS bundle 的 source→sink 数据流，识别 DOM 型 XSS 风险点。",
      {"url": "str，目标 URL（可自带查询串）",
       "params": "list[str]，可选，指定要检测的参数名"},
      phase="scan", category="注入与参数")
def xss_check(sess: ScanSession, url: str, params: list | None = None) -> dict:
    origin = origin_of(url)
    html, status, ctype = _page_text(sess, url)
    issues: list[dict] = []
    notes: list[str] = []

    # ---------------- 反射型 ----------------
    default_names = ["q", "s", "search", "keyword", "name", "msg", "message", "title",
                     "content", "text", "comment", "callback", "lang", "redirect",
                     "url", "next", "return", "ref", "id", "page", "view", "action"]
    given = _same_origin_params(url)
    extra = [p for p in (params or []) if isinstance(p, str) and p.strip()]
    names = uniq(given + extra + [p for p in default_names if p not in given])[:12]

    # 落点：入口 URL + api_surface 采集到的带参 URL。
    # 反射型 XSS 的参数通常不在首页——它长在「搜索 / 详情 / 回显消息」这类功能页上
    # （`?q=`、`?keyword=`、`?msg=`）。只测入口时，报告里的「未发现」并不代表
    # 站点没有反射点，只代表没找到落点。
    landings: list[tuple[str, list[str]]] = [(url, names)]
    seen_paths = {urlparse(url).path}
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
        landings.append((du, own[:6]))
        disc_added += 1

    confirmed: list[tuple[str, str, str, str, str, str, str]] = []  # …, 落点URL
    likely: list[tuple[str, str, str, str, str, str, str]] = []
    encoded = 0
    blocked = 0
    tested = 0

    for base, bnames in landings:
        for name in bnames:
            for label, probe in XSS_PROBES:
                tested += 1
                try:
                    resp, _e = sess.request("GET", base, params={name: probe})
                except (BudgetExceeded, OSError):
                    break
                if resp is None:
                    continue
                rct = (resp.headers.get("content-type") or "").lower()
                body = resp.text or ""
                if _looks_blocked(resp.status_code, body):
                    blocked += 1
                    continue
                if "html" not in rct:
                    continue                    # 非 HTML 上下文里标签不会被解析
                verdict, ctx, why = _judge_reflection(body, probe)
                if verdict == "confirmed":
                    confirmed.append((name, label, probe, ctx, why, body, base))
                    break                       # 同一参数已确认，不必再试其它载荷
                if verdict == "likely":
                    likely.append((name, label, probe, ctx, why, body, base))
                elif XSS_MARKER in body:
                    encoded += 1                # 标记在但载荷被编码/过滤 → 无效反射

    for name, label, probe, ctx, why, body, base in confirmed:
        issues.append(_issue(
            "xss-check", "high", "注入与参数", f"反射型 XSS 参数 `{name}`", base,
            f"用「{label}」载荷确认参数 `{name}` 的取值被原样写入页面，"
            f"且落在{ctx}。{why}。攻击者可构造链接在受害者浏览器中执行任意脚本，"
            "用于窃取会话 Cookie、冒充用户操作。",
            "对输出做**上下文相关**的编码（HTML 文本用实体编码、属性值用引号+实体编码、"
            "脚本内用 JSON 序列化）；对输入做白名单校验；辅以 CSP 作为第二道防线。",
            cwe="CWE-79", method="GET", param=name, payload=probe,
            evidence=_snippet(body, needle=XSS_MARKER, width=260), confidence="high"))

    for name, label, probe, ctx, why, body, base in likely:
        issues.append(_issue(
            "xss-check", "medium", "注入与参数", f"疑似反射型 XSS 参数 `{name}`", base,
            f"参数 `{name}` 的取值被原样回显，落在{ctx}。{why}。"
            "本次未取得「可直接执行」的确证，但输出未做编码是事实，建议人工构造浏览器验证。",
            "对输出做上下文相关编码；不要在脚本块内直接拼接用户输入。",
            cwe="CWE-79", method="GET", param=name, payload=probe,
            evidence=_snippet(body, needle=XSS_MARKER, width=260), confidence="medium"))

    # 入口 URL 与页面表单可能都反射同一个参数名，同一个根因只报一条
    issues = dedup_issues(issues)

    if encoded:
        notes.append(f"{encoded} 次反射中标记被回显，但载荷被编码、或落在无法逃逸的上下文里，"
                     "已判定为不可利用，未计入问题")
    if blocked:
        notes.append(f"{blocked} 次探测被 WAF/防护拦截，反射型 XSS 结论不完整")
    if disc_added:
        notes.append(f"除入口路径外，还在该站 {disc_added} 个带参数的落点上做了反射测试"
                     f"（如 `{urlparse(landings[1][0]).path}?{urlparse(landings[1][0]).query}`）")
    elif not given:
        notes.append("入口 URL 未携带参数，且未取得带参数的落点清单"
                     "（`api_surface` 未运行，或页面里没有带查询串的链接/表单），"
                     "反射型结论覆盖面受限")
    if not confirmed and not likely:
        notes.append(f"测试 {len(names)} 个参数共 {tested} 次载荷，未发现可利用的反射型 XSS")

    # ---------------- DOM 型（静态数据流） ----------------
    dom_hits: list[tuple[str, str, str, str]] = []
    bundles = _iter_scripts(sess, origin, html, {"quick": 4, "standard": 10, "deep": 18}
                            .get(sess.depth, 10))
    for src in bundles:
        text, _e = sess.fetch_text(src)
        if not text:
            continue
        dom_hits += _scan_dom_sinks(src, text)
        if len(dom_hits) >= 8:
            break

    for src, sink, source, window in dom_hits[:6]:
        issues.append(_issue(
            "xss-check", "medium", "注入与参数", f"疑似 DOM 型 XSS：{sink}", src,
            f"页面脚本中，来自 {source} 的数据在未做净化的情况下流入了 {sink}。"
            f"静态数据流片段：…{window}…。这类漏洞不经过服务端，"
            "服务端输出编码对它无效，只能在浏览器里复现验证。",
            "改用 textContent / createElement 等安全 API；必须写 HTML 时先做白名单净化"
            "（如 DOMPurify）；对外部输入做 URL 参数解析与长度限制。",
            cwe="CWE-79", method="GET",
            evidence=window, confidence="medium"))
    if not dom_hits and bundles:
        notes.append(f"静态分析 {len(bundles)} 个 JS bundle，未发现明显的 source→sink 数据流")

    summary = (f"反射型：测试 {len(names)} 个参数，确认 {len(confirmed)} 个、"
               f"疑似 {len(likely)} 个；DOM 型：静态命中 {len(dom_hits)} 处")
    return {"ok": True, "summary": summary,
            "data": {"url": url, "status": status, "params": names,
                     "reflected_confirmed": [x[0] for x in confirmed],
                     "reflected_likely": [x[0] for x in likely],
                     "dom_sinks": [{"script": s, "sink": k, "source": sr}
                                   for s, k, sr, _w in dom_hits],
                     "bundles_analyzed": len(bundles)},
            "issues": issues, "notes": notes}


# DOM 型 XSS 的两端：数据来源（source）与危险落点（sink）
_DOM_SOURCES = re.compile(
    r"(?i)\b(location\s*\.\s*(?:hash|search|href|pathname|protocol)|"
    r"document\s*\.\s*(?:URL|documentURI|referrer)|window\s*\.\s*name|"
    r"event\s*\.\s*data|\.\s*getParameter\s*\(|"
    r"decodeURIComponent\s*\(\s*location|URLSearchParams)")

_DOM_SINKS: list[tuple[str, re.Pattern]] = [
    ("innerHTML 赋值", re.compile(r"\.\s*innerHTML\s*\+?=")),
    ("outerHTML 赋值", re.compile(r"\.\s*outerHTML\s*\+?=")),
    ("document.write", re.compile(r"document\s*\.\s*write(?:ln)?\s*\(")),
    ("insertAdjacentHTML", re.compile(r"insertAdjacentHTML\s*\(")),
    ("eval 执行", re.compile(r"\beval\s*\(")),
    ("Function 构造器", re.compile(r"\bnew\s+Function\s*\(")),
    ("setTimeout 字符串执行", re.compile(r"setTimeout\s*\(\s*[\"']")),
    ("setInterval 字符串执行", re.compile(r"setInterval\s*\(\s*[\"']")),
    ("jQuery html()", re.compile(r"\.\s*html\s*\(\s*[^)]{0,80}\)")),
    ("location 赋值（可被 javascript: 利用）",
     re.compile(r"location\s*\.\s*(?:href|assign|replace)\s*[=(]")),
    ("iframe srcdoc 注入", re.compile(r"\.\s*srcdoc\s*=")),
    ("jQuery $() 选择器注入", re.compile(r"\$\s*\(\s*(?:location|document\.URL|decodeURIComponent)")),
]

# source 与 sink 相距多远还算「同一条数据流」。
# 实测压缩过的 bundle 里两者常被压到很近；放宽到 600 字符能覆盖多数
# `var x = location.hash; ... el.innerHTML = x` 的写法，又不至于把
# 整个文件里毫不相干的两处凑成一对。
_DOM_WINDOW = 600


def _scan_dom_sinks(src: str, text: str) -> list[tuple[str, str, str, str]]:
    """在一个 JS 文件里找 source→sink 的近邻共现。

    每个 sink 只取第一处命中：一个文件里同一个 sink 被写了十遍，
    报告出十条「疑似 DOM 型 XSS」只会淹没真正该看的那一条。
    """
    out: list[tuple[str, str, str, str]] = []
    sources = [(m.start(), m.group(0)) for m in _DOM_SOURCES.finditer(text)]
    if not sources:
        return out
    for sink_name, pat in _DOM_SINKS:
        for m in pat.finditer(text):
            lo, hi = max(0, m.start() - _DOM_WINDOW), min(len(text), m.end() + _DOM_WINDOW)
            near = [s for pos, s in sources if lo <= pos <= hi]
            if not near:
                continue
            start = max(0, m.start() - 140)
            end = min(len(text), m.end() + 180)
            out.append((src, sink_name, near[0], re.sub(r"\s+", " ", text[start:end])[:230]))
            break
    return out


# ============================================================ CSRF

_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
_INPUT_RE = re.compile(r"<(?:input|select|textarea|button)\b([^>]*)>", re.I)
_ATTR_RE = re.compile(r"""([\w:.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))""")

# 各框架的 token 字段名（Laravel / Rails / Django / ASP.NET / Spring Security / Express）
_CSRF_TOKEN_RE = re.compile(
    r"(?i)(csrf|xsrf|_token|authenticity_token|__requestverificationtoken|"
    r"anticsrf|csrfmiddlewaretoken|_csrf|nonce|verification[_-]?token|form[_-]?token)")

# 状态变更语义的动词 —— 出现在 action 或字段名里都算
_STATE_VERB_RE = re.compile(
    r"(?i)\b(delete|remove|create|update|edit|save|submit|approve|reject|disable|"
    r"enable|reset|revoke|grant|transfer|pay|payment|confirm|cancel|logout|signout|"
    r"sign_out|upload|import|publish|unpublish|add|modify|set|change|bind|unbind)\b")


def _forms(html: str) -> list[dict]:
    """把页面里的表单解析成结构化描述。"""
    out: list[dict] = []
    for m in _FORM_RE.finditer(html or ""):
        attrs = {k.lower(): (v1 or v2 or v3)
                 for k, v1, v2, v3 in _ATTR_RE.findall(m.group(1))}
        fields: list[tuple[str, str, str]] = []
        for im in _INPUT_RE.finditer(m.group(2)):
            ia = {k.lower(): (v1 or v2 or v3)
                  for k, v1, v2, v3 in _ATTR_RE.findall(im.group(1))}
            typ = (ia.get("type") or "text").lower()
            fields.append((ia.get("name", ""), typ, ia.get("value", "")))
        tokens = [(n, v) for n, t, v in fields
                  if n and (t == "hidden" or _CSRF_TOKEN_RE.search(n))]
        out.append({
            "action": attrs.get("action", ""),
            "method": (attrs.get("method") or "get").lower(),
            "fields": fields,
            "token_names": [n for n, _v in tokens],
            "token_empty": bool(tokens) and all(not v.strip() for _n, v in tokens),
        })
    return out


@tool("csrf_check",
      "跨站请求伪造（CSRF）防护检测（**只读，不提交任何表单**）：解析页面表单与响应头，"
      "判断状态变更表单是否携带 CSRF token、会话 Cookie 是否用 SameSite 兜底、"
      "是否存在用 GET 承载状态变更的端点。",
      {"url": "str，目标 URL（通常是含表单的页面）"},
      phase="scan", category="逻辑缺陷")
def csrf_check(sess: ScanSession, url: str) -> dict:
    html, status, _ct = _page_text(sess, url)
    issues: list[dict] = []
    notes: list[str] = []

    # 会话 Cookie 的 SameSite 是 CSRF 的最后一道兜底，必须一起看
    samesite: dict[str, str] = {}
    try:
        resp, _e = sess.request("GET", url)
        raw_cookies = resp.headers.get_list("set-cookie") if resp is not None else []
    except (BudgetExceeded, OSError):
        resp, raw_cookies = None, []
    for c in raw_cookies:
        name = c.split("=", 1)[0].strip()
        m = re.search(r"(?i)samesite\s*=\s*([\w]+)", c)
        samesite[name] = (m.group(1).capitalize() if m else "（未设置）")
    weak_cookie = [n for n, v in samesite.items() if v in ("（未设置）", "None")]
    strong_cookie = [n for n, v in samesite.items() if v in ("Lax", "Strict")]

    forms = _forms(html)
    if not forms:
        notes.append("页面中未解析到任何 <form>；若前端用 fetch/axios 提交 JSON，"
                     "CSRF 防护需在接口层人工确认（脚本类提交通常依赖自定义头，"
                     "浏览器跨站请求无法自动携带，风险相对较低）")
    state_forms = [f for f in forms
                   if _STATE_VERB_RE.search(f["action"]) or
                   any(_STATE_VERB_RE.search(n) or t == "password"
                       for n, t, _v in f["fields"])]
    post_no_token = [f for f in state_forms
                     if f["method"] == "post" and not f["token_names"]]
    get_state = [f for f in state_forms if f["method"] == "get"]
    empty_token = [f for f in forms if f["token_names"] and f["token_empty"]]

    for f in empty_token:
        issues.append(_issue(
            "csrf-check", "high", "逻辑缺陷", "CSRF token 存在但取值为空", url,
            f"表单 `{f['action'] or '(当前页)'}` 里虽有 `{f['token_names'][0]}` 字段，"
            "但值是空的。服务端如果只检查「字段是否存在」而不校验取值，"
            "这个 token 形同虚设，攻击者可以构造任意值的请求通过校验。",
            "在服务端校验 token 的**取值**（与会话绑定、一次性、有有效期），"
            "而不是只判断字段是否存在。", cwe="CWE-352", method=f["method"].upper(),
            evidence=f"form action={f['action']} token={f['token_names']} value=(空)",
            confidence="high"))

    for f in post_no_token:
        action = f["action"] or url
        if not samesite:
            sev, why, conf = "medium", "响应未下发任何 Cookie，跨站请求无法自动携带凭据，" \
                                       "实际利用需要目标具备基于 Cookie 的会话", "medium"
        elif weak_cookie:
            sev, why, conf = "high", (
                f"会话 Cookie {weak_cookie} 没有设置 SameSite（或设为 None），"
                "浏览器会在跨站请求中自动携带，攻击者只需诱导受害者访问一个页面即可完成操作"), "high"
        else:
            sev, why, conf = "medium", (
                f"会话 Cookie 设置了 SameSite={'/'.join(sorted(set(strong_cookie)))}，"
                "对跨站 POST 有缓解作用，但对跨站 GET 型与部分浏览器降级场景仍不充分"), "medium"
        issues.append(_issue(
            "csrf-check", sev, "逻辑缺陷", "状态变更表单缺少 CSRF token", action,
            f"表单 `{action}`（method=POST）会执行状态变更，但没有任何 CSRF token 字段。"
            f"{why}。攻击者可构造一个自动提交的页面，在受害者已登录的情况下代替其完成该操作。",
            "为所有状态变更请求加入与会话绑定、一次性的 CSRF token 并在服务端严格校验；"
            "同时给会话 Cookie 设置 `SameSite=Lax/Strict` 作为第二道防线。",
            cwe="CWE-352", method="POST",
            evidence=f"form action={action} method=post fields="
                     f"{[n for n, _t, _v in f['fields']][:8]}",
            confidence=conf))

    for f in get_state:
        action = f["action"] or url
        issues.append(_issue(
            "csrf-check", "medium", "逻辑缺陷", "使用 GET 承载状态变更", action,
            f"表单 `{action}` 用 GET 提交带状态变更语义的字段。GET 请求可以被"
            "`<img src=…>`、`<a>`、预取（prefetch）等任意方式触发，"
            "且不受 SameSite=Lax 保护，CSRF 防护难度大幅上升。",
            "状态变更一律使用 POST/PUT/DELETE，并配套 CSRF token；"
            "GET 只用于查询语义。", cwe="CWE-352", method="GET",
            evidence=f"form action={action} method=get fields="
                     f"{[n for n, _t, _v in f['fields']][:8]}",
            confidence="high"))

    protected = [f for f in forms if f["token_names"] and not f["token_empty"]]
    if protected and not post_no_token and not empty_token:
        notes.append(f"{len(protected)} 个表单已带有效 CSRF token")

    summary = (f"解析 {len(forms)} 个表单（其中 {len(state_forms)} 个含状态变更语义）："
               f"缺 token {len(post_no_token)} 个、空 token {len(empty_token)} 个、"
               f"GET 改状态 {len(get_state)} 个")
    return {"ok": True, "summary": summary,
            "data": {"url": url, "forms": [{"action": f["action"], "method": f["method"],
                                            "token": f["token_names"],
                                            "fields": [n for n, _t, _v in f["fields"]][:10]}
                                           for f in forms],
                     "samesite": samesite,
                     "state_forms": len(state_forms),
                     "no_token": len(post_no_token),
                     "get_state_change": len(get_state)},
            "issues": issues, "notes": notes}


# ============================================================ 凭据与密钥泄漏

# 云厂商 / 平台的凭据格式。这些格式由各厂商刻意设计得足够特征化，
# 因此「格式对得上」本身就构成强证据，不需要上下文推断。
_CRED_RULES: list[tuple[str, str, str, str]] = [
    ("AWS Access Key ID", "high", "CWE-798",
     r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"),
    ("GitHub Token", "critical", "CWE-798",
     r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b"),
    ("Slack Token", "high", "CWE-798",
     r"\b(xox[baprs]-[0-9A-Za-z-]{10,80})\b"),
    ("Stripe 密钥", "critical", "CWE-798",
     r"\b(sk_live_[0-9a-zA-Z]{24,})\b"),
    ("Google API Key", "high", "CWE-798",
     r"\b(AIza[0-9A-Za-z_\-]{35})\b"),
    ("Google OAuth 客户端 ID", "low", "CWE-200",
     r"\b(\d{10,}-[0-9a-z_]{32}\.apps\.googleusercontent\.com)\b"),
    ("阿里云 AccessKey ID", "high", "CWE-798",
     r"\b(LTAI[0-9A-Za-z]{12,20})\b"),
    ("腾讯云 SecretId", "high", "CWE-798",
     r"\b(AKID[0-9A-Za-z]{13,32})\b"),
    ("Azure 存储账号密钥", "critical", "CWE-798",
     r"(?i)AccountKey\s*=\s*([A-Za-z0-9+/=]{40,90})"),
    ("私钥内容", "critical", "CWE-798",
     r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----)"),
]

_DSN_RE = re.compile(
    r"(?i)\b((?:mysql|mariadb|postgres|postgresql|mongodb|mongodb\+srv|redis|rediss|"
    r"amqp|amqps|mssql|sqlserver|clickhouse|oracle|jdbc:(?:mysql|postgresql|oracle|sqlserver))"
    r"://[^\s'\"<>\\|]{8,240})")

# 带内嵌凭据的连接串（`scheme://user:pass@host`）才是真泄漏；
# 只有主机没有账号的（`redis://cache.internal:6379/0`）算端点信息暴露，降一级。
_DSN_WITH_CRED_RE = re.compile(r"://[^:/@\s]{1,64}:[^@\s/]{1,64}@")

_HARDCODED_RE = re.compile(
    r"""(?i)\b(?:password|passwd|pwd|pass|secret|token|apikey|api_key|access_key|"""
    r"""auth_token|client_secret|private_key)\s*[:=]\s*["']([^"'\s]{8,80})["']""")

# 占位符识别是这一整类检测的命门：
# `AKIAIOSFODNN7EXAMPLE` 是 AWS 官方文档的示例密钥，`your_password_here`
# 是脚手架模板的默认值。把它们报成泄漏，用户第一次翻报告就会认定扫描器不可信。
#
# 但也不能反过来把随机密钥误判成占位符 —— 第一版把 `abcdefgh`、`1234567890`
# 当成通用占位词，结果 `ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij` 这种
# 完全正常的令牌被整条漏掉。**漏报真凭据比误报示例值严重得多**，
# 所以判据收紧为：占位词必须被定界符（串首/串尾/`_`/`-`/`.`/空格）包住。
_PLACEHOLDER_TOKEN_RE = re.compile(
    r"(?i)(?:^|[_\-. ])(?:your|my|some|the|example|sample|demo|dummy|fake|test|"
    r"todo|fixme|placeholder|redacted|changeme|change|replace|here|unset|none|null|"
    r"empty|notset|x{4,})(?:$|[_\-. ])")

# 各厂商文档里公开的示例值：这些字符串在互联网上到处都是，
# 扫到它们只说明「这里抄了文档」，不说明有泄漏。
_KNOWN_EXAMPLE_VALUES = {
    "AKIAIOSFODNN7EXAMPLE",
    "WJALRXUTNFEMI/K7MDENG/BPXR FICYEXAMPLEKEY".replace(" ", ""),
    "AIZASYDAGMWKA4JSXZ-HJGW7ISLN_3NAMBGEWQE",
    "XOXB-000000000000-000000000000-XXXXXXXXXXXXXXXXXXXXXXXX",
}

# 纯口令占位：`password123`、`admin888` 这类脚手架默认值
_WEAK_DEFAULT_RE = re.compile(
    r"(?i)^(?:password|passwd|pwd|admin|root|test|user|guest|secret|token|qwerty|"
    r"letmein|welcome|changeme|default|iloveyou|monkey|dragon|abc123)\d*[!@#$%^&*_.-]*$")


def _is_placeholder(val: str) -> bool:
    """这个值看起来是不是「示例/占位/未填写」。"""
    v = (val or "").strip()
    if len(v) < 6:
        return True
    if v.upper() in _KNOWN_EXAMPLE_VALUES:
        return True
    if _PLACEHOLDER_TOKEN_RE.search(v):
        return True
    if _WEAK_DEFAULT_RE.match(v):
        return True
    if len(set(v)) <= 2:
        return True
    return False


def _clip(val: str) -> str:
    """证据里的凭据只留可人工比对的头尾，中间打码。

    报告本身不能成为新的泄漏源：把完整密钥写进 PDF/HTML 报告并转发出去，
    等于把泄漏面从服务器扩大到了每一个读过报告的人。
    """
    v = (val or "").strip()
    if len(v) <= 12:
        return v[:3] + "***"
    return f"{v[:6]}…{v[-4:]}（长度 {len(v)}）"


def _decode_jwt(tok: str) -> tuple[dict, dict]:
    """解出 JWT 的 header 与 payload；解不出返回两个空字典。"""
    parts = tok.split(".")
    if len(parts) != 3:
        return {}, {}
    out = []
    for seg in parts[:2]:
        pad = seg + "=" * (-len(seg) % 4)
        try:
            out.append(json.loads(base64.urlsafe_b64decode(pad.encode())))
        except Exception:
            return {}, {}
    if not isinstance(out[0], dict) or not isinstance(out[1], dict):
        return {}, {}
    return out[0], out[1]


_JWT_RE = re.compile(r"\b(eyJ[A-Za-z0-9_\-]{6,}\.eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]*)")


def _scan_text_for_secrets(label: str, text: str, url: str) -> tuple[list[dict], list[str]]:
    """在一段文本里找凭据，返回 (问题列表, 统计说明)。"""
    issues: list[dict] = []
    seen: set[tuple[str, str]] = set()
    notes: list[str] = []

    def add(kind: str, sev: str, cwe: str, value: str, detail: str, advice: str,
            evidence: str) -> None:
        key = (kind, value)
        if key in seen:
            return
        seen.add(key)
        issues.append(_issue("secret-scan", sev, "敏感信息", f"{kind}泄漏", url,
                             detail, advice, cwe=cwe, evidence=evidence,
                             confidence="high", method="GET"))

    for kind, sev, cwe, pat in _CRED_RULES:
        for m in re.finditer(pat, text):
            val = m.group(1)
            if _is_placeholder(val):
                continue
            # 私钥只报头，不报内容
            shown = val[:64] if "PRIVATE KEY" in val else _clip(val)
            add(kind, sev, cwe, val,
                f"在{label}中发现符合 {kind} 格式的字符串（{shown}）。"
                "该格式由服务方刻意设计得足够特征化，一旦出现在前端可读位置，"
                "即可被判明归属并直接用于访问对应云资源。",
                "立即在对应平台吊销并轮换该凭据；把配置改为从环境变量或密钥管理服务读取；"
                "检查构建产物中是否打包进了密钥文件。",
                f"来源：{label}\n匹配：{shown}")

    # 数据库 / 中间件连接串
    for m in re.finditer(_DSN_RE, text):
        dsn = m.group(1)
        with_cred = bool(_DSN_WITH_CRED_RE.search(dsn))
        if with_cred:
            userinfo = dsn.split("://", 1)[1].split("@", 1)[0]
            if _is_placeholder(userinfo) or _is_placeholder(userinfo.split(":")[-1]):
                continue
            masked = dsn.replace(userinfo, _clip(userinfo), 1)
            add("数据库连接串（含内嵌账号口令）", "high", "CWE-798", dsn,
                f"在{label}中发现带内嵌账号口令的连接串：{masked}。"
                "攻击者拿到该串即可直连数据库，读取甚至篡改业务数据。",
                "连接串不要写进前端代码与配置文件的默认值；改由服务端注入环境变量；"
                "为应用分配最小权限账号并限制来源 IP。",
                f"来源：{label}\n匹配：{masked}")
        else:
            add("内网服务端点暴露", "low", "CWE-200", dsn,
                f"在{label}中发现内部服务连接串（不含凭据）：{dsn}。"
                "会泄漏内网拓扑与所用中间件类型，为后续横向移动提供线索。",
                "避免把内部端点写入前端可读的配置。",
                f"来源：{label}\n匹配：{dsn}")

    # 硬编码口令
    for m in re.finditer(_HARDCODED_RE, text):
        val = m.group(1)
        if _is_placeholder(val):
            continue
        if val.startswith(("http://", "https://", "/", "%", "#")):
            continue
        classes = sum(bool(re.search(p, val))
                      for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
        if classes < 2 and len(val) < 12:
            continue                     # 纯小写单词，多半只是变量名或配置项名
        add("硬编码口令", "medium", "CWE-798", val,
            f"在{label}中发现疑似硬编码口令：`{masked_name(m.group(0), val)}`。"
            "口令写死在代码或配置文件里，任何能读到该位置的人都能获得凭据，"
            "且轮换口令必须重新发版。",
            "改为从环境变量/密钥管理服务读取；轮换该口令；"
            "在 CI 中加入密钥扫描作为提交门禁。",
            f"来源：{label}\n匹配：{masked_name(m.group(0), val)}")

    # JWT
    for m in re.finditer(_JWT_RE, text):
        tok = m.group(1)
        header, payload = _decode_jwt(tok)
        if not header:
            continue
        alg = str(header.get("alg", "")).lower()
        shown = _clip(tok)
        if alg == "none":
            add("JWT（alg=none 无签名）", "critical", "CWE-347", tok,
                f"在{label}中发现一个 `alg` 为 `none` 的 JWT（{shown}）。"
                "这类令牌不含签名，任何人都可以自行构造任意身份的令牌通过校验——"
                "只要服务端没有显式拒绝 `none` 算法，就等于完全没有鉴权。",
                "服务端必须固定允许的签名算法白名单，显式拒绝 `none`；"
                "升级 JWT 库并关闭「允许无签名」的兼容开关。",
                f"来源：{label}\n匹配：{shown}\nheader={json.dumps(header)[:120]}")
            continue
        if label.startswith("接口") :
            continue                      # 接口正常下发令牌不算泄漏
        interesting = {k: v for k, v in payload.items()
                       if k.lower() in ("role", "roles", "admin", "isadmin", "scope",
                                        "permissions", "uid", "userid", "user", "sub")}
        add("硬编码 JWT", "high", "CWE-798", tok,
            f"在{label}中发现硬编码的 JWT（{shown}，alg={header.get('alg')}）。"
            + (f"载荷中含身份相关声明 `{json.dumps(interesting, ensure_ascii=False)[:120]}`，"
               "可据此判断权限模型。"
               if interesting else "")
            + "令牌写入前端可读位置后，任何访问者都能以该身份调用接口，"
              "直到令牌过期——而代码里的令牌往往有效期很长或永不过期。",
            "不要把令牌硬编码进前端资源；改用服务端会话或短期令牌下发；"
            "已泄漏的令牌立即作废并轮换签名密钥。",
            f"来源：{label}\n匹配：{shown}")

    if any(i["category"] == "敏感信息" for i in issues):
        notes.append(f"{label}：命中 {len(issues)} 项")
    return issues, notes


def masked_name(matched: str, val: str) -> str:
    """把 `password = "xxx"` 这样的整段匹配打码后回显。"""
    return matched.replace(val, _clip(val))


@tool("secret_scan",
      "敏感凭据与密钥泄漏扫描（**只读**）：在内网可达页面的 HTML、JS bundle 与接口响应中"
      "搜索云凭据（AWS/GCP/Azure/阿里云/腾讯云）、各类平台 Token（GitHub/Slack/Stripe）、"
      "数据库连接串、私钥、JWT（含 alg=none 高危配置）以及硬编码口令。"
      "自动剔除示例值与占位符，证据在报告中打码。",
      {"url": "str，站点入口 URL（通常是首页）"},
      phase="scan", category="敏感信息")
def secret_scan(sess: ScanSession, url: str) -> dict:
    origin = origin_of(url)
    issues: list[dict] = []
    notes: list[str] = []
    scanned: list[str] = []

    html, _status, _ct = _page_text(sess, url)
    if html:
        scanned.append("首页 HTML")
        found, n = _scan_text_for_secrets("首页 HTML", html, url)
        issues += found
        notes += n

    bundles = _iter_scripts(sess, origin, html, {"quick": 4, "standard": 10, "deep": 18}
                            .get(sess.depth, 10))
    for src in bundles:
        text, _e = sess.fetch_text(src)
        if not text:
            continue
        scanned.append(src)
        found, n = _scan_text_for_secrets(f"JS {src.rsplit('/', 1)[-1]}", text, url)
        issues += found
        notes += n

    # 已发现的接口响应：api_surface 跑过就有缓存，没跑过则本工具按价值取前几个
    endpoints = (sess.discovered.get("endpoints") or {}).get(origin) or []
    limit = {"quick": 6, "standard": 20, "deep": 40}.get(sess.depth, 20)
    for path in endpoints[:limit]:
        full = origin + path
        text, _e = sess.fetch_text(full)
        if not text or len(text) > 200000:
            continue
        scanned.append(full)
        found, n = _scan_text_for_secrets(f"接口 {path}", text, full)
        issues += found
        notes += n

    # URL 里携带令牌 —— 会顺着 Referer、访问日志、浏览器历史外泄
    qs = urlparse(url).query
    for m in _JWT_RE.finditer(qs):
        issues.append(_issue(
            "secret-scan", "medium", "敏感信息", "会话令牌出现在 URL 查询串", url,
            f"URL 的查询串中携带了 JWT 令牌（{_clip(m.group(1))}）。"
            "URL 会被浏览器历史、代理与网关访问日志、以及跨站请求的 Referer 头完整记录，"
            "令牌因此大范围扩散，且无法通过退出登录彻底收回。",
            "令牌放在 `Authorization` 头或 HttpOnly Cookie 中传递；"
            "确需放在 URL 时使用一次性的短期凭据并立即失效。",
            cwe="CWE-598", evidence=f"query 中出现 JWT：{_clip(m.group(1))}",
            confidence="high", method="GET"))

    if not scanned:
        notes.append("未能取得任何可扫描的文本内容，凭据扫描未生效")
    summary = f"扫描 {len(scanned)} 处文本来源，发现 {len(issues)} 项凭据类问题"
    return {"ok": True, "summary": summary,
            "data": {"url": url, "sources": len(scanned),
                     "source_list": scanned[:20],
                     "kinds": sorted({i["title"] for i in issues})},
            "issues": issues, "notes": notes}


# ============================================================ CRLF / 响应头注入

CRLF_MARKER = "aih0leycrlf"
CRLF_HEADER = "X-Aiholey-Crlf"

# 服务端对 CRLF 的过滤粒度差异极大，这几种写法分别对应不同的实现缺陷：
# 只挡 `%0d%0a` 的、只挡明文换行的、先解码再过滤的，命中的变体各不相同。
CRLF_ESCAPES: list[tuple[str, str]] = [
    ("标准 %0d%0a", "%0d%0a"),
    ("仅换行 %0a", "%0a"),
    ("仅回车 %0d", "%0d"),
    ("UTF-8 过编码 %E5%98%8A%E5%98%8D", "%E5%98%8A%E5%98%8D"),
    ("双重编码 %250d%250a", "%250d%250a"),
]

CRLF_PARAMS = ["url", "redirect", "redirect_uri", "next", "return", "returnUrl",
               "goto", "target", "r", "u", "link", "continue", "dest",
               "path", "file", "page", "view", "name", "callback", "lang", "theme", "id"]


def _crlf_injected(headers: dict) -> bool:
    """响应头里有没有凭空多出我们注入的那个头。"""
    if CRLF_HEADER.lower() in headers:
        return True
    for k, v in headers.items():
        if CRLF_MARKER in k or CRLF_MARKER in v:
            # 值里出现标记有两种可能：真的注入成功（值里带换行），
            # 或者只是把参数原文照抄进了某个头的值（那是普通反射，不是注入）。
            # 判据是「标记出现在一个新头的**名字**里」或「值里含裸换行」。
            return CRLF_MARKER in k or "\r" in v or "\n" in v
    return False


@tool("crlf_inject",
      "HTTP 响应头注入（CRLF 注入）检测（**只读**）：在查询参数、请求路径与请求头中"
      "注入多种换行编码变体，判定服务端是否把它们写进了响应头——"
      "一旦成立，攻击者可凭空注入 `Set-Cookie`、污染 `Location` 实施会话固定与开放重定向链。",
      {"url": "str，目标 URL（可自带查询串）",
       "params": "list[str]，可选，指定要检测的参数名"},
      phase="scan", category="注入与参数")
def crlf_inject(sess: ScanSession, url: str, params: list | None = None) -> dict:
    issues: list[dict] = []
    notes: list[str] = []
    hits: list[tuple[str, str, str, str]] = []      # (落点, 变体, 证据, 载荷)
    tried = 0

    parsed = urlparse(url)
    base_path = parsed.path or "/"
    base_q = parsed.query

    given = _same_origin_params(url)
    extra = [p for p in (params or []) if isinstance(p, str) and p.strip()]
    names = uniq(given + extra + [p for p in CRLF_PARAMS if p not in given])[:10]

    # 落点：入口路径 + api_surface 采集到的带参 URL。
    # CRLF 注入成立的前提是「这个参数被写进了响应头」，而写响应头的参数
    # 几乎总是 `?url=` / `?redirect=` 这类跳转型功能页——首页通常没有。
    # 只测入口路径时，一个跳转页上的真实缺陷会被判成「未发现」。
    landings: list[tuple[str, str, list[str]]] = [(base_path, base_q, names)]
    seen_paths = {base_path}
    disc_cap = DISCOVERED_LANDING_CAP.get(sess.depth, 10)
    _origin = f"{parsed.scheme}://{parsed.netloc}"
    disc_added = 0
    for du in ((sess.discovered.get("param_urls") or {}).get(_origin) or []):
        if disc_added >= disc_cap:
            break
        dp = urlparse(du)
        if dp.path in seen_paths or not dp.query:
            continue
        own = [k for k, _v in parse_qsl(dp.query, keep_blank_values=True)
               if k and k not in CRLF_PARAMS] or \
              [k for k, _v in parse_qsl(dp.query, keep_blank_values=True) if k]
        if not own:
            continue
        seen_paths.add(dp.path)
        landings.append((dp.path or "/", dp.query, own[:6]))
        disc_added += 1

    def inject_value(esc: str) -> str:
        """构造一个「前半段看起来正常、后半段夹带换行」的取值。

        冒号后的分隔必须写成 `%20` 而**不能**是字面空格：裸 socket 通道是按
        字节发请求行的，一个空格就把 `GET <path> HTTP/1.1` 拆成三段，
        服务端直接回 400，载荷根本走不到应用逻辑里。
        实测这一处写错会让整类 CRLF 检测静默失效（试了 61 次全 400，
        报告写「未发现」，看起来像个正常的阴性结论）。
        """
        return f"http://aih0ley.invalid/{esc}{CRLF_HEADER}:%20{CRLF_MARKER}"

    def try_url(raw_path: str, where: str, payload: str) -> bool:
        nonlocal tried
        tried += 1
        try:
            r = sess.request_raw(url, raw_path)
        except (BudgetExceeded, OSError):
            return False
        if r.error:
            return False
        if _crlf_injected(r.headers):
            hits.append((where, payload, "响应头："
                         + "、".join(f"{k}: {v[:60]}" for k, v in list(r.headers.items())[:6]),
                         raw_path))
            return True
        return False

    # ---- 落点一：查询参数（最常见）----
    # 用裸通道手工拼查询串：httpx/urllib 会把 `%0d` 当成普通字符原样发出还行，
    # 但明文 `\r\n` 会被直接拒绝（httpx 判定为非法头/URL 字符），
    # 走裸通道才能覆盖「服务端实际上接受裸换行」这类情形。
    for lpath, lq, lnames in landings:
        for name in lnames:
            done = False
            for _label, esc in CRLF_ESCAPES:
                val = inject_value(esc)
                raw = f"{lpath}?{_raw_query_with(lq, name, val)}"
                if try_url(raw, f"查询参数 {name}（{lpath}）", f"{name}={val}"):
                    done = True
                    break
            if done:
                break
        if hits:
            break

    # ---- 落点二：请求路径（404 处理器常把路径写进 Location）----
    if not hits:
        for _label, esc in CRLF_ESCAPES[:3]:
            raw = f"/{esc}{CRLF_HEADER}:{CRLF_MARKER}"
            if try_url(raw, "请求路径", raw):
                break

    # ---- 落点三：请求头（应用把 UA/Referer 回写进响应头时成立）----
    if not hits:
        for hname in ("User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host"):
            for _label, esc in CRLF_ESCAPES[:2]:
                val = inject_value(esc)
                try:
                    r = sess.request_raw(url, base_path + (f"?{base_q}" if base_q else ""),
                                         headers={hname: val})  # 路径保持原样，注入点在头部
                except (BudgetExceeded, OSError):
                    break
                tried += 1
                if not r.error and _crlf_injected(r.headers):
                    hits.append((f"请求头 {hname}", f"{hname}: {val}",
                                 "响应头中出现注入头", f"{hname}: {val}"))
                    break
            if hits:
                break

    # 顺带确认「反射但无注入」的情形，写进 notes 而不是当漏洞报——
    # `Location: /x%0aabc` 说明换行被过滤了，是正确实现
    reflected_only = 0
    if not hits:
        val = inject_value(CRLF_ESCAPES[0][1])
        raw = f"{base_path}?{_raw_query_with(base_q, 'url', val)}"
        try:
            r = sess.request_raw(url, raw)
            loc = (r.headers.get("location") or "") if not r.error else ""
            if CRLF_MARKER in loc and "\r" not in loc and "\n" not in loc:
                reflected_only = 1
        except (BudgetExceeded, OSError):
            pass

    for where, payload, evidence, raw in hits[:3]:
        issues.append(_issue(
            "crlf-inject", "high", "注入与参数", f"HTTP 响应头注入（CRLF）—— {where}", url,
            f"在{where}注入换行序列后，响应头中凭空出现了 `{CRLF_HEADER}` 头。"
            "这说明服务端把未过滤的输入直接写进了响应头。攻击者可借此注入任意响应头，"
            "最常见的是伪造 `Set-Cookie`（会话固定）、污染 `Location`（钓鱼跳转），"
            "在存在反向代理缓存时还能进一步演变为响应拆分与缓存投毒。",
            "对写入响应头的任何输入做严格白名单过滤，直接剥离 `\\r`、`\\n` 及其各种编码形式；"
            "框架层使用提供安全头写入 API 的接口，不要手工拼接响应报文。",
            cwe="CWE-113", method="GET",
            payload=payload, evidence=evidence, confidence="high"))

    if reflected_only:
        notes.append("参数被回显进 Location 但换行已被过滤 —— 该落点实现正确，未构成注入")
    if disc_added:
        notes.append(f"除入口路径外，还在 {disc_added} 个带参数的落点"
                     f"（如 `{landings[1][0]}?{landings[1][1]}`）上试了响应头注入")
    if not hits:
        notes.append(f"在 {len(landings)} 个落点上尝试 {tried} 次注入组合，未发现响应头注入")

    summary = (f"在 {len(landings)} 个落点尝试 {tried} 次注入，"
               f"命中 {len(hits)} 处响应头注入")
    return {"ok": True, "summary": summary,
            "data": {"url": url, "attempts": tried,
                     "locations_tested": len(names), "hits": [h[0] for h in hits],
                     "reflected_without_injection": bool(reflected_only)},
            "issues": issues, "notes": notes}
