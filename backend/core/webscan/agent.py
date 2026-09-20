"""AI 自主规划执行器。

两种执行模式：

1. **AI 模式**（配了模型 API Key）
   把「总纲 + 启用技能 + 工具清单」交给模型，模型每一步输出一个 JSON 决定
   下一步调用哪个工具、参数是什么；执行结果回喂给它，直到它判定 `done` 或
   用满步数预算。最后由 AI 补充它自己读出来的语义发现。

2. **规则模式**（未配 Key 的兜底）
   按固定顺序跑一遍全部确定性检查项，保证不配模型也能出报告。

无论哪种模式，工具自身产出的 `issues` 都是确定性结论，直接进报告；
AI 只额外贡献它从响应内容里推理出的发现。
"""
from __future__ import annotations

from typing import Callable
from urllib.parse import urlparse

from backend.config import WEB_DEPTHS
from backend.core.llm import LLMClient, LLMError, extract_json
from backend.core.webscan import tools as T
from backend.core.webscan.skills_seed import SKILL_TOOLS, render_prompt

# 深度档位 → 预算。steps 与 max_requests 以 config.WEB_DEPTHS 为唯一来源，
# 避免这里和 config 各写一份导致改了一处忘了另一处。
_DETAIL_BY_DEPTH = {"quick": 900, "standard": 1300, "deep": 1800}
DEPTH_LIMITS: dict[str, dict] = {
    k: {"steps": int(v.get("steps", 10)),
        "max_requests": int(v.get("max_requests", 800)),
        "detail": _DETAIL_BY_DEPTH.get(k, 1300)}
    for k, v in WEB_DEPTHS.items()
}

# 每轮最多允许 AI 连续给出无效动作的次数
_MAX_INVALID = 2

# 规则模式的固定工具顺序（覆盖全部确定性检查）
#
# 顺序不是随意的：越靠前越「便宜且是后面工具的输入」，越靠后越「贵或带副作用」。
# 预算一旦被前面的工具吃掉，后面的就永远跑不到，所以顺序本身就是一种取舍。
DETERMINISTIC_ORDER = [
    # api_surface 必须排最前：它把前端接口清单缓存进会话，
    # 后面的 param_probe / traversal_probe / lfi_probe / api_audit / secret_scan
    # 才有真实落点可用；顺序错了它们只能在站点根路径上猜。
    "api_surface",
    # 这两个几乎不花额外请求：它们读的是 api_surface 已经抓回来的 JS/JSON
    # （会话级 text_cache），却各自覆盖一整类高价值结论，性价比最高。
    "secret_scan",
    "component_vuln",
    "sensitive_paths", "backup_files",
    "header_audit", "cookie_audit", "cors_check", "http_methods",
    "xss_check", "csrf_check",
    "param_probe", "traversal_probe", "lfi_probe",
    "crlf_inject", "api_audit", "auth_audit",
    "info_leak", "redirect_check", "dir_scan",
    # waf_detect 放最后：它要主动投递 5 类攻击载荷来验证防护是否生效。
    # 放前面一旦触发了 WAF 的自动封禁（Cloudflare 提高安全等级、安全狗默认策略
    # 都可能），后续所有检查都会失败 —— 而失败会被记成「未发现」，
    # 等于拿一次被封禁换回一份看起来干净的假报告。
    "waf_detect",
]

# AI 规划会因步数用尽而漏掉某些检查项。这些工具是**确定性**的，漏掉等于整类问题不报
# （尤其 sensitive_paths / backup_files / param_probe 常出 critical），
# 因此在 AI 判定完成后自动补齐。顺序与 DETERMINISTIC_ORDER 保持一致。
GUARANTEED_TOOLS = [
    "api_surface",
    "secret_scan", "component_vuln",
    "sensitive_paths", "backup_files",
    "cors_check", "cookie_audit", "http_methods", "header_audit",
    "xss_check", "csrf_check",
    "param_probe", "traversal_probe", "lfi_probe",
    "crlf_inject", "api_audit", "auth_audit",
    "redirect_check", "dir_scan",
    "waf_detect",
]

# 工具 → 所属技能（补跑时用于判断该技能是否被启用）
TOOL_SKILL = {t: s for s, ts in SKILL_TOOLS.items() for t in ts}

# 规则模式下「工具 → 启用它的技能」。缺一项的表现是：用户在界面上取消了这个
# 技能，规则模式却照跑不误，把用户明确关掉的检查项又报了回来。
DETERMINISTIC_SKILL_GATE = {
    "dir_scan": "web-content-discovery",
    "backup_files": "web-backup-leak",
    "param_probe": "web-param-injection",
    "traversal_probe": "web-path-traversal",
    "lfi_probe": "web-file-include",
    "api_surface": "web-api-surface",
    "api_audit": "web-api-audit",
    "unauth_check": "web-unauth-access",
    "secret_scan": "web-secret-leak",
    "csrf_check": "web-csrf",
    "xss_check": "web-xss",
    "crlf_inject": "web-crlf-injection",
    "component_vuln": "web-component-vuln",
    "auth_audit": "web-auth-attack",
    "waf_detect": "web-waf-detect",
}

SYSTEM_RULES = (
    "你是一名资深 Web 渗透测试工程师。你只输出一行 JSON，不输出解释性文字，"
    "不使用代码块标记。所有结论必须能追溯到工具的真实输出，禁止臆造。"
)


# ============================================================ 提示词装配

def build_system_prompt(target: str, skills: list[dict]) -> str:
    """总纲 + 启用技能正文 + 工具清单。"""
    flow = [s for s in skills if s.get("phase") == "flow"]
    checks = [s for s in skills if s.get("phase") != "flow"]
    ctx = {"target": target, "origin": T.origin_of(target), "host": T.host_of(target), "tools": ""}

    parts: list[str] = [SYSTEM_RULES, ""]

    # 总纲
    for s in flow:
        parts.append(render_prompt(s["prompt"], ctx))
        parts.append("")

    # 检测技能：正文 + 该技能对应的工具
    if checks:
        parts.append("## 本次启用的检测项\n")
        for s in checks:
            tool_names = SKILL_TOOLS.get(s["name"], [])
            parts.append(f"### {s['name']} — {s['description']}")
            if tool_names:
                parts.append(f"对应工具：`{'`、`'.join(tool_names)}`")
            parts.append(render_prompt(s["prompt"], ctx))
            parts.append("")

    # 工具清单
    catalog = T.tool_catalog()
    ctx["tools"] = "\n".join(
        f"- **{t['name']}**（{t['category']}）{t['description']} 参数：{t['params']}"
        for t in catalog
    )
    parts.append("## 可用工具清单\n")
    parts.append(ctx["tools"])
    return "\n".join(parts)


def _compact(res: dict, limit: int) -> str:
    """把工具结果压成给模型看的文本，避免上下文被原始数据撑爆。"""
    if not res:
        return "（无输出）"
    chunks = [f"ok={res.get('ok')}", f"summary={res.get('summary', '')}"]
    data = res.get("data") or {}
    if data:
        try:
            from json import dumps
            text = dumps(data, ensure_ascii=False)
        except (TypeError, ValueError):
            text = str(data)
        chunks.append("data=" + (text[:limit] + "…" if len(text) > limit else text))
    issues = res.get("issues") or []
    if issues:
        chunks.append("判定问题=" + "; ".join(
            f"[{i.get('severity')}] {i.get('title')} @ {i.get('url')}" for i in issues[:8]))
    return " | ".join(chunks)


def _absorb_notes(res: dict, notes: list[str]) -> None:
    """把工具自己产生的「说明/局限」并入作业 notes。

    工具在结果里用 ``notes`` 声明本次结论的适用范围（例如「该端点对任意路径都返回
    2xx，已启用兜底页过滤」）。这类信息必须传到报告里——否则用户看到"没扫出问题"
    会以为目标干净，而不是「这个端点的路径发现结论本来就不该信」。
    """
    for n in res.get("notes") or []:
        text = str(n or "").strip()
        if text and text not in notes:
            notes.append(text)


def _state_text(target: str, history: list[dict], step: int, max_steps: int, detail: int) -> str:
    lines = [f"目标：{target}", f"已完成 {step} 步，剩余 {max(0, max_steps - step)} 步。", ""]
    if not history:
        lines.append("（尚未执行任何探测，请从确认目标可达性开始）")
    else:
        lines.append("已执行的动作与结果：")
        for i, h in enumerate(history, 1):
            lines.append(f"{i}. 调用 `{h['tool']}`，参数 {h['args']}")
            lines.append(f"   结果：{h['brief']}")
            if h.get("note"):
                lines.append(f"   说明：{h['note']}")
    lines += [
        "",
        "请输出下一步动作的 JSON。若已完成全部必要探测，输出：",
        '{"thought":"...","tool":"done","args":{"summary":"一句话结论","extra_findings":[]}}',
    ]
    return "\n".join(lines)


# ============================================================ 结果归并

def dedupe_findings(findings: list[dict]) -> list[dict]:
    """按 (标题, URL, 参数) 去重；同一条保留等级更高的。"""
    order = {s: i for i, s in enumerate(T.SEVERITY_ORDER)}
    best: dict[tuple, dict] = {}
    for f in findings:
        key = (str(f.get("title", "")).strip(), str(f.get("url", "")).strip(), str(f.get("param", "")).strip())
        cur = best.get(key)
        if cur is None or order.get(f.get("severity", "low"), 9) < order.get(cur.get("severity", "low"), 9):
            best[key] = f
    out = list(best.values())
    out.sort(key=lambda f: (order.get(f.get("severity", "low"), 9), str(f.get("target", ""))))
    return out


def stats_of(findings: list[dict]) -> dict:
    st = {s: 0 for s in T.SEVERITY_ORDER}
    for f in findings:
        st[f.get("severity", "info")] = st.get(f.get("severity", "info"), 0) + 1
    st["total"] = len(findings)
    return st


def _normalize_ai_findings(raw, target: str, skill_names: set[str]) -> list[dict]:
    """把 AI 补充的发现规整成和工具一致的 finding 结构。"""
    if not isinstance(raw, list):
        return []
    out: list[dict] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        sev = str(item.get("severity", "low")).lower()
        if sev not in T.SEVERITY_ORDER:
            sev = "low"
        skill = str(item.get("skill") or "web-info-leak")
        if skill not in skill_names:
            skill = "web-info-leak"
        title = str(item.get("title") or "").strip()
        if not title:
            continue
        out.append({
            "skill": skill,
            "severity": sev,
            "category": str(item.get("category") or "AI 研判"),
            "title": title[:200],
            "url": str(item.get("url") or target)[:500],
            "method": str(item.get("method") or "GET")[:10],
            "param": str(item.get("param") or "")[:80],
            "payload": str(item.get("payload") or "")[:200],
            "evidence": T.sanitize_text(T.mask_evidence(str(item.get("evidence") or "")))[:800],
            "detail": T.sanitize_text(str(item.get("detail") or ""))[:1200],
            "advice": str(item.get("advice") or "")[:600],
            "cwe": str(item.get("cwe") or "")[:24],
            "confidence": str(item.get("confidence") or "low"),
            "source": "ai",
        })
    return out


# ============================================================ 执行

def scan_target(target: str, client: LLMClient | None, skills: list[dict],
                sess: T.ScanSession, say: Callable[[str], None],
                depth: str = "standard") -> dict:
    """扫描单个目标，返回 {findings, notes, steps, requests}。"""
    limit = DEPTH_LIMITS.get(depth, DEPTH_LIMITS["standard"])
    if client is None:
        return _run_deterministic(target, skills, sess, say, limit)

    skill_names = {s["name"] for s in skills if s.get("phase") != "flow"}
    system = build_system_prompt(target, skills)
    history: list[dict] = []
    findings: list[dict] = []
    notes: list[str] = []
    invalid = 0
    used: set[str] = set()

    for step in range(limit["steps"]):
        user = _state_text(target, history, step, limit["steps"], limit["detail"])
        try:
            reply = client.chat(
                [{"role": "system", "content": system}, {"role": "user", "content": user}],
                temperature=0.1, max_tokens=1200)
        except LLMError as e:
            notes.append(f"模型调用失败，改为规则模式：{e}")
            fallback = _run_deterministic(target, skills, sess, say, limit)
            fallback["findings"] = dedupe_findings(findings + fallback["findings"])
            fallback["notes"] = notes + fallback["notes"]
            return fallback

        action = extract_json(reply)
        if isinstance(action, list):
            action = action[0] if action else None
        if not isinstance(action, dict):
            invalid += 1
            notes.append(f"第 {step + 1} 步模型输出无法解析为 JSON，已跳过")
            say(f"  模型输出无法解析，跳过该步")
            if invalid >= _MAX_INVALID:
                notes.append("模型连续输出无效动作，提前结束规划")
                break
            continue

        tool_name = str(action.get("tool") or "").strip()
        args = action.get("args") if isinstance(action.get("args"), dict) else {}
        thought = str(action.get("thought") or "")[:200]

        if tool_name in ("", "done", "finish", "stop"):
            extra = _normalize_ai_findings((action.get("args") or {}).get("extra_findings"),
                                           target, skill_names)
            if extra:
                findings.extend(extra)
                say(f"  AI 补充 {len(extra)} 项语义发现")
            summary = str((action.get("args") or {}).get("summary") or "")
            if summary:
                notes.append(f"AI 结论：{summary}")
            break

        if tool_name not in T.TOOLS:
            invalid += 1
            notes.append(f"模型请求了不存在的工具 `{tool_name}`")
            say(f"  模型请求不存在的工具 {tool_name}，已忽略")
            if invalid >= _MAX_INVALID:
                break
            continue

        # 参数里可能夹带 AI 自己编的 url（例如把相对路径写进去）
        if "url" in T.TOOLS[tool_name]["params"] and not args.get("url"):
            args["url"] = T.origin_of(target)

        say(f"  ▸ {tool_name} {thought}"
            if thought else f"  ▸ {tool_name}")
        res = T.run_tool(sess, tool_name, args)
        if res.get("fatal"):
            notes.append(f"请求预算耗尽（{sess.max_requests} 次），提前结束")
            findings.extend(res.get("issues") or [])
            break

        if res.get("ok"):
            used.add(tool_name)
        issues = res.get("issues") or []
        for it in issues:
            it["target"] = target
        findings.extend(issues)
        _absorb_notes(res, notes)

        history.append({
            "tool": tool_name, "args": args,
            "brief": _compact(res, limit["detail"]),
            "note": "" if res.get("ok") else res.get("summary", ""),
        })
        if issues:
            say(f"    命中 {len(issues)} 项：{'、'.join(i['title'] for i in issues[:3])}")

    # ---- 补全：AI 因步数用尽而未覆盖的确定性检查项 ----
    attempted = {h["tool"] for h in history} | used
    missing = [t for t in GUARANTEED_TOOLS
               if t not in attempted and (not skill_names or TOOL_SKILL.get(t) in skill_names)]
    if missing:
        say(f"  补齐 AI 未覆盖的检查项：{'、'.join(missing)}")
        for name in missing:
            res = T.run_tool(sess, name, {"url": target, "host": T.host_of(target)})
            if res.get("fatal"):
                notes.append("请求预算耗尽，补全检查提前结束")
                break
            if not res.get("ok"):
                # 补跑失败必须可见 —— 否则"跑了但没结果"会被误读成"目标没问题"
                say(f"    {name} 执行失败：{res.get('summary')}")
                notes.append(f"补全检查 {name} 执行失败：{res.get('summary')}")
                continue
            issues = res.get("issues") or []
            for it in issues:
                it["target"] = target
            findings.extend(issues)
            used.add(name)
            _absorb_notes(res, notes)
            if issues:
                say(f"    {name} 命中 {len(issues)} 项：{'、'.join(i['title'] for i in issues[:3])}")
        notes.append("AI 规划未覆盖的检查项已自动补跑：" + "、".join(missing))

    return {
        "findings": dedupe_findings(findings),
        "notes": notes,
        "steps": len(history) + len(missing),
        "tools_used": sorted(used),
        "requests": sess.requests_made,
        "mode": "ai",
    }


def _run_deterministic(target: str, skills: list[dict], sess: T.ScanSession,
                       say: Callable[[str], None], limit: dict) -> dict:
    """不依赖模型：按固定顺序跑一遍确定性检查项。"""
    skill_names = {s["name"] for s in skills if s.get("phase") != "flow"}
    origin, host = T.origin_of(target), T.host_of(target)
    findings: list[dict] = []
    notes: list[str] = []
    used: list[str] = []

    # 先确认可达性
    say("  ▸ http_probe 确认目标可达性")
    probe = T.run_tool(sess, "http_probe", {"url": target})
    if not probe.get("ok"):
        return {"findings": [], "notes": [f"目标不可达：{probe.get('summary')}"],
                "steps": 1, "tools_used": ["http_probe"], "requests": sess.requests_made, "mode": "rule"}
    for it in probe.get("issues") or []:
        it["target"] = target
    findings.extend(probe.get("issues") or [])
    used.append("http_probe")

    say("  ▸ fingerprint 识别技术栈")
    fp = T.run_tool(sess, "fingerprint", {"url": target})
    for it in fp.get("issues") or []:
        it["target"] = target
    findings.extend(fp.get("issues") or [])
    used.append("fingerprint")

    # 未启用对应技能时跳过该检查项（与 AI 模式的 GUARANTEED_TOOLS 过滤保持一致）
    for name in DETERMINISTIC_ORDER:
        need = DETERMINISTIC_SKILL_GATE.get(name)
        if need and need not in skill_names:
            continue
        say(f"  ▸ {name}")
        res = T.run_tool(sess, name, {"url": target, "host": host})
        if res.get("fatal"):
            notes.append("请求预算耗尽，提前结束")
            break
        for it in res.get("issues") or []:
            it["target"] = target
        findings.extend(res.get("issues") or [])
        used.append(name)
        # 工具的自我说明（软 404、WAF、探测能力边界…）必须一并收进报告。
        # 规则模式早期漏掉了这一步：报告里只剩「未发现」，而工具明明声明过
        # 「这个端点的路径类结论不可信」，用户读到的却是一个干净的结论。
        _absorb_notes(res, notes)

    if "web-port-exposure" in skill_names:
        say(f"  ▸ port_scan 探测常见端口")
        res = T.run_tool(sess, "port_scan", {"host": host})
        for it in res.get("issues") or []:
            it["target"] = target
        findings.extend(res.get("issues") or [])
        used.append("port_scan")
        _absorb_notes(res, notes)

    # TLS 只在目标本身就是 HTTPS 时才检查（否则对一个纯 HTTP 端点做 TLS 握手
    # 只会白白耗掉 8 秒超时，还会在报告里留下一条"连接失败"的噪声）。
    if "web-security-headers" in skill_names and target.startswith("https://"):
        say(f"  ▸ tls_info 检查证书与加密配置")
        res = T.run_tool(sess, "tls_info", {"host": host,
                                           "port": int(urlparse(target).port or 443)})
        if res.get("ok"):
            for it in res.get("issues") or []:
                it["target"] = target
            findings.extend(res.get("issues") or [])
            used.append("tls_info")
            _absorb_notes(res, notes)

    notes.append("未配置模型 API Key，本次仅执行确定性检查项（不做 AI 语义研判）")
    return {"findings": dedupe_findings(findings), "notes": notes, "steps": len(used),
            "tools_used": sorted(set(used)), "requests": sess.requests_made, "mode": "rule"}
