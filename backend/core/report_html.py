"""把一次运行的扫描结果渲染成单文件 HTML 报告。

设计约束：
- **完全自包含**：内联 CSS，无 CDN / 无外链字体 / 无 JS 依赖，离线可看、可直接存档、可发邮件；
- **打印友好**：带 @media print 规则与「打印 / 另存为 PDF」按钮（浏览器原生打印即得 PDF，无需服务端依赖）；
- **不泄漏凭据**：仓库地址一律脱敏，不渲染 username / password / ssh_key。

与 CLI 版 report.py 的 render_html 保持同一套视觉语言（浅色、卡片、左侧色条）。
"""
from __future__ import annotations

import base64
import hashlib
import html
import time
from urllib.parse import urlsplit, urlunsplit, quote

# ---------------------------------------------------------------- 打印按钮
#
# 报告页顶部的「打印 / 另存为 PDF」需要一个内联脚本，但报告页**不能**放行
# CSP 的 'unsafe-inline'：报告里嵌的正是扫描到的原始内容（代码片段、响应证据、
# 仓库名），一旦有人在这些内容里塞进脚本，放行 inline 就等于把「内容注入」
# 直接升级成「脚本执行」。
#
# 所以改成给这段固定脚本算 sha256，CSP 里只白名单它这一个哈希。
# 关键点：脚本内容与哈希都在这里定义，模板引用同一个常量——不会出现
# 「改了脚本忘了更新哈希 → 按钮静默失效」的经典事故。
PRINT_BTN_ID = "aih-print-btn"
PRINT_SCRIPT = (
    "document.getElementById('aih-print-btn')"
    ".addEventListener('click',function(){window.print()})"
)
PRINT_SCRIPT_HASH = base64.b64encode(
    hashlib.sha256(PRINT_SCRIPT.encode("utf-8")).digest()
).decode("ascii")


def print_toolbar() -> str:
    """打印按钮 + 配套内联脚本（其哈希已登记在报告页 CSP 白名单中）。"""
    return (f'<div class="toolbar"><button class="btn" id="{PRINT_BTN_ID}">'
            f'打印 / 另存为 PDF</button></div>'
            f'<script>{PRINT_SCRIPT}</script>')

# 严重度：中文标签 + 主题色 + 排序权重
SEV_META = {
    "critical": {"label": "严重", "color": "#b91c1c", "bg": "#fef2f2", "border": "#fecaca"},
    "high":     {"label": "高危", "color": "#dc2626", "bg": "#fff7ed", "border": "#fed7aa"},
    "medium":   {"label": "中危", "color": "#c2410c", "bg": "#fffbeb", "border": "#fde68a"},
    "low":      {"label": "低危", "color": "#1d4ed8", "bg": "#eff6ff", "border": "#bfdbfe"},
}
SEV_ORDER = ["critical", "high", "medium", "low"]

DEPTH_LABELS = {"quick": "快速", "standard": "标准", "deep": "深度"}


def _mask_url(url: str) -> str:
    """脱敏：去掉 URL 里的 user:password@，保留主机与路径。"""
    if not url:
        return ""
    try:
        if "://" in url:
            p = urlsplit(url)
            host = p.hostname or ""
            if p.port:
                host = f"{host}:{p.port}"
            return urlunsplit((p.scheme, host, p.path, p.query, p.fragment))
        return url
    except ValueError:
        return url


def _mono(v) -> str:
    """等宽样式包裹（用于分支名、提交号这类标识符）。**内部已转义**。

    这类小工具存在的意义：模板里经常需要「包一层标签但内容要转义」，
    直接写 f'<span class="mono">{v}</span>' 就会漏掉转义——仓库名、分支名都是
    用户可控且会落进报告的数据，漏一次就是一个存储型 XSS。
    """
    return f'<span class="mono">{_esc(v)}</span>'


def _esc(v) -> str:
    return html.escape(str(v if v is not None else ""), quote=True)


def safe_repo(repo: dict | None) -> dict | None:
    """仓库信息脱敏：清空凭据字段、屏蔽 URL 内嵌的 user:pass@。

    报告会落盘并被下载/转发，绝不能带着明文凭据出门。
    """
    if not repo:
        return None
    out = dict(repo)
    for k in ("password", "ssh_key", "token"):
        if k in out:
            out[k] = ""
    if out.get("url"):
        out["url"] = _mask_url(out["url"])
    return out


def _first_line(text: str, limit: int = 90) -> str:
    line = (text or "").splitlines()[0] if text else ""
    return line[:limit]


def _by_skill(findings: list[dict]) -> list[dict]:
    agg: dict[str, dict] = {}
    for f in findings:
        s = f.get("skill") or "unknown"
        row = agg.setdefault(s, {"skill": s, "critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0})
        sev = f.get("severity") if f.get("severity") in SEV_META else "low"
        row[sev] += 1
        row["total"] += 1
    return sorted(agg.values(), key=lambda r: (-r["total"], r["skill"]))


def _stats(findings: list[dict]) -> dict:
    st = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": len(findings)}
    for f in findings:
        sev = f.get("severity") if f.get("severity") in SEV_META else "low"
        st[sev] += 1
    return st


def parse_notes_from_md(md: str) -> list[str]:
    """从已生成的 markdown 里取回 AI 分析提示（notes 未落库，只能从报告正文回收）。"""
    if not md:
        return []
    lines = md.splitlines()
    notes: list[str] = []
    for i, line in enumerate(lines):
        if "AI 分析提示" in line and "条" in line:
            j = i + 1
            while j < len(lines):
                cur = lines[j]
                if cur.strip().startswith("- "):
                    notes.append(cur.strip()[2:].strip())
                elif not cur.strip():
                    pass
                else:
                    break
                j += 1
            break
    return notes


_CSS = """
:root{
  --bg:#f5f6f8; --card:#fff; --line:#e6e8ec; --text:#1f2937; --muted:#6b7280;
  --crit:#b91c1c; --high:#dc2626; --med:#c2410c; --low:#1d4ed8; --accent:#4f46e5;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--text);
  font:14px/1.7 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;}
.wrap{max-width:1000px;margin:0 auto;padding:0 20px 60px}
a{color:var(--accent);text-decoration:none}
code,kbd,pre,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace}

/* ---------- 头部 ---------- */
.hero{background:linear-gradient(135deg,#111827 0%,#1f2937 55%,#312e81 100%);color:#fff;padding:34px 0 30px;margin-bottom:26px}
.hero .wrap{padding-bottom:0}
.hero h1{margin:0 0 10px;font-size:26px;line-height:1.35;letter-spacing:.2px}
.hero .sub{color:#c7cbd4;font-size:13px;display:flex;flex-wrap:wrap;gap:8px 18px}
.hero .sub b{color:#fff;font-weight:600}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;border:1px solid rgba(255,255,255,.28);color:#e5e7eb}
.pill.ai{background:rgba(79,70,229,.35);border-color:rgba(129,140,248,.6);color:#e0e7ff}

/* ---------- 工具条 ---------- */
.toolbar{display:flex;justify-content:flex-end;gap:10px;margin:-14px 0 16px}
.btn{appearance:none;border:1px solid var(--line);background:#fff;color:var(--text);
  padding:8px 16px;border-radius:8px;font-size:13px;cursor:pointer;box-shadow:0 1px 2px rgba(16,24,40,.05)}
.btn:hover{border-color:#c7cad1;background:#fafafa}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.btn.primary:hover{background:#4338ca}

/* ---------- 卡片 ---------- */
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px 22px;margin-bottom:18px;
  box-shadow:0 1px 2px rgba(16,24,40,.04)}
h2.sec{font-size:16px;margin:0 0 14px;padding-left:11px;border-left:4px solid var(--accent);line-height:1.2}
h3.grp{font-size:14px;margin:22px 0 10px;color:var(--muted);letter-spacing:.4px}

/* ---------- 概要数字 ---------- */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(132px,1fr));gap:12px;margin-bottom:18px}
.stat{background:#fff;border:1px solid var(--line);border-radius:12px;padding:14px 16px;position:relative;overflow:hidden}
.stat .k{font-size:12px;color:var(--muted);margin-bottom:4px}
.stat .v{font-size:26px;font-weight:700;line-height:1.1}
.stat .u{font-size:12px;color:var(--muted);margin-left:3px;font-weight:400}
.stat::after{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--c,var(--accent))}

/* ---------- 键值表 ---------- */
.kv{display:grid;grid-template-columns:132px 1fr;gap:0;border-top:1px solid var(--line)}
.kv dt{padding:9px 0;color:var(--muted);font-size:13px;border-bottom:1px solid var(--line)}
.kv dd{padding:9px 0;margin:0;border-bottom:1px solid var(--line);word-break:break-word}
.kv dd .mono{font-size:12.5px;background:#f3f4f6;padding:1px 6px;border-radius:5px}

/* ---------- 表格 ---------- */
table.tb{width:100%;border-collapse:collapse;font-size:13px}
table.tb th{text-align:left;font-weight:600;color:var(--muted);padding:9px 10px;border-bottom:1px solid var(--line);white-space:nowrap}
table.tb td{padding:9px 10px;border-bottom:1px solid #f1f2f4;vertical-align:middle}
table.tb tr:last-child td{border-bottom:none}
table.tb td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
td .sk{font-size:12.5px;background:#f3f4f6;padding:1px 7px;border-radius:5px}
.bar{height:7px;border-radius:4px;background:#eef0f3;overflow:hidden;min-width:70px}
.bar i{display:block;height:100%;border-radius:4px}

/* ---------- 漏洞条目 ---------- */
.finding{border:1px solid var(--line);border-left:4px solid var(--c,#6b7280);border-radius:10px;
  padding:15px 18px;margin-bottom:12px;background:#fff}
.finding .fhead{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-bottom:8px}
.finding .idx{font-weight:700;color:var(--muted);font-variant-numeric:tabular-nums}
.finding .title{font-weight:600;font-size:14.5px;flex:1 1 240px;min-width:0}
.badge{display:inline-block;padding:1px 9px;border-radius:999px;font-size:12px;font-weight:600;
  color:var(--c);background:var(--bgc);border:1px solid var(--bdc)}
.chip{display:inline-block;padding:1px 8px;border-radius:6px;font-size:12px;background:#f3f4f6;color:#4b5563;
  border:1px solid #e5e7eb}
.loc{font-size:12.5px;color:#374151;background:#f8f9fb;border:1px solid #eceef1;border-radius:6px;
  padding:5px 9px;display:inline-block;margin-bottom:10px;word-break:break-all}
pre.code{margin:0 0 10px;background:#0f172a;color:#e2e8f0;padding:12px 14px;border-radius:8px;
  font-size:12.5px;line-height:1.6;overflow-x:auto;white-space:pre-wrap;word-break:break-word}
.detail{margin:0 0 8px;font-size:13.5px;color:#374151}
.detail b.lbl{display:block;font-size:12px;color:var(--muted);letter-spacing:.3px;margin-bottom:3px;font-weight:600}
.advice{background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:10px 12px;font-size:13.5px;color:#14532d}
.advice b.lbl{display:block;font-size:12px;color:#15803d;letter-spacing:.3px;margin-bottom:3px;font-weight:600}

/* ---------- 技术栈画像 ---------- */
.stack{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:14px}
.tag{font-size:12.5px;padding:3px 10px;border-radius:999px;background:#eef2ff;color:#3730a3;border:1px solid #c7d2fe}
.adapt{border:1px solid var(--line);border-radius:9px;padding:11px 13px;margin-bottom:9px;background:#fcfcfd}
.adapt .an{font-weight:600;font-size:13.5px;margin-bottom:4px}
.adapt .ad{font-size:13px;color:#4b5563;margin:0}
.adapt .at{margin-top:6px;display:flex;flex-wrap:wrap;gap:6px}
.adapt .at span{font-size:11.5px;color:#6b7280;background:#f3f4f6;padding:1px 7px;border-radius:5px}

/* ---------- 说明 / 页脚 ---------- */
.note{background:#fff;border:1px dashed #d7dae0;border-radius:10px;padding:14px 18px;font-size:13px;color:#4b5563}
.note ul{margin:8px 0 0;padding-left:20px}
.note li{margin-bottom:3px}
.warn{color:#92400e;background:#fffbeb;border:1px solid #fde68a;border-radius:8px;padding:10px 12px;font-size:13px;margin-top:12px}
.foot{text-align:center;color:#9ca3af;font-size:12px;margin-top:26px;line-height:1.9}
.empty{color:var(--muted);font-size:13.5px;padding:6px 0}

/* ---------- 打印 / 导出 PDF ---------- */
@media print{
  body{background:#fff}
  .wrap{max-width:none;padding:0 6mm 0}
  .toolbar{display:none!important}
  .hero{background:linear-gradient(135deg,#111827 0%,#1f2937 55%,#312e81 100%)!important;
    -webkit-print-color-adjust:exact;print-color-adjust:exact;padding:18px 0}
  .card,.finding,.adapt,.stat{box-shadow:none;break-inside:avoid;page-break-inside:avoid}
  .finding{break-inside:avoid;page-break-inside:avoid}
  h2.sec{break-after:avoid;page-break-after:avoid}
  h3.grp{break-after:avoid;page-break-after:avoid}
  pre.code{background:#f6f8fa!important;color:#24292f!important;border:1px solid #e5e7eb;
    -webkit-print-color-adjust:exact;print-color-adjust:exact}
  .badge,.tag,.chip,.bar i,.stat::after{-webkit-print-color-adjust:exact;print-color-adjust:exact}
  a{color:var(--text)}
}
@page{margin:12mm 10mm}
"""


def _stat_card(key: str, value: int, label: str | None = None, color: str | None = None) -> str:
    c = color or (SEV_META[key]["color"] if key in SEV_META else "#4f46e5")
    k = label or (SEV_META[key]["label"] if key in SEV_META else key)
    return (f'<div class="stat" style="--c:{c}"><div class="k">{_esc(k)}</div>'
            f'<div class="v" style="color:{c}">{value}</div></div>')


def _finding_card(i: int, f: dict) -> str:
    sev = f.get("severity") if f.get("severity") in SEV_META else "low"
    m = SEV_META[sev]
    src = "AI 语义分析" if f.get("source") == "ai" else "内置规则"
    conf = f.get("confidence") or "medium"
    parts = [f'<div class="finding" style="--c:{m["color"]}">']
    parts.append('<div class="fhead">')
    parts.append(f'<span class="idx">{i}.</span>')
    parts.append(f'<span class="badge" style="--c:{m["color"]};--bgc:{m["bg"]};--bdc:{m["border"]}">{m["label"]}</span>')
    parts.append(f'<span class="title">{_esc(f.get("title"))}</span>')
    parts.append(f'<span class="chip">{_esc(f.get("skill"))}</span>')
    parts.append(f'<span class="chip">{_esc(src)} · {_esc(conf)}</span>')
    parts.append('</div>')
    parts.append(f'<div class="loc mono">{_esc(f.get("file"))}:{_esc(f.get("line"))}</div>')
    if f.get("snippet"):
        parts.append(f'<pre class="code">{_esc(f["snippet"])}</pre>')
    if f.get("detail"):
        parts.append(f'<div class="detail"><b class="lbl">成因与攻击路径</b>{_esc(f["detail"])}</div>')
    if f.get("advice"):
        parts.append(f'<div class="advice"><b class="lbl">修复建议</b>{_esc(f["advice"])}</div>')
    parts.append('</div>')
    return "".join(parts)


def _profile_block(profile: dict, esc) -> str:
    ts = (profile or {}).get("tech_stack") or {}
    tags: list[str] = []
    for key in ("language", "framework", "framework_version", "build_tool"):
        v = ts.get(key)
        if v and str(v) not in ("unknown", "None"):
            tags.append(f'<span class="tag">{_esc(v)}</span>')
    for item in (ts.get("security_mechanism") or [])[:6]:
        tags.append(f'<span class="tag">{_esc(item)}</span>')
    for item in (ts.get("modules") or [])[:12]:
        tags.append(f'<span class="tag">{_esc(item)}</span>')

    out = ['<h2 class="sec">项目技术栈与审计增强</h2>']
    if profile.get("project_name"):
        out.append(f'<div class="detail" style="margin-bottom:10px">项目：<b>{_esc(profile["project_name"])}</b></div>')
    if tags:
        out.append('<div class="stack">' + "".join(tags) + '</div>')

    adapts = (profile or {}).get("adaptations") or []
    if adapts:
        out.append(f'<h3 class="grp">本次启用的适配规则（{len(adapts)} 条）</h3>')
        for a in adapts:
            out.append('<div class="adapt">')
            out.append(f'<div class="an">{_esc(a.get("name") or a.get("id"))}</div>')
            if a.get("description"):
                out.append(f'<p class="ad">{_esc(a["description"])}</p>')
            applies = a.get("applies_to") or []
            if applies:
                out.append('<div class="at">' + "".join(f'<span>{_esc(x)}</span>' for x in applies) + '</div>')
            out.append('</div>')
    return "".join(out)


def render_html(run: dict, findings: list[dict], *, repo: dict | None = None,
                skills: list[dict] | None = None, profile: dict | None = None,
                notes: list[str] | None = None, ai_used: bool = False,
                generated_at: float | None = None, allow_print: bool = True) -> str:
    """渲染单文件 HTML 报告。findings 建议已按严重度排序。"""
    st = _stats(findings)
    by_skill = _by_skill(findings)
    title = run.get("repo_name") or run.get("task_name") or "未命名项目"
    depth = DEPTH_LABELS.get(run.get("depth") or "", run.get("depth") or "-")
    repo_url = _mask_url((repo or {}).get("url") or "")
    commit = _first_line((repo or {}).get("last_pull_msg") or "")
    finished = run.get("finished_at") or run.get("created_at") or time.time()
    gen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(generated_at or time.time()))
    dur = (run.get("duration_ms") or 0) / 1000

    out: list[str] = []
    out.append('<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">')
    out.append('<meta name="viewport" content="width=device-width,initial-scale=1">')
    out.append(f'<title>代码安全审计报告 · {_esc(title)}</title>')
    out.append(f'<style>{_CSS}</style></head><body>')

    # ---------- 头部 ----------
    out.append('<header class="hero"><div class="wrap">')
    out.append(f'<h1>代码安全审计报告 · {_esc(title)}</h1>')
    out.append('<div class="sub">')
    out.append(f'<span>运行 ID <b class="mono">{_esc(run.get("run_id"))}</b></span>')
    if repo_url:
        out.append(f'<span>仓库 <b>{_esc(repo_url)}</b></span>')
    if (repo or {}).get("branch"):
        out.append(f'<span>分支 <b>{_esc(repo.get("branch"))}</b></span>')
    out.append(f'<span>审计深度 <b>{_esc(depth)}</b></span>')
    out.append(f'<span>完成时间 <b>{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(finished))}</b></span>')
    out.append('</div><div class="sub" style="margin-top:10px">')
    if ai_used:
        out.append(f'<span class="pill ai">AI 语义分析 · {_esc(run.get("engine") or "-")}</span>')
    else:
        out.append('<span class="pill">仅规则引擎（未配置 API Key）</span>')
    out.append(f'<span class="pill">扫描 {run.get("files_scanned", 0)} 文件 · {run.get("loc", 0)} 行</span>')
    out.append(f'<span class="pill">耗时 {dur:.1f}s</span>')
    out.append('</div></div></header>')

    out.append('<div class="wrap">')

    # ---------- 工具条 ----------
    if allow_print:
        out.append(print_toolbar())

    # ---------- 概要 ----------
    out.append('<div class="stats">')
    out.append(_stat_card("total", st["total"], "漏洞合计", "#4f46e5"))
    for k in SEV_ORDER:
        out.append(_stat_card(k, st[k]))
    out.append('</div>')

    # ---------- 元信息 ----------
    out.append('<section class="card"><h2 class="sec">审计概况</h2><dl class="kv">')
    # 值分两类，别混：**纯文本一律 _esc()**，需要等宽样式用 _mono()（内部已转义）。
    # 这里曾经直接把 run["repo_name"] / run["task_name"] 当 HTML 插入，
    # 而仓库名和任务名是用户自己填的 —— 起个带 <script> 的名字，报告一打开就执行，
    # 报告还会被转发给同事，属于典型的存储型 XSS。
    rows = [
        ("任务名称", _esc(run.get("task_name") or "-")),
        ("仓库", _esc(run.get("repo_name") or "-")),
        ("仓库地址", _mono(repo_url) if repo_url else "-"),
        ("分支", _mono((repo or {}).get("branch") or "-")),
    ]
    if commit:
        rows.append(("本次提交", _mono(commit)))
    rows += [
        ("审计深度", _esc(depth)),
        ("执行引擎", _esc(run.get("engine") or "-")
                   + ("（AI 语义分析已启用）" if ai_used else "（仅规则引擎）")),
        ("扫描规模", f'{_esc(run.get("files_scanned", 0))} 个文件 · '
                   f'{_esc(run.get("loc", 0))} 行代码'),
        ("耗时", f"{dur:.2f} 秒"),
        ("完成时间", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(finished))),
        ("报告导出", f"{gen}（打开本报告时实时生成）"),
    ]
    for k, v in rows:
        out.append(f'<dt>{_esc(k)}</dt><dd>{v}</dd>')
    out.append('</dl></section>')

    # ---------- 技术栈画像 ----------
    if profile:
        out.append(f'<section class="card">{_profile_block(profile, _esc)}</section>')

    # ---------- 参与技能 ----------
    if skills:
        hit = {b["skill"]: b["total"] for b in by_skill}
        out.append('<section class="card"><h2 class="sec">本次参与的审计技能</h2>')
        out.append('<table class="tb"><thead><tr><th>技能</th><th>说明</th><th style="text-align:right">命中</th></tr></thead><tbody>')
        for s in skills:
            out.append(f'<tr><td><span class="sk">{_esc(s.get("name"))}</span></td>'
                       f'<td>{_esc(s.get("description") or "")}</td>'
                       f'<td class="num">{hit.get(s.get("name"), 0)}</td></tr>')
        out.append('</tbody></table></section>')

    # ---------- 漏洞清单 ----------
    out.append('<section class="card"><h2 class="sec">确认漏洞清单</h2>')
    if not findings:
        out.append('<div class="empty">本次扫描未发现可确认的安全漏洞。</div>')
        out.append('</section>')
    else:
        out.append('</section>')
        idx = 0
        for sev in SEV_ORDER:
            group = [f for f in findings if (f.get("severity") if f.get("severity") in SEV_META else "low") == sev]
            if not group:
                continue
            m = SEV_META[sev]
            out.append(f'<h3 class="grp" style="color:{m["color"]}">{m["label"]}（{len(group)} 项）</h3>')
            for f in group:
                idx += 1
                out.append(_finding_card(idx, f))

    # ---------- 按技能统计 ----------
    if by_skill:
        peak = max((b["total"] for b in by_skill), default=1) or 1
        out.append('<section class="card"><h2 class="sec">按技能统计</h2>')
        out.append('<table class="tb"><thead><tr><th>技能</th>'
                   '<th style="text-align:right">严重</th><th style="text-align:right">高危</th>'
                   '<th style="text-align:right">中危</th><th style="text-align:right">低危</th>'
                   '<th style="text-align:right">合计</th><th style="width:150px">占比</th></tr></thead><tbody>')
        for b in by_skill:
            top = next((s for s in SEV_ORDER if b[s] > 0), "low")
            pct = max(4, round(b["total"] * 100 / peak))
            out.append('<tr>'
                       f'<td><span class="sk">{_esc(b["skill"])}</span></td>'
                       f'<td class="num">{b["critical"]}</td><td class="num">{b["high"]}</td>'
                       f'<td class="num">{b["medium"]}</td><td class="num">{b["low"]}</td>'
                       f'<td class="num"><b>{b["total"]}</b></td>'
                       f'<td><div class="bar"><i style="width:{pct}%;background:{SEV_META[top]["color"]}"></i></div></td>'
                       '</tr>')
        out.append('</tbody></table></section>')

    # ---------- 扫描说明 ----------
    out.append('<section class="card"><h2 class="sec">扫描说明与误报排除</h2>')
    out.append(f'<div class="note"><div class="mono" style="font-size:12.5px">扫描目录：{_esc(run.get("workdir") or "")}</div>')
    out.append('<ul>')
    out.append('<li>已忽略 <code>.git/</code>、依赖目录（node_modules / target / dist 等）以及 .gitignore 所列文件</li>')
    out.append('<li>单文件上限 500 KB，超限文件按前 400 行截断参与分析</li>')
    if notes:
        out.append(f'<li>AI 分析提示（共 {len(notes)} 条）：<ul>')
        for n in notes[:20]:
            out.append(f'<li>{_esc(n)}</li>')
        out.append('</ul></li>')
    else:
        out.append('<li>AI 分析未产生异常提示</li>')
    out.append('</ul>')
    out.append('<div class="warn"><b>误报提示：</b>规则引擎命中项为模式匹配结果，存在误报可能；'
               'AI 语义分析项已做攻击路径确认。修复前请结合业务上下文二次确认。</div>')
    out.append('</div></section>')

    out.append(f'<div class="foot">本报告由 Aiholey 代码审计平台自动生成 · {_esc(gen)}<br>'
               '报告为静态快照，代码变更后请重新扫描</div>')
    out.append('</div></body></html>')
    return "".join(out)
