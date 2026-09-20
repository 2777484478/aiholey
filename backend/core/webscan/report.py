"""Web 漏扫报告渲染（Markdown / 自包含 HTML）。"""
from __future__ import annotations

import html
from datetime import datetime

from backend.core.report_html import print_toolbar
from backend.core.webscan.tools import SEVERITY_ORDER
from backend.core.webscan.skills_seed import FLOW_SKILLS

SEV_LABEL = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "提示"}
SEV_COLOR = {"critical": "#7f1d1d", "high": "#b91c1c", "medium": "#c2410c", "low": "#1d4ed8", "info": "#4b5563"}
CONF_LABEL = {"high": "高", "medium": "中", "low": "低"}


def _ts(v) -> str:
    if not v:
        return "-"
    try:
        return datetime.fromtimestamp(float(v)).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError):
        return "-"


def _dur(ms) -> str:
    try:
        s = int(ms or 0) / 1000
    except (TypeError, ValueError):
        return "-"
    if s < 60:
        return f"{s:.1f}s"
    return f"{int(s // 60)}m{int(s % 60):02d}s"


def _esc(v) -> str:
    return html.escape(str(v if v is not None else ""), quote=True)


def group_by_target(findings: list[dict]) -> dict[str, list[dict]]:
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    out: dict[str, list[dict]] = {}
    for f in findings:
        out.setdefault(f.get("target") or f.get("url") or "（未知目标）", []).append(f)
    for k in out:
        out[k].sort(key=lambda f: order.get(f.get("severity", "info"), 9))
    return out


def by_skill(findings: list[dict]) -> list[dict]:
    agg: dict[str, dict] = {}
    for f in findings:
        s = f.get("skill") or "（未分类）"
        row = agg.setdefault(s, {"skill": s, "total": 0, **{k: 0 for k in SEVERITY_ORDER}})
        row["total"] += 1
        row[f.get("severity", "info")] = row.get(f.get("severity", "info"), 0) + 1
    return sorted(agg.values(), key=lambda r: (-r["total"], r["skill"]))


def stats_of(findings: list[dict]) -> dict:
    st = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        st[f.get("severity", "info")] = st.get(f.get("severity", "info"), 0) + 1
    st["total"] = len(findings)
    return st


def head_risk(st: dict) -> str:
    if st.get("critical"):
        return "存在严重风险，建议立即处置"
    if st.get("high"):
        return "存在高危风险，建议尽快处置"
    if st.get("medium"):
        return "存在中危风险，建议排期修复"
    if st.get("low"):
        return "整体风险可控，建议加固配置"
    return "本次外部探测未发现明显问题"


# ============================================================ Markdown

def render_markdown(job: dict, findings: list[dict], targets: list[str],
                    notes: list[str], skills: list[dict]) -> str:
    st = stats_of(findings)
    L: list[str] = []
    L.append(f"# Web 安全扫描报告 · {job.get('name') or '未命名'}")
    L.append("")
    L.append(f"- **任务 ID**：`{job.get('job_id', '')}`")
    L.append(f"- **扫描目标**：{len(targets)} 个")
    for t in targets:
        L.append(f"  - {t}")
    L.append(f"- **探测强度**：{job.get('depth', 'standard')}")
    L.append(f"- **使用引擎**：{job.get('engine', '')}"
             f"{'（已启用 AI 规划）' if job.get('ai_used') else '（仅确定性检查）'}")
    L.append(f"- **完成时间**：{_ts(job.get('finished_at'))}")
    L.append(f"- **总耗时**：{_dur(job.get('duration_ms'))}")
    L.append(f"- **HTTP 请求总数**：{job.get('requests_made', 0)}")
    L.append("")
    L.append("## 一、结论摘要")
    L.append("")
    L.append(f"**{head_risk(st)}**。共发现 {st['total']} 个问题："
             f"严重 {st['critical']} / 高危 {st['high']} / 中危 {st['medium']} / "
             f"低危 {st['low']} / 提示 {st['info']}。")
    L.append("")
    L.append("## 二、问题清单")
    L.append("")

    if not findings:
        L.append("本次外部探测未发现可确认的安全问题。")
        L.append("")
    else:
        for target, items in group_by_target(findings).items():
            L.append(f"### 目标：{target}")
            L.append("")
            for i, f in enumerate(items, 1):
                L.append(f"#### {i}. [{SEV_LABEL.get(f.get('severity'), f.get('severity'))}] {f.get('title', '')}")
                L.append("")
                L.append(f"- **受影响地址**：`{f.get('url', '')}`")
                if f.get("method"):
                    L.append(f"- **请求方法**：{f.get('method')}")
                if f.get("param"):
                    L.append(f"- **参数**：`{f.get('param')}`")
                if f.get("payload"):
                    L.append(f"- **测试载荷**：`{f.get('payload')}`")
                L.append(f"- **检测技能**：{f.get('skill', '')}")
                L.append(f"- **来源**：{'AI 研判' if f.get('source') == 'ai' else '工具判定'}"
                         f" · 置信度 {CONF_LABEL.get(f.get('confidence'), f.get('confidence', ''))}")
                if f.get("cwe"):
                    L.append(f"- **CWE**：{f.get('cwe')}")
                L.append("")
                L.append(f"**问题说明**：{f.get('detail', '')}")
                L.append("")
                if f.get("evidence"):
                    L.append("**复现证据**：")
                    L.append("")
                    L.append("```text")
                    L.append(str(f.get("evidence", ""))[:900])
                    L.append("```")
                    L.append("")
                L.append(f"**修复建议**：{f.get('advice', '')}")
                L.append("")

    L.append("## 三、按检测项统计")
    L.append("")
    L.append("| 检测项 | 严重 | 高危 | 中危 | 低危 | 提示 | 合计 |")
    L.append("| --- | --- | --- | --- | --- | --- | --- |")
    for r in by_skill(findings):
        L.append(f"| {r['skill']} | {r['critical']} | {r['high']} | {r['medium']} | "
                 f"{r['low']} | {r['info']} | {r['total']} |")
    L.append("")

    if notes:
        L.append("## 四、扫描过程说明")
        L.append("")
        for n in notes:
            L.append(f"- {n}")
        L.append("")

    L.append("## 五、测试范围与限制")
    L.append("")
    L.append("- 本次为**轻量级外部探测**，只发起读取类请求（GET/HEAD/OPTIONS 与有限的重定向探测），"
             "不提交任何会修改服务端状态的请求。")
    L.append("- **未覆盖**：需要账号的越权与权限绕过、业务逻辑缺陷、注入类漏洞的深入验证、"
             "客户端脚本漏洞的实际利用、认证爆破。")
    L.append("- 如目标前置了 WAF / CDN，探测结果可能来自边缘节点，需结合源站情况复核。")
    L.append("- 所有结论建议人工复核后再作为整改依据。")
    L.append("")
    L.append(f"_报告生成时间：{_ts(job.get('finished_at'))} · "
             f"由 Aiholey Web 漏扫模块生成，证据中的凭据类内容已自动遮蔽。_")
    return "\n".join(L)


# ============================================================ HTML

_CSS = """
*{box-sizing:border-box}
body{margin:0;background:#f3f4f6;color:#111827;
 font-family:-apple-system,BlinkMacSystemFont,"PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;
 font-size:14px;line-height:1.7}
.wrap{max-width:1080px;margin:0 auto;padding:0 20px 60px}
.hero{background:linear-gradient(135deg,#111827,#1f2937);color:#f9fafb;padding:32px 0 28px;margin-bottom:24px}
.hero .wrap{padding-bottom:0}
.hero h1{margin:0 0 6px;font-size:22px;font-weight:600}
.hero .sub{color:#9ca3af;font-size:13px}
.meta{display:flex;flex-wrap:wrap;gap:8px 22px;margin-top:16px;font-size:13px;color:#d1d5db}
.meta b{color:#fff;font-weight:500}
.toolbar{margin-top:18px}
.btn{display:inline-block;padding:7px 14px;border-radius:8px;border:1px solid #374151;
 background:#1f2937;color:#e5e7eb;font-size:13px;cursor:pointer}
.btn:hover{background:#374151}
.stats{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:22px}
.stat{flex:1 1 150px;background:#fff;border-radius:12px;padding:16px 18px;
 border-left:4px solid #e5e7eb;box-shadow:0 1px 2px rgba(0,0,0,.05)}
.stat .k{font-size:12px;color:#6b7280}
.stat .v{font-size:26px;font-weight:600;margin-top:2px}
.card{background:#fff;border-radius:12px;padding:20px 22px;margin-bottom:18px;
 box-shadow:0 1px 2px rgba(0,0,0,.05)}
.card h2{font-size:16px;margin:0 0 14px;font-weight:600}
.card h3{font-size:14px;margin:18px 0 8px;font-weight:500;color:#374151}
.badge{display:inline-block;padding:2px 9px;border-radius:6px;font-size:12px;color:#fff;font-weight:500}
.tb{width:100%;border-collapse:collapse;font-size:13px}
.tb th,.tb td{padding:8px 10px;border-bottom:1px solid #e5e7eb;text-align:left}
.tb th{background:#f9fafb;font-weight:500;color:#374151}
.finding{background:#fff;border-radius:12px;padding:18px 20px;margin-bottom:14px;
 box-shadow:0 1px 2px rgba(0,0,0,.05);border-left:4px solid #e5e7eb}
.finding h4{margin:0 0 10px;font-size:15px;font-weight:600;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.kv{display:grid;grid-template-columns:96px 1fr;gap:4px 12px;font-size:13px;margin-bottom:10px}
.kv .k{color:#6b7280}
.sect{margin-top:10px;font-size:13px}
.sect .lb{color:#6b7280;margin-bottom:3px}
.code{background:#0f172a;color:#e2e8f0;padding:11px 13px;border-radius:8px;
 font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;
 line-height:1.55;white-space:pre-wrap;word-break:break-all;max-height:260px;overflow:auto}
.fix{background:#f0fdf4;border:1px solid #bbf7d0;color:#14532d;padding:10px 12px;
 border-radius:8px;font-size:13px}
.warn{background:#fffbeb;border:1px solid #fde68a;color:#78350f;padding:12px 14px;
 border-radius:8px;font-size:13px}
.muted{color:#6b7280;font-size:13px}
footer{text-align:center;color:#9ca3af;font-size:12px;margin-top:26px}
@media print{
 body{background:#fff}
 .toolbar{display:none}
 .hero{background:#1f2937 !important;-webkit-print-color-adjust:exact;print-color-adjust:exact}
 .card,.finding,.stat{box-shadow:none;border:1px solid #e5e7eb}
 .finding{page-break-inside:avoid}
 .code{background:#f8fafc;color:#0f172a;border:1px solid #e2e8f0}
}
"""


def _finding_html(f: dict, idx: int) -> str:
    sev = f.get("severity", "info")
    parts = [f'<div class="finding" style="border-left-color:{SEV_COLOR.get(sev, "#e5e7eb")}">']
    # 注意 fallback：SEV_LABEL 查不到时回落到原始 severity 值，那是**入库的原始数据**，
    # 必须转义后再插进 HTML（同理见下面的置信度）。查表命中的常量则无需处理。
    parts.append(
        f'<h4><span class="badge" style="background:{SEV_COLOR.get(sev, "#6b7280")}">'
        f'{_esc(SEV_LABEL.get(sev, sev))}</span>{_esc(f.get("title", ""))}</h4>')

    rows = [("受影响地址", f'<code>{_esc(f.get("url", ""))}</code>')]
    if f.get("method"):
        rows.append(("请求方法", _esc(f.get("method"))))
    if f.get("param"):
        rows.append(("参数", f'<code>{_esc(f.get("param"))}</code>'))
    if f.get("payload"):
        rows.append(("测试载荷", f'<code>{_esc(f.get("payload"))}</code>'))
    rows.append(("检测项", _esc(f.get("skill", ""))))
    rows.append(("来源", ("AI 研判" if f.get("source") == "ai" else "工具判定")
                 + " · 置信度 "
                 + _esc(CONF_LABEL.get(f.get("confidence"), str(f.get("confidence", ""))))))
    if f.get("cwe"):
        rows.append(("CWE", _esc(f.get("cwe"))))
    parts.append('<div class="kv">' + "".join(
        f'<div class="k">{k}</div><div>{v}</div>' for k, v in rows) + '</div>')

    if f.get("detail"):
        parts.append(f'<div class="sect"><div class="lb">问题说明</div>{_esc(f["detail"])}</div>')
    if f.get("evidence"):
        parts.append(f'<div class="sect"><div class="lb">复现证据</div>'
                     f'<div class="code">{_esc(str(f["evidence"])[:900])}</div></div>')
    if f.get("advice"):
        parts.append(f'<div class="sect"><div class="lb">修复建议</div>'
                     f'<div class="fix">{_esc(f["advice"])}</div></div>')
    parts.append("</div>")
    return "".join(parts)


def render_html(job: dict, findings: list[dict], targets: list[str],
                notes: list[str], skills: list[dict]) -> str:
    st = stats_of(findings)
    ai_used = bool(job.get("ai_used"))

    stats_html = "".join(
        f'<div class="stat" style="border-left-color:{SEV_COLOR[k]}">'
        f'<div class="k">{SEV_LABEL[k]}</div>'
        f'<div class="v" style="color:{SEV_COLOR[k]}">{st[k]}</div></div>'
        for k in SEVERITY_ORDER if k != "info"
    ) + f'<div class="stat" style="border-left-color:#6b7280"><div class="k">合计</div>' \
        f'<div class="v">{st["total"]}</div></div>'

    targets_html = "".join(f"<li><code>{_esc(t)}</code></li>" for t in targets)

    body: list[str] = []
    body.append('<div class="card"><h2>结论摘要</h2>'
                f'<p style="font-size:15px;margin:0 0 8px"><b>{_esc(head_risk(st))}</b></p>'
                f'<p class="muted" style="margin:0">共发现 {st["total"]} 个问题：'
                f'严重 {st["critical"]} / 高危 {st["high"]} / 中危 {st["medium"]} / '
                f'低危 {st["low"]} / 提示 {st["info"]}。</p></div>')

    body.append('<div class="card"><h2>扫描目标</h2>'
                f'<ul style="margin:0;padding-left:20px">{targets_html}</ul>'
                f'<p class="muted" style="margin:12px 0 0">'
                f'探测强度 {_esc(job.get("depth"))} · '
                f'{"AI 自主规划" if ai_used else "确定性检查（未启用 AI）"} · '
                f'共发起 {job.get("requests_made", 0)} 次 HTTP 请求 · '
                f'耗时 {_dur(job.get("duration_ms"))}</p></div>')

    if not findings:
        body.append('<div class="card"><h2>问题清单</h2>'
                    '<div class="warn">本次外部探测未发现可确认的安全问题。'
                    '这不代表目标绝对安全 —— 轻量探测覆盖不了需要账号的业务逻辑缺陷与深度注入验证，'
                    '建议结合实际业务场景做进一步评估。</div></div>')
    else:
        for target, items in group_by_target(findings).items():
            cards = "".join(_finding_html(f, i) for i, f in enumerate(items, 1))
            body.append(f'<h2 style="font-size:15px;margin:26px 0 12px;color:#374151">'
                        f'目标：{_esc(target)}（{len(items)} 项）</h2>')
            body.append(cards)

    rows = "".join(
        f'<tr><td>{_esc(r["skill"])}</td>'
        + "".join(f'<td>{r[k]}</td>' for k in SEVERITY_ORDER)
        + f'<td><b>{r["total"]}</b></td></tr>'
        for r in by_skill(findings))
    body.append('<div class="card"><h2>按检测项统计</h2>'
                '<table class="tb"><thead><tr><th>检测项</th>'
                + "".join(f'<th>{SEV_LABEL[k]}</th>' for k in SEVERITY_ORDER)
                + '<th>合计</th></tr></thead><tbody>' + (rows or '<tr><td colspan="7">无</td></tr>')
                + '</tbody></table></div>')

    if notes:
        body.append('<div class="card"><h2>扫描过程说明</h2><ul style="margin:0;padding-left:20px">'
                    + "".join(f"<li>{_esc(n)}</li>" for n in notes) + "</ul></div>")

    body.append(
        '<div class="card"><h2>测试范围与限制</h2>'
        '<div class="warn">'
        '<b>本次为轻量级外部探测</b>，只发起读取类请求（GET/HEAD/OPTIONS 及有限的重定向探测），'
        '不提交任何会修改服务端状态的请求。<br><br>'
        '<b>未覆盖范围：</b>需要账号的越权与权限绕过、业务逻辑缺陷、注入类漏洞的深入验证、'
        '客户端脚本漏洞的实际利用、认证爆破。<br>'
        '如目标前置了 WAF / CDN，探测结果可能来自边缘节点，需结合源站情况复核。<br>'
        '<b>所有结论建议人工复核后再作为整改依据。</b>'
        '</div></div>')

    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Web 安全扫描报告 · {_esc(job.get('name') or job.get('job_id', ''))}</title>
<style>{_CSS}</style></head><body>
<div class="hero"><div class="wrap">
  <h1>Web 安全扫描报告</h1>
  <div class="sub">{_esc(job.get('name') or '未命名任务')} · {_esc(job.get('job_id', ''))}</div>
  <div class="meta">
    <span>目标数 <b>{len(targets)}</b></span>
    <span>探测强度 <b>{_esc(job.get('depth'))}</b></span>
    <span>引擎 <b>{_esc(job.get('engine'))}</b></span>
    <span>完成时间 <b>{_esc(_ts(job.get('finished_at')))}</b></span>
    <span>耗时 <b>{_esc(_dur(job.get('duration_ms')))}</b></span>
  </div>
  {print_toolbar()}
</div></div>
<div class="wrap">
  <div class="stats">{stats_html}</div>
  {''.join(body)}
  <footer>本报告由 Aiholey Web 漏洞扫描模块生成 · 证据中的凭据类内容已自动遮蔽</footer>
</div></body></html>"""
