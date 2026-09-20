"""扫描引擎。

流程：收集文件 → 规则预筛 → 技能驱动的 AI 分析 → 去重 → 分级统计 → 生成报告。

关于 AI 阶段的设计取舍：参考系统是 codex CLI 的 agent 模式，每个 Skill 独立跑一遍、
由 agent 自己去读文件。我们只有 chat 接口，若按 31 个技能 × N 个代码块逐个调用，
调用量会爆炸且绝大多数返回空。因此改为「**代码分块 × 全技能维度**」：
每个代码块一次调用，prompt 里把启用技能的清单与关注点作为审计维度列全，
模型按维度输出结构化 JSON，findings 里带 skill 归属。这样既保留技能库的价值，
又把调用次数压到与分块数同级（Quick/Standard/Deep 分别 8/30/80 次上限）。
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Callable

from backend.config import (CODE_EXTS, DEPTHS, IGNORE_DIRS, MAX_FILE_BYTES,
                            MAX_FILES, SEVERITY_LABELS)
from backend.core import rules as rulelib
from backend.core.llm import LLMClient, LLMError, extract_json

Event = Callable[[str, int, str], None]  # (stage, progress, message)

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# 内置规则的分类 → 技能库技能名。让规则命中也归到对应技能维度，
# 报告里的「按技能统计」才有多样性（否则全是 security-scan-base）。
CATEGORY_SKILL = {
    "SQL 注入": "sql-injection-scanner",
    "命令注入": "os-command-injection-scanner",
    "表达式注入": "expression-injection-scanner",
    "不安全反射": "expression-injection-scanner",
    "路径穿越": "path-traversal-scanner",
    "SSRF": "ssrf-scanner",
    "XXE": "xxe-scanner",
    "XSS": "xss-reflected-scanner",
    "凭证泄漏": "credential-exposure-scanner",
    "反序列化": "java-deserialization-scanner",
    "不安全配置": "insecure-configuration-scanner",
    "加密安全": "insecure-configuration-scanner",
    "敏感数据暴露": "sensitive-data-exposure-scanner",
    "文件上传": "insecure-file-upload-scanner",
    "文件下载": "insecure-file-download-scanner",
    "日志注入": "log-injection-crlf-scanner",
}


# ---------------------------------------------------------------- 文件收集

def collect_files(root: Path, max_files: int = MAX_FILES) -> list[Path]:
    root = Path(root)
    if not root.exists():
        return []
    out: list[Path] = []
    for p in root.rglob("*"):
        if len(out) >= max_files:
            break
        if not p.is_file():
            continue
        if any(part in IGNORE_DIRS for part in p.parts):
            continue
        if p.suffix.lower() not in CODE_EXTS and p.name not in (".env", "Dockerfile", "Makefile"):
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES or p.stat().st_size == 0:
                continue
        except OSError:
            continue
        out.append(p)
    return out


def read_text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


# ---------------------------------------------------------------- 规则预筛

def rule_scan(files: list[Path], root: Path) -> list[dict]:
    findings: list[dict] = []
    for path in files:
        text = read_text(path)
        if not text:
            continue
        rel = str(path.relative_to(root))
        # 匹配逻辑统一交给 rules.scan_text（含文件级 / 行级上下文约束与注释过滤），
        # 这里只负责「同一文件同一规则最多 5 条」的限流与技能归类。
        hits: dict[str, int] = {}
        for hit in rulelib.scan_text(rel, text):
            rid = hit["rule_id"]
            if hits.get(rid, 0) >= 5:
                continue
            hits[rid] = hits.get(rid, 0) + 1
            findings.append({
                "skill": CATEGORY_SKILL.get(hit["category"], "security-scan-base"),
                "source": "rule",
                "severity": hit["severity"],
                "category": hit["category"],
                "title": hit["title"],
                "file": rel,
                "line": hit["line"],
                "snippet": hit["snippet"][:300],
                "detail": f"内置规则 {rid} 在 {rel}:{hit['line']} 命中模式：{hit.get('matched', '')}",
                "advice": hit["advice"],
                "confidence": "medium",
            })
    return findings


# ---------------------------------------------------------------- AI 分析

SYS_PROMPT = """你是一名资深代码安全审计专家，正在对一份真实生产代码做人工级审计。
要求：
1. 只报告**能构造出攻击路径**的真实漏洞；不确定的、纯风格的、无安全影响的问题一律不报。
2. 严格按给定的审计维度（技能清单）归类，每条漏洞必须归属到其中一个技能名。
3. 必须给出精确的文件路径与行号，代码片段要能对应到真实代码。
4. 宁可少报也不要臆造：如果某个维度在给定代码里没有发现问题，就不要编造。

只输出 JSON 数组，不要任何解释文字。每个元素结构：
{
  "skill": "技能名（必须来自给定的技能清单）",
  "severity": "critical|high|medium|low",
  "category": "中文风险分类",
  "title": "简短准确的漏洞标题",
  "file": "相对路径",
  "line": 行号(数字),
  "snippet": "触发问题的关键代码（<=200字符）",
  "detail": "漏洞成因 + 具体攻击路径 + 可达性判断",
  "advice": "具体可落地的修复建议",
  "confidence": "high|medium|low"
}
没有任何发现时输出 []。"""


def _build_dimensions(skills: list[dict]) -> str:
    lines = []
    for s in skills:
        lines.append(f"- {s['name']}（{s['description']}）")
    return "\n".join(lines)


# ---- 阶段 A：项目适配分析 -------------------------------------------------

PROFILE_SYS_PROMPT = """你是代码安全审计平台的项目适配分析器。
任务：阅读给定的项目代码样本，识别技术栈，并归纳本项目特有的审计增强规则，
供后续各专项扫描技能使用。只输出 JSON，不要任何解释文字。"""

PROFILE_SCHEMA = """{
  "project_name": "项目/仓库名",
  "tech_stack": {
    "language": "主语言",
    "framework": "主框架",
    "framework_version": "框架版本（无法判断时写 unknown）",
    "security_mechanism": "项目使用的认证/鉴权机制",
    "build_tool": "构建工具",
    "modules": ["主要模块名"]
  },
  "adaptations": [
    {"id": "adapt-001", "type": "framework_specific|security_pattern",
     "name": "适配规则名", "description": "具体怎么追踪/识别",
     "script_ref": null, "applies_to": ["适用技能名"]}
  ],
  "project_patterns": [
    {"name": "模式名", "description": "说明", "file_pattern": "*.ext",
     "code_pattern": "正则", "applies_to": ["适用技能名"]}
  ],
  "framework_refs": [],
  "cross_service_refs": [],
  "scan_enhancements": {
    "encoding": ["UTF-8"], "method_body_depth": 3,
    "preceding_comment_lines": 10, "impl_lookup": true
  }
}"""


def project_adapt(files: list[Path], root: Path, client: LLMClient,
                  depth: str = "standard", on_event: Event | None = None) -> tuple[dict | None, str]:
    """分析项目技术栈与审计增强规则。返回 (profile, note)。"""
    cfg = DEPTHS.get(depth, DEPTHS["standard"])
    sample_chunks = _chunk_files(files, root, cfg["chunk_chars"], 3)
    if not sample_chunks:
        return None, "无可分析文件"
    if on_event:
        on_event("adapt", 20, "正在识别技术栈与审计增强规则")

    # 优先把「构建清单 / 配置文件 / 入口文件」排在前面，技术栈识别更准
    index_lines: list[str] = []
    for path in files[:400]:
        index_lines.append(str(path.relative_to(root)))
    tree = "\n".join(index_lines[:400])
    sample = "\n\n".join(c[1] for c in sample_chunks)

    user = (
        f"项目文件清单（相对路径）：\n{tree}\n\n"
        f"代码样本：\n{sample}\n\n"
        f"请按以下 JSON 结构输出项目适配画像：\n{PROFILE_SCHEMA}"
    )
    try:
        raw = client.chat([
            {"role": "system", "content": PROFILE_SYS_PROMPT},
            {"role": "user", "content": user},
        ], temperature=0.1, max_tokens=2048)
    except LLMError as e:
        return None, f"项目适配分析失败：{e}"

    data = extract_json(raw)
    if not isinstance(data, dict):
        return None, "项目适配分析返回内容不是 JSON 对象"
    if on_event:
        ts = data.get("tech_stack") or {}
        if on_event:
            on_event("adapt", 30, f"识别到 {ts.get('language','?')} / {ts.get('framework','?')}")
    return data, ""


def _profile_digest(profile: dict | None) -> str:
    """把 profile 压成一段紧凑文本，注入扫描 prompt。"""
    if not profile:
        return "（未提供项目适配画像，按通用规则审计）"
    ts = profile.get("tech_stack") or {}
    parts = [
        "【项目适配画像】",
        f"- 语言/框架：{ts.get('language','?')} / {ts.get('framework','?')} {ts.get('framework_version','')}",
        f"- 构建工具：{ts.get('build_tool','?')}；安全机制：{ts.get('security_mechanism','?')}",
    ]
    mods = ts.get("modules") or []
    if mods:
        parts.append(f"- 模块：{', '.join(str(m) for m in mods[:10])}")
    ads = profile.get("adaptations") or []
    if ads:
        parts.append("- 本项目审计适配（务必据此调整判断）:")
        for a in ads[:12]:
            parts.append(f"  · {a.get('name','')}：{a.get('description','')}"
                         f"（适用：{', '.join(a.get('applies_to') or []) or '全部'}）")
    pats = profile.get("project_patterns") or []
    if pats:
        parts.append("- 项目特有代码模式（优先在匹配这些模式的代码里找问题）:")
        for p in pats[:12]:
            parts.append(f"  · {p.get('name','')}：文件 {p.get('file_pattern','*')} 匹配 {p.get('code_pattern','')}")
    en = profile.get("scan_enhancements") or {}
    if en:
        parts.append(f"- 扫描增强：编码 {','.join(en.get('encoding') or ['UTF-8'])}；"
                     f"方法体深度 {en.get('method_body_depth','-')}；"
                     f"前置注释 {en.get('preceding_comment_lines','-')} 行")
    return "\n".join(parts)


def _chunk_files(files: list[Path], root: Path, chunk_chars: int, max_chunks: int) -> list[tuple[str, str]]:
    """把文件按字符预算切成若干块，返回 [(标题, 内容)]。"""
    chunks: list[tuple[str, str]] = []
    buf: list[str] = []
    size = 0
    names: list[str] = []

    def flush():
        nonlocal buf, size, names
        if buf:
            header = "以下代码来自文件：" + "、".join(names[:20])
            chunks.append((header, "\n".join(buf)))
            buf, size, names = [], 0, []

    for path in files:
        if len(chunks) >= max_chunks:
            break
        text = read_text(path)
        if not text:
            continue
        rel = str(path.relative_to(root))
        body = "\n".join(text.splitlines()[:400])
        piece = f"\n===== FILE: {rel} =====\n{body}\n"
        if len(piece) > chunk_chars:
            piece = piece[:chunk_chars] + "\n...[截断]...\n"
        if size + len(piece) > chunk_chars:
            flush()
            if len(chunks) >= max_chunks:
                break
        buf.append(piece)
        names.append(rel)
        size += len(piece)
    flush()
    return chunks


def ai_scan(files: list[Path], root: Path, skills: list[dict], client: LLMClient,
            depth: str = "standard", on_event: Event | None = None,
            profile: dict | None = None) -> tuple[list[dict], list[str]]:
    cfg = DEPTHS.get(depth, DEPTHS["standard"])
    chunks = _chunk_files(files, root, cfg["chunk_chars"], cfg["max_chunks"])
    dims = _build_dimensions(skills)
    digest = _profile_digest(profile)
    findings: list[dict] = []
    notes: list[str] = []
    total = max(len(chunks), 1)

    for i, (header, content) in enumerate(chunks, 1):
        if on_event:
            on_event("ai", int(45 + 50 * (i - 1) / total), f"AI 分析第 {i}/{len(chunks)} 块（{len(content)//1024} KB）")
        user = (
            f"{digest}\n\n"
            f"【本次审计维度（技能清单）】\n{dims}\n\n"
            f"{header}\n\n{content}\n\n"
            f"请按上述维度审计，输出 JSON 数组。"
        )
        try:
            raw = client.chat([
                {"role": "system", "content": SYS_PROMPT},
                {"role": "user", "content": user},
            ], max_tokens=4096)
        except LLMError as e:
            notes.append(f"第 {i} 块分析失败：{e}")
            if on_event:
                on_event("ai", int(45 + 50 * i / total), f"第 {i} 块失败：{e}")
            continue
        data = extract_json(raw)
        if isinstance(data, dict):
            data = data.get("findings") or data.get("data") or []
        if not isinstance(data, list):
            notes.append(f"第 {i} 块返回内容不是 JSON 数组，已跳过")
            continue
        for item in data:
            if not isinstance(item, dict):
                continue
            sev = str(item.get("severity", "medium")).lower()
            if sev not in SEV_ORDER:
                sev = "medium"
            try:
                line = int(item.get("line") or 0)
            except (TypeError, ValueError):
                line = 0
            findings.append({
                "skill": str(item.get("skill") or "security-scan-base").strip(),
                "source": "ai",
                "severity": sev,
                "category": str(item.get("category") or "未分类")[:60],
                "title": str(item.get("title") or "未命名问题")[:160],
                "file": str(item.get("file") or "")[:300],
                "line": line,
                "snippet": str(item.get("snippet") or "")[:300],
                "detail": str(item.get("detail") or "")[:1500],
                "advice": str(item.get("advice") or "")[:600],
                "confidence": str(item.get("confidence") or "medium")[:10],
            })
    return findings, notes


# ---------------------------------------------------------------- 去重与统计

def dedupe(findings: list[dict]) -> list[dict]:
    seen: dict[tuple, dict] = {}
    for f in findings:
        key = (f.get("file", ""), f.get("line", 0), f.get("category", ""))
        cur = seen.get(key)
        if cur is None:
            seen[key] = f
            continue
        # AI 结果优先于规则结果；同级则保留描述更完整的
        better = (f["source"] == "ai" and cur["source"] != "ai") or \
                 (f["source"] == cur["source"] and len(f.get("detail", "")) > len(cur.get("detail", "")))
        if better:
            seen[key] = f
    out = list(seen.values())
    out.sort(key=lambda x: (SEV_ORDER.get(x["severity"], 9), x.get("file", ""), x.get("line", 0)))
    return out


def stats_of(findings: list[dict]) -> dict:
    s = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        s[f["severity"]] = s.get(f["severity"], 0) + 1
    s["total"] = len(findings)
    return s


def by_skill(findings: list[dict]) -> list[dict]:
    agg: dict[str, dict] = {}
    for f in findings:
        k = f.get("skill") or "security-scan-base"
        a = agg.setdefault(k, {"skill": k, "critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0})
        a[f["severity"]] = a.get(f["severity"], 0) + 1
        a["total"] += 1
    return sorted(agg.values(), key=lambda x: -x["total"])


# ---------------------------------------------------------------- 报告

def build_markdown(run: dict, findings: list[dict], repo: dict | None = None,
                   skills: list[dict] | None = None, notes: list[str] | None = None,
                   ai_used: bool = False) -> str:
    st = stats_of(findings)
    L: list[str] = []
    L.append(f"# 代码安全审计报告 · {run.get('repo_name') or run.get('task_name') or '未命名'}")
    L.append("")
    L.append("| 项目 | 内容 |")
    L.append("|---|---|")
    L.append(f"| 运行 ID | `{run.get('run_id','')}` |")
    L.append(f"| 任务 | {run.get('task_name','-')} |")
    L.append(f"| 仓库 | {run.get('repo_name','-')} |")
    if repo:
        L.append(f"| 仓库地址 | {repo.get('url','-')} |")
        L.append(f"| 分支 | `{repo.get('branch','-')}` |")
        if repo.get("last_pull_msg"):
            L.append(f"| 提交 | `{str(repo['last_pull_msg']).splitlines()[0][:80]}` |")
    L.append(f"| 审计深度 | {DEPTHS.get(run.get('depth','standard'),{}).get('label', run.get('depth'))} |")
    L.append(f"| 引擎 | {run.get('engine','-')}{'（AI 语义分析已启用）' if ai_used else '（仅规则引擎）'} |")
    L.append(f"| 扫描文件 | {run.get('files_scanned',0)} 个 · {run.get('loc',0)} 行 |")
    L.append(f"| 耗时 | {run.get('duration_ms',0)/1000:.2f} 秒 |")
    L.append(f"| 完成时间 | {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(run.get('finished_at') or time.time()))} |")
    L.append("")
    L.append("## 一、漏洞总览")
    L.append("")
    L.append("| 严重 | 高危 | 中危 | 低危 | 合计 |")
    L.append("|---|---|---|---|---|")
    L.append(f"| {st['critical']} | {st['high']} | {st['medium']} | {st['low']} | {st['total']} |")
    L.append("")

    if skills:
        L.append("## 二、本次参与的审计技能")
        L.append("")
        L.append("| 技能 | 说明 | 命中 |")
        L.append("|---|---|---|")
        hit = {b["skill"]: b["total"] for b in by_skill(findings)}
        for s in skills:
            L.append(f"| `{s['name']}` | {s.get('description','')} | {hit.get(s['name'],0)} |")
        L.append("")

    L.append("## 三、确认漏洞清单")
    L.append("")
    if not findings:
        L.append("本次扫描未发现可确认的安全漏洞。")
        L.append("")
    cur = None
    for i, f in enumerate(findings, 1):
        if f["severity"] != cur:
            cur = f["severity"]
            L.append(f"### {SEVERITY_LABELS.get(cur, cur)}（{st.get(cur,0)} 项）")
            L.append("")
        L.append(f"#### {i}. {f['title']}")
        L.append("")
        L.append(f"- **位置**：`{f['file']}:{f['line']}`")
        L.append(f"- **技能**：`{f['skill']}` · **来源**：{'AI 语义分析' if f['source']=='ai' else '内置规则'} · **置信度**：{f.get('confidence','medium')}")
        if f.get("snippet"):
            L.append("")
            L.append("```")
            L.append(f["snippet"])
            L.append("```")
        if f.get("detail"):
            L.append("")
            L.append(f"**成因与攻击路径**：{f['detail']}")
        if f.get("advice"):
            L.append("")
            L.append(f"**修复建议**：{f['advice']}")
        L.append("")

    bs = by_skill(findings)
    if bs:
        L.append("## 四、按技能统计")
        L.append("")
        L.append("| 技能 | 严重 | 高危 | 中危 | 低危 | 合计 |")
        L.append("|---|---|---|---|---|---|")
        for b in bs:
            L.append(f"| `{b['skill']}` | {b['critical']} | {b['high']} | {b['medium']} | {b['low']} | {b['total']} |")
        L.append("")

    L.append("## 五、扫描说明与误报排除")
    L.append("")
    L.append(f"- 扫描目录：`{run.get('workdir','')}`")
    L.append(f"- 已忽略：`.git/`、依赖目录（node_modules/target/dist 等）、`.gitignore` 所列文件")
    L.append(f"- 单文件上限 {MAX_FILE_BYTES//1000} KB，超限文件按前 400 行截断参与分析")
    if notes:
        L.append(f"- AI 分析提示（共 {len(notes)} 条）：")
        for n in notes[:20]:
            L.append(f"  - {n}")
    else:
        L.append("- AI 分析未产生异常提示。")
    L.append("")
    L.append("> 规则引擎命中项为**模式匹配**结果，存在误报可能；AI 语义分析项已做攻击路径确认。")
    L.append("> 修复前请结合业务上下文二次确认。")
    return "\n".join(L)
