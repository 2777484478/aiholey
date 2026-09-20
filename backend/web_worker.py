"""Web 漏扫执行体（独立子进程入口）。

由 API 在收到「开始扫描」请求时直接拉起：
    python -m backend.web_worker <job_id>

**不走任务队列** —— 拉起即执行，与代码审计的调度器完全隔离，互不占用并发槽位。
进度写在 web_jobs 表（stage / progress / message），前端轮询即可；
过程日志复用 run_logs 表，以 job_id 为键。
"""
from __future__ import annotations

import json
import sys
import time
import traceback
from pathlib import Path

from backend.config import WEBSCAN_DIR, WEB_DEPTHS
from backend.core import db, engineconf
from backend.core.webscan import agent, endpoints, report
from backend.core.webscan import tools as T


def _log(job_id: str, message: str, level: str = "info") -> None:
    db.log_line(job_id, message, level)
    print(message, flush=True)


def _say(job_id: str, stage: str, progress: int, message: str) -> None:
    db.execute("UPDATE web_jobs SET stage=?, progress=?, message=? WHERE job_id=?",
               (stage, max(0, min(100, progress)), message[:300], job_id))
    _log(job_id, f"[{stage}] {message}")


def _fail(job_id: str, msg: str, started: float) -> None:
    db.execute("UPDATE web_jobs SET status='failed', stage='失败', error=?, finished_at=?, "
               "duration_ms=? WHERE job_id=?",
               (msg[:600], time.time(), int((time.time() - started) * 1000), job_id))
    _log(job_id, f"扫描失败：{msg}", "error")


def load_web_skills(job: dict) -> list[dict]:
    """取出本次启用的技能；流程型技能（总纲/验证/报告）强制包含。"""
    try:
        names = set(json.loads(job.get("skill_names") or "[]"))
    except json.JSONDecodeError:
        names = set()
    all_skills = db.query("SELECT * FROM web_skills ORDER BY sort_order")
    if not all_skills:
        return []
    if not names:
        names = {s["name"] for s in all_skills if s["enabled"]}
    chosen = {s["name"] for s in all_skills if s["name"] in names}
    chosen |= {s["name"] for s in all_skills if s["phase"] == "flow"}
    return [s for s in all_skills if s["name"] in chosen]


def run_job(job_id: str) -> int:
    started = time.time()
    job = db.query_one("SELECT * FROM web_jobs WHERE job_id=?", (job_id,))
    if not job:
        print(f"找不到扫描记录 {job_id}", flush=True)
        return 2

    out_dir = WEBSCAN_DIR / job_id
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        # ---------- 1. 目标整理 ----------
        raw_targets = json.loads(job.get("targets") or "[]")
        targets = [t for t in (T.normalize_target(x) for x in raw_targets) if t]
        if not targets:
            _fail(job_id, "没有有效的扫描目标", started)
            return 4
        depth = job.get("depth") or "standard"
        dcfg = WEB_DEPTHS.get(depth, WEB_DEPTHS["standard"])
        db.execute("UPDATE web_jobs SET targets_total=? WHERE job_id=?", (len(targets), job_id))
        _say(job_id, "准备", 3, f"共 {len(targets)} 个目标，探测强度 {depth}")

        # ---------- 2. 技能与引擎 ----------
        skills = load_web_skills(job)
        checks = [s for s in skills if s["phase"] != "flow"]
        if not skills:
            _fail(job_id, "Web 扫描技能库为空，请先初始化", started)
            return 5
        _say(job_id, "加载技能", 5, f"启用 {len(checks)} 项检测技能")

        client = engineconf.client_for(job.get("engine") or "codex")
        ai_used = client is not None
        notes: list[str] = []
        if client is None:
            notes.append("未配置模型 API Key，本次仅执行确定性检查项（无 AI 语义研判）")
            _say(job_id, "AI 规划", 6, "未配置 API Key，采用确定性检查模式")
        else:
            _say(job_id, "AI 规划", 6, f"模型 {client.model} 将自主规划每个目标的渗透流程")

        # ---------- 3. 逐目标扫描：端口发现 → 逐端口深入 ----------
        sess = T.ScanSession(timeout=dcfg["timeout"], delay=dcfg["delay"],
                             max_requests=dcfg["max_requests"], depth=depth)
        all_findings: list[dict] = []
        tool_usage: dict[str, int] = {}
        mode_seen: set[str] = set()

        def on_agent(msg: str) -> None:
            _log(job_id, msg)

        try:
            base, span = 8, 84
            for idx, target in enumerate(targets):
                t0 = time.time()
                share = span / len(targets)
                pct0 = base + int(share * idx)
                _say(job_id, "端口发现", pct0, f"[{idx + 1}/{len(targets)}] 目标：{target}")

                # ---- ① 展开：端口发现 + 服务识别 ----
                try:
                    exp = endpoints.expand_target(
                        target, sess, depth=depth,
                        say=lambda m, lv="info": _log(job_id, m, lv))
                except Exception as e:
                    traceback.print_exc()
                    notes.append(f"{target} 端口展开异常：{type(e).__name__}: {e}")
                    _log(job_id, f"{target} 端口展开异常：{type(e).__name__}: {e}", "warn")
                    exp = {"http": [], "services": [], "ports": [], "issues": [], "notes": []}

                notes.extend(exp.get("notes") or [])
                found_target: list[dict] = list(exp.get("issues") or [])
                eps = exp.get("http") or []
                if not eps:
                    # 端口阶段没识别出 HTTP 服务时，仍按原始目标扫一遍，避免整体空转
                    eps = [{"url": target, "port": 0, "service": "", "is_primary": True}]
                if exp.get("ports"):
                    _log(job_id, f"  开放端口：{endpoints.port_summary(exp['ports'])}")

                # ---- ② 逐 HTTP 端点：完整 Web 检测链（AI 自主规划）----
                for ei, ep in enumerate(eps):
                    if len(eps) > 1:
                        _say(job_id, "扫描端点",
                             pct0 + int(share * 0.3 * ei / max(1, len(eps))),
                             f"[{idx + 1}/{len(targets)}] 端点 {ei + 1}/{len(eps)}：{ep['url']}")
                    _log(job_id, f"  → 端点 {ep['url']}"
                                 + ("（主端点）" if ep.get("is_primary") else ""))
                    try:
                        res = agent.scan_target(ep["url"], client, skills, sess, on_agent, depth)
                    except Exception as e:
                        traceback.print_exc()
                        notes.append(f"{ep['url']} 扫描异常：{type(e).__name__}: {e}")
                        _log(job_id, f"{ep['url']} 扫描异常：{type(e).__name__}: {e}", "warn")
                        continue
                    got = res.get("findings") or []
                    for f in got:
                        f["target"] = target
                    found_target.extend(got)
                    notes.extend(res.get("notes") or [])
                    mode_seen.add(res.get("mode", ""))
                    for name in res.get("tools_used") or []:
                        tool_usage[name] = tool_usage.get(name, 0) + 1
                    if got:
                        _log(job_id, f"    {ep['url']} 发现 {len(got)} 项")

                # ---- ③ 逐服务端口：未授权访问检测（只读）----
                host = T.host_of(target)
                for sp in exp.get("services") or []:
                    r = T.run_tool(sess, "unauth_check",
                                   {"host": host, "port": sp["port"], "service": sp["service"]})
                    issues = r.get("issues") or []
                    for it in issues:
                        it["target"] = target
                    found_target.extend(issues)
                    tool_usage["unauth_check"] = tool_usage.get("unauth_check", 0) + 1
                    _log(job_id, f"  → 端口 {sp['port']}（{sp['service']}）：{r.get('summary')}")

                all_findings.extend(found_target)
                db.execute("UPDATE web_jobs SET targets_done=?, requests_made=? WHERE job_id=?",
                           (idx + 1, sess.requests_made, job_id))
                _say(job_id, "扫描目标", base + int(share * (idx + 1)),
                     f"[{idx + 1}/{len(targets)}] 完成：{target}，发现 {len(found_target)} 项，"
                     f"耗时 {time.time() - t0:.1f}s")
        finally:
            sess.close()

        if tool_usage:
            _log(job_id, "工具调用统计：" + "、".join(
                f"{k}×{v}" for k, v in sorted(tool_usage.items(), key=lambda x: -x[1])))

        # ---------- 4. 去重 / 统计 ----------
        _say(job_id, "生成报告", 94, "合并去重、分级统计")
        findings = agent.dedupe_findings(all_findings)
        st = agent.stats_of(findings)

        db.execute("DELETE FROM web_findings WHERE job_id=?", (job_id,))
        for f in findings:
            db.insert("web_findings", {
                "job_id": job_id, "target": f.get("target", ""), "skill": f.get("skill", ""),
                "source": f.get("source", "tool"), "severity": f.get("severity", "low"),
                "category": f.get("category", ""), "title": f.get("title", ""),
                "url": f.get("url", ""), "method": f.get("method", "GET"),
                "param": f.get("param", ""), "payload": f.get("payload", ""),
                "evidence": f.get("evidence", ""), "detail": f.get("detail", ""),
                "advice": f.get("advice", ""), "cwe": f.get("cwe", ""),
                "confidence": f.get("confidence", "medium"),
            })

        # ---------- 5. 出报告 ----------
        job["finished_at"] = time.time()
        job["duration_ms"] = int((time.time() - started) * 1000)
        job["requests_made"] = sess.requests_made
        job["ai_used"] = 1 if ai_used else 0

        md = report.render_markdown(job, findings, targets, notes, skills)
        html_doc = report.render_html(job, findings, targets, notes, skills)
        (out_dir / "report.md").write_text(md, encoding="utf-8")
        (out_dir / "report.html").write_text(html_doc, encoding="utf-8")
        (out_dir / "findings.json").write_text(
            json.dumps({"job": {k: v for k, v in job.items() if k != "report_md"},
                        "targets": targets, "findings": findings,
                        "tool_usage": tool_usage, "notes": notes},
                       ensure_ascii=False, indent=2), encoding="utf-8")

        db.execute(
            "UPDATE web_jobs SET status='success', stage='已完成', progress=100, message=?, "
            "finished_at=?, duration_ms=?, targets_done=?, requests_made=?, "
            "sev_critical=?, sev_high=?, sev_medium=?, sev_low=?, sev_info=?, "
            "report_md=?, ai_used=? WHERE job_id=?",
            (f"发现 {st['total']} 个问题（严重 {st['critical']} / 高危 {st['high']} / "
             f"中危 {st['medium']} / 低危 {st['low']} / 提示 {st['info']}）",
             job["finished_at"], job["duration_ms"], len(targets), sess.requests_made,
             st["critical"], st["high"], st["medium"], st["low"], st["info"],
             md, 1 if ai_used else 0, job_id))
        _say(job_id, "已完成", 100,
             f"扫描完成：{st['total']} 个问题，{len(targets)} 个目标，"
             f"{sess.requests_made} 次请求，耗时 {job['duration_ms'] / 1000:.1f}s")
        return 0

    except Exception as e:  # 兜底：任何异常都要落库，不能留下永远 running 的记录
        import traceback
        traceback.print_exc()
        _fail(job_id, f"{type(e).__name__}: {e}", started)
        return 1


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python -m backend.web_worker <job_id>", flush=True)
        sys.exit(2)
    db.init_db()
    sys.exit(run_job(sys.argv[1]))
