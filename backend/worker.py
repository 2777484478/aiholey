"""扫描执行体（子进程入口）。

被 scheduler 以 `python -m backend.worker <run_id>` 方式拉起，执行完一次扫描后退出。
独立进程的好处：执行引擎监控页能显示真实 PID / 工作目录 / 耗时，并且可以被终止。
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from backend.config import DEPTHS, REPORTS_DIR, REPOS_DIR
from backend.core import db, engine, engineconf, gitops, report_html
from backend.core.skills_seed import FLOW_SKILLS


class Reporter:
    """把进度同时写进 runs 表（供页面轮询）与 run_logs 表（供日志面板）。"""

    def __init__(self, run_id: str):
        self.run_id = run_id

    def __call__(self, stage: str, progress: int, message: str) -> None:
        db.execute("UPDATE runs SET stage=?, progress=?, message=? WHERE run_id=?",
                   (stage, max(0, min(100, progress)), message, self.run_id))
        db.log_line(self.run_id, f"[{stage}] {message}")
        print(f"[{stage}] {message}", flush=True)


def _fail(run_id: str, msg: str, started: float) -> None:
    db.execute(
        "UPDATE runs SET status='failed', stage='失败', error=?, finished_at=?, duration_ms=? WHERE run_id=?",
        (msg[:600], time.time(), int((time.time() - started) * 1000), run_id))
    run = db.query_one("SELECT task_id FROM runs WHERE run_id=?", (run_id,))
    if run and run.get("task_id"):
        db.execute("UPDATE tasks SET status='failed' WHERE id=?", (run["task_id"],))
    db.log_line(run_id, f"扫描失败：{msg}", "error")
    print(f"[失败] {msg}", flush=True)


def run_scan(run_id: str) -> int:
    started = time.time()
    run = db.query_one("SELECT * FROM runs WHERE run_id=?", (run_id,))
    if not run:
        print(f"找不到运行记录 {run_id}", flush=True)
        return 2
    report_dir = REPORTS_DIR / run_id
    report_dir.mkdir(parents=True, exist_ok=True)
    say = Reporter(run_id)

    try:
        repo = db.query_one("SELECT * FROM repos WHERE id=?", (run["repo_id"],)) if run.get("repo_id") else None

        # ---------- 1. 拉取代码（绑定仓库时）或直接使用给定目录（快速扫描） ----------
        if repo:
            say("拉取代码", 5, f"准备仓库 {repo['name']}（分支 {repo['branch']}）")
            local = REPOS_DIR / str(repo["id"])
            say("拉取代码", 8, f"执行 git 拉取到 {local}")
            ok, msg = gitops.pull(repo)
            if not ok:
                db.execute("UPDATE repos SET last_pull_at=?, last_pull_status='failed', last_pull_msg=? WHERE id=?",
                           (time.time(), msg[:500], repo["id"]))
                _fail(run_id, f"代码拉取失败：{msg}", started)
                return 4
            db.execute("UPDATE repos SET last_pull_at=?, last_pull_status='success', last_pull_msg=?, local_path=? WHERE id=?",
                       (time.time(), msg[:500], str(local), repo["id"]))
            say("拉取代码", 12, "代码已就绪：" + msg.splitlines()[0][:80])
            db.execute("UPDATE runs SET workdir=? WHERE run_id=?", (str(local), run_id))
        else:
            local = Path(run.get("workdir") or "")
            if not local.exists():
                _fail(run_id, f"扫描目录不存在：{local}", started)
                return 4
            say("拉取代码", 12, f"快速扫描模式，直接使用目录：{local}")

        # ---------- 2. 收集文件 ----------
        depth = run.get("depth") or "standard"
        dcfg = DEPTHS.get(depth, DEPTHS["standard"])
        say("收集文件", 16, f"按 {depth} 档收集源码（上限 {dcfg['max_files']} 个文件）")
        files = engine.collect_files(local, dcfg["max_files"])
        loc = 0
        for f in files:
            try:
                loc += len(f.read_text(encoding="utf-8", errors="ignore").splitlines())
            except OSError:
                pass
        db.execute("UPDATE runs SET files_scanned=?, loc=? WHERE run_id=?", (len(files), loc, run_id))
        say("收集文件", 20, f"共 {len(files)} 个源码文件、{loc} 行")
        if not files:
            _fail(run_id, "目录下未找到可扫描的源码文件", started)
            return 5

        # ---------- 3. 规则预筛 ----------
        say("规则预筛", 25, "执行内置规则库模式匹配")
        findings = engine.rule_scan(files, local)
        say("规则预筛", 40, f"规则命中 {len(findings)} 项，进入 AI 语义分析")
        db.execute("UPDATE runs SET progress=42 WHERE run_id=?", (run_id,))

        # ---------- 4. AI 阶段 ----------
        skill_names = json.loads(run.get("skill_names") or "[]")
        all_skills = db.query("SELECT * FROM skills ORDER BY sort_order")
        by_name = {s["name"]: s for s in all_skills}
        if not skill_names:
            skill_names = [s["name"] for s in all_skills
                           if s["enabled"] and s["name"] not in FLOW_SKILLS]
        chosen = [by_name[n] for n in skill_names if n in by_name and n not in FLOW_SKILLS]

        client = engineconf.client_for(run.get("engine") or "codex")
        notes: list[str] = []
        ai_used = False
        profile: dict | None = None

        if client is None:
            say("AI 分析", 45, "未配置该引擎的 API Key，本次仅使用内置规则扫描")
            notes.append("未配置 API Key，AI 语义分析未执行")
        else:
            ai_used = True
            say("AI 分析", 46, f"引擎 {run.get('engine')} · 模型 {client.model} · 参与技能 {len(chosen)} 项")
            say("项目适配", 48, "分析技术栈与审计增强规则")
            profile, note = engine.project_adapt(files, local, client, depth, say)
            if note:
                notes.append(note)
            if profile:
                (report_dir / "profile.json").write_text(
                    json.dumps(profile, ensure_ascii=False, indent=2), encoding="utf-8")
                ts = profile.get("tech_stack") or {}
                ts_line = f"{ts.get('language','?')} / {ts.get('framework','?')} · {ts.get('build_tool','?')}"
                db.execute("UPDATE runs SET message=? WHERE run_id=?", (f"技术栈：{ts_line}", run_id))
                say("项目适配", 52, f"技术栈：{ts_line}")

            ai_findings, ai_notes = engine.ai_scan(files, local, chosen, client, depth, say, profile)
            notes.extend(ai_notes)
            findings.extend(ai_findings)
            say("AI 分析", 95, f"AI 产出 {len(ai_findings)} 项，开始去重与分级")

        # ---------- 5. 去重 / 统计 / 报告 ----------
        say("生成报告", 96, "合并去重、分级统计")
        findings = engine.dedupe(findings)
        st = engine.stats_of(findings)

        for f in findings:
            db.insert("findings", {
                "run_id": run_id, "skill": f["skill"], "source": f["source"],
                "severity": f["severity"], "category": f["category"], "title": f["title"],
                "file": f["file"], "line": f["line"], "snippet": f["snippet"],
                "detail": f["detail"], "advice": f["advice"], "confidence": f["confidence"],
            })

        run["files_scanned"] = len(files)
        run["loc"] = loc
        run["duration_ms"] = int((time.time() - started) * 1000)
        run["finished_at"] = time.time()
        md = engine.build_markdown(run, findings, repo=repo, skills=chosen, notes=notes, ai_used=ai_used)
        (report_dir / "report.md").write_text(md, encoding="utf-8")
        (report_dir / "report.json").write_text(
            json.dumps({"run": {k: v for k, v in run.items() if k != "report_md"},
                        "repo": report_html.safe_repo(repo), "findings": findings,
                        "by_skill": engine.by_skill(findings), "profile": profile},
                       ensure_ascii=False, indent=2), encoding="utf-8")

        db.execute(
            "UPDATE runs SET status='success', stage='已完成', progress=100, message=?, finished_at=?, "
            "duration_ms=?, files_scanned=?, loc=?, sev_critical=?, sev_high=?, sev_medium=?, sev_low=?, "
            "report_md=?, ai_used=? WHERE run_id=?",
            (f"发现 {st['total']} 个漏洞（严重 {st['critical']} / 高危 {st['high']} / 中危 {st['medium']} / 低危 {st['low']}）",
             time.time(), run["duration_ms"], len(files), loc,
             st["critical"], st["high"], st["medium"], st["low"], md, 1 if ai_used else 0, run_id))
        if run.get("task_id"):
            db.execute("UPDATE tasks SET status='success' WHERE id=?", (run["task_id"],))
        say("已完成", 100, f"扫描完成：{st['total']} 个漏洞，耗时 {run['duration_ms']/1000:.1f}s")
        return 0

    except Exception as e:  # 兜底：任何未捕获异常都要落库，不能留下永远 running 的记录
        import traceback
        traceback.print_exc()
        _fail(run_id, f"{type(e).__name__}: {e}", started)
        return 1


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python -m backend.worker <run_id>", flush=True)
        sys.exit(2)
    db.init_db()
    sys.exit(run_scan(sys.argv[1]))
