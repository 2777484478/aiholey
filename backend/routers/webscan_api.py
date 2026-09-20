"""Web 漏洞扫描接口。

与代码审计的区别：**不使用任务队列**。
`POST /api/webscan/jobs` 会立即拉起 `python -m backend.web_worker <job_id>` 独立子进程，
前端轮询 job 详情获取进度，互不占用审计队列的并发槽位。
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import signal
import sys
import time
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel

from backend.config import BASE_DIR, LOGS_DIR, WEBSCAN_DIR, WEB_DEPTHS
from backend.core import db
from backend.core.sec_headers import REPORT_CSP
from backend.core.webscan import report as web_report
from backend.core.webscan import tools as T

router = APIRouter(prefix="/api/webscan", tags=["webscan"])

MAX_TARGETS = 20
_procs: dict[str, asyncio.subprocess.Process] = {}


# ============================================================ 元信息

@router.get("/meta")
def meta():
    return {
        "depths": [{"value": k, **v} for k, v in WEB_DEPTHS.items()],
        "max_targets": MAX_TARGETS,
        "engines": [
            {"value": "codex", "label": "Codex（OpenAI 兼容端点）"},
            {"value": "claude", "label": "Claude Code"},
        ],
    }


@router.get("/tools")
def list_tools():
    return {"items": T.tool_catalog()}


@router.get("/skills")
def list_skills():
    rows = db.query("SELECT * FROM web_skills ORDER BY sort_order, id")
    return {"items": rows}


class SkillIn(BaseModel):
    name: str
    description: str = ""
    prompt: str = ""
    category: str = "通用"
    phase: str = "scan"
    enabled: int = 1


@router.post("/skills")
def create_skill(body: SkillIn):
    if not body.name.strip():
        raise HTTPException(status_code=400, detail="技能名不能为空")
    if db.query_one("SELECT id FROM web_skills WHERE name=?", (body.name.strip(),)):
        raise HTTPException(status_code=400, detail="同名技能已存在")
    sid = db.insert("web_skills", {
        "name": body.name.strip(), "description": body.description, "prompt": body.prompt,
        "category": body.category, "phase": body.phase, "builtin": 0,
        "enabled": body.enabled, "sort_order": 500, "created_at": time.time(),
    })
    return {"ok": True, "skill": db.query_one("SELECT * FROM web_skills WHERE id=?", (sid,))}


@router.put("/skills/{skill_id}")
def update_skill(skill_id: int, body: SkillIn):
    if not db.query_one("SELECT id FROM web_skills WHERE id=?", (skill_id,)):
        raise HTTPException(status_code=404, detail="技能不存在")
    db.update("web_skills", skill_id, {
        "name": body.name.strip(), "description": body.description, "prompt": body.prompt,
        "category": body.category, "phase": body.phase, "enabled": body.enabled,
    })
    return {"ok": True, "skill": db.query_one("SELECT * FROM web_skills WHERE id=?", (skill_id,))}


@router.delete("/skills/{skill_id}")
def delete_skill(skill_id: int):
    row = db.query_one("SELECT * FROM web_skills WHERE id=?", (skill_id,))
    if not row:
        raise HTTPException(status_code=404, detail="技能不存在")
    if row.get("builtin"):
        raise HTTPException(status_code=400, detail="内置技能不可删除，可将其停用")
    db.execute("DELETE FROM web_skills WHERE id=?", (skill_id,))
    return {"ok": True}


# ============================================================ 扫描作业

class JobIn(BaseModel):
    name: str = ""
    targets: list[str] = []
    depth: str = "standard"
    engine: str = "codex"
    skill_names: list[str] = []
    authorized: bool = False


def _new_job_id() -> str:
    return "web-" + datetime.now().strftime("%Y%m%d-%H%M%S-%f")


def _job_public(j: dict, with_report: bool = False) -> dict:
    out = dict(j)
    if not with_report:
        out.pop("report_md", None)
    out["alive"] = j["job_id"] in _procs
    try:
        out["targets"] = json.loads(j.get("targets") or "[]")
    except json.JSONDecodeError:
        out["targets"] = []
    try:
        out["skill_names"] = json.loads(j.get("skill_names") or "[]")
    except json.JSONDecodeError:
        out["skill_names"] = []
    if j.get("started_at"):
        end = j.get("finished_at") or time.time()
        out["elapsed_ms"] = int((end - j["started_at"]) * 1000)
    else:
        out["elapsed_ms"] = 0
    return out


async def spawn_job(job_id: str, engine: str) -> int:
    """拉起独立子进程执行扫描（不入队）。"""
    from backend.config import LOGS_DIR as _LOGS
    _LOGS.mkdir(parents=True, exist_ok=True)
    fh = open(_LOGS / f"{job_id}.log", "ab")
    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "1"
    env.setdefault("PYTHONPATH", str(BASE_DIR))
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "backend.web_worker", job_id,
        cwd=str(BASE_DIR), env=env,
        stdout=fh, stderr=asyncio.subprocess.STDOUT,
        start_new_session=True,
    )
    fh.close()
    _procs[job_id] = proc
    db.execute("UPDATE web_jobs SET pid=? WHERE job_id=?", (proc.pid, job_id))
    db.log_line(job_id, f"已启动 Web 扫描进程 PID={proc.pid}")
    asyncio.create_task(_reap(job_id, proc))
    return proc.pid


async def _reap(job_id: str, proc: asyncio.subprocess.Process) -> None:
    """子进程退出后兜底写终态（异常退出时它可能来不及更新）。"""
    code = await proc.wait()
    _procs.pop(job_id, None)
    job = db.query_one("SELECT * FROM web_jobs WHERE job_id=?", (job_id,))
    if not job or job["status"] not in ("running", "queued"):
        return
    status = "success" if code == 0 else "stopped" if code < 0 else "failed"
    db.execute(
        "UPDATE web_jobs SET status=?, stage=?, finished_at=?, duration_ms=?, "
        "error=COALESCE(NULLIF(error,''), ?) WHERE job_id=?",
        (status, {"success": "已完成", "stopped": "已停止", "failed": "执行失败"}[status],
         time.time(),
         int((time.time() - (job.get("started_at") or time.time())) * 1000),
         "" if status == "success" else f"进程异常退出（exit={code}）", job_id))
    db.log_line(job_id, f"进程退出，code={code}", "warn" if code else "info")


@router.post("/jobs")
async def create_job(body: JobIn):
    if not body.authorized:
        raise HTTPException(status_code=400, detail="请先确认已获得目标站点的测试授权")
    targets: list[str] = []
    for raw in body.targets:
        t = T.normalize_target(raw)
        if not t:
            continue
        if not t.startswith(("http://", "https://")):
            raise HTTPException(status_code=400, detail=f"只支持 http/https 目标：{raw}")
        if t not in targets:
            targets.append(t)
    if not targets:
        raise HTTPException(status_code=400, detail="请至少填写一个有效的目标地址")
    if len(targets) > MAX_TARGETS:
        raise HTTPException(status_code=400, detail=f"单次最多 {MAX_TARGETS} 个目标，当前 {len(targets)} 个")
    if body.depth not in WEB_DEPTHS:
        raise HTTPException(status_code=400, detail="探测强度取值非法")

    job_id = _new_job_id()
    name = body.name.strip() or f"Web 扫描 · {len(targets)} 个目标"
    db.insert("web_jobs", {
        "job_id": job_id, "name": name, "targets": json.dumps(targets, ensure_ascii=False),
        "depth": body.depth, "engine": body.engine,
        "skill_names": json.dumps(body.skill_names, ensure_ascii=False),
        "status": "running", "progress": 1, "stage": "启动中",
        "message": f"正在启动扫描进程（{len(targets)} 个目标）",
        "started_at": time.time(), "targets_total": len(targets), "created_at": time.time(),
    })
    db.log_line(job_id, f"新建 Web 扫描：{', '.join(targets)}")

    try:
        pid = await spawn_job(job_id, body.engine)
    except Exception as e:
        db.execute("UPDATE web_jobs SET status='failed', stage='启动失败', error=?, "
                   "finished_at=? WHERE job_id=?", (f"{type(e).__name__}: {e}"[:500],
                                                    time.time(), job_id))
        raise HTTPException(status_code=500, detail=f"扫描进程启动失败：{e}")
    return {"ok": True, "job_id": job_id, "pid": pid,
            "job": _job_public(db.query_one("SELECT * FROM web_jobs WHERE job_id=?", (job_id,)))}


@router.get("/jobs")
def list_jobs(limit: int = 50):
    rows = db.query("SELECT * FROM web_jobs ORDER BY created_at DESC LIMIT ?",
                    (max(1, min(limit, 200)),))
    return {"items": [_job_public(r) for r in rows]}


@router.get("/jobs/{job_id}")
def get_job(job_id: str):
    j = db.query_one("SELECT * FROM web_jobs WHERE job_id=?", (job_id,))
    if not j:
        raise HTTPException(status_code=404, detail="扫描记录不存在")
    out = _job_public(j, with_report=True)
    out["findings"] = db.query(
        "SELECT * FROM web_findings WHERE job_id=? ORDER BY CASE severity "
        "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
        "WHEN 'low' THEN 3 ELSE 4 END, target, id", (job_id,))
    out["by_skill"] = db.query(
        "SELECT skill, SUM(severity='critical') critical, SUM(severity='high') high, "
        "SUM(severity='medium') medium, SUM(severity='low') low, SUM(severity='info') info, "
        "COUNT(*) total FROM web_findings WHERE job_id=? GROUP BY skill ORDER BY total DESC",
        (job_id,))
    out["by_target"] = db.query(
        "SELECT target, COUNT(*) total, SUM(severity IN ('critical','high')) serious "
        "FROM web_findings WHERE job_id=? GROUP BY target ORDER BY serious DESC, total DESC",
        (job_id,))
    out["logs"] = db.query("SELECT ts, level, message FROM run_logs WHERE run_id=? "
                           "ORDER BY id ASC LIMIT 800", (job_id,))
    return out


@router.get("/jobs/{job_id}/logs")
def job_logs(job_id: str, after: int = 0):
    return {"items": db.query(
        "SELECT id, ts, level, message FROM run_logs WHERE run_id=? AND id>? ORDER BY id ASC",
        (job_id, after))}


@router.post("/jobs/{job_id}/stop")
async def stop_job(job_id: str):
    j = db.query_one("SELECT * FROM web_jobs WHERE job_id=?", (job_id,))
    if not j:
        raise HTTPException(status_code=404, detail="扫描记录不存在")
    if j["status"] not in ("running", "queued"):
        raise HTTPException(status_code=400, detail=f"该扫描已是「{j['status']}」状态")

    proc = _procs.get(job_id)
    pid = (proc.pid if proc else None) or j.get("pid")
    killed = False
    if pid:
        for fn in (lambda: os.killpg(os.getpgid(pid), signal.SIGTERM),
                   lambda: os.kill(pid, signal.SIGTERM)):
            try:
                fn()
                killed = True
                break
            except (ProcessLookupError, PermissionError, OSError):
                continue
    db.execute("UPDATE web_jobs SET status='stopped', stage='已停止', finished_at=?, "
               "duration_ms=?, error='手动终止' WHERE job_id=?",
               (time.time(), int((time.time() - (j.get("started_at") or time.time())) * 1000), job_id))
    db.log_line(job_id, "已被手动终止", "warn")
    return {"ok": True, "killed": killed}


class DeleteJobsIn(BaseModel):
    job_ids: list[str] = []


def _job_undeletable_reason(job_id: str) -> str | None:
    """返回不可删除的原因；可以删则返回 None。

    判定要用两道闸：数据库 status 与环境里的子进程表 `_procs`。
    只看 status 会漏掉「进程刚起来、状态还没落到 running」的那一瞬间；
    只看 `_procs` 会漏掉服务重启后残留的 running 记录（进程早没了但状态还是 running，
    这种恰恰是用户最想删掉的死记录）。两者取或，再对「服务重启后的孤儿记录」放行。
    """
    j = db.query_one("SELECT status FROM web_jobs WHERE job_id=?", (job_id,))
    if not j:
        return "记录不存在"
    if job_id in _procs:
        return "扫描进程仍在运行，请先终止"
    if j["status"] == "running":
        return "扫描正在执行中，请先终止"
    return None


def _purge_job(job_id: str) -> None:
    """删除一条扫描记录的全部痕迹：数据库三张表 + 磁盘报告目录。"""
    db.execute("DELETE FROM web_findings WHERE job_id=?", (job_id,))
    db.execute("DELETE FROM run_logs WHERE run_id=?", (job_id,))
    db.execute("DELETE FROM web_jobs WHERE job_id=?", (job_id,))
    d = WEBSCAN_DIR / job_id
    if d.is_dir():
        shutil.rmtree(d, ignore_errors=True)


@router.delete("/jobs/{job_id}")
def delete_job(job_id: str):
    why = _job_undeletable_reason(job_id)
    if why:
        raise HTTPException(status_code=404 if why == "记录不存在" else 400,
                            detail="扫描记录不存在" if why == "记录不存在" else f"无法删除：{why}")
    _purge_job(job_id)
    return {"ok": True}


@router.post("/jobs/delete")
def delete_jobs(body: DeleteJobsIn):
    """批量删除扫描记录。逐条判定，返回删掉了几条、哪几条没删以及原因。"""
    if not body.job_ids:
        raise HTTPException(status_code=400, detail="请选择要删除的扫描记录")
    deleted: list[str] = []
    skipped: list[dict] = []
    for jid in dict.fromkeys(body.job_ids):        # 去重且保持原顺序
        why = _job_undeletable_reason(jid)
        if why:
            skipped.append({"job_id": jid, "reason": why})
            continue
        _purge_job(jid)
        deleted.append(jid)
    return {"ok": True, "deleted": len(deleted), "deleted_ids": deleted, "skipped": skipped}


# ============================================================ 报告导出

def build_html(job_id: str) -> str:
    """实时渲染 HTML 报告；磁盘上有缓存则直接复用。"""
    cached = WEBSCAN_DIR / job_id / "report.html"
    j = db.query_one("SELECT * FROM web_jobs WHERE job_id=?", (job_id,))
    if not j:
        raise HTTPException(status_code=404, detail="扫描记录不存在")
    if cached.exists() and j.get("finished_at") and cached.stat().st_mtime >= j["finished_at"]:
        return cached.read_text(encoding="utf-8")
    findings = db.query("SELECT * FROM web_findings WHERE job_id=?", (job_id,))
    try:
        targets = json.loads(j.get("targets") or "[]")
    except json.JSONDecodeError:
        targets = []
    notes = [r["message"] for r in db.query(
        "SELECT message FROM run_logs WHERE run_id=? AND message LIKE '%未配置%' ORDER BY id",
        (job_id,))][:5]
    doc = web_report.render_html(j, findings, targets, notes, [])
    try:
        cached.parent.mkdir(parents=True, exist_ok=True)
        cached.write_text(doc, encoding="utf-8")
    except OSError:
        pass
    return doc


@router.get("/jobs/{job_id}/html", response_class=HTMLResponse)
def job_html(job_id: str, download: int = 0):
    doc = build_html(job_id)
    headers = {"Content-Disposition": f'attachment; filename="aiholey-{job_id}.html"'} if download else {}
    # 报告正文含目标站点的响应片段，比主站更不可信 → 用更严的 CSP（中间件是
    # setdefault，这里先设就不会被覆盖）。
    headers["Content-Security-Policy"] = REPORT_CSP
    return HTMLResponse(doc, headers=headers)


@router.get("/jobs/{job_id}/markdown", response_class=PlainTextResponse)
def job_markdown(job_id: str):
    p = WEBSCAN_DIR / job_id / "report.md"
    if p.exists():
        try:
            return PlainTextResponse(p.read_text(encoding="utf-8"),
                                     media_type="text/markdown; charset=utf-8")
        except OSError:
            pass                                  # 缓存不可读 → 回落实时渲染（见 build_html 注释）
    j = db.query_one("SELECT * FROM web_jobs WHERE job_id=?", (job_id,))
    if not j:
        raise HTTPException(status_code=404, detail="扫描记录不存在")
    findings = db.query("SELECT * FROM web_findings WHERE job_id=?", (job_id,))
    try:
        targets = json.loads(j.get("targets") or "[]")
    except json.JSONDecodeError:
        targets = []
    return PlainTextResponse(web_report.render_markdown(j, findings, targets, [], []),
                             media_type="text/markdown; charset=utf-8")


@router.get("/jobs/{job_id}/json")
def job_json(job_id: str):
    p = WEBSCAN_DIR / job_id / "findings.json"
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))
    j = db.query_one("SELECT * FROM web_jobs WHERE job_id=?", (job_id,))
    if not j:
        raise HTTPException(status_code=404, detail="扫描记录不存在")
    return {"job": _job_public(j), "findings": db.query(
        "SELECT * FROM web_findings WHERE job_id=?", (job_id,))}


@router.get("/stats")
def webscan_stats():
    """给仪表盘/总览用的小统计。"""
    return {
        "jobs": db.query_one("SELECT COUNT(*) c FROM web_jobs")["c"],
        "running": db.query_one("SELECT COUNT(*) c FROM web_jobs WHERE status='running'")["c"],
        "critical": db.query_one("SELECT COALESCE(SUM(sev_critical),0) c FROM web_jobs")["c"],
        "high": db.query_one("SELECT COALESCE(SUM(sev_high),0) c FROM web_jobs")["c"],
        "medium": db.query_one("SELECT COALESCE(SUM(sev_medium),0) c FROM web_jobs")["c"],
        "low": db.query_one("SELECT COALESCE(SUM(sev_low),0) c FROM web_jobs")["c"],
    }
