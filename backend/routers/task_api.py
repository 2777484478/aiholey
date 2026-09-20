"""任务与运行接口：审计任务 CRUD、手动/定时触发、执行监控、日志。"""
from __future__ import annotations

import json
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.config import LOGS_DIR
from backend.core import db, scheduler

router = APIRouter(prefix="/api", tags=["tasks"])


class TaskIn(BaseModel):
    name: str
    repo_id: int
    depth: str = "standard"
    engine: str = "codex"
    skill_names: list[str] = []
    schedule_type: str = "manual"
    interval_seconds: int = 0
    cron: str = ""
    run_at: float | None = None
    enabled: int = 1


def _public(t: dict) -> dict:
    out = dict(t)
    try:
        out["skill_names"] = json.loads(t.get("skill_names") or "[]")
    except json.JSONDecodeError:
        out["skill_names"] = []
    repo = db.query_one("SELECT name, branch, url FROM repos WHERE id=?", (t["repo_id"],))
    out["repo_name"] = (repo or {}).get("name", "（仓库已删除）")
    out["repo_branch"] = (repo or {}).get("branch", "")
    last = db.query_one("SELECT * FROM runs WHERE task_id=? ORDER BY created_at DESC LIMIT 1", (t["id"],))
    out["last_run"] = {
        "run_id": last["run_id"], "status": last["status"], "duration_ms": last["duration_ms"],
        "finished_at": last["finished_at"], "sev_critical": last["sev_critical"],
        "sev_high": last["sev_high"], "sev_medium": last["sev_medium"], "sev_low": last["sev_low"],
    } if last else None
    return out


def _next_of(body: TaskIn) -> float | None:
    now = time.time()
    if body.schedule_type == "interval" and body.interval_seconds > 0:
        return now + max(60, body.interval_seconds)
    if body.schedule_type == "cron" and body.cron.strip():
        return scheduler._next_cron(body.cron.strip(), now)
    if body.schedule_type == "once" and body.run_at:
        return float(body.run_at)
    return None


@router.get("/tasks")
def list_tasks(name: str = "", repo_id: str = "", status: str = "", schedule_type: str = ""):
    # 筛选参数一律用 str 接收：前端下拉为空时会传 `repo_id=`，
    # 用 int 声明会被 FastAPI 判成 422，报错信息还会退化成 [object Object]。
    sql = "SELECT * FROM tasks WHERE 1=1"
    args: list = []
    if name:
        sql += " AND name LIKE ?"
        args.append(f"%{name}%")
    if repo_id.isdigit() and int(repo_id):
        sql += " AND repo_id=?"
        args.append(int(repo_id))
    if status:
        sql += " AND status=?"
        args.append(status)
    if schedule_type:
        sql += " AND schedule_type=?"
        args.append(schedule_type)
    sql += " ORDER BY id DESC"
    return {"items": [_public(t) for t in db.query(sql, args)]}


@router.post("/tasks")
def create_task(body: TaskIn):
    if not body.name.strip():
        raise HTTPException(status_code=400, detail="任务名称不能为空")
    if not db.query_one("SELECT id FROM repos WHERE id=?", (body.repo_id,)):
        raise HTTPException(status_code=400, detail="绑定的仓库不存在")
    if body.schedule_type == "cron" and body.cron.strip():
        if scheduler._next_cron(body.cron.strip(), time.time()) is None:
            raise HTTPException(status_code=400, detail="cron 表达式无法解析，请用「分 时 日 月 周」格式")
    tid = db.insert("tasks", {
        "name": body.name.strip(), "repo_id": body.repo_id, "depth": body.depth,
        "engine": body.engine, "skill_names": json.dumps(body.skill_names, ensure_ascii=False),
        "schedule_type": body.schedule_type, "interval_seconds": body.interval_seconds,
        "cron": body.cron.strip(), "run_at": body.run_at,
        "enabled": body.enabled, "status": "pending",
        "next_run_at": _next_of(body), "created_at": time.time(),
    })
    return {"ok": True, "task": _public(db.query_one("SELECT * FROM tasks WHERE id=?", (tid,)))}


@router.put("/tasks/{task_id}")
def update_task(task_id: int, body: TaskIn):
    if not db.query_one("SELECT id FROM tasks WHERE id=?", (task_id,)):
        raise HTTPException(status_code=404, detail="任务不存在")
    db.update("tasks", task_id, {
        "name": body.name.strip(), "repo_id": body.repo_id, "depth": body.depth,
        "engine": body.engine, "skill_names": json.dumps(body.skill_names, ensure_ascii=False),
        "schedule_type": body.schedule_type, "interval_seconds": body.interval_seconds,
        "cron": body.cron.strip(), "run_at": body.run_at,
        "enabled": body.enabled, "next_run_at": _next_of(body),
    })
    return {"ok": True, "task": _public(db.query_one("SELECT * FROM tasks WHERE id=?", (task_id,)))}


@router.delete("/tasks/{task_id}")
def delete_task(task_id: int):
    if not db.query_one("SELECT id FROM tasks WHERE id=?", (task_id,)):
        raise HTTPException(status_code=404, detail="任务不存在")
    active = db.query_one("SELECT run_id FROM runs WHERE task_id=? AND status IN ('queued','running')", (task_id,))
    if active:
        raise HTTPException(status_code=400, detail="该任务正在排队或执行中，请先停止")
    db.execute("DELETE FROM tasks WHERE id=?", (task_id,))
    return {"ok": True}


@router.post("/tasks/{task_id}/run")
def run_task(task_id: int):
    task = db.query_one("SELECT * FROM tasks WHERE id=?", (task_id,))
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    active = db.query_one("SELECT run_id FROM runs WHERE task_id=? AND status IN ('queued','running')", (task_id,))
    if active:
        return {"ok": True, "run_id": active["run_id"], "message": "该任务已在队列中"}
    run = scheduler.enqueue(task, trigger="manual")
    return {"ok": True, "run_id": run["run_id"], "message": "已进入执行队列"}


@router.post("/tasks/{task_id}/stop")
async def stop_task(task_id: int):
    run = db.query_one("SELECT * FROM runs WHERE task_id=? AND status IN ('queued','running') "
                       "ORDER BY created_at DESC LIMIT 1", (task_id,))
    if not run:
        raise HTTPException(status_code=400, detail="该任务当前没有执行中的运行")
    await scheduler.stop_run(run["run_id"])
    return {"ok": True, "run_id": run["run_id"]}


# ============================================================ 运行记录 / 执行监控

def _run_public(r: dict, with_report: bool = False) -> dict:
    out = {k: v for k, v in r.items() if k != "report_md"}
    if with_report:
        out["report_md"] = r.get("report_md") or ""
    out["findings_count"] = db.query_one("SELECT COUNT(*) c FROM findings WHERE run_id=?", (r["run_id"],))["c"]
    if r.get("started_at"):
        end = r.get("finished_at") or time.time()
        out["elapsed_ms"] = int((end - r["started_at"]) * 1000)
    else:
        out["elapsed_ms"] = 0
    out["alive"] = scheduler.has_run(r["run_id"])
    return out


@router.get("/runs")
def list_runs(task_id: str = "", repo_id: str = "", status: str = "", limit: int = 100):
    sql = "SELECT * FROM runs WHERE 1=1"
    args: list = []
    if task_id.isdigit() and int(task_id):
        sql += " AND task_id=?"
        args.append(int(task_id))
    if repo_id.isdigit() and int(repo_id):
        sql += " AND repo_id=?"
        args.append(int(repo_id))
    if status:
        sql += " AND status=?"
        args.append(status)
    sql += " ORDER BY created_at DESC LIMIT ?"
    args.append(max(1, min(limit, 500)))
    return {"items": [_run_public(r) for r in db.query(sql, args)]}


@router.get("/runs/{run_id}")
def get_run(run_id: str):
    r = db.query_one("SELECT * FROM runs WHERE run_id=?", (run_id,))
    if not r:
        raise HTTPException(status_code=404, detail="运行记录不存在")
    out = _run_public(r, with_report=True)
    try:
        out["skill_names"] = json.loads(r.get("skill_names") or "[]")
    except json.JSONDecodeError:
        out["skill_names"] = []
    out["findings"] = db.query(
        "SELECT * FROM findings WHERE run_id=? ORDER BY CASE severity "
        "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, file, line",
        (run_id,))
    out["by_skill"] = db.query(
        "SELECT skill, "
        "SUM(severity='critical') critical, SUM(severity='high') high, "
        "SUM(severity='medium') medium, SUM(severity='low') low, COUNT(*) total "
        "FROM findings WHERE run_id=? GROUP BY skill ORDER BY total DESC", (run_id,))
    out["logs"] = db.query("SELECT ts, level, message FROM run_logs WHERE run_id=? ORDER BY id ASC LIMIT 500", (run_id,))
    return out


@router.get("/runs/{run_id}/logs")
def run_logs(run_id: str, after: int = 0):
    return {"items": db.query("SELECT id, ts, level, message FROM run_logs WHERE run_id=? AND id>? ORDER BY id ASC",
                              (run_id, after))}


@router.get("/runs/{run_id}/stdout")
def run_stdout(run_id: str, tail: int = 20000):
    """读子进程原始 stdout 日志文件（对照参考系统的「日志」页）。"""
    p = LOGS_DIR / f"{run_id}.log"
    if not p.exists():
        return {"text": "", "exists": False}
    try:
        text = p.read_text(encoding="utf-8", errors="ignore")
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"日志读取失败：{e}")
    return {"text": text[-tail:], "exists": True, "size": p.stat().st_size}


@router.post("/runs/{run_id}/stop")
async def stop_run(run_id: str):
    r = db.query_one("SELECT * FROM runs WHERE run_id=?", (run_id,))
    if not r:
        raise HTTPException(status_code=404, detail="运行记录不存在")
    if r["status"] not in ("queued", "running"):
        raise HTTPException(status_code=400, detail=f"该运行已是「{r['status']}」状态，无需终止")
    await scheduler.stop_run(run_id)
    return {"ok": True}


@router.get("/monitor")
def monitor(limit: int = 50):
    """执行引擎监控：进程视角的运行列表。"""
    rows = db.query("SELECT * FROM runs ORDER BY created_at DESC LIMIT ?", (max(1, min(limit, 200)),))
    items = []
    for r in rows:
        items.append({
            "run_id": r["run_id"],
            "engine": r["engine"],
            "entry": "audit",
            "pid": r.get("pid"),
            "status": r["status"],
            "task_name": r.get("task_name"),
            "task_id": r.get("task_id"),
            "repo_name": r.get("repo_name"),
            "depth": r.get("depth"),
            "workdir": r.get("workdir"),
            "error": r.get("error"),
            "started_at": r.get("started_at"),
            "finished_at": r.get("finished_at"),
            "progress": r.get("progress"),
            "stage": r.get("stage"),
            "duration_ms": r.get("duration_ms") or (
                int((time.time() - r["started_at"]) * 1000) if r.get("started_at") and r["status"] == "running" else 0),
            "alive": scheduler.has_run(r["run_id"]),
            "vulns": [r["sev_critical"], r["sev_high"], r["sev_medium"], r["sev_low"]],
        })
    return {"items": items, "running": scheduler.running_count(), "queued": db.query_one(
        "SELECT COUNT(*) c FROM runs WHERE status='queued'")["c"]}


@router.get("/dashboard")
def dashboard():
    runs = db.query("SELECT * FROM runs WHERE status='success' ORDER BY finished_at DESC LIMIT 200")
    agg = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for k in agg:
        agg[k] = db.query_one(f"SELECT COALESCE(SUM(sev_{k}),0) s FROM runs WHERE status='success'")["s"]
    cats = db.query("SELECT category, COUNT(*) c FROM findings WHERE severity IN ('critical','high','medium','low') "
                    "GROUP BY category ORDER BY c DESC LIMIT 12")

    # 漏洞趋势：近 7 天按天聚合（以运行完成时间为准）
    trend = []
    day = 86400
    today0 = time.time() - (time.time() % day)
    for i in range(6, -1, -1):
        lo = today0 - i * day
        hi = lo + day
        row = db.query_one(
            "SELECT COALESCE(SUM(sev_critical),0) c, COALESCE(SUM(sev_high),0) h, "
            "COALESCE(SUM(sev_medium),0) m, COALESCE(SUM(sev_low),0) l "
            "FROM runs WHERE status='success' AND finished_at>=? AND finished_at<?", (lo, hi))
        trend.append({"date": time.strftime("%m-%d", time.localtime(lo)),
                      "critical": row["c"], "high": row["h"], "medium": row["m"], "low": row["l"],
                      "total": row["c"] + row["h"] + row["m"] + row["l"]})

    # 仓库风险排名
    repo_risk = db.query(
        "SELECT r.id, r.name, "
        "COALESCE(SUM(run.sev_critical),0) critical, COALESCE(SUM(run.sev_high),0) high, "
        "COALESCE(SUM(run.sev_medium),0) medium, COALESCE(SUM(run.sev_low),0) low "
        "FROM repos r LEFT JOIN runs run ON run.repo_id=r.id AND run.status='success' "
        "GROUP BY r.id ORDER BY (critical*4+high*2+medium) DESC, r.id ASC")

    recent = [_run_public(r) for r in db.query(
        "SELECT * FROM runs ORDER BY created_at DESC LIMIT 10")]

    totals = {
        "repos": db.query_one("SELECT COUNT(*) c FROM repos")["c"],
        "skills": db.query_one("SELECT COUNT(*) c FROM skills")["c"],
        "tasks": db.query_one("SELECT COUNT(*) c FROM tasks")["c"],
        "runs": db.query_one("SELECT COUNT(*) c FROM runs")["c"],
        "running": scheduler.running_count(),
        "queued": db.query_one("SELECT COUNT(*) c FROM runs WHERE status='queued'")["c"],
    }
    return {"counts": agg, "total": sum(agg.values()),
            "categories": [{"name": c["category"], "value": c["c"]} for c in cats],
            "trend": trend, "repo_risk": repo_risk, "recent": recent, "totals": totals}
