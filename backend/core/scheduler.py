"""任务调度器与执行队列。

设计：
- 定时任务由 `_tick` 每 2 秒扫描一次 next_run_at，到点就生成 run 记录进入队列。
- 队列消费时以**子进程**方式执行扫描（`python -m backend.worker <run_id>`），
  这样执行引擎监控页能显示真实 PID、能 kill、也有独立 stdout 日志文件。
- 并发上限 MAX_CONCURRENT_RUNS（默认 1），模拟参考系统「排队中」的行为。

注意：调度器只能有一个实例。用 uvicorn 单进程启动，不要开多 worker。
"""
from __future__ import annotations

import asyncio
import os
import signal
import sys
import time
from datetime import datetime, timedelta

from backend.config import BASE_DIR, LOGS_DIR, MAX_CONCURRENT_RUNS
from backend.core import db

TICK_SECONDS = 2.0
_procs: dict[str, asyncio.subprocess.Process] = {}
_started = False
_lock = asyncio.Lock()


# ---------------------------------------------------------------- 队列操作

def new_run_id() -> str:
    return datetime.now().strftime("%Y-%m-%dT%H-%M-%S-%f")


def enqueue(task: dict, trigger: str = "manual") -> dict:
    """为任务创建一次运行记录并进入排队。"""
    repo = db.query_one("SELECT * FROM repos WHERE id=?", (task["repo_id"],))
    run_id = new_run_id()
    db.insert("runs", {
        "run_id": run_id,
        "task_id": task["id"],
        "repo_id": task.get("repo_id"),
        "task_name": task.get("name", ""),
        "repo_name": (repo or {}).get("name", ""),
        "depth": task.get("depth", "standard"),
        "engine": task.get("engine", "codex"),
        "skill_names": task.get("skill_names") or "[]",
        "status": "queued",
        "progress": 0,
        "stage": "排队中",
        "message": f"由{ '定时调度' if trigger == 'schedule' else '手动' }触发，等待执行",
        "workdir": str((repo or {}).get("local_path") or ""),
        "created_at": time.time(),
    })
    db.execute("UPDATE tasks SET status='queued', last_run_at=? WHERE id=?", (time.time(), task["id"]))
    db.log_line(run_id, f"任务「{task.get('name')}」已入队（触发方式：{trigger}）")
    return db.query_one("SELECT * FROM runs WHERE run_id=?", (run_id,)) or {}


# ---------------------------------------------------------------- 子进程

async def _spawn(run_id: str) -> None:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    log_path = LOGS_DIR / f"{run_id}.log"
    fh = open(log_path, "ab")
    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "1"
    env.setdefault("PYTHONPATH", str(BASE_DIR))
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "backend.worker", run_id,
        cwd=str(BASE_DIR), env=env,
        stdout=fh, stderr=asyncio.subprocess.STDOUT,
        start_new_session=True,  # 独立进程组，便于整组终止
    )
    fh.close()
    _procs[run_id] = proc
    db.execute("UPDATE runs SET pid=?, started_at=?, stage='准备中', progress=2 WHERE run_id=?",
               (proc.pid, time.time(), run_id))
    db.log_line(run_id, f"已启动扫描进程 PID={proc.pid}")
    asyncio.create_task(_reap(run_id, proc))


async def _reap(run_id: str, proc: asyncio.subprocess.Process) -> None:
    """等待子进程结束；若它没来得及写终态（例如被 kill），这里兜底。"""
    code = await proc.wait()
    _procs.pop(run_id, None)
    run = db.query_one("SELECT * FROM runs WHERE run_id=?", (run_id,))
    if not run:
        return
    if run["status"] in ("running", "queued"):
        status = "success" if code == 0 else "stopped" if code < 0 else "failed"
        db.execute(
            "UPDATE runs SET status=?, progress=?, stage=?, finished_at=?, "
            "duration_ms=?, error=COALESCE(NULLIF(error,''), ?) WHERE run_id=?",
            (status, 100 if status == "success" else run["progress"],
             {"success": "已完成", "stopped": "已停止", "failed": "执行失败"}[status],
             time.time(), int((time.time() - (run["started_at"] or time.time())) * 1000),
             "" if status == "success" else f"进程异常退出（exit={code}）", run_id),
        )
        if run.get("task_id"):
            db.execute("UPDATE tasks SET status=? WHERE id=?", (status, run["task_id"]))
        db.log_line(run_id, f"进程退出，code={code}", "warn" if code else "info")


# ---------------------------------------------------------------- 调度循环

def _compute_next(task: dict, base: float | None = None) -> float | None:
    """算出任务的下一次执行时间。"""
    now = base or time.time()
    st = task.get("schedule_type")
    if st == "interval" and task.get("interval_seconds"):
        return now + max(60, int(task["interval_seconds"]))
    if st == "cron" and task.get("cron"):
        nxt = _next_cron(task["cron"], now)
        return nxt
    if st == "once" and task.get("run_at"):
        return float(task["run_at"])
    return None


def _next_cron(expr: str, base: float) -> float | None:
    """极简 cron：支持 `分 时 日 月 周`，每段可为 * 或具体数字或 */n。

    不引入 croniter 依赖；精度到分钟，逐分钟向前试探（上限 366 天）。
    """
    fields = expr.split()
    if len(fields) != 5:
        return None
    minute, hour, dom, month, dow = fields

    def match(f: str, v: int) -> bool:
        if f == "*":
            return True
        if f.startswith("*/"):
            try:
                return v % int(f[2:]) == 0
            except ValueError:
                return False
        return any(part.strip().isdigit() and int(part) == v for part in f.split(","))

    t = datetime.fromtimestamp(base).replace(second=0, microsecond=0) + timedelta(minutes=1)
    for _ in range(366 * 24 * 60):
        if (match(minute, t.minute) and match(hour, t.hour) and match(dom, t.day)
                and match(month, t.month) and match(dow, (t.weekday() + 1) % 7)):
            return t.timestamp()
        t += timedelta(minutes=1)
    return None


async def _tick() -> None:
    now = time.time()

    # 1) 到点的定时/单次任务 → 入队
    for task in db.query("SELECT * FROM tasks WHERE enabled=1 AND schedule_type IN ('interval','cron','once')"):
        due = task.get("next_run_at")
        if due is None:
            nxt = _compute_next(task)
            if nxt:
                db.execute("UPDATE tasks SET next_run_at=? WHERE id=?", (nxt, task["id"]))
            continue
        if due > now:
            continue
        if db.query_one("SELECT id FROM runs WHERE task_id=? AND status IN ('queued','running')", (task["id"],)):
            continue  # 上一轮还没跑完，跳过本次
        enqueue(task, trigger="schedule")
        if task["schedule_type"] == "once":
            db.execute("UPDATE tasks SET enabled=0, next_run_at=NULL WHERE id=?", (task["id"],))
        else:
            db.execute("UPDATE tasks SET next_run_at=? WHERE id=?",
                       (_compute_next(task) or now + 86400, task["id"]))

    # 2) 有并发余量就派发队列中的运行
    running = len(_procs)
    while running < MAX_CONCURRENT_RUNS:
        nxt = db.query_one(
            "SELECT * FROM runs WHERE status='queued' ORDER BY created_at ASC LIMIT 1")
        if not nxt:
            break
        # 先占位再启动，避免同一 tick 里被重复派发
        db.execute("UPDATE runs SET status='running', stage='启动中', progress=3 WHERE run_id=?",
                   (nxt["run_id"],))
        if nxt.get("task_id"):
            db.execute("UPDATE tasks SET status='running' WHERE id=?", (nxt["task_id"],))
        await _spawn(nxt["run_id"])
        running += 1


async def _loop() -> None:
    while True:
        try:
            await _tick()
        except Exception as e:  # 调度器不能因单次异常整个挂掉
            print(f"[scheduler] tick 异常: {type(e).__name__}: {e}", flush=True)
        await asyncio.sleep(TICK_SECONDS)


async def start() -> None:
    global _started
    if _started:
        return
    _started = True
    _recover_stale()
    asyncio.create_task(_loop())
    print("[scheduler] 已启动", flush=True)


def _recover_stale() -> None:
    """服务重启后，上一轮遗留的 running/queued 记录不可能再继续，标记为失败。"""
    rows = db.query("SELECT run_id, task_id FROM runs WHERE status IN ('running','queued')")
    for r in rows:
        db.execute("UPDATE runs SET status='failed', stage='已中断', finished_at=?, "
                   "error='服务重启导致执行中断' WHERE run_id=?", (time.time(), r["run_id"]))
        if r.get("task_id"):
            db.execute("UPDATE tasks SET status='failed' WHERE id=?", (r["task_id"],))
    if rows:
        print(f"[scheduler] 清理了 {len(rows)} 条中断的运行记录", flush=True)


# ---------------------------------------------------------------- 停止

async def stop_run(run_id: str) -> bool:
    run = db.query_one("SELECT * FROM runs WHERE run_id=?", (run_id,))
    if not run:
        return False
    proc = _procs.get(run_id)
    pid = (proc.pid if proc else None) or run.get("pid")
    killed = False
    if pid:
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
            killed = True
        except (ProcessLookupError, PermissionError, OSError):
            try:
                os.kill(pid, signal.SIGTERM)
                killed = True
            except (ProcessLookupError, PermissionError, OSError):
                killed = False
    db.execute("UPDATE runs SET status='stopped', stage='已停止', finished_at=?, "
               "error='手动终止' WHERE run_id=?", (time.time(), run_id))
    if run.get("task_id"):
        db.execute("UPDATE tasks SET status='stopped' WHERE id=?", (run["task_id"],))
    db.log_line(run_id, "已被手动终止", "warn")
    return killed


def running_count() -> int:
    return len(_procs)


def has_run(run_id: str) -> bool:
    return run_id in _procs
