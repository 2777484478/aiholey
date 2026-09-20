"""报告接口：报告列表/详情/导出/复扫，以及不建任务的快速目录扫描。"""
from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel

from backend.config import REPORTS_DIR
from backend.core import db, report_html, scheduler
from backend.core.sec_headers import REPORT_CSP
from backend.core.skills_seed import FLOW_SKILLS

router = APIRouter(prefix="/api", tags=["reports"])


def _read_text(path: Path) -> str | None:
    """读报告产物文本，读不到返回 None（不抛异常）。

    这些落盘文件只是「省一次渲染」的缓存，不是唯一数据源。受限运行环境（沙箱、
    只读挂载、权限收紧）下可能读不出来，此时必须回落到数据库；否则用户看到的是
    报告页/下载按钮直接 500，而库里数据其实完好——白白以为报告丢了。
    """
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def _read_json(path: Path):
    """读报告产物 JSON，读不到或内容损坏都返回 None。"""
    txt = _read_text(path)
    if txt is None:
        return None
    try:
        return json.loads(txt)
    except json.JSONDecodeError:
        return None


def _public(r: dict, with_md: bool = False) -> dict:
    out = {k: v for k, v in r.items() if k != "report_md"}
    if with_md:
        out["report_md"] = r.get("report_md") or ""
    out["findings_count"] = db.query_one("SELECT COUNT(*) c FROM findings WHERE run_id=?", (r["run_id"],))["c"]
    out["elapsed_ms"] = r.get("duration_ms") or 0
    return out


@router.get("/reports")
def list_reports(task_name: str = "", status: str = "", repo_id: str = "",
                 severity: str = "", keyword: str = "", limit: int = 200):
    sql = "SELECT * FROM runs WHERE 1=1"
    args: list = []
    if task_name:
        sql += " AND task_name LIKE ?"
        args.append(f"%{task_name}%")
    if status:
        sql += " AND status=?"
        args.append(status)
    if repo_id.isdigit() and int(repo_id):
        sql += " AND repo_id=?"
        args.append(int(repo_id))
    if severity == "critical":
        sql += " AND sev_critical>0"
    elif severity == "high":
        sql += " AND sev_high>0"
    elif severity == "medium":
        sql += " AND sev_medium>0"
    elif severity == "low":
        sql += " AND sev_low>0"
    if keyword:
        sql += " AND (report_md LIKE ? OR task_name LIKE ?)"
        args.extend([f"%{keyword}%", f"%{keyword}%"])
    sql += " ORDER BY created_at DESC LIMIT ?"
    args.append(max(1, min(limit, 500)))
    items = [_public(r) for r in db.query(sql, args)]
    summary = db.query_one(
        "SELECT COALESCE(SUM(sev_critical),0) c, COALESCE(SUM(sev_high),0) h, "
        "COALESCE(SUM(sev_medium),0) m, COALESCE(SUM(sev_low),0) l FROM runs WHERE status='success'")
    return {"items": items,
            "summary": {"critical": summary["c"], "high": summary["h"],
                        "medium": summary["m"], "low": summary["l"],
                        "total": summary["c"] + summary["h"] + summary["m"] + summary["l"]}}


@router.get("/reports/{run_id}")
def get_report(run_id: str):
    r = db.query_one("SELECT * FROM runs WHERE run_id=?", (run_id,))
    if not r:
        raise HTTPException(status_code=404, detail="报告不存在")
    out = _public(r, with_md=True)
    try:
        out["skill_names"] = json.loads(r.get("skill_names") or "[]")
    except json.JSONDecodeError:
        out["skill_names"] = []
    out["findings"] = db.query(
        "SELECT * FROM findings WHERE run_id=? ORDER BY CASE severity "
        "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, file, line", (run_id,))
    out["by_skill"] = db.query(
        "SELECT skill, SUM(severity='critical') critical, SUM(severity='high') high, "
        "SUM(severity='medium') medium, SUM(severity='low') low, COUNT(*) total "
        "FROM findings WHERE run_id=? GROUP BY skill ORDER BY total DESC", (run_id,))
    profile_path = REPORTS_DIR / run_id / "profile.json"
    out["profile"] = json.loads(profile_path.read_text(encoding="utf-8")) if profile_path.exists() else None
    out["logs"] = db.query("SELECT ts, level, message FROM run_logs WHERE run_id=? ORDER BY id ASC LIMIT 500",
                           (run_id,))
    repo = db.query_one("SELECT name, url, branch FROM repos WHERE id=?", (r["repo_id"],)) if r["repo_id"] else None
    out["repo"] = repo
    return out


@router.get("/reports/{run_id}/markdown", response_class=PlainTextResponse)
def download_markdown(run_id: str):
    r = db.query_one("SELECT report_md FROM runs WHERE run_id=?", (run_id,))
    if not r or not r["report_md"]:
        p = REPORTS_DIR / run_id / "report.md"
        if p.exists():
            return p.read_text(encoding="utf-8")
        raise HTTPException(status_code=404, detail="报告内容不存在")
    return r["report_md"]


@router.get("/reports/{run_id}/json")
def download_json(run_id: str):
    p = REPORTS_DIR / run_id / "report.json"
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))
    r = db.query_one("SELECT * FROM runs WHERE run_id=?", (run_id,))
    if not r:
        raise HTTPException(status_code=404, detail="报告不存在")
    return {"run": _public(r), "findings": db.query("SELECT * FROM findings WHERE run_id=?", (run_id,))}


_SQL_FINDINGS = ("SELECT * FROM findings WHERE run_id=? ORDER BY CASE severity "
                 "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, file, line")


def _report_skills(r: dict) -> list[dict]:
    """本次运行参与的技能（含说明），用于报告的「参与技能」表。"""
    rows = db.query("SELECT name, description, enabled FROM skills ORDER BY sort_order")
    try:
        names = json.loads(r.get("skill_names") or "[]")
    except (json.JSONDecodeError, TypeError):
        names = []
    if names:
        by = {s["name"]: s for s in rows}
        return [by[n] for n in names if n in by and n not in FLOW_SKILLS]
    return [s for s in rows if s["enabled"] and s["name"] not in FLOW_SKILLS]


def _build_html(run_id: str) -> str:
    r = db.query_one("SELECT * FROM runs WHERE run_id=?", (run_id,))
    if not r:
        raise HTTPException(status_code=404, detail="报告不存在")
    pp = REPORTS_DIR / run_id / "profile.json"
    profile = json.loads(pp.read_text(encoding="utf-8")) if pp.exists() else None
    repo = db.query_one("SELECT * FROM repos WHERE id=?", (r["repo_id"],)) if r.get("repo_id") else None
    doc = report_html.render_html(
        r, db.query(_SQL_FINDINGS, (run_id,)),
        repo=repo, skills=_report_skills(r), profile=profile,
        notes=report_html.parse_notes_from_md(r.get("report_md") or ""),
        ai_used=bool(r.get("ai_used")),
    )
    try:  # 顺手落盘一份，便于直接取用与归档；写失败不影响在线返回
        d = REPORTS_DIR / run_id
        d.mkdir(parents=True, exist_ok=True)
        (d / "report.html").write_text(doc, encoding="utf-8")
    except OSError:
        pass
    return doc


@router.get("/reports/{run_id}/html")
def download_html(run_id: str, download: int = 0):
    """自包含 HTML 报告：默认浏览器内预览（可一键打印成 PDF），download=1 时作为文件下载。"""
    doc = _build_html(run_id)
    headers = {"Content-Disposition": f'attachment; filename="aiholey-{run_id}.html"'} if download else {}
    # 报告正文含被扫描项目的代码/响应片段，比主站更不可信 → 用更严的 CSP。
    # 中间件用的是 setdefault，这里先设就不会被覆盖。
    headers["Content-Security-Policy"] = REPORT_CSP
    return HTMLResponse(doc, headers=headers)


class ExportIn(BaseModel):
    run_ids: list[str] = []


@router.post("/reports/export")
def export_reports(body: ExportIn):
    """把多份报告拼成一份整合 Markdown。"""
    if not body.run_ids:
        raise HTTPException(status_code=400, detail="请选择要导出的报告")
    parts = ["# 代码审计平台 · 批量导出报告", "",
             f"导出时间：{time.strftime('%Y-%m-%d %H:%M:%S')}　共 {len(body.run_ids)} 份", "", "---", ""]
    ok = 0
    for rid in body.run_ids:
        r = db.query_one("SELECT * FROM runs WHERE run_id=?", (rid,))
        if not r:
            continue
        md = r.get("report_md") or ""
        if not md:
            md = _read_text(REPORTS_DIR / rid / "report.md") or f"（{rid} 无报告内容）"
        parts.append(md)
        parts.append("\n\n---\n")
        ok += 1
    return PlainTextResponse("\n".join(parts), media_type="text/markdown; charset=utf-8",
                             headers={"Content-Disposition": 'attachment; filename="aiholey-export.md"'})


@router.post("/reports/{run_id}/rescan")
def rescan(run_id: str):
    """复扫：拿同一仓库、同一技能集重新跑一次。"""
    old = db.query_one("SELECT * FROM runs WHERE run_id=?", (run_id,))
    if not old:
        raise HTTPException(status_code=404, detail="报告不存在")
    if not old.get("repo_id"):
        raise HTTPException(status_code=400, detail="该运行没有绑定仓库（快速扫描），无法复扫")
    active = db.query_one("SELECT COUNT(*) c FROM runs WHERE repo_id=? AND status IN ('queued','running')",
                          (old["repo_id"],))["c"]
    if active:
        raise HTTPException(status_code=400, detail="该仓库已有运行在排队或执行中")
    task = {
        "id": old.get("task_id"), "name": f"复扫：{old.get('task_name') or old.get('repo_name')}",
        "repo_id": old["repo_id"], "depth": old.get("depth"), "engine": old.get("engine"),
        "skill_names": old.get("skill_names"),
    }
    run = scheduler.enqueue(task, trigger="rescan")
    return {"ok": True, "run_id": run["run_id"]}


# ============================================================ 删除报告

class DeleteReportsIn(BaseModel):
    run_ids: list[str] = []


def _undeletable_reason(run_id: str) -> str | None:
    """返回不可删除的原因；可以删则返回 None。

    正在排队/执行的运行绝不能删：调度线程还持有它的记录，删掉之后
    写回状态时要么报错、要么把状态写到一条已经不存在的主键上，
    结果是一条永远卡在「运行中」的幽灵记录。
    """
    r = db.query_one("SELECT status FROM runs WHERE run_id=?", (run_id,))
    if not r:
        return "记录不存在"
    if r["status"] in ("queued", "running"):
        return "正在排队或执行中，请先停止"
    return None


def _purge_run(run_id: str) -> None:
    """删掉一份报告的全部痕迹：数据库三张表 + 磁盘产物目录。

    只动 `REPORTS_DIR/<run_id>`（本系统自己生成的报告目录），
    **绝不碰 `runs.workdir`**——那是仓库工作目录，同一仓库的多次运行共用一份，
    删报告时连带删掉会把其它任务和仓库本身一起毁掉，而且无法恢复。
    """
    db.execute("DELETE FROM findings WHERE run_id=?", (run_id,))
    db.execute("DELETE FROM run_logs WHERE run_id=?", (run_id,))
    db.execute("DELETE FROM runs WHERE run_id=?", (run_id,))
    d = REPORTS_DIR / run_id
    if d.is_dir():
        shutil.rmtree(d, ignore_errors=True)


@router.delete("/reports/{run_id}")
def delete_report(run_id: str):
    why = _undeletable_reason(run_id)
    if why:
        raise HTTPException(status_code=404 if why == "记录不存在" else 400,
                            detail="报告不存在" if why == "记录不存在" else f"无法删除：{why}")
    _purge_run(run_id)
    return {"ok": True}


@router.post("/reports/delete")
def delete_reports(body: DeleteReportsIn):
    """批量删除。逐条判定，能删的删、不能删的回报原因，不用一条失败打断整批。

    前端需要知道「哪几条没删掉、为什么」——静默跳过会让用户以为全删了，
    下次刷新发现还在，反而更慌。
    """
    if not body.run_ids:
        raise HTTPException(status_code=400, detail="请选择要删除的报告")
    deleted: list[str] = []
    skipped: list[dict] = []
    for rid in dict.fromkeys(body.run_ids):        # 去重且保持原顺序
        why = _undeletable_reason(rid)
        if why:
            skipped.append({"run_id": rid, "reason": why})
            continue
        _purge_run(rid)
        deleted.append(rid)
    return {"ok": True, "deleted": len(deleted), "deleted_ids": deleted, "skipped": skipped}


# ============================================================ 快速扫描（不建任务）

class QuickScanIn(BaseModel):
    path: str = ""
    repo_id: int = 0
    name: str = ""
    depth: str = "standard"
    engine: str = "codex"
    skill_names: list[str] = []


@router.post("/quick-scan")
def quick_scan(body: QuickScanIn):
    """直接扫服务器上的任意目录，或指定已拉取的仓库，不创建审计任务。"""
    if body.repo_id:
        repo = db.query_one("SELECT * FROM repos WHERE id=?", (body.repo_id,))
        if not repo:
            raise HTTPException(status_code=404, detail="仓库不存在")
        local = repo.get("local_path") or ""
        if not local or not Path(local).exists():
            raise HTTPException(status_code=400, detail="该仓库尚未拉取到本地，请先在仓库管理里点「拉取」")
        target, name = local, (body.name or repo["name"])
    else:
        if not body.path.strip():
            raise HTTPException(status_code=400, detail="请指定要扫描的目录")
        p = Path(body.path).expanduser()
        if not p.exists() or not p.is_dir():
            raise HTTPException(status_code=400, detail=f"目录不存在：{p}")
        target, name = str(p), (body.name or p.name)

    run_id = scheduler.new_run_id()
    db.insert("runs", {
        "run_id": run_id, "task_id": None, "repo_id": body.repo_id or None,
        "task_name": f"快速扫描：{name}", "repo_name": name,
        "depth": body.depth, "engine": body.engine,
        "skill_names": json.dumps(body.skill_names, ensure_ascii=False),
        "status": "queued", "progress": 0, "stage": "排队中",
        "message": "快速扫描任务，等待执行", "workdir": target, "created_at": time.time(),
    })
    db.log_line(run_id, f"快速扫描目录：{target}")
    return {"ok": True, "run_id": run_id}
