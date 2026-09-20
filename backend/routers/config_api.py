"""配置类接口：Git 仓库管理、技能库、引擎设置、目录浏览。"""
from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.config import BASE_DIR, DEPTHS, REPOS_DIR
from backend.core import db, engineconf, gitops
from backend.core import skills_seed

router = APIRouter(prefix="/api", tags=["config"])


# ============================================================ Git 仓库

class RepoIn(BaseModel):
    name: str
    type: str = "gitlab"
    url: str
    branch: str = "main"
    username: str = ""
    password: str = ""
    ssh_key: str = ""


def _repo_public(r: dict) -> dict:
    """返回给前端时隐去凭据。"""
    out = dict(r)
    out["password"] = "***" if r.get("password") else ""
    out["has_credential"] = bool(r.get("password") or r.get("ssh_key"))
    return out


@router.get("/repos")
def list_repos(name: str = "", status: str = ""):
    sql = "SELECT * FROM repos WHERE 1=1"
    args: list = []
    if name:
        sql += " AND name LIKE ?"
        args.append(f"%{name}%")
    if status:
        sql += " AND status=?"
        args.append(status)
    sql += " ORDER BY id DESC"
    rows = db.query(sql, args)
    for r in rows:
        r["task_count"] = db.query_one("SELECT COUNT(*) c FROM tasks WHERE repo_id=?", (r["id"],))["c"]
        r["local_exists"] = (REPOS_DIR / str(r["id"]) / ".git").exists()
    return {"items": [_repo_public(r) for r in rows]}


@router.post("/repos")
async def create_repos(items: list[RepoIn]):
    created = []
    for it in items:
        if not it.name.strip() or not it.url.strip():
            continue
        rid = db.insert("repos", {
            "name": it.name.strip(), "type": it.type, "url": it.url.strip(),
            "branch": it.branch.strip() or "main", "username": it.username.strip(),
            "password": it.password, "ssh_key": it.ssh_key.strip(),
            "status": "active", "created_at": time.time(),
        })
        created.append(_repo_public(db.query_one("SELECT * FROM repos WHERE id=?", (rid,))))
    if not created:
        raise HTTPException(status_code=400, detail="没有有效的仓库记录")
    return {"ok": True, "created": created}


@router.put("/repos/{repo_id}")
def update_repo(repo_id: int, body: RepoIn):
    r = db.query_one("SELECT * FROM repos WHERE id=?", (repo_id,))
    if not r:
        raise HTTPException(status_code=404, detail="仓库不存在")
    data = {"name": body.name.strip(), "type": body.type, "url": body.url.strip(),
            "branch": body.branch.strip() or "main", "username": body.username.strip(),
            "ssh_key": body.ssh_key.strip()}
    # 前端回传 "***" 表示不改密码
    if body.password and body.password != "***":
        data["password"] = body.password
    db.update("repos", repo_id, data)
    return {"ok": True, "repo": _repo_public(db.query_one("SELECT * FROM repos WHERE id=?", (repo_id,)))}


@router.delete("/repos/{repo_id}")
def delete_repo(repo_id: int, remove_files: bool = False):
    if not db.query_one("SELECT id FROM repos WHERE id=?", (repo_id,)):
        raise HTTPException(status_code=404, detail="仓库不存在")
    n = db.query_one("SELECT COUNT(*) c FROM tasks WHERE repo_id=?", (repo_id,))["c"]
    if n:
        raise HTTPException(status_code=400, detail=f"该仓库下还有 {n} 个审计任务，请先删除任务")
    db.execute("DELETE FROM repos WHERE id=?", (repo_id,))
    if remove_files:
        shutil.rmtree(REPOS_DIR / str(repo_id), ignore_errors=True)
    return {"ok": True}


@router.post("/repos/test")
async def test_repos(items: list[RepoIn]):
    """批量测试连接。已有记录的仓库若密码传 *** 则用库里存的。"""
    out = []
    for it in items:
        repo = it.model_dump()
        if repo.get("password") == "***":
            old = db.query_one("SELECT * FROM repos WHERE name=? AND url=?", (it.name, it.url))
            if old:
                repo["password"] = old.get("password") or ""
        ok, msg = await asyncio.to_thread(gitops.test_connection, repo)
        out.append({"name": it.name, "ok": ok, "message": msg[:400]})
    return {"items": out}


@router.post("/repos/{repo_id}/pull")
async def pull_repo(repo_id: int):
    repo = db.query_one("SELECT * FROM repos WHERE id=?", (repo_id,))
    if not repo:
        raise HTTPException(status_code=404, detail="仓库不存在")
    ok, msg = await asyncio.to_thread(gitops.pull, repo)
    db.execute("UPDATE repos SET last_pull_at=?, last_pull_status=?, last_pull_msg=?, local_path=? WHERE id=?",
               (time.time(), "success" if ok else "failed", msg[:500],
                str(REPOS_DIR / str(repo_id)), repo_id))
    if not ok:
        raise HTTPException(status_code=400, detail=msg[:500])
    return {"ok": True, "message": msg}


# ============================================================ 技能库

class SkillIn(BaseModel):
    name: str
    description: str = ""
    prompt: str = ""
    category: str = "通用"
    enabled: int = 1


@router.get("/skills")
def list_skills(name: str = "", category: str = ""):
    sql = "SELECT * FROM skills WHERE 1=1"
    args: list = []
    if name:
        sql += " AND name LIKE ?"
        args.append(f"%{name}%")
    if category:
        sql += " AND category=?"
        args.append(category)
    sql += " ORDER BY sort_order ASC, id ASC"
    items = db.query(sql, args)
    cats = [r["category"] for r in db.query("SELECT DISTINCT category FROM skills ORDER BY category")]
    return {"items": items, "categories": cats, "total": len(items)}


@router.post("/skills")
def create_skill(body: SkillIn):
    if not body.name.strip():
        raise HTTPException(status_code=400, detail="技能名不能为空")
    if db.query_one("SELECT id FROM skills WHERE name=?", (body.name.strip(),)):
        raise HTTPException(status_code=400, detail="同名技能已存在")
    sid = db.insert("skills", {"name": body.name.strip(), "description": body.description,
                               "prompt": body.prompt, "category": body.category,
                               "builtin": 0, "enabled": body.enabled, "sort_order": 999,
                               "created_at": time.time()})
    return {"ok": True, "skill": db.query_one("SELECT * FROM skills WHERE id=?", (sid,))}


@router.put("/skills/{skill_id}")
def update_skill(skill_id: int, body: SkillIn):
    if not db.query_one("SELECT id FROM skills WHERE id=?", (skill_id,)):
        raise HTTPException(status_code=404, detail="技能不存在")
    db.update("skills", skill_id, {"name": body.name.strip(), "description": body.description,
                                   "prompt": body.prompt, "category": body.category,
                                   "enabled": body.enabled})
    return {"ok": True, "skill": db.query_one("SELECT * FROM skills WHERE id=?", (skill_id,))}


@router.delete("/skills/{skill_id}")
def delete_skill(skill_id: int):
    s = db.query_one("SELECT * FROM skills WHERE id=?", (skill_id,))
    if not s:
        raise HTTPException(status_code=404, detail="技能不存在")
    if s.get("builtin"):
        raise HTTPException(status_code=400, detail="内置技能不可删除，可以编辑或停用")
    db.execute("DELETE FROM skills WHERE id=?", (skill_id,))
    return {"ok": True}


@router.post("/skills/reset")
def reset_skills():
    """把内置技能恢复到出厂提示词。"""
    n = 0
    for s in skills_seed.SEED_SKILLS():
        old = db.query_one("SELECT id FROM skills WHERE name=?", (s["name"],))
        if old:
            db.update("skills", old["id"], {"description": s["description"], "prompt": s["prompt"],
                                            "category": s["category"], "builtin": 1})
        else:
            s["created_at"] = time.time()
            db.insert("skills", s)
        n += 1
    return {"ok": True, "count": n}


# ============================================================ 引擎设置

def _which(cmd: str) -> tuple[bool, str, str]:
    path = shutil.which(cmd) or ""
    if not path:
        return False, "", ""
    try:
        r = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10)
        return True, path, (r.stdout or r.stderr).strip().splitlines()[0][:80]
    except (OSError, subprocess.SubprocessError):
        return True, path, ""


@router.get("/engines")
def list_engines():
    default = engineconf.default_engine()
    out = []
    for name, cli in (("codex", "codex"), ("claude", "claude")):
        cfg = engineconf.masked(name)
        installed, path, version = _which(cli)
        cfg.update({"installed": installed, "cli_path": path, "cli_version": version,
                    "is_default": name == default})
        out.append(cfg)
    return {"items": out, "default": default}


class EngineIn(BaseModel):
    api_key: str | None = None
    model: str | None = None
    base_url: str | None = None


@router.put("/engines/{name}")
def update_engine(name: str, body: EngineIn):
    if name not in ("codex", "claude"):
        raise HTTPException(status_code=404, detail="未知引擎")
    key = body.api_key
    if key == "***":          # 前端未改动
        key = None
    engineconf.set_engine(name, key, body.model, body.base_url)
    return {"ok": True, "engine": engineconf.masked(name)}


@router.post("/engines/{name}/test")
async def test_engine(name: str, body: EngineIn | None = None):
    if name not in ("codex", "claude"):
        raise HTTPException(status_code=404, detail="未知引擎")
    if body and body.api_key and body.api_key != "***":
        engineconf.set_engine(name, body.api_key,
                              body.model or None, body.base_url or None)
    client = engineconf.client_for(name)
    if client is None:
        return {"ok": False, "message": "尚未配置 API Key"}
    ok, msg = await asyncio.to_thread(client.test)
    return {"ok": ok, "message": msg}


@router.post("/engines/default/{name}")
def set_default(name: str):
    if name not in ("codex", "claude"):
        raise HTTPException(status_code=404, detail="未知引擎")
    engineconf.set_default_engine(name)
    return {"ok": True, "default": name}


# ============================================================ 目录浏览

@router.get("/fs/list")
def fs_list(path: str = ""):
    """浏览服务器目录，用于「快速扫描」直接指定目录。默认从仓库根目录开始。"""
    base = Path(path).expanduser() if path else REPOS_DIR
    try:
        base = base.resolve()
    except OSError:
        raise HTTPException(status_code=400, detail="路径无效")
    if not base.exists() or not base.is_dir():
        raise HTTPException(status_code=400, detail=f"目录不存在：{base}")
    dirs, files = [], []
    try:
        for p in sorted(base.iterdir(), key=lambda x: x.name):
            if p.name.startswith("."):
                continue
            try:
                if p.is_dir():
                    dirs.append({"name": p.name, "path": str(p)})
                else:
                    files.append({"name": p.name, "size": p.stat().st_size})
            except OSError:
                continue
    except PermissionError:
        raise HTTPException(status_code=403, detail="没有权限读取该目录")
    return {"path": str(base), "parent": str(base.parent), "home": str(BASE_DIR),
            "dirs": dirs[:200], "files": files[:200]}


@router.get("/meta")
def meta():
    from backend.config import DEPTHS as D, MAX_CONCURRENT_RUNS
    return {
        "depths": [{"value": k, "label": v["label"]} for k, v in D.items()],
        "max_concurrent": MAX_CONCURRENT_RUNS,
        "schedule_types": [
            {"value": "manual", "label": "手动触发"},
            {"value": "interval", "label": "定时执行（间隔）"},
            {"value": "cron", "label": "定时执行（cron）"},
            {"value": "once", "label": "单次执行"},
        ],
        "run_status": [
            {"value": "pending", "label": "待执行"},
            {"value": "queued", "label": "排队中"},
            {"value": "running", "label": "运行中"},
            {"value": "success", "label": "完成"},
            {"value": "failed", "label": "失败"},
            {"value": "stopped", "label": "已停止"},
        ],
    }
