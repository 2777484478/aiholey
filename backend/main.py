"""Aiholey · AI 代码审计平台 —— FastAPI 应用入口。

除业务路由外，这里还负责**把安全边界收口在一处**：所有响应统一附加安全头、
所有跨站写请求在进入业务逻辑前就被挡掉。放在中间件而不是每个路由里，
是为了避免「新加了接口但忘了加防护」。
"""
from __future__ import annotations

import time
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from backend.config import FRONTEND_DIR, HOST, MAX_CONCURRENT_RUNS, PORT
from backend.core import auth, db, scheduler
from backend.core.skills_seed import SEED_SKILLS
from backend.core.webscan.skills_seed import SEED_WEB_SKILLS
from backend.routers import auth as auth_router
from backend.routers import config_api, report_api, task_api, webscan_api

# 安全响应头（报告页还有一份更严的，见 core/sec_headers.py）
from backend.core.sec_headers import SECURITY_HEADERS  # noqa: E402

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
# 允许的页面来源主机名（本地访问可能用 127.0.0.1 / localhost / 局域网 IP）
LOCAL_HOSTNAMES = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}


def _same_origin(request: Request) -> bool:
    """非安全方法必须是同源请求。

    浏览器在跨站写请求上一定会带 `Origin` 头，所以这条规则能在 CSRF 令牌之前
    先把第三方站点发起的 POST/DELETE 挡掉；且它**不依赖前端配合**，
    对 `curl` 之类不带 Origin 的客户端则直接放行（由令牌与 CSRF 负责）。
    """
    if request.method.upper() in SAFE_METHODS:
        return True
    origin = request.headers.get("origin")
    if not origin:
        return True
    host = (request.headers.get("host") or "").lower()
    try:
        parsed = urlparse(origin)
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    if (parsed.netloc or "").lower() == host:
        return True
    hostname = (parsed.hostname or "").lower()
    return hostname in LOCAL_HOSTNAMES or hostname == HOST.lower()


def bootstrap() -> None:
    db.init_db()
    auth.ensure_default_user()
    if not db.query_one("SELECT id FROM skills LIMIT 1"):
        for s in SEED_SKILLS():
            s["created_at"] = time.time()
            db.insert("skills", s)
        print(f"[init] 已初始化 {len(SEED_SKILLS())} 项内置审计技能", flush=True)
    # Web 漏扫技能库：只补缺失项，不覆盖用户改过的提示词
    have = {r["name"] for r in db.query("SELECT name FROM web_skills")}
    seeded = 0
    for s in SEED_WEB_SKILLS():
        if s["name"] not in have:
            s["created_at"] = time.time()
            db.insert("web_skills", s)
            seeded += 1
    if seeded:
        print(f"[init] 已初始化 {seeded} 项 Web 漏扫技能", flush=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    bootstrap()
    await scheduler.start()
    print(f"[init] Aiholey 就绪 · 并发上限 {MAX_CONCURRENT_RUNS} · 端口 {PORT}", flush=True)
    yield
    print("[exit] Aiholey 正在退出", flush=True)


app = FastAPI(title="Aiholey 代码审计平台", version="2.1.0", lifespan=lifespan,
              docs_url=None, redoc_url=None)   # 关掉 /docs：本地工具站不需要，暴露接口清单只会扩大攻击面


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """统一挂安全头 + 拦截跨站写请求 + 禁止缓存接口响应。"""
    if not _same_origin(request):
        return JSONResponse({"detail": "跨站请求已被拒绝"}, status_code=403)

    response = await call_next(request)

    for key, value in SECURITY_HEADERS.items():
        response.headers.setdefault(key, value)
    # 接口响应里有令牌、报告、仓库凭据等信息，一律禁止浏览器/代理缓存
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    # 覆盖 uvicorn 的默认 Server 头，不对外泄露实现与版本
    response.headers["Server"] = "aiholey"
    return response


# 认证路由自身不挂保护：登录、续期、登出都必须能在「令牌已失效」时访问，
# 它们各自按需校验（写操作都过了 CSRF，见 routers/auth.py）。
app.include_router(auth_router.router)

# 其余全部接口统一挂鉴权依赖 —— 新增路由时只要加进这个元组就自动受保护
_protected = [Depends(auth_router.current_user)]
for r in (config_api.router, task_api.router, report_api.router, webscan_api.router):
    app.include_router(r, dependencies=_protected)


@app.get("/api/health")
def health():
    return {"ok": True, "service": "aiholey", "running": scheduler.running_count(),
            "time": time.strftime("%Y-%m-%d %H:%M:%S")}


@app.get("/login")
def login_page():
    return FileResponse(FRONTEND_DIR / "login.html")


@app.get("/")
def index(request: Request):
    """控制台首页。

    access token 只有 30 分钟，但会话寿命是 7 天 —— 所以「access 过期」不能直接
    跳登录页（用户每半小时就被弹一次）。这里判断的是**会话是否还活着**：
    access 有效、或 refresh 仍有效，都放行，剩下的交给前端静默续期。
    """
    if auth_router.optional_user(request):
        return FileResponse(FRONTEND_DIR / "index.html")
    if auth.refresh_alive(request.cookies.get(auth_router.RT_COOKIE)):
        return FileResponse(FRONTEND_DIR / "index.html")
    return RedirectResponse("/login")


@app.exception_handler(404)
async def not_found(request: Request, exc):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": "接口不存在"}, status_code=404)
    return JSONResponse({"detail": "页面不存在"}, status_code=404)


app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")
