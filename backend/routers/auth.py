"""认证路由：登录、令牌续期、登出、当前用户、改密、会话管理。

## Cookie 策略

| Cookie | 内容 | httponly | path | 说明 |
| --- | --- | --- | --- | --- |
| `aiholey_at` | access JWT | 是 | `/` | JS 读不到，XSS 也偷不走 |
| `aiholey_rt` | refresh 随机串 | 是 | `/api/auth` | **限定路径**，只有换令牌时才发送，其余接口的请求里根本不带它 |
| `aiholey_csrf` | CSRF 令牌 | **否** | `/` | double-submit 模式要求 JS 能读到它并与请求头比对 |

三者都是 `SameSite=Lax`：跨站的 POST 请求不会携带它们，从浏览器层面就挡掉大部分 CSRF；
`aiholey_csrf` 是在此之上的第二道锁，防的是"同站子域被拿下"这类 SameSite 管不到的情况。

## 为什么 CSRF 令牌还要和 JWT 内的声明比对

只比 cookie 与请求头是 classic double-submit，但它有一个前提：攻击者无法给受害者
种 cookie。若攻击者能操控子域（或 Cookie tossing），就能同时种下 cookie 和伪造请求头。
而 `csrf` 值同时被签进了 access JWT，**签名改不了**，于是攻击者没法让两者同时自洽。
"""
from __future__ import annotations

import hashlib
import hmac
import time

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from backend.config import COOKIE_SECURE, REFRESH_TTL
from backend.core import auth, db

router = APIRouter(prefix="/api/auth", tags=["auth"])

AT_COOKIE = "aiholey_at"          # access token
RT_COOKIE = "aiholey_rt"          # refresh token
CSRF_COOKIE = "aiholey_csrf"      # CSRF 令牌（JS 可读）
RT_PATH = "/api/auth"             # refresh cookie 限定路径
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


# ---------------------------------------------------------------- 工具


def _const_eq(a: str, b: str) -> bool:
    """常量时间比较。用 bytes 比较，避免非 ASCII 输入让 compare_digest 抛 TypeError。"""
    try:
        return hmac.compare_digest((a or "").encode("utf-8"), (b or "").encode("utf-8"))
    except Exception:
        return False


def assert_csrf(request: Request, payload: dict | None = None) -> None:
    """非安全方法必须通过 CSRF 校验。"""
    if request.method.upper() in SAFE_METHODS:
        return
    cookie = request.cookies.get(CSRF_COOKIE) or ""
    header = request.headers.get("X-CSRF-Token") or ""
    if not cookie or not header or not _const_eq(cookie, header):
        raise HTTPException(status_code=403, detail="CSRF 校验失败，请刷新页面后重试")
    if payload is not None:
        claim = str(payload.get("csrf") or "")
        if not claim or not _const_eq(cookie, claim):
            raise HTTPException(status_code=403, detail="CSRF 令牌与会话不匹配，请重新登录")


def _set_cookies(response: Response, tok: dict) -> None:
    common = {"httponly": True, "samesite": "lax", "secure": COOKIE_SECURE}
    # access cookie 的 Max-Age 按**会话寿命**给，而不是按 access 的 30 分钟。
    # 若两者绑定，浏览器会在 30 分钟一到就把 cookie 删掉，服务端之后收到的请求
    # 里根本没有令牌 → 只能报"缺少令牌"，无法区分"过期了去续期"和"压根没登录"。
    # 让它跟 refresh 同寿，过期与否一律由签名里的 exp 判定，语义才准确。
    session_life = int(tok.get("refresh_expires_in") or REFRESH_TTL)
    response.set_cookie(AT_COOKIE, tok["access"], max_age=session_life,
                        path="/", **common)
    response.set_cookie(RT_COOKIE, tok["refresh"], max_age=tok["refresh_expires_in"],
                        path=RT_PATH, **common)
    # 必须非 httponly：前端要读出来放进 X-CSRF-Token 头
    response.set_cookie(CSRF_COOKIE, tok["csrf"], max_age=tok["refresh_expires_in"],
                        path="/", httponly=False, samesite="lax", secure=COOKIE_SECURE)


def _clear_cookies(response: Response) -> None:
    response.delete_cookie(AT_COOKIE, path="/")
    response.delete_cookie(RT_COOKIE, path=RT_PATH)
    response.delete_cookie(CSRF_COOKIE, path="/")


def _client(request: Request) -> tuple[str, str]:
    ip = request.client.host if request.client else ""
    return ip or "", request.headers.get("user-agent", "")


def _public_user(user: dict) -> dict:
    """只返回前端需要的字段——绝不把 password_hash 之类的字段漏出去。"""
    return {
        "username": user["username"],
        "display_name": user.get("display_name") or user["username"],
        "must_change_password": bool(user.get("must_change_password")),
        "last_login_at": user.get("last_login_at"),
    }


# ---------------------------------------------------------------- 依赖


def current_user(request: Request) -> dict:
    """依赖：验证 access token + CSRF，未通过抛 401/403。

    `X-Auth-Reason` 头带上机器可读的原因（token_expired / token_revoked / ...），
    前端据此决定"静默续期"还是"直接跳登录页"。
    """
    try:
        payload, user = auth.verify_access(request.cookies.get(AT_COOKIE))
    except auth.AuthError as exc:
        raise HTTPException(status_code=401, detail=exc.message,
                            headers={"X-Auth-Reason": exc.code}) from None
    assert_csrf(request, payload)
    request.state.jwt_payload = payload
    return user


def optional_user(request: Request) -> dict | None:
    try:
        _, user = auth.verify_access(request.cookies.get(AT_COOKIE))
    except auth.AuthError:
        return None
    return user


# ---------------------------------------------------------------- 请求体


class LoginBody(BaseModel):
    username: str
    password: str


class PasswordBody(BaseModel):
    old_password: str
    new_password: str


class RevokeBody(BaseModel):
    id: str = ""


# ---------------------------------------------------------------- 端点


@router.post("/login")
def login(body: LoginBody, request: Request, response: Response):
    ip, ua = _client(request)
    try:
        res = auth.authenticate(body.username, body.password, ip, ua)
    except auth.AuthError as exc:
        headers = {"Retry-After": str(exc.retry_after)} if exc.retry_after else None
        status = 429 if exc.code == "locked" else 401
        raise HTTPException(status_code=status, detail=exc.message, headers=headers) from None

    auth.purge_expired()
    _set_cookies(response, res)
    return {"ok": True, **_public_user(res["user"]),
            "access_expires_in": res["access_expires_in"]}


@router.post("/refresh")
def refresh_token(request: Request, response: Response):
    """用 refresh cookie 换一对新令牌。前端收到 401 时自动调用。"""
    assert_csrf(request)
    ip, ua = _client(request)
    try:
        tok = auth.rotate_refresh(request.cookies.get(RT_COOKIE), ip, ua)
    except auth.AuthError as exc:
        _clear_cookies(response)
        raise HTTPException(status_code=401, detail=exc.message,
                            headers={"X-Auth-Reason": exc.code}) from None
    _set_cookies(response, tok)
    return {"ok": True, "username": tok["username"],
            "access_expires_in": tok["access_expires_in"]}


@router.post("/logout")
def logout(request: Request, response: Response):
    # 登出也要 CSRF：否则第三方站点能构造请求把用户踢下线
    assert_csrf(request)
    auth.logout_refresh(request.cookies.get(RT_COOKIE))
    _clear_cookies(response)
    return {"ok": True}


@router.get("/me")
def me(request: Request, response: Response, user: dict = Depends(current_user)):
    # CSRF cookie 可能被用户手动清掉（或换了浏览器 profile），此时前端所有写操作都会
    # 403 且无法自愈。access JWT 里签着 csrf 值，直接用它把 cookie 补回来。
    payload = getattr(request.state, "jwt_payload", {}) or {}
    if payload.get("csrf") and not _const_eq(request.cookies.get(CSRF_COOKIE) or "",
                                             str(payload["csrf"])):
        response.set_cookie(CSRF_COOKIE, str(payload["csrf"]), path="/", httponly=False,
                            samesite="lax", secure=COOKIE_SECURE)
    return {**_public_user(user), "token": _token_info(payload)}


@router.post("/password")
def change_password(body: PasswordBody, response: Response,
                    user: dict = Depends(current_user)):
    try:
        res = auth.change_password(user["username"], body.old_password, body.new_password)
    except auth.AuthError as exc:
        raise HTTPException(status_code=400, detail=exc.message) from None
    # 改密后旧令牌全废，但当前这台设备换发一对新的，免得用户改完就被踢出去
    _set_cookies(response, res["tokens"])
    return {"ok": True, "revoked_sessions": res["revoked_sessions"]}


@router.get("/sessions")
def sessions(request: Request, user: dict = Depends(current_user)):
    payload = getattr(request.state, "jwt_payload", {}) or {}
    current = _current_family(request)
    items = auth.list_sessions(user["username"])
    for it in items:
        # 标出当前设备：界面上不给它「踢出」按钮——把自己踢下线只会让人莫名其妙
        it["current"] = bool(current) and it["id"] == current
    return {"items": items, "count": len(items), "token": _token_info(payload)}


@router.post("/sessions/revoke")
def revoke_session(body: RevokeBody, request: Request, response: Response,
                   user: dict = Depends(current_user)):
    """撤销一个会话；id 传 "*" 表示踢掉除当前设备外的全部会话。"""
    target = (body.id or "").strip()
    if not target:
        raise HTTPException(status_code=400, detail="缺少会话标识")

    payload = getattr(request.state, "jwt_payload", {}) or {}
    if target == "*":
        keep = _current_family(request)
        removed = 0
        for s in auth.list_sessions(user["username"]):
            if s["id"] == keep:
                continue
            if auth.revoke_session(user["username"], s["id"]):
                removed += 1
        return {"ok": True, "revoked": removed}

    # 不允许把当前设备自己踢掉——那会让用户莫名其妙被登出；想退出去点「退出登录」
    if target == _current_family(request):
        raise HTTPException(status_code=400, detail="不能在这里撤销当前设备，请使用「退出登录」")
    if not auth.revoke_session(user["username"], target):
        raise HTTPException(status_code=404, detail="会话不存在或已失效")
    return {"ok": True, "revoked": 1, "by": payload.get("sub")}


def _current_family(request: Request) -> str:
    """从 refresh cookie 反查当前会话家族（cookie 只在 /api/auth 下发送）。"""
    raw = request.cookies.get(RT_COOKIE)
    if not raw:
        return ""
    row = db.query_one("SELECT family FROM refresh_tokens WHERE token_hash=?",
                       (hashlib.sha256(raw.encode()).hexdigest(),))
    return row["family"] if row else ""


def _token_info(payload: dict) -> dict:
    """给前端展示用的令牌元信息（不含任何可用于伪造的内容）。"""
    exp = payload.get("exp")
    remain = max(0, int(exp - time.time())) if isinstance(exp, (int, float)) else 0
    return {
        "alg": "HS256",
        "access_expires_in": remain,
        "family": payload.get("jti", "")[:8],
        "issued_at": payload.get("iat"),
    }
