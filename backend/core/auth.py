"""认证：JWT 双令牌、密码哈希、登录限流与审计。

## 为什么是「双令牌」而不是纯 JWT

JWT 最大的好处是自包含、服务端不用查库；最大的坏处也在这里——**签发后在有效期内
收不回来**。用户点了「退出登录」、改了密码、或者手机丢了想踢掉某台设备时，
纯 JWT 方案只能干等它自然过期。所以长期凭证仍然要「有状态」：

| | access token | refresh token |
| --- | --- | --- |
| 形态 | HS256 JWT（自包含） | 随机串（`secrets.token_urlsafe`） |
| 有效期 | `ACCESS_TTL`，默认 30 分钟 | `REFRESH_TTL`，默认 7 天 |
| 存储 | 只在浏览器 httponly cookie | **库内存 sha256 哈希**，可吊销 |
| 作用 | 每个接口请求带上，验签即可 | 只用来换新的 access |

## 三件必须做对的事

1. **即时吊销**：JWT 无法收回，所以 `users.token_version` 改了密码/踢下线时 +1，
   每次校验都比对 JWT 里的 `tv` 声明——旧令牌当场失效，代价是每请求读一次
   `users` 表（本地 SQLite，可忽略）。
2. **刷新令牌轮换 + 复用检测**：每次刷新都换一个新的 refresh，旧的标成已撤销。
   如果**已轮换过的旧令牌再次出现**，说明它多半被复制走了（攻击者与用户各持一份，
   谁后用谁露馅），此时吊销整个会话家族。留 60 秒宽限窗口，
   否则多标签页并发刷新会互相把对方踢下线。
3. **令牌不以明文落盘**：库里只存 sha256。`data/*.db` 是明文 SQLite，
   被拷走就等于拿到登录凭证——存哈希则拿到也没用。
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import time

from backend.config import (
    ACCESS_TTL,
    DATA_DIR,
    DEFAULT_PASSWORD,
    DEFAULT_USER,
    LOGIN_FAIL_WINDOW,
    LOGIN_LOCK_SECONDS,
    LOGIN_MAX_FAILS,
    MIN_PASSWORD_LEN,
    REFRESH_TTL,
)
from backend.core import db, jwt_util

# 刷新令牌轮换后的宽限窗口（秒）：见模块开头第 2 点
ROTATION_GRACE = 60
# 登录审计保留天数
LOGIN_EVENT_TTL = 30 * 86400


class AuthError(Exception):
    """认证/授权失败。`code` 供前端判断（如是否该去刷新令牌）。"""

    def __init__(self, code: str, message: str, retry_after: int = 0):
        super().__init__(message)
        self.code = code
        self.message = message
        self.retry_after = retry_after


# ---------------------------------------------------------------- 密钥

_secret_cache: str | None = None


def jwt_secret() -> str:
    """JWT 签名密钥：优先环境变量，其次 `data/.jwt_secret`（自动生成并 0600）。

    绝不内置默认密钥——硬编码密钥等于没有签名。第一次启动时生成随机密钥并落盘，
    这样服务重启后已登录用户不会被集体登出。
    """
    global _secret_cache
    if _secret_cache:
        return _secret_cache

    env = (os.environ.get("AIHOLEY_JWT_SECRET") or "").strip()
    if len(env) >= 16:
        _secret_cache = env
        return _secret_cache
    if env:
        print("[auth] 警告：AIHOLEY_JWT_SECRET 长度不足 16 字符，已忽略，改用自动生成的密钥",
              flush=True)

    path = DATA_DIR / ".jwt_secret"
    try:
        saved = path.read_text(encoding="utf-8").strip()
        if len(saved) >= 16:
            _secret_cache = saved
            return _secret_cache
    except OSError:
        pass

    generated = secrets.token_urlsafe(48)
    try:
        path.write_text(generated, encoding="utf-8")
        path.chmod(0o600)
    except OSError as exc:
        print(f"[auth] 警告：JWT 密钥无法持久化（{exc}）；本次进程内有效，重启后需重新登录",
              flush=True)
    _secret_cache = generated
    return generated


# ---------------------------------------------------------------- 密码


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000)
    return f"pbkdf2_sha256${salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, salt, _ = stored.split("$", 2)
    except (ValueError, AttributeError):
        return False
    if algo != "pbkdf2_sha256":
        return False
    return hmac.compare_digest(hash_password(password, salt), stored)


def check_password_strength(password: str, username: str = "") -> str | None:
    """返回不合规的原因；合规返回 None。"""
    if len(password) < MIN_PASSWORD_LEN:
        return f"新密码至少 {MIN_PASSWORD_LEN} 位"
    if len(password) > 128:
        return "新密码过长（最多 128 位）"
    if username and password.lower() == username.lower():
        return "新密码不能与用户名相同"
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        return "新密码需同时包含字母和数字"
    if password.lower() in ("admin123", "password", "12345678", "admin@123"):
        return "该密码过于常见，请更换"
    return None


def ensure_default_user() -> None:
    if db.query_one("SELECT id FROM users LIMIT 1"):
        return
    db.insert("users", {
        "username": DEFAULT_USER,
        "password_hash": hash_password(DEFAULT_PASSWORD),
        "display_name": DEFAULT_USER,
        "must_change_password": 1,
        "created_at": time.time(),
        "token_version": 0,
    })


# ---------------------------------------------------------------- 用户


def get_user(username: str) -> dict | None:
    if not username:
        return None
    return db.query_one("SELECT * FROM users WHERE username=?", (username,))


def _tv(user: dict) -> int:
    try:
        return int(user.get("token_version") or 0)
    except (TypeError, ValueError):
        return 0


def bump_token_version(username: str) -> int:
    """让该用户已签发的所有 access token 立即失效（改密、强制下线时用）。"""
    db.execute("UPDATE users SET token_version = COALESCE(token_version, 0) + 1 WHERE username=?",
               (username,))
    user = get_user(username) or {}
    return _tv(user)


# ---------------------------------------------------------------- 登录审计 / 限流


def record_login(username: str, ip: str, user_agent: str, success: bool, reason: str = "") -> None:
    try:
        db.insert("login_events", {
            "username": username or "", "ip": ip or "", "success": 1 if success else 0,
            "reason": reason or "", "user_agent": (user_agent or "")[:200], "ts": time.time(),
        })
    except Exception as exc:                       # 审计失败不能挡住登录主流程
        print(f"[auth] 登录事件写入失败：{exc}", flush=True)


# 只有"真有人在猜密码"才计入爆破限流。刷新令牌的并发竞态、复用检测这类事件
# 也会写进审计表，但它们不是口令失败——算进去的话，多标签页同时刷新的用户会
# 莫名其妙被锁定 5 分钟。
LOCKABLE_REASONS = ("bad_credentials", "locked")


def _recent_fails(column: str, value: str) -> tuple[int, float]:
    """窗口内**口令失败**次数 + 最后一次失败时间。"""
    if not value:
        return 0, 0.0
    since = time.time() - LOGIN_FAIL_WINDOW
    ph = ",".join("?" * len(LOCKABLE_REASONS))
    r = db.query_one(
        f"SELECT COUNT(*) AS c, COALESCE(MAX(ts), 0) AS last FROM login_events "
        f"WHERE {column}=? AND success=0 AND ts>=? AND reason IN ({ph})",
        (value, since, *LOCKABLE_REASONS),
    ) or {}
    return int(r.get("c") or 0), float(r.get("last") or 0)


def lock_remaining(username: str, ip: str = "") -> int:
    """还需等待多少秒才能再试。0 表示未被锁定。"""
    now = time.time()
    for column, value, limit in (("username", username, LOGIN_MAX_FAILS),
                                 ("ip", ip, LOGIN_MAX_FAILS * 3)):
        count, last = _recent_fails(column, value)
        if count >= limit and last:
            remain = int(last + LOGIN_LOCK_SECONDS - now)
            if remain > 0:
                return remain
    return 0


# ---------------------------------------------------------------- 令牌签发


def _store_refresh(raw: str, username: str, family: str, csrf: str, ip: str, ua: str,
                   ttl: int = REFRESH_TTL) -> None:
    now = time.time()
    db.insert("refresh_tokens", {
        "token_hash": hashlib.sha256(raw.encode()).hexdigest(),
        "username": username,
        "family": family,
        "csrf": csrf,
        "user_agent": (ua or "")[:200],
        "ip": ip or "",
        "created_at": now,
        "expires_at": now + ttl,
    })


def _access_for(user: dict, csrf: str) -> str:
    return jwt_util.encode({
        "sub": user["username"],
        "uid": user.get("id"),
        "tv": _tv(user),
        "csrf": csrf,
    }, jwt_secret(), ttl=ACCESS_TTL, typ="access")


def new_session(user: dict, ip: str = "", user_agent: str = "") -> dict:
    """登录成功后建立新会话（新 family）。"""
    family = secrets.token_urlsafe(16)
    csrf = secrets.token_urlsafe(24)
    refresh = secrets.token_urlsafe(48)
    _store_refresh(refresh, user["username"], family, csrf, ip, user_agent)
    db.execute("UPDATE users SET last_login_at=?, last_login_ip=? WHERE username=?",
               (time.time(), ip or "", user["username"]))
    return {
        "access": _access_for(user, csrf),
        "refresh": refresh,
        "csrf": csrf,
        "family": family,
        "access_expires_in": ACCESS_TTL,
        "refresh_expires_in": REFRESH_TTL,
    }


# 轮换后继缓存：旧令牌哈希 → (新令牌原文, 过期时刻)。
# 只在 ROTATION_GRACE 秒内有效，用于让并发刷新收敛到同一个 refresh。
# 内存中保存的是**轮换后已经发给客户端的**那个串，不是新密钥材料，
# 进程重启即失效（此时走 fail-closed：吊销家族）。
_rotation_cache: dict[str, tuple[str, float]] = {}


def _rotation_successor(old_hash: str) -> str:
    now = time.time()
    hit = _rotation_cache.get(old_hash)
    if not hit:
        return ""
    raw, deadline = hit
    if deadline < now:
        _rotation_cache.pop(old_hash, None)
        return ""
    return raw


def _remember_rotation(old_hash: str, new_raw: str) -> None:
    now = time.time()
    for k in [k for k, (_, dl) in _rotation_cache.items() if dl < now]:
        _rotation_cache.pop(k, None)
    _rotation_cache[old_hash] = (new_raw, now + ROTATION_GRACE)


def rotate_refresh(raw: str, ip: str = "", user_agent: str = "") -> dict:
    """用 refresh 换一对新令牌。旧令牌立即作废（轮换），并检测复用。"""
    if not raw or not isinstance(raw, str):
        raise AuthError("no_refresh", "缺少刷新令牌，请重新登录")

    now = time.time()
    old_hash = hashlib.sha256(raw.encode()).hexdigest()
    row = db.query_one("SELECT * FROM refresh_tokens WHERE token_hash=?", (old_hash,))
    if not row:
        raise AuthError("invalid_refresh", "刷新令牌无效，请重新登录")

    if row["revoked_at"]:
        grace = now - float(row["revoked_at"])
        # 正常轮换留下的旧令牌，在宽限窗口内被视为「并发刷新」（多标签页），放行；
        # 超出窗口、或本身就是登出/吊销掉的令牌又被使用 → 判定为令牌泄漏。
        #
        # 关键：宽限期内**不能每次都签发新令牌**——那样一份被复制走的旧令牌
        # 能在 60 秒内无限换新。这里返回上次轮换已经发出的那个（幂等），
        # 让并发的标签页收敛到同一个 refresh；缓存里没有（如服务重启过）就
        # 按泄漏处理，fail closed。
        if row["revoke_reason"] == "rotated" and grace <= ROTATION_GRACE:
            record_login(row["username"], ip, user_agent, False, "refresh_rotation_race")
            successor = _rotation_successor(old_hash)
            if successor:
                user = get_user(row["username"])
                if user:
                    return {
                        "access": _access_for(user, row["csrf"] or ""),
                        "refresh": successor,
                        "csrf": row["csrf"] or "",
                        "family": row["family"],
                        "username": row["username"],
                        "access_expires_in": ACCESS_TTL,
                        "refresh_expires_in": max(1, int(float(row["expires_at"]) - now)),
                    }
            # 缓存失效：宁可让用户重新登录，也不给来源不明的旧令牌换发凭证
            revoke_family(row["family"], "refresh_reuse")
            raise AuthError("refresh_reuse",
                            "会话状态异常，已注销该登录，请重新登录")
        else:
            revoke_family(row["family"], "refresh_reuse")
            record_login(row["username"], ip, user_agent, False, "refresh_reuse")
            raise AuthError("refresh_reuse",
                            "检测到刷新令牌被重复使用，已注销该会话的全部登录，请重新登录")

    if float(row["expires_at"]) < now:
        revoke_family(row["family"], "expired")
        raise AuthError("refresh_expired", "登录已过期，请重新登录")

    user = get_user(row["username"])
    if not user:
        revoke_family(row["family"], "user_gone")
        raise AuthError("invalid_refresh", "用户不存在，请重新登录")

    family = row["family"]
    csrf = row["csrf"] or secrets.token_urlsafe(24)
    refresh = secrets.token_urlsafe(48)
    # 一个 family 内只保留一个活跃 refresh：把该家族其余未撤销的全部收掉
    db.execute("UPDATE refresh_tokens SET revoked_at=?, revoke_reason='rotated' "
               "WHERE family=? AND revoked_at IS NULL", (now, family))
    _store_refresh(refresh, user["username"], family, csrf, ip, user_agent)
    _remember_rotation(old_hash, refresh)
    return {
        "access": _access_for(user, csrf),
        "refresh": refresh,
        "csrf": csrf,
        "family": family,
        "username": user["username"],
        "access_expires_in": ACCESS_TTL,
        # 轮换后只是换了同一 family 里的令牌串，会话到期时间仍然是原始那次登录的
        # 时刻 + REFRESH_TTL —— 否则每次刷新都续 7 天，会话就永远不过期了。
        "refresh_expires_in": max(1, int(float(row["expires_at"]) - now)),
    }


def verify_access(token: str | None) -> tuple[dict, dict]:
    """校验 access token，返回 (payload, user)。失败抛 AuthError。"""
    try:
        payload = jwt_util.decode(token or "", jwt_secret(), typ="access")
    except jwt_util.JWTError as exc:
        # 令牌过期是「正常事件」（前端会自动续期），单独给一个 code 便于区分
        code = "token_expired" if exc.code == "expired" else "invalid_token"
        raise AuthError(code, exc.message) from None

    user = get_user(str(payload.get("sub") or ""))
    if not user:
        raise AuthError("invalid_token", "用户不存在")
    if int(payload.get("tv") or 0) != _tv(user):
        raise AuthError("token_revoked", "登录状态已失效（密码已修改或被强制下线），请重新登录")
    return payload, user


# ---------------------------------------------------------------- 会话管理


def revoke_family(family: str, reason: str = "revoked") -> None:
    db.execute("UPDATE refresh_tokens SET revoked_at=?, revoke_reason=? "
               "WHERE family=? AND revoked_at IS NULL", (time.time(), reason, family))


def revoke_all(username: str, reason: str = "revoked") -> int:
    """踢掉该用户的全部会话（改密、强制下线）。"""
    cur = db.execute("UPDATE refresh_tokens SET revoked_at=?, revoke_reason=? "
                     "WHERE username=? AND revoked_at IS NULL", (time.time(), reason, username))
    return int(cur.rowcount or 0)


def logout_refresh(raw: str | None) -> str | None:
    """按 cookie 里的 refresh 令牌登出（撤销整个 family）。"""
    if not raw:
        return None
    row = db.query_one("SELECT * FROM refresh_tokens WHERE token_hash=?",
                       (hashlib.sha256(raw.encode()).hexdigest(),))
    if not row:
        return None
    revoke_family(row["family"], "logout")
    return row["username"]


def refresh_alive(raw: str | None) -> bool:
    """refresh 令牌是否仍然有效（未撤销、未过期）。

    用途：access token 过期但会话还活着时，访问首页不该被踢到登录页——
    前端拿到页面后会自动续期。否则用户每 30 分钟就被弹回登录页一次。
    """
    if not raw:
        return False
    row = db.query_one("SELECT revoked_at, expires_at FROM refresh_tokens WHERE token_hash=?",
                       (hashlib.sha256(raw.encode()).hexdigest(),))
    return bool(row and not row["revoked_at"] and float(row["expires_at"]) > time.time())


def list_sessions(username: str) -> list[dict]:
    """列出该用户当前活跃的登录会话（一个 family = 一条）。"""
    rows = db.query(
        "SELECT family, MIN(created_at) AS first_seen, MAX(created_at) AS last_seen, "
        "       MAX(ip) AS ip, MAX(user_agent) AS user_agent "
        "FROM refresh_tokens WHERE username=? AND revoked_at IS NULL AND expires_at>? "
        "GROUP BY family ORDER BY last_seen DESC",
        (username, time.time()),
    )
    return [{
        "id": r["family"],
        "first_seen": r["first_seen"],
        "last_seen": r["last_seen"],
        "ip": r["ip"] or "",
        "user_agent": r["user_agent"] or "",
    } for r in rows]


def revoke_session(username: str, family: str) -> bool:
    """踢掉指定会话（校验归属，避免越权踢别人的会话）。"""
    row = db.query_one("SELECT id FROM refresh_tokens WHERE family=? AND username=?",
                       (family, username))
    if not row:
        return False
    revoke_family(family, "kicked")
    return True


def purge_expired() -> None:
    """清理过期数据。留一天缓冲，让「过期后才被拿来用」也能被识别成复用。"""
    now = time.time()
    db.execute("DELETE FROM refresh_tokens WHERE expires_at < ?", (now - 86400,))
    db.execute("DELETE FROM login_events WHERE ts < ?", (now - LOGIN_EVENT_TTL,))


# ---------------------------------------------------------------- 登录


def authenticate(username: str, password: str, ip: str = "", user_agent: str = "") -> dict:
    """校验账号密码并建立会话。

    返回 `{"ok": True, "user": ..., **tokens}` 或
    `{"ok": False, "reason": ..., "message": ..., "retry_after": int}`。
    不抛异常——限流、密码错、账号不存在都走同一个返回值，便于路由层统一处理。
    """
    username = (username or "").strip()

    remain = lock_remaining(username, ip)
    if remain > 0:
        record_login(username, ip, user_agent, False, "locked")
        raise AuthError("locked", f"尝试次数过多，请 {remain} 秒后再试", retry_after=remain)

    user = get_user(username)
    # 用户名不存在与密码错误返回同样的文案，避免账号枚举
    if not user or not verify_password(password or "", user["password_hash"]):
        record_login(username, ip, user_agent, False, "bad_credentials")
        remain = lock_remaining(username, ip)
        msg = "用户名或密码错误"
        if remain > 0:
            msg = f"用户名或密码错误，尝试次数过多，请 {remain} 秒后再试"
        raise AuthError("bad_credentials", msg, retry_after=remain)

    tokens = new_session(user, ip, user_agent)
    record_login(username, ip, user_agent, True, "ok")
    return {"ok": True, "user": user, **tokens}


def change_password(username: str, old_password: str, new_password: str) -> dict:
    """改密：校验原密码 → 复杂度检查 → 更新 → 吊销其它会话并换发当前会话令牌。

    改完必须让旧令牌失效，否则「密码泄露后改密」这个最常见的补救动作形同虚设。
    但当前这台设备要留着登录状态（否则用户改完密码立刻被踢，体验很差），
    所以吊销全部 → 再给当前浏览器签一对新令牌。
    """
    user = get_user(username)
    if not user or not verify_password(old_password or "", user["password_hash"]):
        raise AuthError("bad_old_password", "原密码不正确")
    if verify_password(new_password or "", user["password_hash"]):
        raise AuthError("same_password", "新密码不能与原密码相同")
    weak = check_password_strength(new_password or "", username)
    if weak:
        raise AuthError("weak_password", weak)

    db.execute("UPDATE users SET password_hash=?, must_change_password=0 WHERE username=?",
               (hash_password(new_password), username))
    revoked = revoke_all(username, "password_changed")
    # 自增版本号：签发在改密之前的 access token 全部立即失效
    bump_token_version(username)
    fresh = get_user(username)
    return {"tokens": new_session(fresh, "", ""), "revoked_sessions": revoked}
