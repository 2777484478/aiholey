"""JWT（HS256）签发与校验 —— 只用标准库，不引 PyJWT。

为什么自己写：本项目坚持零第三方依赖（离线可用是硬要求，`requirements.txt` 只有
fastapi/uvicorn/httpx/pydantic/dotenv）。HS256 的签名部分本身就是标准库的
`hmac` + `hashlib.sha256`，**真正容易写出漏洞的是校验逻辑**，所以这里逐条做死：

1. **固定算法**：永远用 HS256 重算签名，**绝不根据 header 里的 `alg` 去选算法**
   —— 这是 `alg: none` 和 RS256→HS256 算法混淆攻击的根源。header 里的 `alg`
   只用来做"是不是 HS256"的检查，不参与算法选择。
2. **常量时间比较签名**：`hmac.compare_digest`，避免时序侧信道。
3. **严格校验声明**：`exp` 必须存在且未过期、`nbf` 未到不认、`iss`/`aud`/`typ`
   全部强制匹配，防止"用别的用途签出来的 token"被拿来当访问令牌。
4. **严格解析**：base64url 字符集先过正则（Python 的 `b64decode` 默认会静默丢弃
   非法字符，会让畸形 token 蒙混过关），签名长度必须是 32 字节。

⚠️ 这不是通用 JWT 库：只支持 HS256 + JSON payload。若将来需要 RS256/ES256 或
JWK 发现，应当换成 PyJWT 或 authlib，而不是在这里加分支。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time

ALG = "HS256"
ISSUER = "aiholey"
AUDIENCE = "aiholey-web"

# 允许的时钟偏移（秒）：客户端与服务端时间不可能完全一致
LEEWAY = 5

_B64_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_HMAC_LEN = hashlib.sha256().digest_size  # 32


class JWTError(Exception):
    """JWT 校验失败。`code` 是机器可读原因，`message` 是给人看的说明。"""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(seg: str) -> bytes:
    if not seg or not _B64_RE.match(seg):
        raise ValueError("非法 base64url 字符")
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _dump(obj: dict) -> str:
    # 固定分隔符，保证签名可复现（不要依赖默认的 ", " / ": " 空格）
    return _b64e(json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def new_jti() -> str:
    return secrets.token_urlsafe(12)


def encode(payload: dict, secret: str, ttl: int | None = None, typ: str = "access") -> str:
    """签发一个 HS256 JWT。

    ttl 为 None 时**不写 exp**——只用于测试构造"永不过期"的 token，
    业务代码一律要传 ttl（校验侧也要求 exp 必须存在）。
    """
    now = int(time.time())
    body = dict(payload)
    body["iss"] = ISSUER
    body["aud"] = AUDIENCE
    body["typ"] = typ
    body["iat"] = now
    body["nbf"] = now
    body.setdefault("jti", new_jti())
    if ttl is not None:
        body["exp"] = now + int(ttl)
    header = {"alg": ALG, "typ": "JWT"}
    signing_input = f"{_dump(header)}.{_dump(body)}"
    sig = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{_b64e(sig)}"


def sign_raw(signing_input: str, secret: str) -> str:
    """给任意 `header.payload` 签名——测试专用（伪造篡改 token 时用）。"""
    sig = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    return _b64e(sig)


def decode(token: str, secret: str, typ: str = "access", leeway: int = LEEWAY) -> dict:
    """校验并解析 JWT，失败抛 `JWTError`。"""
    if not isinstance(token, str) or not token.strip():
        raise JWTError("malformed", "缺少令牌")
    parts = token.split(".")
    if len(parts) != 3:
        raise JWTError("malformed", "令牌结构不正确")
    h_b64, p_b64, s_b64 = parts

    try:
        header = json.loads(_b64d(h_b64))
        payload = json.loads(_b64d(p_b64))
        sig = _b64d(s_b64)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        raise JWTError("malformed", "令牌编码无法解析") from None

    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise JWTError("malformed", "令牌结构不正确")

    # ① 算法白名单：只看不选。即使 header 写 alg=none 也照样按 HS256 重算签名，
    #    没有密钥就不可能对上，天然免疫 alg 混淆攻击。
    if str(header.get("alg", "")).strip().upper() != ALG:
        raise JWTError("bad_alg", "不支持的签名算法")

    # ② 先验签名，再信 payload 里的任何字段
    expected = hmac.new(
        secret.encode("utf-8"), f"{h_b64}.{p_b64}".encode("ascii"), hashlib.sha256
    ).digest()
    if len(sig) != _HMAC_LEN or not hmac.compare_digest(expected, sig):
        raise JWTError("bad_signature", "令牌签名校验失败")

    now = int(time.time())

    exp = payload.get("exp")
    if not isinstance(exp, (int, float)):
        raise JWTError("invalid", "令牌缺少有效期")
    if now > exp + leeway:
        raise JWTError("expired", "令牌已过期")

    nbf = payload.get("nbf")
    if isinstance(nbf, (int, float)) and nbf > now + leeway:
        raise JWTError("invalid", "令牌尚未生效")

    if payload.get("iss") != ISSUER:
        raise JWTError("invalid", "签发者不匹配")
    if payload.get("aud") != AUDIENCE:
        raise JWTError("invalid", "受众不匹配")
    if payload.get("typ") != typ:
        raise JWTError("wrong_type", "令牌类型不匹配")

    return payload
