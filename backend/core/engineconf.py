"""引擎配置读写（存 settings 表，回落到 config 默认值）。"""
from __future__ import annotations

from backend.config import DEFAULT_ENGINE, ENGINE_DEFAULTS
from backend.core import db
from backend.core.llm import LLMClient


def get_engine(name: str) -> dict:
    base = dict(ENGINE_DEFAULTS.get(name, ENGINE_DEFAULTS["codex"]))
    for k in ("api_key", "model", "base_url"):
        v = db.get_setting(f"engine.{name}.{k}", "")
        if v:
            base[k] = v
    base["name"] = name
    return base


def set_engine(name: str, api_key: str | None = None, model: str | None = None,
               base_url: str | None = None) -> dict:
    if api_key is not None:
        db.set_setting(f"engine.{name}.api_key", api_key)
    if model is not None:
        db.set_setting(f"engine.{name}.model", model)
    if base_url is not None:
        db.set_setting(f"engine.{name}.base_url", base_url)
    return get_engine(name)


def default_engine() -> str:
    return db.get_setting("engine.default", DEFAULT_ENGINE)


def set_default_engine(name: str) -> None:
    db.set_setting("engine.default", name)


def client_for(name: str) -> LLMClient | None:
    """按引擎名构造 LLM 客户端；未配置 API Key 时返回 None（此时退回纯规则扫描）。"""
    cfg = get_engine(name)
    if not cfg.get("api_key"):
        return None
    return LLMClient(cfg["base_url"], cfg["api_key"], cfg["model"])


def masked(name: str) -> dict:
    cfg = get_engine(name)
    key = cfg.get("api_key") or ""
    cfg["api_key_masked"] = (key[:8] + "***" + key[-4:]) if len(key) > 14 else ("***" if key else "")
    cfg["configured"] = bool(key)
    return cfg
