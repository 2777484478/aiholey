"""全局配置：路径、默认账号、引擎默认值。"""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
REPOS_DIR = DATA_DIR / "repos"
REPORTS_DIR = DATA_DIR / "reports"
LOGS_DIR = DATA_DIR / "logs"
WEBSCAN_DIR = DATA_DIR / "webscan"
DB_PATH = DATA_DIR / "aiholey.db"
FRONTEND_DIR = BASE_DIR / "frontend"

for _d in (DATA_DIR, REPOS_DIR, REPORTS_DIR, LOGS_DIR, WEBSCAN_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# ---- 服务 ----
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8787"))
MAX_CONCURRENT_RUNS = int(os.environ.get("MAX_CONCURRENT_RUNS", "1"))  # 同时执行的扫描数

# ---- 身份认证（JWT 双令牌）----
# access 是自包含 JWT，短有效期：即使被窃取，能利用的窗口也很小。
ACCESS_TTL = int(os.environ.get("AIHOLEY_ACCESS_TTL", str(30 * 60)))
# refresh 是随机串（库里存哈希、可吊销），长有效期：避免用户频繁重登。
REFRESH_TTL = int(os.environ.get("AIHOLEY_REFRESH_TTL", str(7 * 24 * 3600)))
# 部署到 https 后应置 1，让浏览器只在加密连接上发送 Cookie。
COOKIE_SECURE = os.environ.get("AIHOLEY_COOKIE_SECURE", "0").strip() in ("1", "true", "yes")

# 登录失败限流：同一账号/同一 IP 在窗口内失败达上限则锁定，挡住离线爆破
LOGIN_MAX_FAILS = int(os.environ.get("AIHOLEY_LOGIN_MAX_FAILS", "5"))
LOGIN_FAIL_WINDOW = int(os.environ.get("AIHOLEY_LOGIN_FAIL_WINDOW", "300"))
LOGIN_LOCK_SECONDS = int(os.environ.get("AIHOLEY_LOGIN_LOCK_SECONDS", "300"))

MIN_PASSWORD_LEN = 8

# ---- 默认账号（首次初始化时创建）----
DEFAULT_USER = os.environ.get("AIHOLEY_USER", "admin")
DEFAULT_PASSWORD = os.environ.get("AIHOLEY_PASSWORD", "admin123")

# ---- 扫描范围 ----
CODE_EXTS = {
    ".java", ".kt", ".scala", ".jsp", ".js", ".jsx", ".ts", ".tsx", ".vue",
    ".py", ".go", ".rb", ".php", ".cs", ".c", ".cc", ".cpp", ".h", ".hpp",
    ".xml", ".yml", ".yaml", ".properties", ".toml", ".ini", ".conf",
    ".sql", ".sh", ".env", ".json", ".gradle", ".pom",
}
IGNORE_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "vendor", "dist", "build",
    "target", "out", ".idea", ".vscode", "__pycache__", ".venv", "venv",
    ".next", ".nuxt", "coverage", ".gradle", ".mvn", "logs", "test", "tests",
}
MAX_FILE_BYTES = 400_000
MAX_FILES = 3000

# ---- 扫描深度：控制 AI 分析强度 ----
DEPTHS = {
    "quick":    {"label": "Quick (快速审计)",    "chunk_chars": 6000,  "max_chunks": 8,   "max_files": 400},
    "standard": {"label": "Standard (标准审计)", "chunk_chars": 9000,  "max_chunks": 30,  "max_files": 1500},
    "deep":     {"label": "Deep (深度审计)",     "chunk_chars": 12000, "max_chunks": 80,  "max_files": 3000},
}

# ---- Web 漏扫深度：控制探测强度、步数预算与请求节流 ----
WEB_DEPTHS = {
    # 逐端口扫描模式下，每个 HTTP 端点都会跑一整条检测链（含备份泄漏、参数探测、
    # 目录遍历、文件包含、XSS、CSRF、凭据扫描、组件比对、API 审计等约 20 项），
    # 因此请求预算按「端点数 × 单端点约 900 次」量级给足。
    # 预算给紧的代价不是"跑得慢"，而是**后面的检查项静默跑不到**——
    # 报告里没有对应条目，看起来像"检查过了没问题"。
    # 端口扫描是 TCP connect，不计入 HTTP 请求预算。
    "quick":    {"label": "Quick (常见端口 · 单端点)",        "steps": 8,  "max_requests": 1400,  "delay": 0.03, "timeout": 8.0,
                 "ports": "common", "endpoints": 1},
    "standard": {"label": "Standard (全端口 · 最多 4 端点)",   "steps": 14, "max_requests": 5000,  "delay": 0.02, "timeout": 10.0,
                 "ports": "full",   "endpoints": 4},
    "deep":     {"label": "Deep (全端口 · 最多 8 端点)",       "steps": 24, "max_requests": 14000, "delay": 0.0,  "timeout": 12.0,
                 "ports": "full",   "endpoints": 8},
}

# ---- 引擎默认配置（可被 settings 表覆盖）----
ENGINE_DEFAULTS = {
    "codex": {
        "label": "Codex",
        "api_key": os.environ.get("DASHSCOPE_API_KEY", ""),
        "model": os.environ.get("AIHOLEY_MODEL", "qwen-plus"),
        "base_url": os.environ.get("AIHOLEY_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1"),
    },
    "claude": {
        "label": "Claude Code",
        "api_key": "",
        "model": "claude-sonnet-4-5",
        "base_url": "https://api.anthropic.com/v1",
    },
}
DEFAULT_ENGINE = "codex"

SEVERITIES = ["critical", "high", "medium", "low"]
SEVERITY_LABELS = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危"}
