#!/usr/bin/env bash
# Aiholey 启动脚本（macOS / Linux）
# 用法: ./start.sh [--wait 30]
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT="${PORT:-8787}"
HOST="${HOST:-127.0.0.1}"
VENV="${PROJECT_DIR}/.venv"
LOG_DIR="${PROJECT_DIR}/data"
OUT_LOG="${LOG_DIR}/server.log"
INDEX_URL="${PIP_INDEX_URL:-https://pypi.tuna.tsinghua.edu.cn/simple}"

WAIT="${WAIT:-30}"
while [ $# -gt 0 ]; do
  case "$1" in
    --wait) WAIT="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
done

pids_on_port() {
  lsof -nP -iTCP:"${PORT}" -sTCP:LISTEN -t 2>/dev/null | sort -u
}

python_ok() {
  "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1
}

find_python() {
  local cand
  for cand in "${PYTHON:-}" python3.13 python3.12 python3.11 python3.10 python3 python; do
    [ -n "${cand}" ] || continue
    if command -v "${cand}" >/dev/null 2>&1 && python_ok "$(command -v "${cand}")"; then
      command -v "${cand}"; return 0
    fi
  done
  for cand in /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3; do
    [ -x "${cand}" ] && python_ok "${cand}" && { echo "${cand}"; return 0; }
  done
  return 1
}

mkdir -p "${LOG_DIR}"

# ---------- 0. 已在运行则拒绝重复启动 ----------
RUNNING="$(pids_on_port || true)"
if [ -n "${RUNNING}" ]; then
  echo "!! 端口 ${PORT} 已被占用（PID: ${RUNNING}），服务可能已在运行。" >&2
  echo "   如需重启：./stop.sh && ./start.sh" >&2
  exit 1
fi

# ---------- 1. 已有虚拟环境优先（不依赖 PATH 里的 python3） ----------
if [ -e "${VENV}" ] && ! "${VENV}/bin/python" -c "import sys" >/dev/null 2>&1; then
  mv "${VENV}" "${VENV}.broken.$(date +%Y%m%d%H%M%S)"
  echo "· 检测到不可用的虚拟环境，已重命名备份"
fi
if [ -x "${VENV}/bin/python" ] && ! python_ok "${VENV}/bin/python"; then
  mv "${VENV}" "${VENV}.old.$(date +%Y%m%d%H%M%S)"
  echo "· 虚拟环境 Python 版本过低，已重命名备份"
fi

# ---------- 2. 需要时才创建环境并装依赖 ----------
if [ ! -x "${VENV}/bin/python" ]; then
  PY="$(find_python)" || {
    echo "!! 找不到 Python 3.10+。" >&2
    echo "   请用 PYTHON=/path/to/python3.11 ./start.sh 指定解释器" >&2
    exit 1
  }
  echo "· 使用解释器 ${PY} 创建虚拟环境"
  "${PY}" -m venv "${VENV}"
  NEED_INSTALL=1
else
  NEED_INSTALL=0
  "${VENV}/bin/python" -c "import fastapi, uvicorn, httpx" >/dev/null 2>&1 || NEED_INSTALL=1
fi

if [ "${NEED_INSTALL}" = "1" ]; then
  echo "· 安装依赖（镜像: ${INDEX_URL}）"
  if command -v uv >/dev/null 2>&1; then
    uv pip install -r "${PROJECT_DIR}/requirements.txt" \
      --python "${VENV}/bin/python" --index-url "${INDEX_URL}"
  else
    "${VENV}/bin/pip" install -q --upgrade pip
    "${VENV}/bin/pip" install -r "${PROJECT_DIR}/requirements.txt" -i "${INDEX_URL}"
  fi
fi

# ---------- 3. double-fork + setsid 脱离终端 ----------
if [ ! -f "${PROJECT_DIR}/.env" ] && [ -f "${PROJECT_DIR}/.env.example" ]; then
  cp "${PROJECT_DIR}/.env.example" "${PROJECT_DIR}/.env"
  echo "· 已从 .env.example 生成 .env（可填入大模型 API Key）"
fi

echo "· 启动服务 http://${HOST}:${PORT}"
cd "${PROJECT_DIR}"
"${VENV}/bin/python" - "${VENV}/bin/python" "${OUT_LOG}" "${HOST}" "${PORT}" <<'PYDAEMON'
import os, sys
exe, log, host, port = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

if os.fork() > 0:
    os._exit(0)
os.setsid()
if os.fork() > 0:
    os._exit(0)

fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
os.dup2(fd, 1)
os.dup2(fd, 2)
os.dup2(os.open(os.devnull, os.O_RDONLY), 0)
# --no-server-header：uvicorn 默认会加 `Server: uvicorn`，泄露实现与版本。
# 关掉它，由应用中间件统一设 `Server: aiholey`（不去重的话会出现两个 Server 头）。
os.execv(exe, [exe, "-m", "uvicorn", "backend.main:app",
               "--host", host, "--port", port, "--log-level", "info",
               "--no-server-header"])
PYDAEMON

# ---------- 4. 验证端口就绪 ----------
READY=0
i=0
while [ "${i}" -lt $((WAIT * 5)) ]; do
  if [ -n "$(pids_on_port || true)" ]; then READY=1; break; fi
  sleep 0.2
  i=$((i + 1))
done

if [ "${READY}" -ne 1 ]; then
  echo "!! 启动失败：${WAIT} 秒内端口 ${PORT} 未就绪。" >&2
  echo "---- 日志末尾 ----" >&2
  tail -25 "${OUT_LOG}" >&2 || true
  echo "------------------" >&2
  exit 1
fi

printf '%s' "$(pids_on_port | head -1)" > "${LOG_DIR}/server.pid"

CODE="$(curl -s -o /dev/null -w '%{http_code}' "http://${HOST}:${PORT}/api/health" || echo 000)"
echo "✅ 服务已就绪  http://${HOST}:${PORT}   (健康检查 ${CODE})"
echo "   登录: 默认账号 admin / admin123（登录后建议修改密码）"
echo "   日志: ${OUT_LOG}"
echo "   停止: ./stop.sh"

if grep -q "sandbox_apply: Operation not permitted" "${OUT_LOG}" 2>/dev/null; then
  echo "!! 检测到沙箱限制：请在本地终端重新执行 ./start.sh" >&2
fi
