#!/usr/bin/env bash
# Aiholey 停止脚本：按端口定位 + 工作目录校验归属，绝不误杀
# 用法: ./stop.sh [--force]
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT="${PORT:-8787}"
FORCE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --force) FORCE=1; shift ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
done

pids_on_port() {
  lsof -nP -iTCP:"${PORT}" -sTCP:LISTEN -t 2>/dev/null | sort -u
}

owns_project() {
  local pid="$1" cwd
  cwd="$(lsof -p "${pid}" -a -d cwd -Fn 2>/dev/null | awk '/^n/{print substr($0,2); exit}')"
  [ -n "${cwd}" ] && [ "${cwd}" = "${PROJECT_DIR}" ] && return 0
  lsof -p "${pid}" 2>/dev/null | grep -qF "${PROJECT_DIR}" && return 0
  return 1
}

descendants_of() {
  local pid="$1" kid
  for kid in $(pgrep -P "${pid}" 2>/dev/null || true); do
    echo "${kid}"
    descendants_of "${kid}"
  done
}

TARGETS="$(pids_on_port || true)"

if [ -z "${TARGETS}" ]; then
  echo "· 端口 ${PORT} 无监听进程，服务本来就是停止的。"
  rm -f "${PROJECT_DIR}/data/server.pid"
  exit 0
fi

OWNED=""
FOREIGN=""
for pid in ${TARGETS}; do
  if owns_project "${pid}"; then OWNED="${OWNED} ${pid}"; else FOREIGN="${FOREIGN} ${pid}"; fi
done

if [ -n "${FOREIGN}" ]; then
  echo "!! 端口 ${PORT} 上的进程不属于本项目（PID:${FOREIGN}），已跳过。" >&2
  echo "   确认要强制终止请加 --force" >&2
  if [ "${FORCE}" -ne 1 ]; then
    [ -n "${OWNED}" ] || exit 1
  fi
fi

if [ "${FORCE}" -eq 1 ]; then
  OWNED="${TARGETS}"
fi

[ -n "${OWNED}" ] || exit 1

# ⚠️ 必须在 kill 之前采集后代，否则父进程退出后无法追溯
DESCENDANTS=""
for pid in ${OWNED}; do
  DESCENDANTS="${DESCENDANTS} $(descendants_of "${pid}")"
done
DESCENDANTS="$(echo "${DESCENDANTS}" | tr -s ' \n' '\n' | awk 'NF' | sort -u | tr '\n' ' ' || true)"

echo "· 正在停止 PID:$(echo "${OWNED}" | tr -s ' \n' ' \n' | tr '\n' ' ')"
kill -TERM ${OWNED} 2>/dev/null || true

for _ in $(seq 1 25); do
  [ -z "$(pids_on_port || true)" ] && break
  sleep 0.2
done

REMAIN="$(pids_on_port || true)"
if [ -n "${REMAIN}" ]; then
  echo "· 优雅退出超时，强制终止"
  kill -9 ${REMAIN} 2>/dev/null || true
  sleep 0.5
fi

for pid in ${DESCENDANTS}; do
  kill -0 "${pid}" 2>/dev/null && kill -9 "${pid}" 2>/dev/null || true
done

rm -f "${PROJECT_DIR}/data/server.pid"

if [ -z "$(pids_on_port || true)" ]; then
  echo "✅ 已停止，端口 ${PORT} 已释放。"
  exit 0
fi

echo "!! 端口 ${PORT} 仍被占用，请手动检查。" >&2
exit 1
