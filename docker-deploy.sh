#!/bin/bash
# ---------------------------------------------------------------------------
# Aiholey 一键 Docker 部署（本机 Mac）
#
#   ./docker-deploy.sh            构建镜像 + 迁移数据 + 启动容器
#   ./docker-deploy.sh --rebuild  强制不使用缓存重新构建
#
# 做了什么：
#   1. 停掉宿主机上跑着的本地实例（避免抢 8787 端口）
#   2. 摘掉代理变量后构建镜像（本机 buildkit 走代理会 502，实测结论）
#   3. 首次部署时把现有数据（db / 报告 / 扫描记录）迁移进 docker-data/
#   4. docker compose 启动并做健康检查
# ---------------------------------------------------------------------------
set -euo pipefail
cd "$(dirname "$0")"

BUILD_FLAG=""
[ "${1:-}" = "--rebuild" ] && BUILD_FLAG="--no-cache"

echo "==> 1/4 停掉宿主机本地实例"
if [ -x ./stop.sh ]; then
  ./stop.sh >/dev/null 2>&1 && echo "    本地实例已停止" || echo "    本地实例本就没在跑"
fi

echo "==> 2/4 构建镜像（已摘掉代理变量，走国内镜像站基镜像）"
# 本机关键经验：buildkit 元数据解析走 http.docker.internal:3128 会 Bad Gateway，
# 直连 Docker Hub 又不通 —— daocloud 基镜像 + 摘代理变量是实测能跑通的路径。
env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy \
  docker build ${BUILD_FLAG} -t aiholey:latest .

echo "==> 3/4 迁移数据到 docker-data/（无旧数据则跳过）"
if [ -f docker-data/aiholey.db ]; then
  echo "    docker-data/aiholey.db 已存在，跳过（不会覆盖现有数据）"
elif [ ! -f data/aiholey.db ]; then
  mkdir -p docker-data
  echo "    未检测到旧数据（全新部署），容器启动时会自动初始化空库"
else
  mkdir -p docker-data
  # SQLite 在线备份：WAL 里可能还有未落盘的页，用 backup API 拿到的才是一致的
  # 完整库，直接 cp 文件有风险。Python 优先用项目 venv，没有就用系统 python3。
  PYBIN=".venv/bin/python"; [ -x "$PYBIN" ] || PYBIN="python3"
  "$PYBIN" - <<'PY'
import sqlite3
src = sqlite3.connect("data/aiholey.db")
dst = sqlite3.connect("docker-data/aiholey.db")
src.backup(dst)
dst.close(); src.close()
print("    aiholey.db 已通过 backup API 迁移")
PY
  # 报告与扫描产物是纯文件，直接拷
  [ -d data/reports ] && cp -R data/reports docker-data/reports && echo "    reports/ 已迁移"
  [ -d data/webscan ] && cp -R data/webscan docker-data/webscan && echo "    webscan/ 已迁移"
  # JWT 密钥带上，迁移后已登录的会话不会全部失效
  [ -f data/.jwt_secret ] && cp data/.jwt_secret docker-data/.jwt_secret && echo "    .jwt_secret 已迁移"
  # 仓库克隆体积大且可重新拉取，不迁移——容器里首次审计会自动 clone
fi

echo "==> 4/4 启动容器"
env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy \
  docker compose up -d

echo "    等待健康检查通过…"
for i in $(seq 1 20); do
  code=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8787/api/health 2>/dev/null || echo 000)
  if [ "$code" = "200" ]; then
    echo ""
    echo "✅ 部署完成：http://127.0.0.1:8787  (admin / admin123，数据在 ./docker-data/)"
    echo "   常用命令：docker logs -f aiholey | docker compose restart | docker compose down"
    exit 0
  fi
  sleep 1
done
echo "⚠️  健康检查 20 秒内未通过，请查看日志：docker logs aiholey" >&2
exit 1
