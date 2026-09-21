# 注意：不要加 `# syntax=docker/dockerfile:1` —— 它会让 buildkit 去 docker.io
# 拉前端镜像，本机网络拉不动；本文件没用到任何需要新版前端解析的语法。
# ---------------------------------------------------------------------------
# Aiholey · AI 代码审计平台 —— 一体化镜像
#
# 本机网络环境（GitHub/Docker Hub 受限）下的两条关键决策，别随手改：
#   1. 基镜像走国内镜像站（docker.m.daocloud.io）。Docker Hub 直连与经
#      http.docker.internal:3128 中转的 buildkit 元数据解析在本机都会失败，
#      镜像站基镜像 + 构建时摘掉代理变量是实测能跑通的路径。
#      换到有外网的环境时：docker build --build-arg BASE_IMAGE=python:3.13-slim
#   2. pip 用阿里云源（pypi.org 直连慢且不稳）。换环境可用
#      --build-arg PIP_INDEX_URL=https://pypi.org/simple 覆盖。
# ---------------------------------------------------------------------------

ARG BASE_IMAGE=docker.m.daocloud.io/library/python:3.13-slim
FROM ${BASE_IMAGE}

# git：审计功能通过 `git clone` 拉取仓库（backend/core/gitops.py 用子命令实现），
# slim 镜像不带，必须显式装；openssh-client 支持 SSH 协议的仓库地址。
# apt 源走容器默认的 debian 源（实测容器网络可达）。
RUN apt-get update \
    && apt-get install -y --no-install-recommends git openssh-client \
    && rm -rf /var/lib/apt/lists/*

ARG PIP_INDEX_URL=https://mirrors.aliyun.com/pypi/simple/

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    TZ=Asia/Shanghai \
    HOST=0.0.0.0 \
    PORT=8787

WORKDIR /app

# 先装依赖再拷代码：依赖层不随业务代码变动，构建缓存命中率高
COPY requirements.txt ./
RUN pip install -i ${PIP_INDEX_URL} -r requirements.txt

COPY backend ./backend
COPY frontend ./frontend
COPY start.sh stop.sh docker-entrypoint.sh ./

# 数据目录（SQLite / 报告 / 仓库克隆 / JWT 密钥）——运行时挂载卷持久化，
# 镜像里只放占位。jwt_secret 首次启动自动生成在 data/.jwt_secret。
RUN mkdir -p /app/data

# 非 root 应用用户。注意：不设 USER 指令——容器以 root 起入口脚本，
# 由 docker-entrypoint.sh 修正挂载卷属主后用 runuser 降权到 aiholey 运行。
# （Linux 宿主机 bind mount 保留宿主机属主，直接 USER aiholey 会写不进卷）
RUN groupadd -r aiholey && useradd -r -g aiholey -d /app aiholey \
    && chown -R aiholey:aiholey /app \
    && chmod +x docker-entrypoint.sh

EXPOSE 8787

# slim 镜像没有 curl，用 python 做健康检查
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request,sys;sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8787/api/health',timeout=4).status==200 else 1)"

ENTRYPOINT ["./docker-entrypoint.sh"]

# --no-server-header：关掉 uvicorn 自带的 Server 头（中间件已统一覆写为 aiholey）
CMD ["python", "-m", "uvicorn", "backend.main:app", \
     "--host", "0.0.0.0", "--port", "8787", \
     "--log-level", "info", "--no-server-header"]
