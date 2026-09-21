#!/bin/sh
# 容器入口：修正数据目录属主后降权运行。
#
# 为什么需要这个脚本：
#   docker-compose 把宿主机 ./docker-data 挂载到 /app/data。Linux 的 bind mount
#   保留宿主机 uid/gid——宿主机上用 root 跑部署脚本时，docker-data/ 是 root:root，
#   容器内非 root 用户（aiholey）写不进去，启动即崩：
#   PermissionError: [Errno 13] Permission denied: '/app/data/repos'
#   （macOS Docker Desktop 的挂载经 virtiofs 转发，权限被抹平，所以 Mac 上测不出。）
#
# 做法：容器以 root 起入口，先把数据目录属主修正为应用用户，再降权 exec。
# 进程本身仍以非 root 运行，安全性不变。
set -e

if [ -d /app/data ]; then
    chown -R aiholey:aiholey /app/data
fi

# runuser 来自 util-linux（Debian 里 Priority: required，slim 镜像自带）。
# 与 su 不同，它只对 root 可用、不开 PAM 会话，适合脚本降权。
exec runuser -u aiholey -- "$@"
