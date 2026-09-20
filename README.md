# Aiholey · AI 代码审计平台

自托管的一体化安全审计平台：**Git 仓库代码审计 + Web 漏洞扫描**，规则引擎打底、
大模型（OpenAI 兼容接口）做语义增强与自主渗透规划。全部数据存在本地 SQLite，
一个 Docker 容器即可跑起来。

- **代码审计**：克隆仓库 → 规则预筛 → AI 项目适配 → 按技能维度分析 → 去重分级 →
  产出 HTML / Markdown / JSON 报告；支持定时调度（间隔 / cron / 单次）
- **Web 漏洞扫描**：先扫全端口再逐端口深扫——HTTP 端点走完整 Web 检测链
  （AI 自主规划渗透流程），数据/管理端口走未授权访问检测；独立于审计队列，点完即等结果
- **不配置 API Key 也能用**：自动降级为纯内置规则扫描，照样产出完整报告

技术栈：FastAPI + SQLite + 零依赖原生前端（无 Node 构建），Python 3.10+。

---

## 一、环境要求

### Docker 部署（推荐）

| 依赖 | 版本要求 |
|---|---|
| Docker Engine | **≥ 20.10**（需含 BuildKit，`docker build` 默认走 BuildKit） |
| Docker Compose | **v2**（`docker compose` 子命令；Docker Desktop 自带，Linux 装 `docker-compose-plugin`） |
| Docker Desktop（Mac/Windows） | ≥ 4.0，Apple Silicon（arm64）与 Intel（amd64）均可 |
| Linux 发行版 | 任意能跑上述 Docker 版本的发行版（Ubuntu 20.04+ / Debian 11+ / CentOS 7+ 等实测均可） |
| 架构 | `linux/amd64`、`linux/arm64`（基础镜像 `python:3.13-slim` 双架构） |
| 资源 | 内存 ≥ 512MB，磁盘 ≥ 1GB（镜像约 260MB + 数据） |

### 本地开发（不用 Docker）

- Python **≥ 3.10**、Git ≥ 2.20（审计功能依赖 `git clone` 子命令）

---

## 二、Docker 一键部署

```bash
git clone https://github.com/2777484478/aiholey.git
cd aiholey
./docker-deploy.sh
```

脚本自动完成四件事：

```
1. 停掉宿主机上可能存在的本地实例（避免抢 8787 端口）
2. 构建镜像 aiholey:latest（约 260MB）
3. 若检测到旧版部署的 data/ 目录，自动把数据迁移到 docker-data/（全新部署则跳过）
4. docker compose 启动容器并等待健康检查通过
```

完成后打开 **http://127.0.0.1:8787** → 默认账号 **admin / admin123**
（登录后请立即到「系统与账户」修改密码）。

### 常用命令

```bash
docker logs -f aiholey          # 看日志
docker compose restart          # 重启
docker compose down             # 停止并删除容器（数据保留在 ./docker-data/）
./docker-deploy.sh --rebuild    # 代码更新后强制无缓存重建并重新部署
```

### 数据与持久化

所有运行时数据都在 **`./docker-data/`**（SQLite 数据库、审计报告、扫描产物、JWT 密钥），
容器删了数据也在。**备份 = 拷贝这一个目录**。

### 自定义

```bash
# 换端口（例：9000）：编辑 docker-compose.yml 的 ports，或
docker run -d --name aiholey -p 9000:8787 -v "$PWD/docker-data:/app/data" \
  --restart unless-stopped aiholey:latest

# 首次初始化的管理员账号（仅空库初始化时生效）
docker run -d ... -e AIHOLEY_USER=myadmin -e AIHOLEY_PASSWORD='强密码' aiholey:latest

# 有外网的环境可覆盖基镜像与 pip 源
BASE_IMAGE=python:3.13-slim PIP_INDEX_URL=https://pypi.org/simple docker compose build
```

### 网络受限环境说明

Dockerfile 默认使用国内镜像站基镜像（`docker.m.daocloud.io`）+ 阿里云 pip 源，
**Docker Hub 不可达的网络也能直接构建**；两个值都是 `ARG`，可用上面的方式覆盖。

---

## 三、本地开发

```bash
./start.sh          # 首次自动建虚拟环境并装依赖（走国内镜像）
./stop.sh           # 停止
PORT=9000 ./start.sh
```

---

## 四、AI 引擎配置（可选）

不配置也能跑（纯规则扫描）。要启用 AI 语义分析与自主渗透规划，到界面
「模型设置」填入任意 **OpenAI 兼容接口**（阿里云百炼 / OpenAI / DeepSeek / 本地 vLLM）：

- Base URL：如 `https://dashscope.aliyuncs.com/compatible-mode/v1`
- API Key + 模型名（如 `qwen-plus`）

也可复制 `.env.example` 为 `.env` 预填（本地开发模式生效；Docker 模式在
`docker-compose.yml` 的 `environment` 里加同名变量）。

---

## 五、功能模块

| 菜单 | 能力 |
|---|---|
| **仪表盘** | 漏洞等级统计卡、近 7 天趋势、等级/分类分布、仓库风险排名、最近完成的审计 |
| **仓库管理** | Git 仓库配置（地址/分支/账密 Token/SSH Key），批量添加、批量测试连接、手动拉取 |
| **审计任务** | 绑定仓库 + 深度 + 引擎 + 调度（手动 / 定时间隔 / cron / 单次）；运行、停止、日志、删除（确认弹窗） |
| **审计报告** | 漏洞统计、按技能统计；查看详情、下载 HTML（可打印 PDF）/ Markdown / JSON、复扫、单条与批量删除、批量导出整合报告 |
| **执行引擎** | 扫描子进程实时监控（PID / 时长 / 进度 / 工作目录），可终止，3 秒自动刷新 |
| **技能库** | 29 项内置审计技能，增删改查、启停、恢复出厂提示词；支持 `${scanPath}` 等占位符 |
| **快速扫描** | 不建任务，直接扫服务器任意目录（内建目录浏览器）或已拉取仓库 |
| **Web 漏洞扫描** | 端口发现 → 服务识别 → 按端口分派检测链；27 项只读探测（XSS / SQLi / 目录遍历 / CSRF / CRLF / 组件 CVE / 凭据泄露 / API 审计 / WAF 识别 / TLS 弱配置…）；AI 自主规划；quick/standard/deep 三档 |
| **模型设置** | 双引擎（Codex / Claude Code）的 Key / 模型 / Base URL 配置与连接测试 |
| **系统与账户** | 修改密码、登录安全（活跃会话列表、踢出设备、一键退出其它设备）、系统信息 |

### 代码审计链路

```
① 拉取代码   git clone/fetch 到 data/repos/<id>（凭据/SSH Key 注入，日志脱敏）
② 收集文件   按扩展名与忽略目录筛选，执行 gitignore 与体积上限
③ 规则预筛   22 条内置正则（凭证泄漏/SQL 注入/命令注入/反序列化/路径穿越…）
④ 项目适配   AI 识别技术栈，产出审计增强规则与项目特有模式（无 Key 时跳过）
⑤ 技能分析   按启用技能逐块分析，产出结构化 JSON
⑥ 去重分级   同文件同行合并（AI 优先于规则），按等级排序统计
⑦ 生成报告   Markdown + JSON + 可打印单文件 HTML
```

### Web 漏洞扫描链路

```
① 目标确认   归一化输入，逐个探测可达性
② 端口发现   quick 常见端口 / standard+ 全 65535（asyncio 并发，全端口约 3 秒）+ 服务识别
③ 按端口分派 HTTP → 完整 Web 检测链；Redis/ES/Docker/MySQL… → 未授权只读检测
④ 内容发现   目录遍历、敏感文件、备份泄漏、信息泄漏
⑤ 安全配置   安全响应头、Cookie 属性、CORS、危险方法、开放重定向
⑥ 参数注入   反射 XSS、错误型 SQLi、路径穿越、模板注入、命令注入回显
⑦ AI 研判    每轮把总纲+技能+工具清单+已有结果交给模型，模型决定下一步
⑧ 补齐去重   AI 步数耗尽时自动补跑未覆盖的确定性检查，避免整类漏报
⑨ 生成报告   report.md / report.html / findings.json
```

---

## 六、安全机制

- **JWT 双令牌认证**：access（HS256，30 分钟）+ refresh（随机串哈希入库，7 天，
  Cookie path 限定 `/api/auth`）；固定算法校验免疫 `alg:none` 与算法混淆
- **即时吊销**：`token_version` 自增使全部已签发令牌当场失效；refresh 轮换 +
  复用检测（旧令牌复用 → 吊销整个会话家族）
- **CSRF 三重校验**：double-submit cookie + 请求头 + JWT 内签名声明比对；
  跨站 `Origin` 直接 403
- **登录防爆破**：失败计数限流 + 临时锁定，且不枚举账号是否存在
- **安全响应头**：CSP（报告页单独收紧到 `default-src 'none'`，打印脚本走 sha256 白名单）、
  `X-Frame-Options: DENY`、`nosniff`、接口禁缓存；报告模板全字段转义防存储型 XSS
- **容器安全**：非 root 用户运行、只暴露一个端口、`--no-server-header` 不泄露实现

---

## 七、目录结构

```
aiholey/
├── backend/                # FastAPI 应用
│   ├── main.py             #   应用装配（安全头中间件 / 路由保护）
│   ├── config.py           #   全部配置走环境变量
│   ├── core/               #   认证(JWT)/数据库/调度/git 操作/扫描引擎/报告生成
│   │   ├── jwt_util.py     #     零依赖 HS256 实现（固定算法、强制 exp/iss/aud/typ）
│   │   └── webscan/        #     Web 漏扫：端口扫描 + 27 个探测工具 + AI 规划
│   └── routers/            #   auth / 配置 / 任务 / 报告 / 漏扫 API
├── frontend/               # 零依赖原生前端（HTML/CSS/JS，无构建步骤）
├── examples/               # 示例仓库（demo-repo.git + demo-vuln），内置体验用
├── Dockerfile              # 一体化镜像（非 root + 健康检查）
├── docker-compose.yml      # 单服务编排
├── docker-deploy.sh        # 一键部署：停旧实例→构建→迁移数据→起容器
├── requirements.txt
└── start.sh / stop.sh      # 本地开发启动脚本
```

### 快速体验

示例仓库已内置，启动后直接在界面里操作：

```text
仓库管理 → 新增仓库 → 地址填 <项目路径>/examples/demo-repo.git → 拉取
审计任务 → 新增任务 → 选该仓库 → 运行
```

---

## 八、常见问题

**Q：构建镜像时拉不动基础镜像？**
A：Dockerfile 默认已走国内镜像站；若你的网络反过来（可直连 Docker Hub），用
`BASE_IMAGE=python:3.13-slim PIP_INDEX_URL=https://pypi.org/simple docker compose build`。

**Q：忘记密码？**
A：删库重初始化（`docker compose down && rm -rf docker-data && ./docker-deploy.sh`，
数据会丢），或挂载卷进容器改 `users` 表。

**Q：审计功能在容器里提示 git 不存在？**
A：镜像已内置 `git` 与 `openssh-client`；若是自己改过的镜像，确保安装这两个包。
