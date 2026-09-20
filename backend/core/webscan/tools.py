"""Web 扫描工具集 —— 可被 AI 调用的原子探测能力。

统一约定
--------
- 入参都是 JSON 可序列化的简单类型；
- 出参固定为 ``{"ok": bool, "summary": str, "data": dict, "issues": list}``；
- ``issues`` 是工具自身能**确定判定**的问题（确定性检查），直接进报告；
  需要语义推理的部分留在 ``data`` 里，交给 AI 判断。

安全边界
--------
只做**读取类探测**：GET / HEAD / OPTIONS 与有限的重定向探测。
不提交任何可能修改服务端状态的攻击性 payload（不带 SQLi/XSS 串去写库）。
端口探测只做 TCP connect，不发应用层数据。
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import ipaddress
import os
import re
import socket
import ssl
import tempfile
import time
from datetime import datetime, timezone
from typing import NamedTuple
from urllib.parse import urljoin, urlparse

import httpx

# ============================================================ 常量表

DEFAULT_UA = "Mozilla/5.0 (compatible; Aiholey-WebScan/1.0; security-audit)"

# 重点探测端口（(端口, 服务名, 风险等级, 说明)）—— 风险等级 None 表示仅记录
COMMON_PORTS: list[tuple[int, str, str | None, str]] = [
    (21, "ftp", "medium", "FTP 服务对外可达，注意匿名登录与明文传输"),
    (22, "ssh", None, "SSH 服务，确认是否限制来源与禁用口令登录"),
    (23, "telnet", "high", "Telnet 明文协议对外可达"),
    (25, "smtp", None, "SMTP 服务"),
    (80, "http", None, "HTTP 服务"),
    (110, "pop3", None, "POP3 服务"),
    (443, "https", None, "HTTPS 服务"),
    (445, "smb", "high", "SMB 端口对外可达"),
    (1433, "mssql", "high", "SQL Server 端口对外暴露"),
    (1521, "oracle", "high", "Oracle 端口对外暴露"),
    (2049, "nfs", "high", "NFS 端口对外暴露"),
    (2375, "docker", "critical", "Docker Daemon 未加密端口对外暴露，可被直接控制"),
    (3000, "dev-server", None, "常见开发服务器端口"),
    (3306, "mysql", "high", "MySQL 端口对外暴露"),
    (3389, "rdp", "high", "RDP 远程桌面对外暴露"),
    (5432, "postgres", "high", "PostgreSQL 端口对外暴露"),
    (5601, "kibana", "medium", "Kibana 端口对外可达"),
    (5672, "rabbitmq", None, "RabbitMQ 端口对外可达"),
    (6379, "redis", "critical", "Redis 端口对外暴露（未授权访问可导致数据泄漏与写入）"),
    (8080, "http-alt", None, "常见应用端口"),
    (8443, "https-alt", None, "常见应用 HTTPS 端口"),
    (8888, "http-alt", None, "常见应用/管理端口"),
    (9000, "app", None, "常见应用端口"),
    (9090, "prometheus", "medium", "Prometheus 监控端点对外可达"),
    (9200, "elasticsearch", "critical", "Elasticsearch 端口对外暴露（未授权可读写全部索引）"),
    (11211, "memcached", "high", "Memcached 端口对外暴露"),
    (27017, "mongodb", "critical", "MongoDB 端口对外暴露（未授权可读写数据库）"),
]

# 目录/文件探测字典（轻量，只放高频目标）
DIR_WORDLIST: list[str] = [
    "admin", "api", "api/v1", "api/v2", "backup", "backups", "console", "dashboard",
    "debug", "docs", "download", "files", "graphql", "health", "help", "info",
    "internal", "log", "logs", "manage", "metrics", "monitor", "old", "private",
    "robots.txt", "sitemap.xml", "status", "swagger", "test", "tmp", "upload",
    "uploads", "user", "users", "ws", "actuator", "error", "server-status",
]

# 敏感路径探测表（路径, 命中等级, 标题, 说明, 修复建议, CWE）
SENSITIVE_PATHS: list[tuple[str, str, str, str, str, str]] = [
    (".env", "critical", "环境变量文件可公开访问",
     "`.env` 通常存放数据库口令、API Key 等凭证，暴露后可导致系统被完全接管。",
     "在 Web 服务器配置中禁止访问以 `.` 开头的文件，并将配置文件移出站点根目录。", "CWE-538"),
    (".env.local", "critical", "环境变量文件可公开访问",
     "本地环境配置暴露，常含密钥与调试开关。",
     "禁止 Web 访问点文件，清理已部署目录中的 .env* 文件。", "CWE-538"),
    (".git/config", "high", "Git 仓库元数据暴露",
     "可读取 `.git` 目录意味着攻击者能下载完整源码历史，从中挖掘硬编码凭证与未修复漏洞。",
     "禁止访问 `.git` 目录；确认服务器不再直接暴露工作目录。", "CWE-538"),
    (".git/HEAD", "high", "Git 仓库元数据暴露",
     "`.git/HEAD` 可访问，说明 Git 目录整体暴露。",
     "禁止 Web 访问 `.git` 目录。", "CWE-538"),
    (".svn/entries", "high", "SVN 仓库元数据暴露",
     "SVN 元数据暴露，可能泄漏源码。",
     "禁止访问 `.svn` 目录。", "CWE-538"),
    (".DS_Store", "low", "目录索引文件暴露",
     "macOS 的 `.DS_Store` 会泄漏目录结构信息。",
     "部署时排除 `.DS_Store`，禁止 Web 访问点文件。", "CWE-538"),
    ("actuator/env", "critical", "Spring Actuator 环境端点暴露",
     "`/actuator/env` 会回显全部环境变量与配置（含数据库口令、密钥），是典型严重后果泄漏点。",
     "生产环境关闭 Actuator 敏感端点（management.endpoints.web.exposure.exclude），或限制管理端口仅内网可访问。", "CWE-200"),
    ("actuator/heapdump", "critical", "Spring Actuator 堆转储端点暴露",
     "`/actuator/heapdump` 可下载 JVM 堆快照，内含内存中的凭证与会话信息。",
     "关闭 heapdump 端点并限制 Actuator 访问来源。", "CWE-200"),
    ("actuator/health", "info", "Spring Actuator 健康端点可访问",
     "健康端点暴露会泄漏组件与中间件信息。",
     "生产环境仅对内部监控开放该端点。", "CWE-200"),
    ("druid/index.html", "high", "Druid 监控台暴露",
     "Druid 监控页面会泄漏 SQL 语句与数据源配置，部分版本存在未授权访问。",
     "为 Druid 监控台设置账号口令，或仅在运维内网开放。", "CWE-284"),
    ("swagger-ui.html", "medium", "接口文档对外暴露",
     "在线接口文档会暴露全部 API 路径与参数结构，便于攻击者构造请求。",
     "生产环境关闭接口文档，或加上鉴权。", "CWE-200"),
    ("v2/api-docs", "medium", "接口文档对外暴露",
     "Swagger 描述文件暴露全部接口定义。",
     "生产环境关闭接口文档或加鉴权。", "CWE-200"),
    ("phpinfo.php", "high", "phpinfo 页面暴露",
     "phpinfo 会泄漏 PHP 版本、扩展、环境变量与服务器路径。",
     "删除该文件。", "CWE-200"),
    ("server-status", "medium", "Apache 状态页暴露",
     "会泄漏当前请求 URL、客户端 IP 与工作进程信息。",
     "限制 `/server-status` 仅本机访问。", "CWE-200"),
    ("WEB-INF/web.xml", "high", "WEB-INF 目录可访问",
     "Java Web 应用配置暴露，可能泄漏数据库连接与路由信息。",
     "禁止 Web 访问 WEB-INF / META-INF 目录。", "CWE-538"),
    ("pom.xml", "medium", "Maven 构建文件暴露",
     "可据此推断依赖与版本，直接对应已知 CVE。",
     "禁止访问构建文件。", "CWE-200"),
    ("docker-compose.yml", "high", "容器编排文件暴露",
     "常含端口映射、环境变量与内部服务拓扑。",
     "禁止访问构建与编排文件。", "CWE-538"),
    ("Dockerfile", "medium", "容器构建文件暴露",
     "泄漏基础镜像与构建过程。",
     "禁止访问构建文件。", "CWE-200"),
    ("backup.zip", "high", "备份文件可下载",
     "备份包通常包含源码与数据库导出。",
     "清理服务器上的备份文件，禁止 Web 访问。", "CWE-530"),
    ("backup.sql", "high", "数据库备份可下载",
     "SQL 备份含全部业务数据。",
     "清理备份文件并限制访问。", "CWE-530"),
    ("db.sql", "high", "数据库备份可下载",
     "SQL 备份含全部业务数据。",
     "清理备份文件并限制访问。", "CWE-530"),
    (".htaccess", "low", "Apache 配置文件暴露",
     "可读取重写规则与访问控制配置。",
     "禁止访问 `.htaccess`。", "CWE-200"),
    ("crossdomain.xml", "low", "跨域策略文件宽松",
     "若允许 `*`，任意站点的 Flash/小程序可携带凭据请求本域。",
     "收紧 crossdomain.xml 的 allow-access-from 列表。", "CWE-942"),
]

# 安全响应头检查表（头名, 缺失等级, 说明, 建议）
SECURITY_HEADERS: list[tuple[str, str, str, str]] = [
    ("Strict-Transport-Security", "low",
     "未启用 HSTS，用户可能被降级到明文 HTTP 并遭受中间人攻击。",
     "配置 `Strict-Transport-Security: max-age=31536000; includeSubDomains`。"),
    ("Content-Security-Policy", "low",
     "未配置 CSP，发生 XSS 时缺少浏览器侧的第二道防线。",
     "按业务实际资源来源配置 CSP，避免使用 `unsafe-inline`。"),
    ("X-Content-Type-Options", "low",
     "未设置 `nosniff`，浏览器可能按内容猜测 MIME 类型，诱发内容嗅探攻击。",
     "添加 `X-Content-Type-Options: nosniff`。"),
    ("X-Frame-Options", "low",
     "未限制页面被嵌套，存在点击劫持风险。",
     "添加 `X-Frame-Options: DENY`，或使用 CSP 的 `frame-ancestors`。"),
    ("Referrer-Policy", "info",
     "未设置 Referrer-Policy，敏感 URL 可能通过 Referer 外泄。",
     "添加 `Referrer-Policy: strict-origin-when-cross-origin`。"),
    ("Permissions-Policy", "info",
     "未限制浏览器特性（摄像头、定位等）的使用范围。",
     "按需配置 `Permissions-Policy`。"),
]

# 开放重定向探测参数
REDIRECT_PARAMS = ["url", "redirect", "redirect_uri", "next", "return", "returnUrl", "goto", "target", "r"]

# 会出现在响应里的「技术栈指纹」(正则, 标签)
FINGERPRINTS: list[tuple[str, str, str]] = [
    (r"wp-content|wp-includes", "body", "WordPress"),
    (r"__NEXT_DATA__|/_next/static", "body", "Next.js"),
    (r"<div id=\"root\"></div>|<div id=\"app\"></div>", "body", "SPA（React/Vue 单页应用）"),
    (r"ng-version=|ng-app", "body", "Angular"),
    (r"csrf-token|laravel_session", "any", "Laravel"),
    (r"Powered by Drupal", "any", "Drupal"),
    (r"Spring|Whitelabel Error Page", "any", "Spring Boot"),
    (r"JSESSIONID", "cookie", "Java（Servlet 容器）"),
    (r"PHPSESSID", "cookie", "PHP"),
    (r"ASP\.NET_SessionId|\.AspNetCore", "cookie", "ASP.NET"),
    (r"connect\.sid", "cookie", "Node.js（Express）"),
    (r"X-Powered-By:\s*Express", "header", "Express"),
    (r"Tomcat|Catalina", "any", "Apache Tomcat"),
    (r"Jetty", "any", "Jetty"),
    (r"cloudflare", "any", "Cloudflare CDN"),
    (r"Varnish", "any", "Varnish 缓存"),
]

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PRIVATE_IP_RE = re.compile(r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b")
_STACK_RE = re.compile(
    r"(?:java\.lang\.[A-Za-z.]+Exception|at [a-z]+\.[a-zA-Z0-9.$]+\.[a-zA-Z0-9_$]+\(|"
    r"Traceback \(most recent call last\)|org\.springframework\.[A-Za-z.]+|"
    r"Warning:\s+\w+\(\)\s+\[function\.|SyntaxError:|com\.mysql\.jdbc)"
)
_ABS_PATH_RE = re.compile(r"(?:/var/www/|/usr/local/|/home/[a-z_]+/|C:\\\\?(?:inetpub|wwwroot)|/opt/[a-z]+/)")
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


# ============================================================ 会话

class BudgetExceeded(RuntimeError):
    """请求预算耗尽 —— 防止 AI 规划的循环把目标打爆。"""


class RawResponse(NamedTuple):
    """裸通道的响应：比 httpx.Response 少很多，但**包含响应头**。

    为什么需要响应头：CRLF 注入（把 `%0d%0a` 塞进参数或路径，看能否在响应头里
    凭空造出一个头）唯一可靠的判据就是「响应头列表里出现了我们注入的头名」。
    只看响应体的话，这类漏洞整类测不出来。
    """

    status: int
    headers: dict[str, str]      # 键统一转小写，重复头用 ", " 合并
    body: bytes
    ctype: str
    error: str

    @property
    def ok(self) -> bool:
        return not self.error and self.status > 0


class ScanSession:
    """一次扫描作业的共享上下文：HTTP 客户端 + 请求预算 + 限速 + 流水记录。"""

    def __init__(self, *, timeout: float = 10.0, delay: float = 0.0, max_requests: int = 1500,
                 verify_tls: bool = False, proxy: str = "", user_agent: str = DEFAULT_UA,
                 depth: str = "standard"):
        self.timeout = timeout
        self.delay = delay
        self.max_requests = max_requests
        # 档位：工具据此缩放字典规模（quick 少探、deep 全量），避免轻量档把目标打爆
        self.depth = depth
        self.requests_made = 0
        self.errors: list[str] = []
        self.flow: list[dict] = []
        # 跨工具共享的发现结果。前端接口清单是最典型的一项：先由一个工具从
        # HTML 与 JS bundle 里提取出来，后面的参数/穿越类工具直接拿去当真实落点，
        # 否则它们只能对着站点根路径瞎猜参数名，在 SPA 上几乎必然空手而归。
        self.discovered: dict[str, list[str]] = {}
        # 已经抓回来的文本资源（JS bundle / JSON / robots.txt …），按 URL 缓存。
        # 密钥扫描与组件版本识别都要把同一批 bundle 从头翻一遍，每次各抓一次
        # 等于把请求预算花在同一条字节流上——实测一整轮扫描里 bundle 会被重复拉 3 遍。
        self.text_cache: dict[str, str] = {}
        self._last_at = 0.0
        kwargs: dict = {
            "trust_env": False,  # 关键：不走系统代理，否则内网目标会被本机代理拦截
            "follow_redirects": False,
            "verify": verify_tls,
            "timeout": httpx.Timeout(timeout, connect=min(6.0, timeout)),
            "headers": {
                "User-Agent": user_agent,
                "Accept": "*/*",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "Connection": "close",
            },
        }
        if proxy:
            kwargs["proxy"] = proxy
        self.client = httpx.Client(**kwargs)

    def close(self) -> None:
        try:
            self.client.close()
        except Exception:
            pass

    def request(self, method: str, url: str, **kw) -> tuple[httpx.Response | None, str]:
        """发一个请求；返回 (响应, 错误文本)。错误不抛出，交给调用方决定如何记录。"""
        if self.requests_made >= self.max_requests:
            raise BudgetExceeded(f"已达请求上限 {self.max_requests}")
        if self.delay > 0:
            gap = time.time() - self._last_at
            if gap < self.delay:
                time.sleep(self.delay - gap)
        try:
            t0 = time.time()
            resp = self.client.request(method, url, **kw)
        except httpx.HTTPError as e:
            self.requests_made += 1
            self._last_at = time.time()
            msg = f"{type(e).__name__}: {e}"
            self.errors.append(f"{method} {url} → {msg}")
            return None, msg
        finally:
            self._last_at = time.time()
        self.requests_made += 1
        self.flow.append({"method": method, "url": url, "status": resp.status_code,
                          "len": len(resp.content or b""), "ms": int((time.time() - t0) * 1000)})
        return resp, ""

    def request_raw(self, url: str, raw_path: str, *, method: str = "GET",
                    headers: dict | None = None, body: bytes = b"",
                    timeout: float = 8.0, limit: int = 262144) -> RawResponse:
        """裸 TCP/TLS 通道发一次请求，返回**完整**响应（含响应头）。

        与 ``request`` 的区别是它不经过 httpx：请求行里的路径逐字节原样发出，
        因此 `../` 不会被归一化、`%2e` 不会被二次编码，也能塞自定义请求头
        （CRLF 注入要在请求头里放载荷，httpx 会拒绝非法头值）。

        代价是绕开了 httpx 的健壮性处理，所以拿到的只有
        ``RawResponse(status, headers, body, ctype, error)``。
        请求仍然计入预算并写入流水，避免这条通道成为绕过限速与配额的暗门。
        """
        if self.requests_made >= self.max_requests:
            raise BudgetExceeded(f"已达请求上限 {self.max_requests}")
        parsed = urlparse(url)
        use_tls = parsed.scheme == "https"
        host = parsed.hostname or ""
        port = parsed.port or (443 if use_tls else 80)
        if not host:
            return RawResponse(0, {}, b"", "", "无法从 URL 解析出主机")
        if self.delay > 0:
            gap = time.time() - self._last_at
            if gap < self.delay:
                time.sleep(self.delay - gap)

        host_hdr = host if port in (80, 443) else f"{host}:{port}"
        lines = [f"{method} {raw_path} HTTP/1.1", f"Host: {host_hdr}",
                 f"User-Agent: {DEFAULT_UA}", "Accept: */*", "Connection: close"]
        for k, v in (headers or {}).items():
            lines.append(f"{k}: {v}")
        payload = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "replace") + (body or b"")

        t0 = time.time()
        raw, err = _socket_exchange(host, port, payload, timeout=timeout,
                                   use_tls=use_tls, limit=limit)
        self.requests_made += 1
        self._last_at = time.time()
        if err or not raw:
            msg = err or "无响应"
            self.errors.append(f"{method} {raw_path} → {msg}")
            return RawResponse(0, {}, b"", "", msg)

        status, hdrs, ctype, rbody = _parse_socket_full(raw)
        self.flow.append({"method": method, "url": f"{parsed.scheme}://{parsed.netloc}{raw_path}",
                          "status": status, "len": len(rbody),
                          "ms": int((time.time() - t0) * 1000)})
        return RawResponse(status, hdrs, rbody, ctype, "")

    def request_exact_path(self, url: str, raw_path: str, *, method: str = "GET",
                           timeout: float = 8.0, limit: int = 262144
                           ) -> tuple[int, bytes, str, str]:
        """``request_raw`` 的轻量封装，只取 (状态码, 响应体, Content-Type, 错误)。

        保留这个签名是因为目录遍历工具到处在用；需要响应头的新工具
        （CRLF 注入）请直接用 ``request_raw``。
        """
        r = self.request_raw(url, raw_path, method=method, timeout=timeout, limit=limit)
        return r.status, r.body, r.ctype, r.error

    def fetch_text(self, url: str, *, limit: int = 400000) -> tuple[str, str]:
        """抓一段文本资源并缓存，返回 (文本, 错误)。

        JS bundle 动辄几百 KB，而密钥扫描、组件版本识别、接口面发现都要读同一份。
        缓存后重复读取是零成本，省下的预算可以多探几个真实落点。
        非文本（二进制/压缩）响应不入缓存，避免把二进制塞进正则匹配。
        """
        if url in self.text_cache:
            return self.text_cache[url], ""
        try:
            resp, err = self.request("GET", url)
        except (httpx.HTTPError, OSError, BudgetExceeded) as e:
            return "", f"{type(e).__name__}: {e}"
        if resp is None:
            return "", err
        if resp.status_code >= 400:
            return "", f"HTTP {resp.status_code}"
        ctype = _content_type(resp)
        raw = resp.content or b""
        if _bytes_look_binary(raw):
            return "", f"二进制响应（{ctype or '未知类型'}）"
        text = raw[:limit].decode(resp.encoding or "utf-8", "replace")
        self.text_cache[url] = text
        return text, ""


def _socket_exchange(host: str, port: int, payload: bytes, *, timeout: float,
                     use_tls: bool, limit: int) -> tuple[bytes, str]:
    """裸 TCP（可选 TLS）发一段字节并读回全部响应。"""
    try:
        sock = socket.create_connection((_resolve_host(host), port), timeout=timeout)
    except (OSError, socket.timeout) as e:
        return b"", f"{type(e).__name__}: {e}"
    try:
        sock.settimeout(timeout)
        if use_tls:
            ctx = ssl._create_unverified_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(payload)
        chunks: list[bytes] = []
        total = 0
        while total < limit:
            try:
                got = sock.recv(65536)
            except (socket.timeout, ssl.SSLError):
                break
            if not got:
                break
            chunks.append(got)
            total += len(got)
    except (OSError, ssl.SSLError) as e:
        return b"", f"{type(e).__name__}: {e}"
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return b"".join(chunks), ""


def _parse_socket_full(raw: bytes) -> tuple[int, dict[str, str], str, bytes]:
    """从原始响应字节里取出 (状态码, 响应头字典, Content-Type, 响应体)。

    响应头**必须**解析出来：CRLF 注入的唯一可靠判据就是「响应头里凭空多出了
    我们注入的那个头」，只返回响应体的旧版解析在这里没有判别力。

    要处理 chunked 与 Content-Length：HTTP/1.1 服务端常用 chunked，
    只按「读到连接关闭」取体会把分块长度前缀混进内容里，特征匹配就会失败。

    响应头键统一小写，重复头（多个 Set-Cookie）用 ", " 合并——
    否则 `Set-Cookie` 只有第一条能被看到，而会话安全判定恰恰要看全部。
    """
    head, sep, rest = raw.partition(b"\r\n\r\n")
    if not sep:
        return 0, {}, "", b""
    m = re.match(rb"HTTP/\d\.\d\s+(\d{3})", head)
    status = int(m.group(1)) if m else 0
    headers: dict[str, str] = {}
    lines = head.split(b"\r\n")[1:]
    for line in lines:
        if line[:1] in (b" ", b"\t") and headers:
            continue                       # 折行续行，忽略
        k, s, v = line.partition(b":")
        if not s:
            continue
        key = k.decode("latin-1", "replace").strip().lower()
        val = v.decode("latin-1", "replace").strip()
        headers[key] = f"{headers[key]}, {val}" if key in headers else val
    ctype = headers.get("content-type", "")
    if b"transfer-encoding: chunked" in head.lower():
        body = b""
        while True:
            line, sep2, rest = rest.partition(b"\r\n")
            if not sep2:
                break
            try:
                size = int(line.split(b";")[0].strip(), 16)
            except ValueError:
                break
            if size == 0:
                break
            body += rest[:size]
            rest = rest[size + 2:]
        return status, headers, ctype, body
    lm = re.search(rb"content-length:\s*(\d+)", head.lower())
    if lm:
        return status, headers, ctype, rest[:int(lm.group(1))]
    return status, headers, ctype, rest


def _parse_socket_response(raw: bytes) -> tuple[int, str, bytes]:
    """``_parse_socket_full`` 的三元组封装，保持既有调用方兼容。"""
    status, _hdrs, ctype, body = _parse_socket_full(raw)
    return status, ctype, body


# ============================================================ 工具注册表

TOOLS: dict[str, dict] = {}


def tool(name: str, description: str, params: dict, phase: str, category: str):
    """把一个函数注册成 AI 可调用的工具。"""
    def deco(fn):
        TOOLS[name] = {
            "name": name, "description": description, "params": params,
            "phase": phase, "category": category, "fn": fn,
        }
        return fn
    return deco


def tool_catalog() -> list[dict]:
    """给 AI 看的工具清单（不含函数对象）。"""
    return [{k: v for k, v in t.items() if k != "fn"} for t in TOOLS.values()]


def tools_by_phase(phase: str) -> list[str]:
    return [t["name"] for t in TOOLS.values() if t["phase"] == phase]


# ============================================================ 通用小工具

def normalize_target(raw: str) -> str:
    """把用户输入整理成可请求的 URL：补协议、去空白与末尾斜杠。"""
    t = (raw or "").strip().strip("\"'")
    if not t:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", t):
        # 常见端口给 https，其余给 http
        t = ("https://" if re.search(r":443(/|$)", t) else "http://") + t
    return t.rstrip("/")


def origin_of(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def uniq(items) -> list:
    """按首次出现顺序去重，丢掉空值。

    参数名列表是「URL 里已有的名字 + 调用方传入的名字 + 常见候选名」三处拼起来的，
    这三处天然会重叠。不去重的后果不只是多花几次请求：对同一个参数跑两轮会让
    同一个漏洞被报成两条标题完全相同的条目，看起来像两个独立缺陷。
    """
    out: list = []
    for x in items:
        if x and x not in out:
            out.append(x)
    return out


# 参数型检测工具（param_probe / xss_check / lfi_probe / crlf_inject）除调用方
# 给的入口 URL 外，还会在 api_surface 采集到的「带参数落点」上各测一轮。
# 上限按档位给：quick 实测整轮扫描只用掉 1400 预算里的 500 上下，
# 留足余量才能覆盖「功能页都挂在子路径上」的传统站点——那里落点多达十几个，
# 卡到 2 个等于把大部分功能页排除在检测之外。
DISCOVERED_LANDING_CAP = {"quick": 5, "standard": 10, "deep": 18}


def dedup_issues(issues: list[dict]) -> list[dict]:
    """按「标题 + 参数 + 目标」去重，保留首条。

    扫描工具会从多个落点测同一个根因（同一段有缺陷的代码挂在多条路径上，
    或被入口 URL 与页面链接各测了一遍）。这些命中在技术上都是真的，
    但报告里并排出现两条标题一模一样的条目，读起来像扫描器重复计数，
    会连带让人怀疑其它条目的可信度。保留首条即可，证据里带着具体 URL。
    """
    seen: set[tuple] = set()
    out: list[dict] = []
    for it in issues:
        k = (it.get("title"), it.get("param"), it.get("target"))
        if k in seen:
            continue
        seen.add(k)
        out.append(it)
    return out


def host_of(url: str) -> str:
    return urlparse(url).hostname or ""


def _issue(skill: str, severity: str, category: str, title: str, url: str,
           detail: str, advice: str, cwe: str = "", evidence: str = "",
           confidence: str = "high", method: str = "GET", param: str = "",
           payload: str = "", source: str = "tool") -> dict:
    return {
        "skill": skill, "severity": severity, "category": category, "title": title,
        "url": url, "method": method, "param": param, "payload": payload,
        "evidence": sanitize_text(mask_evidence(evidence))[:800],
        "detail": sanitize_text(detail), "advice": advice,
        "cwe": cwe, "confidence": confidence, "source": source,
    }


_MASK_RE = re.compile(
    r"""(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)"""
    r"""(\s*[:=]\s*["']?)([^\s"',;]{4,})"""
)


def mask_evidence(text: str) -> str:
    """证据里常夹带口令/密钥，入库前做一次遮蔽，避免报告本身成为泄漏源。"""
    if not text:
        return ""
    def repl(m: re.Match) -> str:
        val = m.group(3)
        keep = val[:2] if len(val) > 6 else ""
        return f"{m.group(1)}{m.group(2)}{keep}***(已遮蔽)"
    return _MASK_RE.sub(repl, str(text))


def _title_of(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html or "", re.S | re.I)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else ""


# C0/C1 控制字符。保留 \n \t 供排版，其余一律不能进报告：
# 实测 .swp 泄漏的响应体证据里带 4 个 \x00，导致整份 report.md 被编辑器与检索工具
# 判定为「二进制文件」——下游连打开都做不到，比没有证据更糟。
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")

# 常见文件魔数：把「读不懂的响应体」变成报告里看得懂的一句话
_BINARY_MAGIC = [
    (b"PK\x03\x04", "ZIP 归档"), (b"PK\x05\x06", "空 ZIP 归档"),
    (b"\x1f\x8b\x08", "gzip 压缩包"), (b"BZh", "bzip2 压缩包"),
    (b"\xfd7zXZ", "xz 压缩包"), (b"Rar!\x1a\x07", "RAR 压缩包"),
    (b"%PDF", "PDF 文档"), (b"\x7fELF", "ELF 可执行文件"),
    (b"SQLite format 3", "SQLite 数据库"), (b"\x89PNG", "PNG 图片"),
]


def sanitize_text(value: str) -> str:
    """把要写进报告的文本洗成安全形式（控制字符替换为 `·`）。

    报告最终会落成 Markdown / JSON，控制字符混进去会让文件变成"二进制"，
    编辑器、diff、检索工具一律失灵。
    """
    return _CTRL_RE.sub("·", value) if value else ""


def _binary_summary(sample: str) -> str:
    """把二进制响应体压成一句可读描述：识别魔数 + 给出头部十六进制。"""
    raw = sample.encode("utf-8", "replace")
    kind = next((name for magic, name in _BINARY_MAGIC if raw.startswith(magic)), "")
    head = raw[:16]
    hexed = " ".join(f"{b:02x}" for b in head)
    label = f"二进制文件（{kind}）" if kind else "非文本内容"
    return f"（{label}，前 {len(head)} 字节：{hexed}）"


_SUSPECT_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\ufffd]")


def _looks_binary(sample: str) -> bool:
    """这段内容是不是「不是给人看的」。

    只看控制字符占比不够稳：ZIP 包开头仅 `PK\\x03\\x04` 两个控制字符（占比极低），
    而 gzip 的 `\\xff` 解码后会变成 U+FFFD 替换字符（不属于控制字符）。
    所以先按魔数判定，再退回「可疑字符（控制字符 + 替换字符）占比」。
    """
    raw = sample.encode("utf-8", "replace")
    if any(raw.startswith(magic) for magic, _ in _BINARY_MAGIC):
        return True
    hits = len(_SUSPECT_RE.findall(sample))
    return hits >= 2 and hits / len(sample) > 0.02


def _bytes_look_binary(raw: bytes) -> bool:
    """按原始字节判断是不是二进制内容。

    不能只看「高位字节多不多」——UTF-8 编码的中文几乎全是高位字节，那样判会把
    正常页面误判成二进制。所以先试 UTF-8 解码：解不开即二进制；解得开再看
    控制字符占比（NUL/`\\x03` 这类）。
    """
    if not raw:
        return False
    ctrl = sum(1 for b in raw if b < 9 or 13 < b < 32 or b == 127)
    if ctrl / len(raw) > 0.05:
        return True
    try:
        raw.decode("utf-8")
        return False
    except UnicodeDecodeError:
        return True


def _binary_label(raw: bytes) -> str:
    return next((name for magic, name in _BINARY_MAGIC if raw.startswith(magic)), "")


def _binary_head(raw: bytes, limit: int = 16) -> str:
    kind = _binary_label(raw)
    label = f"二进制文件（{kind}）" if kind else "非文本内容"
    head = raw[:limit]
    return f"（{label}，前 {len(head)} 字节：{' '.join(f'{b:02x}' for b in head)}）"


def _snippet(text, needle: str = "", width: int = 200) -> str:
    """截取证据片段。

    优先围绕命中关键字取上下文；二进制内容压成一句可读概述（魔数 + 头部十六进制），
    而不是把一屏乱码写进报告。

    既接受 str 也接受 bytes：**能传原始 bytes 就传 bytes**。先解码再判断会丢信息——
    gzip 的 `\\x1f\\x8b` 会被解成 U+008B、`\\xff` 会变成 U+FFFD，解码后就再也认不出魔数了。
    """
    if not text:
        return ""
    if isinstance(text, (bytes, bytearray)):
        raw = bytes(text)
        if needle:
            i = raw.lower().find(needle.lower().encode("utf-8", "replace"))
            if i >= 0:
                lo = max(0, i - width // 3)
                return sanitize_text(raw[lo:lo + width].decode("utf-8", "replace"))
        if _binary_label(raw) or _bytes_look_binary(raw[:1024]):
            return _binary_head(raw)
        flat = re.sub(rb"\s+", b" ", raw[:width * 3]).decode("utf-8", "replace")
        return sanitize_text(flat[:width])

    flat = re.sub(r"\s+", " ", text)
    if needle:
        i = flat.lower().find(needle.lower())
        if i >= 0:
            lo = max(0, i - width // 3)
            return sanitize_text(flat[lo:lo + width])
    if _looks_binary(text[:1024]):
        return _binary_summary(text[:1024])
    return sanitize_text(flat[:width])


# 版本号特征：`nginx/1.24.0`、`PHP/8.1.2`、`Express 4.18`、`ASP.NET 4.0.30319`
_VERSION_RE = re.compile(r"/\s*\d+[\d.]*|\b\d+\.\d+[\d.]*")


def _has_version(value: str) -> bool:
    """判断 Server / X-Powered-By 之类的头是否真的带版本号。

    只写产品名（`Server: nginx`）无法定位到具体版本的已知漏洞，
    此时报「版本信息暴露」属于误报，会把报告可信度拉低。
    """
    return bool(_VERSION_RE.search(value or ""))


# ============================================================ 侦察类工具

@tool("http_probe", "对单个 URL 发一次 GET，返回状态码、响应头、页面标题、内容长度、重定向目标。用于确认目标可达并取得基础信息。",
      {"url": "str，目标 URL"}, phase="recon", category="信息收集")
def http_probe(sess: ScanSession, url: str) -> dict:
    resp, err = sess.request("GET", url)
    if resp is None:
        return {"ok": False, "summary": f"请求失败：{err}", "data": {"url": url, "error": err}, "issues": []}

    body = resp.text or ""
    data = {
        "url": str(resp.url),
        "status": resp.status_code,
        "title": _title_of(body),
        "server": resp.headers.get("Server", ""),
        "powered_by": resp.headers.get("X-Powered-By", ""),
        "content_type": resp.headers.get("Content-Type", ""),
        "content_length": len(resp.content or b""),
        "location": resp.headers.get("Location", ""),
        "headers": {k: v for k, v in resp.headers.items()
                    if k.lower() in ("server", "x-powered-by", "x-aspnet-version",
                                     "x-generator", "via", "x-cache", "set-cookie")},
        "body_head": _snippet(body, width=300),
    }
    issues: list[dict] = []

    if data["server"] or data["powered_by"]:
        leaked = " / ".join(x for x in (data["server"], data["powered_by"]) if x)
        # 只有真的带出版本号才算「版本泄漏」；`Server: nginx` 这类纯产品名不构成可利用信息。
        if _has_version(leaked):
            issues.append(_issue(
                "tech-fingerprint", "info", "信息泄漏", "服务端版本信息对外暴露", url,
                f"响应头暴露了服务端与运行环境信息：`{leaked}`。攻击者可据此检索对应版本的已知漏洞。",
                "在反向代理层移除或改写 `Server`、`X-Powered-By` 等版本标识响应头。",
                cwe="CWE-200", evidence=leaked, confidence="high"))
        else:
            issues.append(_issue(
                "tech-fingerprint", "info", "信息泄漏", "服务端产品标识可见", url,
                f"响应头暴露了服务端产品名：`{leaked}`（未含具体版本号）。可缩小攻击者的指纹猜测范围，"
                "但不足以直接定位版本漏洞。",
                "如需降低暴露面，可在反向代理层统一改写 `Server`、`X-Powered-By` 响应头。",
                cwe="CWE-200", evidence=leaked, confidence="medium"))

    if resp.status_code >= 500:
        issues.append(_issue(
            "error-handling", "low", "错误处理", f"服务端返回 {resp.status_code} 错误", url,
            f"对正常请求返回 {resp.status_code}，可能存在未处理的服务端异常。",
            "检查服务端日志定位异常原因，并为用户返回统一的错误页面。",
            cwe="CWE-755", evidence=_snippet(body, width=200), confidence="medium"))

    if resp.status_code in (301, 302, 303, 307, 308) and not (resp.headers.get("Location") or "").startswith("https://"):
        loc = resp.headers.get("Location", "")
        if loc.startswith("http://"):
            issues.append(_issue(
                "transport-security", "medium", "传输安全", "重定向到明文 HTTP", url,
                f"服务端把请求重定向到明文地址 `{loc}`，链路上可被中间人窃听与篡改。",
                "将重定向目标改为 HTTPS，并配置 HSTS 强制加密访问。",
                cwe="CWE-319", evidence=loc, confidence="medium"))

    return {"ok": True, "summary": f"HTTP {resp.status_code}，标题「{data['title'] or '无'}」，{data['content_length']} 字节",
            "data": data, "issues": issues}


@tool("fingerprint", "基于响应头、Cookie 名与页面特征识别目标的技术栈（Web 框架、语言、中间件、CDN）。",
      {"url": "str，目标 URL"}, phase="recon", category="信息收集")
def fingerprint(sess: ScanSession, url: str) -> dict:
    resp, err = sess.request("GET", url)
    if resp is None:
        return {"ok": False, "summary": f"请求失败：{err}", "data": {"url": url, "error": err}, "issues": []}

    body = (resp.text or "")[:200000]
    headers_text = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    cookies = " ".join(resp.headers.get_list("set-cookie")) if hasattr(resp.headers, "get_list") else \
        resp.headers.get("set-cookie", "")
    haystacks = {"body": body, "header": headers_text, "cookie": cookies, "any": headers_text + "\n" + cookies + "\n" + body}

    hits: list[str] = []
    for pattern, where, label in FINGERPRINTS:
        try:
            if re.search(pattern, haystacks.get(where, ""), re.I):
                if label not in hits:
                    hits.append(label)
        except re.error:
            continue

    generator = ""
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    if m:
        generator = m.group(1).strip()
        hits.append(f"Generator: {generator}")

    issues: list[dict] = []
    if generator:
        issues.append(_issue(
            "tech-fingerprint", "low", "信息泄漏", "页面声明的生成器版本", url,
            f"页面 meta 标签暴露了生成器信息：`{generator}`。",
            "移除 `generator` meta 标签，减少可被检索的版本线索。",
            cwe="CWE-200", evidence=generator, confidence="high"))

    return {"ok": True, "summary": f"识别到 {len(hits)} 项技术特征：{'、'.join(hits) or '无明显特征'}",
            "data": {"url": url, "status": resp.status_code, "technologies": hits,
                     "server": resp.headers.get("Server", ""),
                     "cookies": [c.split("=")[0].strip() for c in re.split(r";\s*", cookies) if "=" in c][:8]},
            "issues": issues}


def _decode_pem_cert(pem: str) -> dict:
    """把 PEM 解成 ``getpeercert()`` 那种字典。

    为什么需要这一步：用 ``verify_mode=CERT_NONE`` 握手时，
    ``ss.getpeercert()`` **恒返回空字典**——这是 OpenSSL 的行为，不是代码写错了。
    结果就是「证书主体 / 有效期 / SAN」全部为空，
    「证书过期」和「证书主机名不匹配」两类检查静默失效，
    报告看起来"查过了没问题"，实际上一个字段都没读到。

    绕法：先把 PEM 落成临时文件，再用标准库的解码函数读回来。
    ``ssl._ssl._test_decode_cert`` 是下划线私有 API，但它与 ``getpeercert()``
    返回同一套结构，且在所有 CPython 3.x 上稳定存在；取不到就返回空字典，
    让上层退化为"只看协议与套件"，而不是抛异常中断整个工具。
    """
    if not pem:
        return {}
    # 服务端可能回整条链，解码函数只认单张证书，先截到第一个 END 标记
    end = pem.find("-----END CERTIFICATE-----")
    if end > 0:
        pem = pem[:end + len("-----END CERTIFICATE-----")] + "\n"
    tmp = ""
    try:
        fd, tmp = tempfile.mkstemp(suffix=".pem")
        with os.fdopen(fd, "w") as fh:
            fh.write(pem)
        return ssl._ssl._test_decode_cert(tmp) or {}
    except Exception:
        return {}
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def _tls_probe_connection(host: str, port: int):
    """建一次宽松握手，返回 (证书字典, 协议版本, 套件三元组, PEM)。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((_resolve_host(host), port), timeout=8) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as ss:
            cert = ss.getpeercert() or {}
            version = ss.version()
            cipher = ss.cipher()
    pem = ssl.get_server_certificate((_resolve_host(host), port), timeout=8)
    if not cert:
        cert = _decode_pem_cert(pem)
    return cert, version, cipher, pem


@tool("tls_info",
      "检查 HTTPS 证书与 TLS 配置：证书主体/有效期/剩余天数/自签名、证书链是否受信、"
      "证书里的主机名是否覆盖被访问的域名、服务端支持的协议版本（含过时的 TLS 1.0/1.1）、"
      "以及是否仍接受 NULL/EXPORT/匿名/RC4/3DES 等弱加密套件。",
      {"host": "str，主机名或 IP", "port": "int，默认 443"}, phase="recon", category="信息收集")
def tls_info(sess: ScanSession, host: str, port: int = 443) -> dict:
    try:
        cert, version, cipher, pem = _tls_probe_connection(host, int(port))
    except Exception as e:
        return {"ok": False, "summary": f"TLS 连接失败：{type(e).__name__}: {e}",
                "data": {"host": host, "port": port, "error": str(e)}, "issues": []}

    data = {
        "host": host, "port": port, "tls_version": version,
        "cipher": cipher[0] if cipher else "",
        "cipher_bits": cipher[2] if cipher and len(cipher) > 2 else None,
        "subject": "", "issuer": "", "not_before": "", "not_after": "", "days_left": None,
        "san": [], "self_signed": False, "cert_pem_len": len(pem or ""),
        "protocols_supported": {}, "weak_ciphers": [], "hostname_match": None,
        "chain_trusted": None,
    }
    issues: list[dict] = []
    endpoint = f"https://{host}:{port}" if int(port) != 443 else f"https://{host}"

    if cert:
        def flat(field):
            out = []
            for rdn in cert.get(field, []):
                for k, v in rdn:
                    out.append(f"{k}={v}")
            return ", ".join(out)
        data["subject"], data["issuer"] = flat("subject"), flat("issuer")
        data["not_before"], data["not_after"] = cert.get("notBefore", ""), cert.get("notAfter", "")
        data["san"] = [v for k, v in cert.get("subjectAltName", ()) if k.lower() == "dns"][:12]
        try:
            exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            data["days_left"] = (exp - datetime.now(timezone.utc)).days
        except (KeyError, ValueError):
            pass
        data["self_signed"] = bool(data["subject"] and data["subject"] == data["issuer"])
    else:
        # CERT_NONE 下某些服务端不返回解析后的证书，退化为只看协议
        data["self_signed"] = False

    if data["days_left"] is not None and data["days_left"] < 0:
        issues.append(_issue("transport-security", "high", "传输安全", "HTTPS 证书已过期", endpoint,
                             f"证书已于 {data['not_after']} 过期（剩余 {data['days_left']} 天），浏览器会阻断访问，用户可能被诱导忽略告警。",
                             "立即续签并部署新证书，同时配置到期自动续期与监控告警。",
                             cwe="CWE-298", evidence=f"notAfter={data['not_after']}", confidence="high"))
    elif data["days_left"] is not None and data["days_left"] < 15:
        issues.append(_issue("transport-security", "medium", "传输安全", "HTTPS 证书即将过期", endpoint,
                             f"证书将在 {data['days_left']} 天后过期（{data['not_after']}）。",
                             "尽快续签证书。", cwe="CWE-298",
                             evidence=f"notAfter={data['not_after']}", confidence="high"))

    if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        issues.append(_issue("transport-security", "medium", "传输安全", f"使用了过时的加密协议 {version}", endpoint,
                             f"服务端与客户端协商到了 {version}，该协议已被证明不安全。",
                             "在服务端禁用 TLS 1.0/1.1 与 SSLv3，仅保留 TLS 1.2+。",
                             cwe="CWE-326", evidence=f"protocol={version}", confidence="high"))

    # ---------- 自签名 ----------
    # 自签名本身在内部系统里是常见且可接受的，但它会训练用户「证书告警直接点继续」，
    # 这个习惯一旦形成，真正的中间人就不再被察觉。所以报，但只报 low。
    if data["self_signed"]:
        issues.append(_issue(
            "transport-security", "low", "传输安全", "HTTPS 使用自签名证书", endpoint,
            "服务端证书由自己签发（subject 与 issuer 相同），任何客户端都无法通过信任链校验它。"
            "在内部系统中可以接受，但会使用户养成忽略证书告警的习惯。",
            "改用内部 CA 统一签发并分发根证书；对外服务必须使用受公网信任的证书。",
            cwe="CWE-295", evidence=f"subject={data['subject']}", confidence="high"))

    # ---------- 证书主机名匹配 ----------
    # 只看「证书是否过期」是不够的：证书本身有效、但名字对不上目标域名的情况
    # （拿了别的站点的证书、或内网自签时随手写的 CN）同样会导致中间人被轻易利用，
    # 而浏览器的告警在用户点过"继续访问"之后就不再拦人。
    match, matched_by, names = _cert_host_match(host, cert)
    data["hostname_match"] = match
    data["cert_names"] = names
    if not match:
        issues.append(_issue(
            "transport-security", "medium", "传输安全", "HTTPS 证书与访问的域名不匹配", endpoint,
            f"证书里声明的名字（{matched_by or '无 SAN 也无 CN'}）不覆盖当前访问的主机名 `{host}`。"
            "攻击者可以用任意一张同签发机构的证书对该域名实施中间人，浏览器告警也容易被用户忽略。",
            "为每个域名签发包含正确 SAN 的证书；内部服务改用内部 CA 并统一分发信任。",
            cwe="CWE-295", evidence=f"host={host}; SAN/CN={matched_by or '空'}", confidence="high"))

    # ---------- 证书链可信性 ----------
    if not _is_ip_literal(host) and not data["self_signed"]:
        trusted, terr = _tls_chain_trusted(host, int(port))
        data["chain_trusted"] = trusted
        if trusted is False:
            issues.append(_issue(
                "transport-security", "medium", "传输安全", "HTTPS 证书链不受公网信任", endpoint,
                f"用系统根证书校验该站点失败：{terr[:160]}。常见原因是缺少中间证书、"
                "或使用了自建 CA 签发的证书。内网场景可接受，但必须保证客户端已预置该 CA，"
                "否则用户会习惯性忽略证书告警。",
                "补全中间证书；若为内部 CA，通过配置管理统一分发根证书并禁止忽略告警。",
                cwe="CWE-295", evidence=terr[:200], confidence="medium"))

    # ---------- 协议版本与弱套件 ----------
    data["protocols_supported"] = _tls_protocols(host, int(port))
    legacy = [v for v in ("TLSv1", "TLSv1.1") if data["protocols_supported"].get(v) is True]
    if legacy:
        issues.append(_issue(
            "transport-security", "high", "传输安全",
            f"服务端仍接受过时协议：{'、'.join(legacy)}", endpoint,
            f"主动降级握手确认服务端接受 {'、'.join(legacy)}。这些协议存在已知缺陷"
            "（BEAST/POODLE 等），且不符合 PCI DSS 要求，攻击者可强制降级后解密流量。",
            "在服务端关闭 TLS 1.0/1.1（nginx `ssl_protocols TLSv1.2 TLSv1.3`；"
            "Tomcat `protocols=\"TLSv1.2,TLSv1.3\"`）。",
            cwe="CWE-326",
            evidence=f"supported={data['protocols_supported']}", confidence="high"))
    # 探测失败（本机 OpenSSL 已禁用该协议）时必须说清楚，否则会被读成"服务端不支持"
    unverified = [v for v in ("TLSv1", "TLSv1.1")
                  if data["protocols_supported"].get(v) is None]
    if unverified:
        data["protocol_probe_note"] = (
            f"{'、'.join(unverified)} 无法在本机完成握手探测（本地 OpenSSL 默认已禁用该协议），"
            "该项结论为「未验证」而非「不支持」，请用 openssl s_client -tls1 手工复核。")

    data["weak_ciphers"], data["weak_cipher_unprobeable"] = _tls_weak_ciphers(host, int(port))
    if data["weak_ciphers"]:
        names = "、".join(f"{fam}（{cip}）" for fam, cip in data["weak_ciphers"][:4])
        issues.append(_issue(
            "transport-security", "high", "传输安全",
            f"服务端接受弱加密套件 {len(data['weak_ciphers'])} 类", endpoint,
            f"主动协商确认服务端仍然接受以下弱套件：{names}。"
            "NULL/EXPORT/匿名套件等于没有加密或可被直接降级破解；RC4 与 3DES 已有实用攻击。",
            "仅保留 TLS 1.2/1.3 的 AEAD 套件（ECDHE+AES-GCM / CHACHA20），"
            "在服务端显式配置 cipher suite 白名单。",
            cwe="CWE-327", evidence=names, confidence="high"))
    if data["weak_cipher_unprobeable"]:
        data["weak_cipher_note"] = (
            f"以下弱套件族因本机 OpenSSL 未内置对应算法而无法探测："
            f"{'、'.join(data['weak_cipher_unprobeable'])}。这些族本次为「未验证」，"
            "请用具备 legacy provider 的 openssl 或专用工具复核。")

    summary = (f"TLS {version}，套件 {data['cipher'] or '未知'}，"
               f"证书剩余 {data['days_left']} 天，颁发者 {data['issuer'] or '未知'}")
    if data["weak_ciphers"]:
        summary += f"；⚠ 接受 {len(data['weak_ciphers'])} 类弱套件"
    if not match:
        summary += "；⚠ 证书主机名不匹配"
    return {"ok": True, "summary": summary, "data": data, "issues": issues}


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _cert_host_match(host: str, cert: dict) -> tuple[bool, str, list[str]]:
    """证书里的 SAN/CN 是否覆盖我们实际访问的主机名。

    SAN 为空时回退到 CN —— 现代浏览器已经不看 CN 了，但内网服务还大量这么签，
    所以两边都看，并把实际用到的名字回显在证据里，方便人工核对。

    通配符只允许出现在最左一段（`*.example.com` 匹配 `a.example.com`，
    但**不**匹配 `a.b.example.com`，也不匹配裸的 `example.com`）——
    这正是 RFC 6125 的语义，写宽了会把"名字其实对不上"的情况放过去。
    """
    dns = [v for k, v in cert.get("subjectAltName", ()) if k.lower() == "dns"]
    ips = [v for k, v in cert.get("subjectAltName", ()) if k.lower() == "ip address"]
    cn = ""
    for rdn in cert.get("subject", []):
        for k, v in rdn:
            if k.lower() == "commonname":
                cn = v
    names = dns + ips + ([cn] if cn else [])
    if not names:
        return True, "", []          # 无从判断，不报；宁可漏也不想造误报
    target = host.strip().lower().rstrip(".")

    if _is_ip_literal(target):
        for n in ips:
            if n.strip().lower() == target:
                return True, f"IP 精确匹配 {n}", names
        return False, "、".join(names[:6]), names

    for n in (dns or ([cn] if cn else [])):
        pat = n.strip().lower().rstrip(".")
        if not pat:
            continue
        if pat.startswith("*."):
            suffix = pat[2:]
            # 只允许少一层标签：a.example.com 命中，a.b.example.com 不命中
            if target.endswith("." + suffix) and "." not in target[: -len(suffix) - 1]:
                return True, f"通配符匹配 {n}", names
        elif pat == target:
            return True, f"精确匹配 {n}", names
    return False, "、".join(names[:6]), names


def _tls_chain_trusted(host: str, port: int) -> tuple[bool | None, str]:
    """用系统根证书校验整条链。返回 (是否受信, 错误文本)；None 表示无法判定。"""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((_resolve_host(host), port), timeout=8) as raw:
            with ctx.wrap_socket(raw, server_hostname=host):
                return True, ""
    except ssl.SSLCertVerificationError as e:
        return False, f"{e.verify_message or e}"
    except (ssl.SSLError, OSError) as e:
        return None, f"{type(e).__name__}: {e}"


def _tls_handshake(host: str, port: int, *, min_v=None, max_v=None,
                   ciphers: str = "", timeout: float = 6.0):
    """按指定协议区间/套件尝试一次握手；失败返回 None。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if min_v is not None:
        ctx.minimum_version = min_v
    if max_v is not None:
        ctx.maximum_version = max_v
    if ciphers:
        try:
            ctx.set_ciphers(ciphers)
        except (ssl.SSLError, ValueError):
            return None
    try:
        with socket.create_connection((_resolve_host(host), port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as ss:
                return (ss.version(), (ss.cipher() or ("",))[0])
    except Exception:
        return None


# 协议版本探测顺序：只探这两个「过时但仍在用」的版本，加上 1.3 做对照。
# 不去探 SSLv2/SSLv3 —— 现代 OpenSSL 已彻底移除，探测只会得到"本机不支持"，
# 既无信息量又容易被读成"服务端不支持"。
_TLS_PROBE_VERSIONS = [("TLSv1", "TLSv1"), ("TLSv1.1", "TLSv1_1"),
                       ("TLSv1.2", "TLSv1_2"), ("TLSv1.3", "TLSv1_3")]


def _tls_protocols(host: str, port: int) -> dict[str, bool | None]:
    """逐个协议版本做一次**只允许该版本**的握手。

    返回 True=服务端接受，False=服务端拒绝，None=本机无法完成探测
    （本地 OpenSSL 配置禁用了该协议）。三态是必要的：把 None 当成 False
    会给出一份"服务端已禁用 TLS 1.0"的假结论，这比不报更危险。
    """
    out: dict[str, bool | None] = {}
    for label, attr in _TLS_PROBE_VERSIONS:
        ver = getattr(ssl.TLSVersion, attr, None)
        if ver is None:
            out[label] = None
            continue
        got = _tls_handshake(host, port, min_v=ver, max_v=ver,
                             ciphers="DEFAULT@SECLEVEL=0")
        out[label] = bool(got)
    # 若连 1.2/1.3 都失败，多半是网络或探测方式的问题，整体可信度不足
    if not any(v for v in out.values()):
        return {k: None for k in out}
    return out


# 弱套件族：每族用一组关键词去 OpenSSL 的套件表里挑选实际可用的套件名。
# 直接用套件名列表硬编码会在不同 OpenSSL 版本上失配（3.0 改名过一批），
# 所以先枚举本机能力，再按关键词归类。
#
# 顺序有意义：命中按先后归属。`AECDH-NULL-SHA` 同时含 AECDH 与 NULL，
# 归到 NULL 更有价值（"没有加密"比"没有身份认证"更严重）。
_WEAK_CIPHER_FAMILIES: list[tuple[str, tuple[str, ...]]] = [
    ("NULL 加密（等于明文传输）", ("-NULL-", "-NULL", "NULL-SHA")),
    ("匿名密钥交换（无身份认证）", ("ADH-", "AECDH-", "ADH_")),
    ("EXPORT 级弱套件", ("EXPORT",)),
    ("RC4 流加密", ("RC4",)),
    ("3DES 弱分组加密", ("3DES", "DES-CBC3")),
    ("单 DES 弱分组加密", ("DES-CBC-", "DES40", "DES-CBC@")),
]

# 枚举本机全部套件必须显式打开 eNULL 并降安全等级：
# 默认上下文只列出安全等级 2 允许的套件（140 → 158 的差额全是 NULL 族），
# 不这么做，"服务端接受 NULL 套件"这种最严重的问题永远看不到。
_ALL_CIPHERS = "ALL:eNULL:@SECLEVEL=0"


def _tls_weak_ciphers(host: str, port: int) -> tuple[list[tuple[str, str]], list[str]]:
    """枚举服务端仍然接受的弱加密套件。

    返回 ``([(族名, 实际协商到的套件名)], [本机无法探测的族名])``。

    第二个返回值不能省。实测本机 OpenSSL 3.5 不再内置 legacy provider，
    RC4 / 3DES / DES / EXPORT 四族在本机**一个套件都没有**，探测必然为空。
    若把这种空当作"服务端不支持"，报告就会给出"未发现弱加密套件"的假结论——
    比不报更危险。所以本机没有的族必须显式列出来，让读者知道这是探测能力的
    边界，而不是目标的状态。
    """
    try:
        probe = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        probe.set_ciphers(_ALL_CIPHERS)
        available = [c["name"] for c in probe.get_ciphers()]
    except Exception:
        return [], [f for f, _ in _WEAK_CIPHER_FAMILIES]

    accepted: list[tuple[str, str]] = []
    unavailable: list[str] = []
    used: set[str] = set()
    for family, keys in _WEAK_CIPHER_FAMILIES:
        names = [n for n in available
                 if any(k in n.upper() for k in keys) and n not in used]
        if not names:
            unavailable.append(family)
            continue
        # 一次握手只带该族套件：服务端若握手成功，就说明它接受了这一族的某个套件
        got = _tls_handshake(host, port, max_v=ssl.TLSVersion.TLSv1_2,
                             ciphers=":".join(names[:24]) + "@SECLEVEL=0")
        if got:
            accepted.append((family, got[1]))
            used.add(got[1])
    return accepted, unavailable




# ============================================================ 并发 TCP 探测

PORT_SCAN_TIMEOUT = 1.1        # 单端口 connect 超时（秒）
PORT_SCAN_CONCURRENCY = 700    # 并发连接数
PORT_SCAN_BATCH = 4096         # 每批提交的协程数，避免一次性创建 6 万个任务


def _run_async(coro):
    """在同步上下文里驱动协程；若当前已在事件循环中则另起线程，避免嵌套报错。"""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(asyncio.run, coro).result()


def _resolve_host(host: str) -> str:
    """把域名解析成 IP：否则全端口扫描会退化成 6 万次 DNS 查询，慢到不可用。"""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        return socket.gethostbyname(host)
    except OSError:
        return host


async def _probe_one(ip: str, port: int, timeout: float,
                     sem: asyncio.Semaphore, sink: list[int]) -> None:
    async with sem:
        try:
            _r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        except (OSError, asyncio.TimeoutError, ValueError):
            return
        sink.append(port)
        w.close()
        try:
            await w.wait_closed()
        except (OSError, asyncio.TimeoutError):
            pass


def tcp_scan(host: str, ports: list[int], *, timeout: float = PORT_SCAN_TIMEOUT,
             concurrency: int = PORT_SCAN_CONCURRENCY) -> list[int]:
    """并发 TCP connect 扫描，返回升序的开放端口列表。"""
    ip = _resolve_host(host)

    async def runner() -> list[int]:
        sem = asyncio.Semaphore(concurrency)
        sink: list[int] = []
        for i in range(0, len(ports), PORT_SCAN_BATCH):
            await asyncio.gather(*(
                _probe_one(ip, p, timeout, sem, sink) for p in ports[i:i + PORT_SCAN_BATCH]))
        return sorted(sink)

    return _run_async(runner())


def _coerce_ports(raw) -> list[int]:
    """把 AI 传来的 ports 归一化成合法端口列表（容忍字符串/浮点/非法值）。"""
    out: set[int] = set()
    if isinstance(raw, (str, int, float)):
        raw = re.split(r"[,\s]+", str(raw))
    for item in (raw or []):
        try:
            p = int(str(item).strip())
        except (TypeError, ValueError):
            continue
        if 0 < p <= 65535:
            out.add(p)
    return sorted(out)


def _service_name(port: int) -> str:
    """端口 → 服务名：优先内置表，其次系统 services 表。"""
    for p, svc, _s, _n in COMMON_PORTS:
        if p == port:
            return svc
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


@tool("port_scan",
      "对主机做 TCP 端口连通性探测。mode=common 探测常见 28 个端口（快）；"
      "mode=full 并发扫描 1-65535 全部端口，用于发现非标准端口上的服务（通常 1-3 分钟）。"
      "只做 TCP connect，不发送任何应用层数据。",
      {"host": "str，主机名或 IP",
       "mode": "'common'（默认）或 'full'",
       "ports": "list[int]，可选，自定义端口列表（指定后忽略 mode）"},
      phase="recon", category="端口与服务")
def port_scan(sess: ScanSession, host: str, mode: str = "common", ports: list | None = None) -> dict:
    custom = _coerce_ports(ports)
    if custom:
        targets, scope = custom, "自定义"
    elif str(mode or "").strip().lower() in ("full", "all", "1-65535", "65535"):
        targets, scope = list(range(1, 65536)), "全端口"
    else:
        targets, scope = [p for p, _s, _v, _n in COMMON_PORTS], "常见端口"

    t0 = time.time()
    opened = tcp_scan(host, targets)
    cost = time.time() - t0

    known = {p: (svc, sev, note) for p, svc, sev, note in COMMON_PORTS}
    open_ports: list[dict] = []
    issues: list[dict] = []
    for port in opened:
        svc, sev, note = known.get(port, ("", None, ""))
        svc = svc or _service_name(port) or "unknown"
        open_ports.append({"port": port, "service": svc})
        if sev:
            issues.append(_issue(
                "port-exposure", sev, "端口暴露",
                f"{svc} 端口 {port} 对外可达",
                f"{host}:{port}",
                f"TCP 端口 {port}（{svc}）可从外部建立连接。{note}",
                "通过防火墙或安全组限制该端口仅对可信来源开放；数据库与缓存服务不应直接暴露在业务网络。",
                cwe="CWE-284", evidence=f"{host}:{port} open", confidence="high"))

    data = {"host": host, "mode": scope, "scanned": len(targets), "open": open_ports,
            "open_count": len(open_ports), "cost_sec": round(cost, 1),
            "risky": [i["title"] for i in issues]}
    return {"ok": True,
            "summary": f"{scope}扫描 {len(targets)} 个端口（{cost:.1f}s），开放 {len(open_ports)} 个"
                       + (f"，其中高风险 {len(issues)} 个" if issues else ""),
            "data": data, "issues": issues}


# ============================================================ 扫描类工具

@tool("header_audit", "检查 HTTP 安全响应头（HSTS / CSP / X-Frame-Options / X-Content-Type-Options 等）是否配置到位。",
      {"url": "str，目标 URL"}, phase="scan", category="安全配置")
def header_audit(sess: ScanSession, url: str) -> dict:
    resp, err = sess.request("GET", url)
    if resp is None:
        return {"ok": False, "summary": f"请求失败：{err}", "data": {"url": url, "error": err}, "issues": []}

    lower = {k.lower(): v for k, v in resp.headers.items()}
    present, missing = {}, []
    for name, sev, detail, advice in SECURITY_HEADERS:
        val = lower.get(name.lower(), "")
        if val:
            present[name] = val[:160]
        else:
            # HSTS 只对 HTTPS 有意义
            if name == "Strict-Transport-Security" and urlparse(url).scheme != "https":
                continue
            missing.append((name, sev, detail, advice))

    issues = [
        _issue("security-headers", sev, "安全配置", f"缺少安全响应头 {name}", url, detail, advice,
               cwe="CWE-693", evidence=f"响应中未出现 {name}", confidence="high")
        for name, sev, detail, advice in missing
    ]
    return {"ok": True, "summary": f"已配置 {len(present)} 项，缺失 {len(missing)} 项",
            "data": {"url": url, "present": present,
                     "missing": [m[0] for m in missing],
                     "raw": {k: v for k, v in lower.items() if k in
                             ("server", "content-type", "x-powered-by", "via", "x-cache")}},
            "issues": issues}


# 会话 Cookie 的常见下发端点：首页通常不下发 Cookie，
# 若只探首页，「Cookie 属性缺失」这一整类问题会漏报。
COOKIE_PROBE_PATHS = ["/login", "/admin", "/api/user", "/user/login", "/index.html"]


@tool("cookie_audit", "检查响应 Set-Cookie 的安全属性：HttpOnly、Secure、SameSite，判断会话 Cookie 是否可被脚本窃取或跨站携带。若首页未下发 Cookie 会自动补测常见会话端点。",
      {"url": "str，目标 URL"}, phase="scan", category="安全配置")
def cookie_audit(sess: ScanSession, url: str) -> dict:
    base = origin_of(url)

    def collect(resp) -> list[str]:
        if hasattr(resp.headers, "get_list"):
            return [c for c in resp.headers.get_list("set-cookie") if c]
        return [resp.headers["set-cookie"]] if "set-cookie" in resp.headers else []

    resp, err = sess.request("GET", url)
    if resp is None:
        return {"ok": False, "summary": f"请求失败：{err}", "data": {"url": url, "error": err}, "issues": []}

    raw = collect(resp)
    tested = [url]                        # 实际请求过的探测点（首页 + 补测端点）
    cookie_from: list[str] = [url] if raw else []   # 真正下发 Cookie 的端点
    if not raw and urlparse(url).path in ("", "/"):
        for p in COOKIE_PROBE_PATHS:
            r2, _ = sess.request("GET", base + p)
            if r2 is None:
                continue
            tested.append(base + p)       # 无论是否命中都要记账，否则"探了 6 个"会显示成"探测点 1 个"
            got = collect(r2)
            if got:
                raw = got
                cookie_from.append(base + p)
                break

    is_https = urlparse(url).scheme == "https"
    cookies, issues = [], []

    for c in raw:
        parts = [p.strip() for p in c.split(";")]
        if not parts or "=" not in parts[0]:
            continue
        name, value = parts[0].split("=", 1)
        flags = {p.split("=")[0].strip().lower() for p in parts[1:]}
        session_like = not re.search(r"expires|max-age", c, re.I)
        cookies.append({"name": name, "http_only": "httponly" in flags, "secure": "secure" in flags,
                        "same_site": next((p.split("=")[1] for p in parts[1:] if p.lower().startswith("samesite=")), ""),
                        "session": session_like})

        if session_like and "httponly" not in flags:
            issues.append(_issue(
                "cookie-security", "medium", "会话安全", f"会话 Cookie「{name}」缺少 HttpOnly", url,
                f"Cookie `{name}` 未设置 HttpOnly，任一 XSS 都可直接读取该会话凭据。",
                "为所有会话 Cookie 添加 `HttpOnly` 与 `Secure` 属性，并显式设置 `SameSite=Lax` 或 `Strict`。",
                cwe="CWE-1004", evidence=f"Set-Cookie: {name}=***{';' if len(parts) > 1 else ''} {';'.join(parts[1:])[:120]}",
                confidence="high"))
        if is_https and "secure" not in flags:
            issues.append(_issue(
                "cookie-security", "medium", "会话安全", f"Cookie「{name}」未设置 Secure", url,
                f"站点使用 HTTPS，但 Cookie `{name}` 未标记 Secure，可能通过明文链路泄漏。",
                "为 Cookie 添加 `Secure` 属性。", cwe="CWE-614",
                evidence=f"Set-Cookie: {name}=***", confidence="high"))
        if "samesite" not in flags and session_like:
            issues.append(_issue(
                "cookie-security", "low", "会话安全", f"会话 Cookie「{name}」未显式设置 SameSite", url,
                f"Cookie `{name}` 未声明 SameSite，浏览器默认策略在不同版本间不一致，存在被跨站携带的风险。",
                "显式设置 `SameSite=Lax`（或 Strict）。", cwe="CWE-1275",
                evidence=f"Set-Cookie: {name}=***", confidence="medium"))

    return {"ok": True,
            "summary": f"探测 {len(tested)} 个端点，发现 {len(cookies)} 个 Cookie，{len(issues)} 项属性缺失",
            "data": {"url": url, "tested": tested, "cookie_from": cookie_from,
                     "cookies": cookies}, "issues": issues}


@tool("cors_check", "用伪造的跨站 Origin 探测 CORS 策略，判断是否存在任意源可读、或「反射 Origin + 允许凭据」的严重配置错误。",
      {"url": "str，目标 URL"}, phase="scan", category="安全配置")
def cors_check(sess: ScanSession, url: str) -> dict:
    probe_origin = "https://aiholey-cors-probe.example"
    resp, err = sess.request("GET", url, headers={"Origin": probe_origin})
    if resp is None:
        return {"ok": False, "summary": f"请求失败：{err}", "data": {"url": url, "error": err}, "issues": []}

    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
    acam = resp.headers.get("Access-Control-Allow-Methods", "")
    acah = resp.headers.get("Access-Control-Allow-Headers", "")
    reflects = acao.strip() == probe_origin
    wildcard = acao.strip() == "*"
    data = {"url": url, "allow_origin": acao, "allow_credentials": acac,
            "allow_methods": acam, "allow_headers": acah,
            "reflects_arbitrary_origin": reflects, "wildcard": wildcard}

    issues: list[dict] = []
    if reflects and acac == "true":
        issues.append(_issue(
            "cors-misconfig", "high", "安全配置", "CORS 反射任意 Origin 且允许携带凭据", url,
            f"服务端把请求中的 `Origin`（{probe_origin}）原样回显到 `Access-Control-Allow-Origin`，"
            "同时 `Access-Control-Allow-Credentials: true`。任意站点都能以受害者身份读取受保护接口的响应，等同于绕过同源策略。",
            "改为白名单校验 Origin（显式列举可信域），不要直接回显请求头；确需跨域时避免同时开启凭据。",
            cwe="CWE-942", evidence=f"Origin: {probe_origin} → ACAO: {acao}; ACAC: {acac}", confidence="high"))
    elif wildcard and acac == "true":
        issues.append(_issue(
            "cors-misconfig", "medium", "安全配置", "CORS 通配符与凭据同时开启", url,
            "`Access-Control-Allow-Origin: *` 与 `Access-Control-Allow-Credentials: true` 同时出现，配置语义冲突且过于宽松。",
            "改为显式 Origin 白名单；若无需携带凭据则关闭 ACAC。",
            cwe="CWE-942", evidence=f"ACAO: {acao}; ACAC: {acac}", confidence="high"))
    elif wildcard:
        issues.append(_issue(
            "cors-misconfig", "low", "安全配置", "CORS 允许任意源访问", url,
            "`Access-Control-Allow-Origin: *` 允许任意站点读取响应。若该接口返回非公开数据，应改为白名单。",
            "对返回业务数据的接口使用显式 Origin 白名单。",
            cwe="CWE-942", evidence=f"ACAO: {acao}", confidence="medium"))

    return {"ok": True, "summary": f"ACAO={acao or '未设置'}，ACAC={acac or '未设置'}",
            "data": data, "issues": issues}


def _method_ignored(sess: ScanSession, url: str, got: httpx.Response | None) -> bool:
    """该方法的 2xx 是否只是「服务器没理会方法」——即响应与普通 GET 无法区分。

    「对根路径发 PUT 得到 200」并不等于服务器真的接受写入。实测本机有两类噪声源：

    ① 方法被忽略：Express 用 `app.all('*')` 之类的兜底处理器，PUT/DELETE/TRACE 的响应
       与普通 GET **逐字节相同**（实测 127.0.0.1:3334 对任意方法都只回 `OK`）。
    ② 端点一律应答：本地 IPC 类服务对任何请求都返回同一个响应，只是内容每次随机
       （实测 127.0.0.1:4310：状态 200、恒定 360 字节、无 Content-Type），
       指纹不可比，于是退化成「长度 + Content-Type」同构判断。

    两种情况的本质一致：**服务器对该方法的响应和普通 GET 分不出区别**，说明它并没有
    按 HTTP 语义处理这个方法。此时报「PUT/DELETE 可用」属于误报。

    注意不要用「对不存在的随机路径也返回同样状态码」来排除：REST/WebDAV 的 PUT 本就
    会在不存在的路径上创建资源并返回 2xx，那样判会误杀真实命中。
    """
    if got is None:
        return False
    base = None
    try:
        base, _ = sess.request("GET", url)
    except (httpx.HTTPError, OSError, BudgetExceeded):
        return False
    if base is None or base.status_code != got.status_code:
        return False
    gb, rb = base.content or b"", got.content or b""
    if len(gb) != len(rb):
        return False
    if _body_signature(base) == _body_signature(got):
        return True
    # 内容每次随机的端点指纹不可比，退化为「长度 + Content-Type」；空响应体不参与，
    # 否则真实的 204 No Content 会被误判成「未处理」。
    return len(gb) > 0 and _content_type(base) == _content_type(got)


# 真实 TRACE 会把请求行原样回显（Apache `TraceEnable on` 即如此）。
# 这是 TRACE 唯一可靠的判据：**不能**用「随机路径也返回 200」排除它——
# 开启 TRACE 的服务器对任意路径都会回显，那样判会把真实命中误杀。
_TRACE_ECHO_RE = re.compile(rb"(?i)\btrace\s+\S+\s+http/1\.[01]")


def _trace_echoed(resp: httpx.Response | None) -> bool:
    """响应体里是否回显了请求行，即 TRACE 是否真的被服务端处理。"""
    if resp is None:
        return False
    return bool(_TRACE_ECHO_RE.search((resp.content or b"")[:4096]))


@tool("http_methods", "探测目标实际允许的 HTTP 方法（OPTIONS/TRACE/PUT/DELETE），识别危险的 TRACE 与写入类方法。",
      {"url": "str，目标 URL"}, phase="scan", category="安全配置")
def http_methods(sess: ScanSession, url: str) -> dict:
    resp, err = sess.request("OPTIONS", url)
    allow = resp.headers.get("Allow", "") if resp else ""
    allowed = [m.strip().upper() for m in allow.split(",") if m.strip()]
    probed: dict[str, int] = {}
    issues: list[dict] = []
    notes: list[str] = []

    if resp:
        probed["OPTIONS"] = resp.status_code
    method_resp: dict[str, httpx.Response] = {}
    for m in ("TRACE", "PUT", "DELETE"):
        if m in allowed or not allowed:
            r2, e2 = sess.request(m, url)
            if r2 is not None:
                probed[m] = r2.status_code
                method_resp[m] = r2
            elif e2:
                probed[m] = -1

    # 只在疑似命中时做加固验证，避免在干净目标上白花请求预算
    skipped: list[str] = []

    if probed.get("TRACE") == 200:
        if _trace_echoed(method_resp.get("TRACE")):
            issues.append(_issue(
                "http-methods", "medium", "安全配置", "TRACE 方法已启用", url,
                "TRACE 会原样回显请求内容，配合浏览器漏洞可构成跨站追踪攻击（XST）。",
                "在 Web 服务器配置中禁用 TRACE（Apache: `TraceEnable off`；Nginx: 只允许 GET/POST）。",
                cwe="CWE-749", evidence=f"TRACE → 200，响应体已回显请求行",
                method="TRACE", confidence="high"))
        else:
            skipped.append("TRACE（响应体未回显请求内容，服务器未真正处理 TRACE）")

    for m in ("PUT", "DELETE"):
        if probed.get(m) not in (200, 201, 204):
            continue
        if _method_ignored(sess, url, method_resp.get(m)):
            skipped.append(f"{m}（响应与普通 GET 无法区分，服务器未处理 {m} 语义）")
            continue
        issues.append(_issue(
            "http-methods", "high", "安全配置", f"{m} 方法可用", url,
            f"目标对 {m} 请求返回 {probed[m]}，且响应与普通 GET 有明显区别，"
            "说明该资源接受了写入/删除类操作。若缺少鉴权，攻击者可直接篡改或删除数据。",
            f"确认该端点是否必须开放 {m}；如仅用于内部管理，请加鉴权并限制来源。",
            cwe="CWE-650", evidence=f"{m} {url} → {probed[m]}", method=m, confidence="medium"))

    if skipped:
        notes.append("以下方法虽返回 2xx，但经加固验证判定为误报，未计入问题：" + "；".join(skipped))

    return {"ok": True, "summary": f"Allow: {allow or '（未返回）'}；实测 {probed}",
            "data": {"url": url, "allow_header": allow, "probed": probed},
            "issues": issues, "notes": notes}


@tool("dir_scan", "对目标做轻量目录/文件遍历，寻找管理后台、接口文档、调试页面等非公开入口。默认使用内置小字典。",
      {"url": "str，站点根地址", "wordlist": "list[str]，可选，自定义路径列表"},
      phase="scan", category="内容发现")
def dir_scan(sess: ScanSession, url: str, wordlist: list | None = None) -> dict:
    base = origin_of(url) if urlparse(url).path in ("", "/") else url.rstrip("/")
    words = [w for w in (wordlist or DIR_WORDLIST)][:120]
    found, interesting = [], []
    fb = FallbackBaseline(sess, base)   # 软 404 站点必须靠基线排除，否则全量误报

    for w in words:
        target = f"{base}/{str(w).lstrip('/')}"
        resp, _ = sess.request("GET", target)
        if resp is None:
            continue
        if fb.is_fallback(resp) or _looks_like_fallback(resp):
            continue
        if resp.status_code in (200, 401, 403, 500) and resp.status_code != 404:
            body = resp.text or ""
            entry = {"path": f"/{str(w).lstrip('/')}", "status": resp.status_code,
                     "length": len(resp.content or b""), "title": _title_of(body)}
            found.append(entry)
            noisy = {"index of /", "directory listing for", "apache tomcat", "whitelabel error page"}
            if 200 <= resp.status_code < 300 and _title_of(body).lower() not in noisy and len(resp.content or b"") > 0:
                interesting.append(entry)

    issues: list[dict] = []
    for e in found:
        low = e["path"].lower()
        if e["status"] in (401, 403):
            continue  # 被拒绝说明有防护，不算问题
        if any(k in low for k in ("/actuator", "/druid", "/console", "/admin", "/manage", "/swagger", "/api-docs")):
            sev = "low"
            issues.append(_issue(
                "content-discovery", sev, "内容发现", f"发现受保护入口 {e['path']}", f"{base}{e['path']}",
                f"路径 `{e['path']}` 返回 {e['status']}（{e['length']} 字节，标题「{e['title'] or '无'}」），"
                "属于管理/监控类入口，是攻击者优先尝试的目标。",
                "确认该入口已启用强认证，并限制来源 IP；生产环境关闭不必要的管理端点。",
                cwe="CWE-200", evidence=f"GET {e['path']} → {e['status']}", confidence="medium"))

    if not found:
        return {"ok": True, "summary": f"遍历 {len(words)} 个路径，未发现明显可疑入口",
                "data": {"base": base, "scanned": len(words), "found": [], "interesting": []},
                "issues": [], "notes": [n for n in [soft404_note(fb, base)] if n]}

    return {"ok": True, "summary": f"遍历 {len(words)} 个路径，命中 {len(found)} 个（其中 {len(interesting)} 个可正常访问）",
            "data": {"base": base, "scanned": len(words), "found": found, "interesting": interesting},
            "issues": issues, "notes": [n for n in [soft404_note(fb, base)] if n]}


@tool("sensitive_paths", "探测高危敏感文件与端点：配置文件、源码仓库元数据、备份包、Spring Actuator、接口文档、监控台等。命中即为真实泄漏。",
      {"url": "str，站点根地址"}, phase="scan", category="敏感文件")
def sensitive_paths(sess: ScanSession, url: str) -> dict:
    base = origin_of(url)
    hits, issues = [], []
    fb = FallbackBaseline(sess, base)   # 软 404 站点必须靠基线排除

    for path, sev, title, detail, advice, cwe in SENSITIVE_PATHS:
        target = f"{base}/{path}"
        resp, _ = sess.request("GET", target)
        if resp is None or resp.status_code != 200:
            continue
        body = resp.content or b""      # 传原始字节：先解码会丢掉二进制魔数
        size = len(body)
        # 排除「站点把所有未知路径都返回 200」的情况：与基线/SPA 壳同构则不算真实命中
        if size < 12 or fb.is_fallback(resp) or _looks_like_fallback(resp):
            continue
        hits.append({"path": f"/{path}", "status": 200, "length": size, "severity": sev})
        issues.append(_issue(
            "sensitive-file", sev, "敏感文件", title, target,
            f"{detail}（实测 `GET /{path}` 返回 200，内容 {size} 字节）",
            advice, cwe=cwe,
            evidence=_snippet(body, needle=path.split("/")[-1], width=260), confidence="high"))

    return {"ok": True, "summary": f"探测 {len(SENSITIVE_PATHS)} 个敏感路径，确认泄漏 {len(hits)} 个",
            "data": {"base": base, "probed": len(SENSITIVE_PATHS), "hits": hits},
            "issues": issues, "notes": [n for n in [soft404_note(fb, base)] if n]}


@tool("redirect_check", "用常见跳转参数探测开放重定向：把参数指向外部域名，观察是否被 Location 原样采纳。",
      {"url": "str，带跳转功能的页面 URL"}, phase="scan", category="逻辑缺陷")
def redirect_check(sess: ScanSession, url: str) -> dict:
    evil = "https://aiholey-redirect-probe.example/landing"
    joiner = "&" if "?" in url else "?"
    tested, issues = [], []

    for param in REDIRECT_PARAMS:
        target = f"{url}{joiner}{param}={evil}"
        resp, _ = sess.request("GET", target)
        if resp is None:
            continue
        loc = resp.headers.get("Location", "")
        if resp.status_code in (301, 302, 303, 307, 308) and "aiholey-redirect-probe.example" in loc:
            tested.append({"param": param, "status": resp.status_code,
                           "location": loc, "url": target})

    # 同一页面上多个跳转参数都不可控，本质是同一个根因，合并成一条更利于阅读
    if tested:
        params = [t["param"] for t in tested]
        first = tested[0]
        head = (f"开放重定向（{len(params)} 个参数可利用）" if len(params) > 1
                else f"开放重定向（参数 {params[0]}）")
        detail = (f"参数 `{'`、`'.join(params)}` 的取值被直接用作跳转目标，服务端返回 3xx "
                  "并跳转到外部域名。攻击者可借此把钓鱼链接伪装成可信域名下的地址，"
                  "也可用于绕过 SSO 回调白名单把授权码带到外部站点。")
        if len(params) > 1:
            detail = f"该入口共有 {len(params)} 个跳转参数均未做校验。" + detail
        issues.append(_issue(
            "open-redirect", "high", "逻辑缺陷", head, first["url"], detail,
            "跳转目标改为服务端维护的白名单或相对路径，禁止直接使用请求参数；"
            "确需跳到外部地址时，校验域名后缀并对用户做二次确认。",
            cwe="CWE-601",
            evidence="\n".join(f"{t['param']} → {t['status']} Location: {t['location']}"
                               for t in tested),
            param=", ".join(params), payload=evil, confidence="high"))

    return {"ok": True, "summary": f"测试 {len(REDIRECT_PARAMS)} 个常见跳转参数，确认开放重定向 {len(tested)} 处",
            "data": {"url": url, "tested_params": REDIRECT_PARAMS, "vulnerable": tested}, "issues": issues}


@tool("info_leak", "检查响应内容中的信息泄漏：HTML 注释里的内部备注、邮箱、内网 IP、绝对路径、异常堆栈，以及错误页是否回显细节。",
      {"url": "str，目标 URL"}, phase="scan", category="信息泄漏")
def info_leak(sess: ScanSession, url: str) -> dict:
    resp, err = sess.request("GET", url)
    if resp is None:
        return {"ok": False, "summary": f"请求失败：{err}", "data": {"url": url, "error": err}, "issues": []}

    body = resp.text or ""
    issues: list[dict] = []
    data: dict = {"url": url, "findings": {}}

    comments = [c.strip() for c in _HTML_COMMENT_RE.findall(body)]
    meaningful = [c for c in comments if len(c) > 8 and not re.match(r"^\[?if\s", c, re.I)][:5]
    if meaningful:
        data["findings"]["html_comments"] = meaningful
        issues.append(_issue(
            "info-leak", "low", "信息泄漏", "页面注释残留内部信息", url,
            f"页面源码中存在 {len(meaningful)} 处有内容的注释，可能包含调试备注、内部主机名或待办说明。",
            "构建发布时移除源码注释。", cwe="CWE-615",
            evidence=" | ".join(meaningful)[:300], confidence="medium"))

    emails = list(dict.fromkeys(_EMAIL_RE.findall(body)))[:6]
    if emails:
        data["findings"]["emails"] = emails
        issues.append(_issue("info-leak", "info", "信息泄漏", "页面暴露邮箱地址", url,
                             f"页面中出现 {len(emails)} 个邮箱地址，可用于钓鱼与账号枚举。",
                             "对联系方式做图片化或前端混淆处理。", cwe="CWE-200",
                             evidence=", ".join(emails), confidence="medium"))

    ips = list(dict.fromkeys(_PRIVATE_IP_RE.findall(body)))[:6]
    if ips:
        data["findings"]["internal_ips"] = ips
        issues.append(_issue("info-leak", "low", "信息泄漏", "页面暴露内网地址", url,
                             f"页面内容包含内网 IP：{', '.join(ips)}，泄漏了内部网络拓扑。",
                             "移除返回内容中的内网地址，改用相对路径或网关地址。", cwe="CWE-200",
                             evidence=", ".join(ips), confidence="medium"))

    stack = _STACK_RE.search(body)
    if stack:
        data["findings"]["stack_trace"] = _snippet(body, stack.group(0)[:24], 300)
        issues.append(_issue("info-leak", "medium", "信息泄漏", "响应中出现异常堆栈", url,
                             "服务端把异常详情回显到了响应中，攻击者可据此摸清框架版本、代码路径与内部类结构。",
                             "统一异常处理，向用户返回通用错误页，详细堆栈只写服务端日志。",
                             cwe="CWE-209", evidence=data["findings"]["stack_trace"], confidence="high"))

    paths = list(dict.fromkeys(_ABS_PATH_RE.findall(body)))[:5]
    if paths:
        data["findings"]["abs_paths"] = paths
        issues.append(_issue("info-leak", "low", "信息泄漏", "响应暴露服务器绝对路径", url,
                             f"响应中出现服务器路径：{', '.join(paths)}。",
                             "移除响应中的文件系统路径。", cwe="CWE-200",
                             evidence=", ".join(paths), confidence="medium"))

    # 触发一次 404，看错误页是否也回显细节
    probe = f"{origin_of(url)}/aiholey-not-exist-{int(time.time())}"
    r404, _ = sess.request("GET", probe)
    if r404 is not None:
        b404 = r404.text or ""
        m = _STACK_RE.search(b404) or _ABS_PATH_RE.search(b404)
        data["error_page"] = {"url": probe, "status": r404.status_code,
                              "server": r404.headers.get("Server", ""),
                              "leaks_detail": bool(m)}
        if m:
            issues.append(_issue(
                "info-leak", "medium", "信息泄漏", "错误页面回显服务端细节", probe,
                f"请求不存在的路径时，响应中出现了框架或路径细节：`{_snippet(b404, m.group(0)[:24], 180)}`。",
                "统一 404 页面，去除框架版本与堆栈信息。", cwe="CWE-209",
                evidence=_snippet(b404, m.group(0)[:24], 240), confidence="medium"))

    if not issues:
        return {"ok": True, "summary": "未发现明显的信息泄漏", "data": data, "issues": []}
    return {"ok": True, "summary": f"发现 {len(issues)} 处信息泄漏", "data": data, "issues": issues}


def _looks_like_fallback(resp: httpx.Response) -> bool:
    """判断是否「所有路径都返回同一个 200 页面」的假命中。

    典型特征是 SPA 的 index.html 兜底：Content-Type 是 HTML 但内容是前端框架壳，
    这类响应不能当作敏感文件泄漏。
    """
    ctype = (resp.headers.get("Content-Type") or "").lower()
    body = (resp.text or "")[:4000]
    if "text/html" not in ctype:
        return False
    spa_markers = ("<div id=\"root\">", "<div id=\"app\">", "__NEXT_DATA__", "ng-version")
    return any(m in body for m in spa_markers) and _EMAIL_RE.search(body) is None and "config" not in body[:200].lower()


def _signature_of(body: bytes) -> str:
    """内容指纹：归一化空白后取摘要，用于识别「每次返回同一页面」的兜底行为。"""
    norm = re.sub(rb"\s+", b" ", (body or b"")[:2048]).strip()
    return hashlib.sha1(norm).hexdigest()[:16]


def _body_signature(resp: httpx.Response) -> str:
    """响应的内容指纹；与 ``_signature_of`` 同一算法，薄封装。"""
    return _signature_of(resp.content or b"")


def _content_type(resp: httpx.Response) -> str:
    """取 Content-Type 的主类型（去掉 charset 等参数），用于兜底页同构比对。"""
    return (resp.headers.get("content-type") or "").split(";")[0].strip().lower()


class FallbackBaseline:
    """软 404 基线。

    不少站点（SPA、Nginx try_files 配错、框架兜底路由）对**任意不存在的路径**
    也返回 200 和同一个页面。此时任何「路径存在」的判定都会全量误报——
    实测在验证靶场上，这会把 20 多个根本没实现的路径全报成敏感文件泄漏。

    做法：先用一个必然不存在的随机路径采样基线；只有基线本身是 2xx
    （即站点确实有软 404）时，后续响应若与之同构就被判定为兜底页丢弃。

    还有一种更刁钻的兜底：**响应体每次都被随机化**（本地 IPC / 加密通道、
    带 nonce 的兜底页）。实测本机 QQ 的本地 HTTP 服务（127.0.0.1:4310）就是——
    对任意路径一律 `200` + 恒定 360 字节，但内容每次都不同。
    此时指纹比对和「首字节比对」永远不可能相等，两道判据一起失效，
    整站路径类结论会全量误报（实测一次扫描刷出 30+ 条假的「备份泄漏」）。

    对这类端点，靠**再采样一次**识别出来：同一路径两次响应「状态码与长度都一致、
    内容指纹却不同」→ 内容在随机化，指纹不可比，改判据为
    「状态码 + 精确长度 + Content-Type 三者一致」。
    """

    def __init__(self, sess: ScanSession, base: str):
        self.soft = False
        self.dynamic = False          # 兜底页内容是否每次随机（指纹不可比）
        self._status = 0
        self._length = 0
        self._head = b""
        self._sig = ""
        self._ctype = ""
        probe = f"{base.rstrip('/')}/aih0ley-missing-{int(time.time() * 1000)}-{os.getpid()}.txt"
        first = self._fetch(sess, probe)
        if first is None:
            return
        self.soft = True
        self._status = first.status_code
        self._length = len(first.content or b"")
        self._head = (first.content or b"")[:64]
        self._sig = _body_signature(first)
        self._ctype = _content_type(first)
        # 第二次采同一路径，验证兜底页是否「同形不同内容」
        second = self._fetch(sess, probe)
        if second is not None:
            same_shape = (second.status_code == self._status
                          and len(second.content or b"") == self._length)
            if same_shape and _body_signature(second) != self._sig:
                self.dynamic = True

    @staticmethod
    def _fetch(sess: ScanSession, url: str) -> httpx.Response | None:
        """采一次基线；失败（网络错误 / 预算耗尽）一律返回 None，不影响主流程。"""
        try:
            resp, _err = sess.request("GET", url)
        except (httpx.HTTPError, OSError, BudgetExceeded):
            return None
        return resp if 200 <= resp.status_code < 300 else None

    @property
    def status(self) -> int:
        """软 404 基线返回的状态码；未识别到软 404 时为 0。"""
        return self._status

    def is_fallback(self, resp: httpx.Response | None) -> bool:
        if not self.soft or resp is None:
            return False
        return self.matches(resp.status_code, resp.content or b"", _content_type(resp))

    def matches(self, status: int, body: bytes, ctype: str = "") -> bool:
        """与 ``is_fallback`` 同一套判据，但吃原始三元组。

        裸 socket 通道（``request_exact_path``）拿不到 httpx.Response 对象，
        而目录遍历必须走那条通道（否则 `../` 会被 httpx 归一化掉）。
        判据只能有一份——两处各写一套迟早会漂移，误报就会从没加固的那处漏出来。
        """
        if not self.soft:
            return False
        if status != self._status:
            return False
        # 强证据：内容指纹完全一致 —— 同一个兜底页
        if _signature_of(body) == self._sig:
            return True
        if self.dynamic:
            # 内容每次都在变，指纹与首字节都不可比；
            # 「状态码 + 精确长度 + Content-Type」一致已是可用的最强判据
            # （兜底响应长度稳定在固定值，真实文件刚好同长度且同类型极为罕见）。
            return len(body) == self._length and (ctype or "").split(";")[0].strip().lower() == self._ctype
        # 弱证据：长度几乎一致「且」开头字节一致。
        # 不能只比长度——不同文件刚好长度相近很常见，只按长度会误杀真实命中。
        return abs(len(body) - self._length) <= 2 and body[:64] == self._head


def soft404_note(fb: FallbackBaseline, base: str) -> str:
    """软 404 站点必须显式告知：这类端点的「路径存在」类结论天然不可靠。

    没有这条说明，用户看到"没扫出问题"会理解成"目标干净"，
    而真实含义是"这个端点对什么都返回 200，路径发现在这里没有判别力"。
    """
    if not fb.soft:
        return ""
    if fb.dynamic:
        return (f"{base} 对任意路径均返回 {fb.status} 且响应体每次随机化，"
                f"已改按「状态码 + 长度」过滤兜底页；该端点的路径发现类结论可信度较低。")
    return (f"{base} 对任意路径均返回 {fb.status}（软 404），已启用兜底页过滤，"
            f"路径类命中均已排除兜底响应。")


# ============================================================ 编排

def run_tool(sess: ScanSession, name: str, args: dict) -> dict:
    """按名字执行工具，异常一律转成结构化失败结果（AI 需要看到失败原因才能改策略）。"""
    entry = TOOLS.get(name)
    if not entry:
        return {"ok": False, "summary": f"未知工具：{name}",
                "data": {"available": list(TOOLS)}, "issues": []}
    fn = entry["fn"]
    # 只保留该工具声明接受的参数。调用方（尤其是 AI，以及补跑时的统一传参）
    # 常会多塞 url/host，多余的键会让 fn(**args) 抛 TypeError，
    # 而异常被下面吞成 ok=False —— 表现为工具"跑了但什么都没发现"，极难排查。
    allowed = set(entry["params"].keys())
    args = {k: v for k, v in (args or {}).items() if k in allowed}
    try:
        out = fn(sess, **args)
    except BudgetExceeded as e:
        return {"ok": False, "summary": f"请求预算耗尽，停止调用：{e}", "data": {}, "issues": [], "fatal": True}
    except TypeError as e:
        return {"ok": False, "summary": f"参数不匹配：{e}", "data": {"参数要求": entry["params"]}, "issues": []}
    except Exception as e:
        return {"ok": False, "summary": f"工具执行异常：{type(e).__name__}: {e}", "data": {}, "issues": []}
    out.setdefault("issues", [])
    out.setdefault("data", {})
    return out
