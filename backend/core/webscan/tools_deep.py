"""Web 扫描深度工具集 —— 端口服务识别与更深入的渗透探测。

与 tools.py 的分工
------------------
tools.py 负责「对 HTTP 端点」的常规检查；本模块负责「对端口/服务」以及
「需要主动构造探测载荷」的深度检查。两者共用 tools.py 里的工具注册表，
只要本模块被 import，其中的 @tool 就会自动注册。

安全边界（与 tools.py 一致，并额外自我约束）
--------------------------------------------
- 未授权访问检测只发**只读**命令（Redis PING/INFO、Elasticsearch GET、Docker GET /version
  等），绝不执行写入、删除、改配置类操作；
- 参数型漏洞探测只发送**探测性**载荷用于触发响应差异（引号触发 SQL 报错、唯一 token
  检测反射），不构造写库/写文件语句；
- 所有探测载荷都带唯一标识串，用于把「真实命中」与「泛泛回显」区分开，压低误报。
"""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import ssl
import time
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from backend.core.webscan.tools import (
    BudgetExceeded,
    DEFAULT_UA,
    DISCOVERED_LANDING_CAP,
    FallbackBaseline,
    soft404_note,
    ScanSession,
    _issue,
    _looks_like_fallback,
    _resolve_host,
    _signature_of,
    _snippet,
    origin_of,
    host_of,
    tool,
    uniq,
    dedup_issues,
)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# ============================================================ 原始 TCP 交互

def _tcp_talk(host: str, port: int, *, send: bytes = b"", read_timeout: float = 3.0,
              use_tls: bool = False, limit: int = 4096) -> tuple[bytes, str]:
    """建立 TCP 连接（可选 TLS），发送 send 并读取响应。

    ``send`` 为空时只做被动 banner 读取——SSH / FTP / SMTP / MySQL 等服务
    会在连接建立后主动送出 banner，这是最不打扰目标的识别方式。
    返回 ``(原始字节, 错误信息)``。
    """
    ip = _resolve_host(host)
    try:
        sock = socket.create_connection((ip, port), timeout=read_timeout)
    except (OSError, socket.timeout) as e:
        return b"", f"{type(e).__name__}: {e}"
    tls_sock = sock
    try:
        sock.settimeout(read_timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            tls_sock = ctx.wrap_socket(sock, server_hostname=None if _is_ip(host) else host)
        if send:
            tls_sock.sendall(send)
        chunks: list[bytes] = []
        got = 0
        while got < limit:
            try:
                part = tls_sock.recv(min(2048, limit - got))
            except (socket.timeout, OSError, ssl.SSLError):
                break
            if not part:
                break
            chunks.append(part)
            got += len(part)
            if not send:
                break           # 被动 banner 读到一段就够了
        return b"".join(chunks), ""
    except (OSError, ssl.SSLError) as e:
        return b"", f"{type(e).__name__}: {e}"
    finally:
        try:
            tls_sock.close()
        except OSError:
            pass


# ============================================================ 服务识别

# 高危服务 → (等级, 风险说明)。用于「无论端口号」地判定暴露风险。
SERVICE_RISK: dict[str, tuple[str, str]] = {
    "redis": ("critical", "未授权访问可直接读写全部数据，并可能借写文件实现命令执行"),
    "mongodb": ("critical", "未授权访问可读写全部数据库"),
    "elasticsearch": ("critical", "未授权访问可读写全部索引，历史上是数据泄漏重灾区"),
    "memcached": ("high", "未授权可读取缓存数据，并可能被利用做反射放大攻击"),
    "docker": ("critical", "Docker API 未加密暴露等同于交出宿主机控制权"),
    "mysql": ("high", "数据库端口对外暴露，爆破与拖库风险显著上升"),
    "postgres": ("high", "数据库端口对外暴露"),
    "mssql": ("high", "数据库端口对外暴露"),
    "oracle": ("high", "数据库端口对外暴露"),
    "smb": ("high", "文件共享端口对外暴露，注意横向移动与历史高危漏洞"),
    "rdp": ("high", "远程桌面对外暴露，存在口令爆破风险"),
    "telnet": ("high", "明文协议，账号口令可被直接嗅探"),
    "vnc": ("high", "远程桌面服务对外暴露，注意弱口令"),
    "ftp": ("medium", "FTP 明文传输，注意匿名登录与弱口令"),
    "smtp": ("medium", "邮件服务对外暴露"),
    "k8s-api": ("critical", "Kubernetes API 对外暴露，未授权可接管集群"),
    "rabbitmq": ("medium", "消息队列管理端对外暴露"),
    "kibana": ("high", "Kibana 对外暴露，未授权可读取全部索引"),
    "jenkins": ("high", "CI/CD 平台对外暴露，未授权可执行构建脚本"),
}

# 端口 → 主动探针（被动 banner 拿不到时才用）
_ACTIVE_PROBES: dict[int, bytes] = {
    6379: b"PING\r\n",
    11211: b"stats\r\n",
    9200: b"GET / HTTP/1.0\r\n\r\n",
    5601: b"GET /api/status HTTP/1.0\r\n\r\n",
    15672: b"GET /api/overview HTTP/1.0\r\n\r\n",
    2375: b"GET /version HTTP/1.0\r\n\r\n",
    2376: b"GET /version HTTP/1.0\r\n\r\n",
}

# 已知的 HTTP 类端口：用 HEAD 探测最省流量
_HTTP_PORTS = {
    80, 81, 88, 443, 591, 2082, 2086, 3000, 4443, 5000, 5601, 6443, 7001, 7002,
    8000, 8001, 8008, 8080, 8081, 8088, 8090, 8443, 8888, 9000, 9080, 9090,
    9200, 9443, 10000, 15672, 2375, 2376,
}

_TLS_PORTS = {443, 465, 636, 993, 995, 2376, 4443, 6443, 8443, 9443, 10443}


def _banner_service(data: bytes) -> tuple[str, str]:
    """从 banner 原始字节识别服务，返回 (服务名, 版本)。"""
    if not data:
        return "", ""
    text = data[:1024].decode("utf-8", "replace")
    low = text.lower()

    if any(k in low for k in ("mysql_native_password", "caching_sha2_password", "mariadb")):
        m = re.search(r"(\d+\.\d+\.\d+[\w.\-]*)", text)
        return "mysql", m.group(1) if m else ""
    m = re.match(r"^SSH-(\d+\.\d+)-(\S+)", text)
    if m:
        return "ssh", m.group(2)
    if text.startswith("+PONG"):
        return "redis", ""
    if text.startswith("STAT "):
        return "memcached", ""
    m = re.match(r"^(?:HTTP|RTSP)/\d\.\d\s+(\d+)", text)
    if m:
        return "http", ""
    m = re.match(r"^RFB\s+(\d{3}\.\d{3})", text)
    if m:
        return "vnc", m.group(1)
    if low.startswith("amqp"):
        return "rabbitmq", ""
    m = re.match(r"^220[ -](.*)", text)
    if m:
        head = m.group(1).lower()
        if "ftp" in head:
            return "ftp", ""
        return "smtp", ""
    if text.startswith("+OK"):
        return "pop3", ""
    if text.startswith("* OK"):
        return "imap", ""
    if low.startswith("-err"):
        return "redis", ""
    if text.startswith("\x16\x03"):
        return "tls", ""
    return "", ""


# 这些端口上的服务会在连接建立后**主动送 banner**，被动读取即可，
# 不必给它们发 HTTP 探针。其余端口一律默认发探针 —— 全端口扫描发现的
# 大多是「未知端口上的 Web 服务」，先等 banner 超时纯属浪费（几十个端口会被放大成分钟级）。
_PASSIVE_PORTS = {21, 22, 23, 25, 110, 143, 465, 587, 993, 995,
                  1433, 1521, 3306, 5432, 5900}


def _probe_for(port: int, host: str) -> bytes:
    """HTTP 类端口用 GET 探测——带响应体才能进一步识别具体应用（ES/Docker/Jenkins…）。"""
    if port in _ACTIVE_PROBES:
        return _ACTIVE_PROBES[port]
    return (f"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: {DEFAULT_UA}\r\n"
            f"Accept: */*\r\nConnection: close\r\n\r\n").encode()


# HTTP 响应特征 → 具体应用。ES/Docker/K8s 的应用层就是 HTTP，
# 只报「http」对使用者没有价值，必须往下识别一层。
_APP_SIGNATURES: list[tuple[str, str]] = [
    (r'"cluster_name"\s*:', "elasticsearch"),
    (r'"build_hash"\s*:', "elasticsearch"),
    (r'"ApiVersion"\s*:\s*"', "docker"),
    (r'"gitVersion"\s*:', "k8s-api"),
    (r'"rabbitmq_version"\s*:', "rabbitmq"),
    (r"<title>\s*Kibana", "kibana"),
    (r"X-Jenkins", "jenkins"),
    (r"Whitelabel Error Page|X-Application-Context", "spring-boot"),
    (r"<title>\s*Apache Tomcat", "tomcat"),
    (r'"swagger"\s*:\s*"', "swagger"),
    (r'"grafana"\s*:', "grafana"),
]

_APP_VERSION_RES = {
    "elasticsearch": r'"number"\s*:\s*"([\w.\-]+)"',
    "docker": r'"Version"\s*:\s*"([\w.\-]+)"',
    "k8s-api": r'"gitVersion"\s*:\s*"([\w.\-]+)"',
    "rabbitmq": r'"rabbitmq_version"\s*:\s*"([\w.\-]+)"',
    "kibana": r'"number"\s*:\s*"([\w.\-]+)"',
    "jenkins": r"X-Jenkins:\s*([\w.\-]+)",
    "grafana": r'"version"\s*:\s*"([\w.\-]+)"',
}


def _http_app_signature(raw: bytes) -> tuple[str, str]:
    """从 HTTP 原始响应里识别具体应用，返回 (应用名, 版本)。"""
    text = raw.decode("utf-8", "replace")
    for pattern, app in _APP_SIGNATURES:
        if not re.search(pattern, text, re.I):
            continue
        ver = ""
        m = re.search(_APP_VERSION_RES.get(app, ""), text, re.I)
        if m:
            ver = m.group(1)
        return app, ver
    return "", ""


@tool("service_probe",
      "对单个开放端口做服务与协议识别：先被动读 banner，拿不到再发只读探针"
      "（Redis PING、HTTP HEAD 等），返回服务名、版本与原始证据。"
      "用于「逐端口扫描」时判断端口上跑的到底是什么服务。",
      {"host": "str，主机名或 IP",
       "port": "int，端口号",
       "use_tls": "bool，可选，是否按 TLS 连接（443/8443/6443 等自动判断）"},
      phase="recon", category="端口与服务")
def service_probe(sess: ScanSession, host: str, port: int, use_tls: bool = False) -> dict:
    try:
        port = int(port)
    except (TypeError, ValueError):
        return {"ok": False, "summary": f"端口非法：{port}", "data": {}, "issues": []}

    tls = bool(use_tls) or port in _TLS_PORTS
    issues: list[dict] = []
    data: bytes = b""
    err = ""

    # 默认「发探针 + 读响应」：一次交互就能识别绝大多数服务 ——
    # HTTP 类直接回响应；SSH / MySQL 会先把 banner 送到；Redis 对非协议数据回 `-ERR`。
    # 只有已知的主动送 banner 的服务端口才走纯被动读取。
    if port in _PASSIVE_PORTS:
        stage = "被动 banner"
        data, err = _tcp_talk(host, port, read_timeout=2.0, use_tls=tls)
        if not data and not err:
            stage = "主动探针"
            data, err = _tcp_talk(host, port, send=_probe_for(port, host),
                                  read_timeout=3.0, use_tls=tls)
    else:
        stage = "主动探针"
        data, err = _tcp_talk(host, port, send=_probe_for(port, host),
                              read_timeout=3.0, use_tls=tls)

    service, version = _banner_service(data)
    banner = data[:300].decode("utf-8", "replace").strip() if data else ""

    # 主动探针拿到 HTTP 但首行不是 HTTP/1.x 时，仍按 http 归类
    if not service and data and b"HTTP/" in data[:64]:
        service = "http"

    # HTTP 之上再识别一层具体应用（Elasticsearch / Docker API / Jenkins …）
    if service == "http":
        app, app_ver = _http_app_signature(data)
        if app:
            service, version = app, app_ver

    if service and service in SERVICE_RISK:
        sev, note = SERVICE_RISK[service]
        issues.append(_issue(
            "port-exposure", sev, "端口暴露", f"{service} 端口 {port} 对外可达",
            f"{host}:{port}",
            f"端口 {port} 上识别到 {service} 服务{'（版本 ' + version + '）' if version else ''}。{note}。",
            "通过防火墙/安全组限制来源，数据库、缓存与容器管理接口不应直接暴露在业务网络。",
            cwe="CWE-284", evidence=f"{host}:{port} → {service} {version} | {banner[:160]}",
            confidence="high" if stage == "被动 banner" else "medium"))

    data_out = {
        "host": host, "port": port, "tls": tls, "stage": stage,
        "service": service or "unknown", "version": version,
        "banner": banner, "error": err,
    }
    if err:
        return {"ok": False, "summary": f"端口 {port} 探测失败：{err}",
                "data": data_out, "issues": []}

    summary = (f"端口 {port}（{stage}）识别为 {service or '未识别'}"
               + (f" 版本 {version}" if version else ""))
    return {"ok": True, "summary": summary, "data": data_out, "issues": issues}


# ============================================================ 未授权访问检测

def _http_via_socket(host: str, port: int, path: str, *, use_tls: bool = False,
                     timeout: float = 4.0) -> tuple[int, str, str]:
    """用裸 socket 发一个 GET，返回 (状态码, 响应体, 错误)。

    刻意不走 httpx：目标可能是任意端口的裸 HTTP 服务，
    且未授权检测不应消耗 HTTP 请求预算。
    """
    req = (f"GET {path} HTTP/1.0\r\nHost: {host}:{port}\r\n"
           f"User-Agent: {DEFAULT_UA}\r\nAccept: */*\r\nConnection: close\r\n\r\n").encode()
    raw, err = _tcp_talk(host, port, send=req, read_timeout=timeout,
                         use_tls=use_tls, limit=16384)
    if err or not raw:
        return 0, "", err or "无响应"
    text = raw.decode("utf-8", "replace")
    m = re.match(r"^HTTP/\d\.\d\s+(\d+)", text)
    status = int(m.group(1)) if m else 0
    body = text.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in text else text
    return status, body, ""


def _unauth_redis(host: str, port: int) -> tuple[bool, str, str]:
    data, err = _tcp_talk(host, port, send=b"PING\r\n", read_timeout=3.0)
    if err or b"+PONG" not in data:
        data2, err2 = _tcp_talk(host, port, send=b"INFO server\r\n", read_timeout=3.0)
        if b"redis_version" not in data2:
            return False, "", ""
    info, _ = _tcp_talk(host, port, send=b"INFO server\r\n", read_timeout=3.0)
    ver = ""
    m = re.search(rb"redis_version:([\w.\-]+)", info)
    if m:
        ver = m.group(1).decode("utf-8", "replace")
    return True, ver, info[:300].decode("utf-8", "replace").strip()


def _unauth_memcached(host: str, port: int) -> tuple[bool, str, str]:
    data, err = _tcp_talk(host, port, send=b"stats\r\n", read_timeout=3.0)
    if err or b"STAT " not in data:
        return False, "", ""
    ver = ""
    m = re.search(rb"STAT version ([\w.\-]+)", data)
    if m:
        ver = m.group(1).decode("utf-8", "replace")
    return True, ver, data[:300].decode("utf-8", "replace").strip()


def _unauth_es(host: str, port: int, use_tls: bool) -> tuple[bool, str, str]:
    st, body, _ = _http_via_socket(host, port, "/", use_tls=use_tls)
    if st != 200 or "cluster_name" not in body:
        return False, "", ""
    ver = ""
    try:
        js = json.loads(body)
        ver = str((js.get("version") or {}).get("number") or "")
    except (ValueError, AttributeError):
        pass
    indices = ""
    st2, body2, _ = _http_via_socket(host, port, "/_cat/indices?v", use_tls=use_tls)
    if st2 == 200 and body2.strip():
        indices = _snippet(body2, width=240)
    return True, ver, f"cluster: {_snippet(body, width=200)} | indices: {indices}"


def _unauth_docker(host: str, port: int, use_tls: bool) -> tuple[bool, str, str]:
    st, body, _ = _http_via_socket(host, port, "/version", use_tls=use_tls)
    if st != 200 or "ApiVersion" not in body:
        return False, "", ""
    ver = ""
    try:
        ver = str(json.loads(body).get("Version") or "")
    except (ValueError, AttributeError):
        pass
    containers = ""
    st2, body2, _ = _http_via_socket(host, port, "/containers/json", use_tls=use_tls)
    if st2 == 200:
        try:
            n = len(json.loads(body2))
            containers = f"可列出 {n} 个容器"
        except (ValueError, TypeError):
            containers = _snippet(body2, width=160)
    return True, ver, f"/version: {_snippet(body, width=180)} | {containers}"


def _unauth_k8s(host: str, port: int, use_tls: bool) -> tuple[bool, str, str]:
    st, body, _ = _http_via_socket(host, port, "/version", use_tls=use_tls)
    if st != 200 or "gitVersion" not in body:
        return False, "", ""
    ver = ""
    try:
        ver = str(json.loads(body).get("gitVersion") or "")
    except (ValueError, AttributeError):
        pass
    ns = ""
    st2, body2, _ = _http_via_socket(host, port, "/api/v1/namespaces", use_tls=use_tls)
    if st2 == 200:
        ns = f"匿名可列出命名空间：{_snippet(body2, width=160)}"
    return True, ver, f"/version: {_snippet(body, width=180)} | {ns}"


def _unauth_kibana(host: str, port: int, use_tls: bool) -> tuple[bool, str, str]:
    st, body, _ = _http_via_socket(host, port, "/api/status", use_tls=use_tls)
    if st != 200 or "version" not in body:
        return False, "", ""
    ver = ""
    try:
        ver = str((json.loads(body).get("version") or {}).get("number") or "")
    except (ValueError, AttributeError):
        pass
    return True, ver, _snippet(body, width=220)


def _unauth_rabbitmq(host: str, port: int, use_tls: bool) -> tuple[bool, str, str]:
    st, body, _ = _http_via_socket(host, port, "/api/overview", use_tls=use_tls)
    if st != 200 or "rabbitmq_version" not in body:
        return False, "", ""
    ver = ""
    try:
        ver = str(json.loads(body).get("rabbitmq_version") or "")
    except (ValueError, AttributeError):
        pass
    return True, ver, _snippet(body, width=220)


_UNAUTH_CHECKS = {
    "redis": (6379, _unauth_redis),
    "memcached": (11211, _unauth_memcached),
    "elasticsearch": (9200, _unauth_es),
    "docker": (2375, _unauth_docker),
    "k8s-api": (6443, _unauth_k8s),
    "kibana": (5601, _unauth_kibana),
    "rabbitmq": (15672, _unauth_rabbitmq),
}

# 端口 → 候选服务（未显式指定 service 时按端口猜）
_PORT_HINTS = {
    6379: "redis", 11211: "memcached", 9200: "elasticsearch", 2375: "docker",
    2376: "docker", 6443: "k8s-api", 8001: "k8s-api", 5601: "kibana", 15672: "rabbitmq",
}


@tool("unauth_check",
      "对服务端口做未授权访问检测（**只读**）。覆盖 Redis、Elasticsearch、Memcached、"
      "Docker API、Kubernetes API、Kibana、RabbitMQ 管理端。只发送读取类命令，"
      "不做任何写入、删除或配置修改。",
      {"host": "str，主机名或 IP",
       "port": "int，端口号",
       "service": "str，可选，服务名（不传则按端口推断）"},
      phase="scan", category="未授权访问")
def unauth_check(sess: ScanSession, host: str, port: int, service: str = "") -> dict:
    try:
        port = int(port)
    except (TypeError, ValueError):
        return {"ok": False, "summary": f"端口非法：{port}", "data": {}, "issues": []}

    svc = (service or "").strip().lower() or _PORT_HINTS.get(port, "")
    if not svc:
        # 非标准端口：先自动识别一次服务再决定检测项。
        # 否则「9201 上跑着 Elasticsearch」这类情况会被直接判成「无检测项」跳过，
        # 而逐端口扫描恰恰几乎全是非标准端口。
        probe = service_probe(sess, host, port)
        detected = str((probe.get("data") or {}).get("service") or "")
        if detected in _UNAUTH_CHECKS:
            svc = detected
    if svc not in _UNAUTH_CHECKS:
        return {"ok": True, "summary": f"端口 {port} 无对应的未授权检测项（服务：{svc or '未知'}）",
                "data": {"host": host, "port": port, "service": svc, "checked": False},
                "issues": []}

    _, fn = _UNAUTH_CHECKS[svc]
    use_tls = port in (2376, 6443, 8443)
    try:
        if svc in ("redis", "memcached"):
            hit, version, evidence = fn(host, port)
        else:
            hit, version, evidence = fn(host, port, use_tls)
    except (OSError, ValueError, TypeError) as e:
        return {"ok": False, "summary": f"未授权检测异常：{type(e).__name__}: {e}",
                "data": {"host": host, "port": port, "service": svc}, "issues": []}

    data = {"host": host, "port": port, "service": svc, "version": version,
            "unauthorized": hit, "evidence": evidence, "checked": True}
    if not hit:
        return {"ok": True,
                "summary": f"{svc}（端口 {port}）未发现未授权访问，已确认需要鉴权",
                "data": data, "issues": []}

    issues = [_issue(
        "unauth-access", "critical", "未授权访问",
        f"{svc} 未授权访问（端口 {port}）",
        f"{host}:{port}",
        f"无需任何凭据即可读取 {svc} 数据（版本 {version or '未知'}）。"
        f"这是可直接导致数据泄漏甚至服务器接管的严重问题。",
        f"为 {svc} 启用认证与访问控制，并绑定内网地址；如无必要，不要将管理端口暴露到公网。",
        cwe="CWE-306",
        evidence=f"匿名请求成功：{evidence[:400]}", confidence="high")]

    return {"ok": True, "summary": f"⚠ {svc}（端口 {port}）存在未授权访问",
            "data": data, "issues": issues}


# ============================================================ 备份文件与源码泄漏

BACKUP_BASENAMES = [
    "backup", "bak", "www", "web", "site", "html", "public_html", "wwwroot",
    "db", "database", "dump", "data", "app", "src", "source", "code",
    "release", "dist", "build", "admin", "test", "old", "temp", "2025", "2024",
]
BACKUP_EXTS = [".zip", ".tar.gz", ".tgz", ".rar", ".7z", ".tar", ".gz", ".sql", ".bak"]

# 直接命中的固定路径（编辑器临时文件、源码元数据、配置备份）
BACKUP_FIXED = [
    "/.git/config", "/.git/HEAD", "/.svn/entries", "/.svn/wc.db", "/.hg/requires",
    "/.DS_Store", "/.env", "/.env.bak", "/.env.old", "/.env.local", "/.env.production",
    "/web.config", "/web.config.bak", "/config.php.bak", "/config.php.old",
    "/application.yml", "/application.yml.bak", "/application.properties",
    "/WEB-INF/web.xml", "/index.php~", "/index.php.bak", "/index.php.swp",
    "/index.html~", "/index.html.swp", "/.index.php.swp", "/.index.html.swp",
    "/id_rsa", "/.ssh/id_rsa", "/phpinfo.php", "/info.php", "/test.php",
    "/composer.json", "/package.json", "/.bowerrc", "/Dockerfile", "/docker-compose.yml",
]


@tool("backup_files",
      "专项探测备份文件与源码泄漏：站点备份压缩包（.zip/.tar.gz/.sql 等）、"
      "源码仓库元数据（.git/.svn）、编辑器临时文件、配置与凭据文件。"
      "这类文件常可直接下载整个站点源码或数据库，是外部暴露面里最值钱的一类。",
      {"url": "str，目标 URL"},
      phase="scan", category="敏感文件")
def backup_files(sess: ScanSession, url: str) -> dict:
    base = origin_of(url)
    # 按档位缩放字典：quick 只探最可能命中的组合，标准/深度跑全量
    quick = str(getattr(sess, "depth", "standard")).lower() == "quick"
    names = BACKUP_BASENAMES[:8] if quick else BACKUP_BASENAMES
    exts = [".zip", ".tar.gz", ".sql", ".bak"] if quick else BACKUP_EXTS
    seen: set[str] = set()
    candidates: list[str] = []
    for name in names:
        for ext in exts:
            path = f"/{name}{ext}"
            if path not in seen:
                seen.add(path)
                candidates.append(path)
    for path in BACKUP_FIXED:
        if path not in seen:
            seen.add(path)
            candidates.append(path)

    hits: list[dict] = []
    issues: list[dict] = []
    fb = FallbackBaseline(sess, base)   # 软 404 站点必须靠基线排除
    for path in candidates:
        probe = base + path
        resp, _err = sess.request("GET", probe)
        if resp is None or resp.status_code != 200:
            continue
        if fb.is_fallback(resp) or _looks_like_fallback(resp):
            continue
        body = resp.content or b""
        if len(body) < 16:
            continue

        low = path.lower()
        if any(k in low for k in (".git", ".svn", ".hg", "id_rsa", ".ssh")):
            sev, cat = "critical", "源码泄漏"
            detail = f"可直接下载版本控制/密钥文件 `{path}`，攻击者可据此还原完整源码乃至登录服务器。"
        elif low.endswith(".sql") or "dump" in low or "database" in low or low.endswith(".zip") or low.endswith(".tar.gz"):
            sev, cat = "critical", "备份泄漏"
            detail = f"可直接下载备份文件 `{path}`，其中通常包含完整数据库或站点源码。"
        elif low.endswith((".swp", "~", ".save")):
            sev, cat = "high", "源码泄漏"
            detail = f"编辑器临时文件 `{path}` 可访问，常残留源码片段与明文凭据。"
        elif low.startswith("/.env"):
            sev, cat = "critical", "配置泄漏"
            detail = f"环境变量文件 `{path}` 可公开访问，其中常含数据库口令、API Key 等核心凭据。"
        else:
            sev, cat = "medium", "敏感文件"
            detail = f"备份/配置文件 `{path}` 可被未授权下载，应确认是否包含敏感信息。"

        hits.append({"path": path, "status": resp.status_code, "size": len(body)})
        issues.append(_issue(
            "sensitive-file", sev, cat, f"{cat}：{path}", probe,
            detail + f"（响应 {len(body)} 字节）",
            "从 Web 根目录移除备份与源码文件，仅保留运行必需文件；"
            "并在反向代理层直接拦截 .git/.svn/.env 等路径。",
            cwe="CWE-538", evidence=_snippet(body, width=220),
            confidence="high"))

    return {"ok": True,
            "summary": f"探测 {len(candidates)} 个备份/泄漏路径，命中 {len(hits)} 个",
            "data": {"base": base, "probed": len(candidates), "hits": hits},
            "issues": issues, "notes": [n for n in [soft404_note(fb, base)] if n]}


# ============================================================ 参数型漏洞探测

# 唯一标识串：把「真实命中」与「泛泛回显」区分开
_TAG = "aih0ley"

SQL_ERROR_SIGNS = [
    "you have an error in your sql syntax", "warning: mysql", "mysql_fetch",
    "unclosed quotation mark", "quoted string not properly terminated",
    "microsoft ole db provider for sql server", "ora-01756", "ora-00933",
    "oracle error", "pg_query", "pg_exec", "postgresql query failed",
    "sqlstate[", "sqlite3.operationalerror", "sqlite error",
    "syntax error at or near", "pdoexception", "doctrine\\db\\", "mybatis",
    "system.data.sqlclient", "jdbc", "hibernate",
]

# (名称, 载荷, 命中判据说明, 检查函数)
XSS_PAYLOAD = f"{_TAG}<svg/onload=1>"
SQLI_PAYLOADS = [f"{_TAG}'", f'{_TAG}"', f"{_TAG}'--", f"{_TAG}')\\"]

# 表达式注入要按引擎分别试：同一段表达式在不同引擎里的**语法**不同，
# 只测 `{{7*7}}` 会漏掉 Spring EL / Struts OGNL / JSP EL 这三个大类，
# 而它们恰好是 Java 技术栈里最高频的入口（Struts2 的 OGNL 更是历史重灾区）。
EXPR_RESULT = "516961"                    # 719 * 719，够独特，不会撞上页面原有数字
EXPR_PAYLOADS: list[tuple[str, str]] = [
    ("模板表达式 {{ }}（Jinja2 / Twig / Handlebars）", "{{719*719}}"),
    ("Spring EL / JSP EL ${ }", "${719*719}"),
    ("Struts2 OGNL %{ }", "%{719*719}"),
    ("EL 井号语法 #{ }（JSF / Spring EL）", "#{719*719}"),
]
CMDI_PAYLOAD = ";id"


def _inject(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    q = dict(parse_qsl(parsed.query, keep_blank_values=True))
    q[name] = value
    return urlunparse(parsed._replace(query=urlencode(q, doseq=True)))


DEFAULT_PARAM_NAMES = [
    "id", "file", "path", "url", "q", "cmd", "name", "page", "search", "keyword",
    "cat", "pid", "uid", "lang", "type", "action", "data", "view",
]

# ---- 盲注类载荷 ----------------------------------------------------------
# 布尔盲注：SQL 里恒真与恒假的表达式。三态对比（原始 / 恒真 / 恒假）是
# 这类漏洞唯一可靠的判据 —— 单看「响应有变化」会把任何一次抖动都算成漏洞。
BOOL_TRUE_SUFFIX = "' && '1'=='1"
BOOL_FALSE_SUFFIX = "' && '1'=='2"

# NoSQL（MongoDB 风格）数组注入。用两个必定产生不同结果的取值做差分：
# 若参数真被解析成查询文档，`$ne` 会返回全部记录，而不匹配的随机值返回空集。
NOSQL_PARAM_FMT = "{base}[$ne]"
NOSQL_MATCH = "1"
NOSQL_NOMATCH = "aih0leynomatch8z"

# 时间盲注载荷。两两覆盖 MySQL / PostgreSQL / SQL Server，末尾的注释符
# 各不相同（MySQL 需要 `-- ` 带空格，PostgreSQL 用 `--`）。
TIME_PAYLOADS: list[tuple[str, str, float]] = [
    ("MySQL SLEEP", f"{_TAG}' AND SLEEP(3)-- -", 3.0),
    ("PostgreSQL pg_sleep", f"{_TAG}'; SELECT pg_sleep(3)-- -", 3.0),
    ("SQL Server WAITFOR", f"{_TAG}'; WAITFOR DELAY '0:0:3'-- -", 3.0),
]
# 判定阈值：必须比基线慢这么多秒才算「疑似延迟」，避免网络抖动误判
TIME_DELTA = 2.2


def _sig_of(resp) -> tuple:
    """响应的可比签名 (状态码, 长度, 内容指纹)。"""
    body = resp.content or b""
    return (resp.status_code, len(body), _signature_of(body))


def _sig_differs(a: tuple, b: tuple, stable: bool) -> bool:
    """两个签名是否有实质差异。

    ``stable=False`` 表示目标响应本身带随机内容（指纹每次都变），
    此时指纹不可比，只能退化为「状态码 + 长度」判据，否则会把
    每一次随机抖动都判成注入成功。
    """
    if a[0] != b[0]:
        return True
    if stable and a[2] != b[2]:
        return True
    return abs(a[1] - b[1]) > max(40, int(0.2 * max(a[1], b[1], 1)))


_PARAM_PROBE_DESC = (
    "参数型漏洞探测（**只读**）：反射型 XSS、错误型 SQL 注入、**布尔盲注与 NoSQL 数组注入**"
    "（三态差分对比）、**时间盲注**（重复确认避免抖动误判）、"
    "模板/表达式注入（Jinja2、Spring EL、Struts OGNL、EL 四种语法）、命令注入回显。"
    "只发送探测载荷触发响应差异，不构造任何写入型语句。"
    "除调用方给的 URL 外，还会自动在 `api_surface` 采集到的**带参数落点**上各测一轮 —— "
    "真实可注入的参数通常不在首页，而在功能页的链接/表单里。"
    "路径穿越请用 `traversal_probe`，文件包含请用 `lfi_probe`，"
    "XSS 的上下文级判定请用 `xss_check`。"
)


def _param_probe_at(sess: ScanSession, url: str, params: list | None = None,
                    *, time_blind: bool = True, expand_defaults: bool = True) -> dict:
    parsed = urlparse(url)
    given: list[str] = []
    for k, _v in parse_qsl(parsed.query, keep_blank_values=True):
        if k and k not in given:
            given.append(k)
    extra = [p for p in (params or []) if isinstance(p, str) and p.strip()]
    # 去重是必须的，不是洁癖：`extra` 与 `given` 常常是同一批名字
    # （调用方把 URL 里已有的参数名又当 params 传回来），
    # 不去重就会对同一个参数跑两轮、把同一个漏洞报两遍 —— 报告里
    # 出现两条标题完全相同的条目，比漏报更伤可信度。
    merged: list[str] = []
    for n in given + extra:
        if n and n not in merged:
            merged.append(n)
    if expand_defaults:
        # 已有参数优先测，其次补充常见参数名；总量封顶避免把目标打爆
        for n in DEFAULT_PARAM_NAMES:
            if n not in merged:
                merged.append(n)
    names = merged[:10]
    # 原始取值：布尔盲注与三态对比要拿它当基线
    origin_vals = dict(parse_qsl(parsed.query, keep_blank_values=True))

    issues: list[dict] = []
    stats: dict[str, int] = {}
    findings_detail: list[str] = []
    sqli_clean: list[str] = []          # 没有报错型 SQLi 的参数，值得再试盲注

    def check(payload: str, name: str) -> str:
        probe_url = _inject(url, name, payload)
        resp, _err = sess.request("GET", probe_url)
        if resp is None:
            return ""
        return resp.text or ""

    def probe(name: str, payload: str):
        """发一次载荷，返回 (响应, 耗时秒)。失败返回 (None, 0)。"""
        t0 = time.time()
        resp, _err = sess.request("GET", _inject(url, name, payload))
        return resp, (time.time() - t0)

    for name in names:
        # ---- 反射型 XSS ----
        # 这里只做「标记是否被原样回显」的粗筛：上下文级判定（能不能真的执行）
        # 交给 `xss_check`。两处判据不同不是重复 —— 粗筛能在更多参数上便宜地跑，
        # 精判则只对粗筛命中的参数展开，合起来才既广又准。
        body = check(XSS_PAYLOAD, name)
        stats["xss"] = stats.get("xss", 0) + 1
        if body and XSS_PAYLOAD in body:
            issues.append(_issue(
                "vuln-verify", "medium", "注入与参数", f"参数 `{name}` 原样回显脚本标签", url,
                f"参数 `{name}` 的取值被原样回显进响应页面且未做 HTML 编码，"
                "可构造脚本在受害者浏览器执行。"
                "（本项为粗筛结论；能否真正执行取决于反射点所在的上下文，"
                "请用 `xss_check` 复核。）",
                "对输出做上下文相关的 HTML 编码；对输入做白名单校验；配合 CSP 兜底。",
                cwe="CWE-79", method="GET", param=name, payload=XSS_PAYLOAD,
                evidence=_snippet(body, needle=XSS_PAYLOAD, width=220), confidence="medium"))
            findings_detail.append(f"{name}(XSS)")

        # ---- 错误型 SQL 注入 ----
        hit_sign = ""
        for pl in SQLI_PAYLOADS:
            body = check(pl, name)
            stats["sqli"] = stats.get("sqli", 0) + 1
            low = (body or "").lower()
            hit_sign = next((s for s in SQL_ERROR_SIGNS if s in low), "")
            if hit_sign:
                issues.append(_issue(
                    "vuln-verify", "critical", "注入与参数", f"疑似 SQL 注入参数 `{name}`", url,
                    f"参数 `{name}` 注入引号后，响应出现数据库报错特征（`{hit_sign}`），"
                    "说明输入被直接拼接进 SQL 语句。",
                    "使用参数化查询/预编译语句；关闭生产环境的详细报错；对输入做类型校验。",
                    cwe="CWE-89", method="GET", param=name, payload=pl,
                    evidence=_snippet(body, needle=hit_sign, width=260), confidence="high"))
                findings_detail.append(f"{name}(SQLi)")
                break
        if not hit_sign:
            sqli_clean.append(name)     # 没有报错回显，值得用盲注再试一轮

        # ---- 模板 / 表达式注入（四种语法一起试）----
        expr_hits: list[tuple[str, str, str]] = []      # (语法名, 载荷, 响应)
        for label, pl in EXPR_PAYLOADS:
            body = check(pl, name)
            stats["expr"] = stats.get("expr", 0) + 1
            if EXPR_RESULT in (body or ""):
                expr_hits.append((label, pl, body))
        if expr_hits:
            listed = "、".join(f"`{l}`（载荷 `{p}`）" for l, p, _b in expr_hits)
            issues.append(_issue(
                "vuln-verify", "critical", "注入与参数",
                f"服务端表达式注入参数 `{name}`", url,
                f"参数 `{name}` 中的表达式被服务端求值：{listed} 都被计算为 {EXPR_RESULT}。"
                "说明用户输入被当作模板/表达式内容执行。这类漏洞在 Java 技术栈上"
                "通常可直接升级为远程命令执行（Spring SpEL 可调用 `Runtime.exec`，"
                "Struts2 OGNL 更是历史上多次造成未授权 RCE）。",
                "不要把用户输入拼进模板或表达式；确需动态求值时使用沙箱化引擎并限制"
                "可访问的对象与方法；升级框架到已修复版本。",
                cwe="CWE-1336", method="GET", param=name, payload=expr_hits[0][1],
                evidence=_snippet(expr_hits[0][2], needle=EXPR_RESULT, width=220),
                confidence="high"))
            findings_detail.append(f"{name}(表达式注入×{len(expr_hits)})")

        # ---- 命令注入（只读命令 id）----
        body = check(CMDI_PAYLOAD, name)
        stats["cmdi"] = stats.get("cmdi", 0) + 1
        if re.search(r"uid=\d+\([\w\-]+\)\s+gid=\d+\(", body or ""):
            issues.append(_issue(
                "vuln-verify", "critical", "注入与参数", f"命令注入参数 `{name}`", url,
                f"参数 `{name}` 传入 `;id` 后响应回显了系统命令执行结果（uid=/gid=），"
                "说明输入被拼接进系统命令执行。",
                "避免把用户输入拼进系统命令；必须调用时使用参数化 API 并严格白名单校验。",
                cwe="CWE-78", method="GET", param=name, payload=CMDI_PAYLOAD,
                evidence=_snippet(body, needle="uid=", width=220), confidence="high"))
            findings_detail.append(f"{name}(命令注入)")

    # ---- 盲注类：只对「报错型没测出来」的参数跑，避免重复消耗预算 ----
    # 顺序上放在最后：它最贵（每参数 4~6 次请求，时间盲注还要真等 3 秒），
    # 而前面几类一旦命中就已有结论，不必再花这个钱。
    blind_targets = sqli_clean[:5]
    osql_hits: list[str] = []
    for name in blind_targets:
        base_val = origin_vals.get(name) or "1"

        # --- 布尔盲注：三态对比 ---
        b1, _t = probe(name, base_val)
        b2, _t = probe(name, base_val)
        if b1 is None or b2 is None:
            continue
        s1, s2 = _sig_of(b1), _sig_of(b2)
        stable = (s1 == s2)
        stats["blind_bool"] = stats.get("blind_bool", 0) + 2
        t_resp, _t = probe(name, f"{base_val}{BOOL_TRUE_SUFFIX}")
        f_resp, _t = probe(name, f"{base_val}{BOOL_FALSE_SUFFIX}")
        stats["blind_bool"] = stats.get("blind_bool", 0) + 2
        if t_resp is None or f_resp is None:
            continue
        st, sf = _sig_of(t_resp), _sig_of(f_resp)
        # 恒真 ≈ 原始、恒假 ≠ 原始、恒真 ≠ 恒假 —— 三条同时成立才算布尔盲注。
        # 只判「恒真与恒假不同」会误报：任何带随机内容的接口都满足这一条。
        if (not _sig_differs(st, s1, stable)) and _sig_differs(sf, s1, stable) \
                and _sig_differs(st, sf, stable):
            issues.append(_issue(
                "vuln-verify", "high", "注入与参数", f"布尔盲注参数 `{name}`", url,
                f"参数 `{name}` 追加恒真条件 `{BOOL_TRUE_SUFFIX.strip()}` 时响应与原始请求一致，"
                f"追加恒假条件 `{BOOL_FALSE_SUFFIX.strip()}` 时响应明显不同。"
                "这种「真假条件导致可区分的响应差异」是典型的布尔盲注特征："
                "即使没有数据库报错回显，攻击者也能逐位推断出数据库内容。",
                "使用参数化查询；对输入做严格类型校验（数字型参数强制转 int）；"
                "统一错误与空结果的响应，减少可区分的信号。",
                cwe="CWE-89", method="GET", param=name,
                payload=f"{base_val}{BOOL_TRUE_SUFFIX} / {base_val}{BOOL_FALSE_SUFFIX}",
                evidence=f"原始 len={s1[1]}；恒真 len={st[1]}；恒假 len={sf[1]}"
                         f"（内容指纹{'可比' if stable else '随机不可比'}）",
                confidence="high"))
            findings_detail.append(f"{name}(布尔盲注)")
            # 注意：这里**不能** continue。布尔盲注与 NoSQL 注入的根因完全不同
            # （SQL 字符串拼接 vs 查询文档被参数直接构造），修复方式也不同，
            # 一个成立不代表另一个也成立。命中布尔盲注就跳过 NoSQL，
            # 等于让结论更严重的那个盖住了另一个——两个都是真实缺陷。

        # --- NoSQL 数组注入：两个取值差分 ---
        ne_param = NOSQL_PARAM_FMT.format(base=name)
        try:
            r_match, _e = sess.request("GET", _inject(url, ne_param, NOSQL_MATCH))
            r_none, _e = sess.request("GET", _inject(url, ne_param, NOSQL_NOMATCH))
        except (BudgetExceeded, OSError):
            continue
        stats["nosql"] = stats.get("nosql", 0) + 2
        if r_match is None or r_none is None:
            continue
        sm, sn = _sig_of(r_match), _sig_of(r_none)
        # 只有「不匹配值给出空/小响应，而匹配值给出明显更大的响应」才算命中。
        # 若两者一致，说明服务端根本没把这个参数当查询文档解析 —— 正常站点就是这样。
        if _sig_differs(sm, sn, stable) and sm[1] > sn[1] + 40:
            issues.append(_issue(
                "vuln-verify", "high", "注入与参数", f"NoSQL 注入参数 `{name}`", url,
                f"把参数写成数组形式 `{ne_param}={NOSQL_MATCH}` 时响应显著变大"
                f"（{sm[1]} 字节），而 `{ne_param}={NOSQL_NOMATCH}` 时响应很小"
                f"（{sn[1]} 字节）。这说明服务端把该参数直接当成了 MongoDB 查询文档，"
                "`$ne`（不等于）操作符绕过了原有的匹配条件并返回了全部记录。",
                "对数组/对象形态的输入做显式类型校验并拒绝；"
                "不要把请求参数直接反序列化成查询文档；"
                "使用 ODM 的参数化查询接口并对键名做白名单。",
                cwe="CWE-943", method="GET", param=ne_param,
                payload=f"{ne_param}={NOSQL_MATCH}",
                evidence=f"{ne_param}={NOSQL_MATCH} → {sm[1]} 字节；"
                         f"{ne_param}={NOSQL_NOMATCH} → {sn[1]} 字节",
                confidence="high"))
            findings_detail.append(f"{name}(NoSQL 注入)")
            osql_hits.append(name)

    # ---- 时间盲注：只对首个参数、且每种载荷必须复现两次 ----
    # 为什么必须复现：一次「慢了 3 秒」完全可能是一次 GC、一次网络重传、
    # 或者目标正在跑批。时间盲注是误报率最高的一类检测，判据只能靠重复。
    time_hits: list[str] = []
    if blind_targets and sess.depth != "quick" and time_blind:
        name = blind_targets[0]
        base_val = origin_vals.get(name) or "1"
        t0 = time.time()
        _r, _e = sess.request("GET", _inject(url, name, base_val))
        baseline = max(time.time() - t0, 0.05)
        stats["blind_time"] = stats.get("blind_time", 0) + 1
        for label, pl, expect in TIME_PAYLOADS[:2]:
            delays = []
            for _ in range(2):
                _r, elapsed = probe(name, pl)
                stats["blind_time"] = stats.get("blind_time", 0) + 1
                delays.append(elapsed)
            if all(d >= baseline + TIME_DELTA for d in delays):
                issues.append(_issue(
                    "vuln-verify", "high", "注入与参数", f"时间盲注参数 `{name}`", url,
                    f"参数 `{name}` 注入 `{label}` 载荷后，响应耗时两次分别为 "
                    f"{delays[0]:.2f}s / {delays[1]:.2f}s，而基线仅 {baseline:.2f}s。"
                    "延迟稳定复现，说明载荷中的延时函数被数据库真实执行。"
                    "时间盲注不需要任何回显，是最隐蔽的一类 SQL 注入，"
                    "攻击者可据此逐字符推断出完整数据库内容。",
                    "使用参数化查询；对输入做类型校验；"
                    "在数据库账号层面禁用不必要的函数执行权限。",
                    cwe="CWE-89", method="GET", param=name, payload=pl,
                    evidence=f"基线 {baseline:.2f}s；载荷两次 {delays[0]:.2f}s / {delays[1]:.2f}s",
                    confidence="high"))
                findings_detail.append(f"{name}(时间盲注)")
                time_hits.append(name)
                break

    detail = f"{sum(stats.values())} 次载荷"
    if stats.get("blind_time"):
        detail += f"（其中时间盲注观测 {stats['blind_time']} 次，每次最长约 3 秒等待）"
    return {"ok": True,
            "summary": f"探测 {len(names)} 个参数共 {detail}，"
                       f"确认 {len(issues)} 项：{'、'.join(findings_detail) if findings_detail else '未发现'}",
            "data": {"url": url, "params": names, "payloads_sent": sum(stats.values()),
                     "by_type": stats, "hits": findings_detail,
                     "blind_tested": blind_targets,
                     "nosql_hits": osql_hits, "time_blind_hits": time_hits},
            "issues": issues}


@tool("param_probe", _PARAM_PROBE_DESC,
      {"url": "str，目标 URL（可自带查询串）",
       "params": "list[str]，可选，指定要检测的参数名"},
      phase="scan", category="注入与参数")
def param_probe(sess: ScanSession, url: str, params: list | None = None) -> dict:
    """在入口 URL 与采集到的带参落点上分别做参数型探测，再合并结论。

    为什么要多落点：调用方（AI 规划或确定性编排）通常只把站点入口传进来，
    而入口往往是首页或 SPA 挂载点——`/` 上没有参数，真实参数都在功能页的
    链接与表单里。只测入口等于「服务端明明有 `?file=` 却没测到」，
    报告写「未发现」，读起来却是已检查过。落点清单来自 `api_surface`，
    是它从页面 `<a href>` / `<form action>` 与 JS bundle 里挖出来的。
    """
    origin = origin_of(url)
    # 入口 URL 优先，且允许扩散常见参数名（老站点的首页常有未链接到的参数化接口）
    landing: list[tuple[str, list | None, bool]] = [(url, params, True)]
    seen_paths = {urlparse(url).path}
    disc_cap = DISCOVERED_LANDING_CAP.get(sess.depth, 10)
    discovered = ((sess.discovered.get("param_urls") or {}).get(origin) or [])
    added = 0
    for du in discovered:
        if added >= disc_cap:
            break
        dp = urlparse(du)
        if dp.path in seen_paths or not dp.query:
            continue
        # 只测它自己带的参数名——这些是页面里真实出现的，比猜准确得多，
        # 又不会把一个 6 参数的页面扩散成「6 × 10 个常见名」的请求爆炸。
        own = [k for k, _v in parse_qsl(dp.query, keep_blank_values=True) if k][:6]
        if not own:
            continue
        seen_paths.add(dp.path)
        landing.append((du, own, False))
        added += 1

    issues: list[dict] = []
    stats: dict[str, int] = {}
    detail: list[str] = []
    sizes: list[int] = []
    for base, ps, primary in landing:
        try:
            # 时间盲注最贵（每载荷真等 3 秒），只在主落点上做一次；
            # 次要落点也不扩散常见参数名：它自己带的参数就是页面里真实存在的，
            # 已经比猜准得多，再乘一轮 DEFAULT_PARAM_NAMES 只是把请求预算
            # 花在必然不存在的参数上，还会挤掉后面的检测项。
            r = _param_probe_at(sess, base, ps, time_blind=primary,
                                expand_defaults=primary)
        except (BudgetExceeded, OSError):
            break
        issues += r.get("issues") or []
        d = r.get("data") or {}
        for k, v in (d.get("by_type") or {}).items():
            stats[k] = stats.get(k, 0) + v
        label = urlparse(base).path or "/"
        for h in (d.get("hits") or []):
            detail.append(f"{label}::{h}")
        sizes.append(len(d.get("params") or []))

    notes: list[str] = []
    # 多落点会命中同一个根因（同一段代码在多个路径上都可注入），
    # 但报告里出现两条标题一模一样的条目只会让人怀疑扫描器本身。
    issues = dedup_issues(issues)
    # detail 也去重，它进的是 summary 与 data.hits
    detail = uniq(detail)

    if added:
        shown = "、".join(f"`{urlparse(b).path}?{urlparse(b).query}`"
                          for b, _p, _f in landing[1:4])
        notes.append(f"除入口路径外，还在该站 {added} 个带参数的落点上做了注入测试"
                     f"（{shown}{' 等' if added > 3 else ''}）——"
                     f"这些落点由页面链接/表单采集而来，是真实参数所在位置")
    elif discovered:
        notes.append("采集到带参数的落点，但它们的路径与入口重复，本轮仅测入口路径")
    else:
        notes.append("未取得带参数的落点清单（`api_surface` 未运行，"
                     "或站点页面里没有带查询串的链接/表单），本次仅对入口路径测试，"
                     "命中率会偏低——这不等于「没有参数型漏洞」")

    total = sum(stats.values())
    suffix = f"（其中时间盲注观测 {stats['blind_time']} 次，每次最长约 3 秒等待）" \
        if stats.get("blind_time") else ""
    return {"ok": True,
            "summary": f"在 {len(landing)} 个落点共 {sum(sizes)} 个参数上发送 {total} 次载荷"
                       f"{suffix}，确认 {len(issues)} 项："
                       f"{'、'.join(detail) if detail else '未发现'}",
            "data": {"url": url, "landing_urls": [b for b, _p, _f in landing],
                     "payloads_sent": total, "by_type": stats, "hits": detail},
            "issues": issues, "notes": notes}


# ============================================================ 目录遍历 / 任意文件读取
#
# 这一类漏洞在扫描器里最容易被整类漏掉，有三个坑，缺一个都测不出来：
#
#   ① 载荷作用在**路径**上而不是参数值上。只做「参数注入」的扫描器完全测不到
#      `/assets/../../../../etc/passwd` 这种形态，哪怕它在真实项目里最常见。
#   ② HTTP 客户端库会把 `../` 归一化掉。实测 httpx 把
#      `GET /a/../../etc/passwd` 发成 `GET /etc/passwd` —— 最基础的载荷
#      根本没到过服务器，扫描器却"跑完了、没报错、零发现"。
#      `urlencode` 还会把已编码的值再编一次（`%2e` → `%252e`），
#      于是"单次编码"实际测成了双重编码。所以本工具全程走裸 socket 通道
#      手工拼请求行，两种模式都不经客户端改写。
#   ③ 判据必须落在**文件内容特征**上，而不是状态码。在「任何路径都返回 200」
#      的端点（SPA 兜底、本地 IPC 服务）上，按状态码判会全量误报。

# (平台, 相对路径, 判据, 最少命中次数, 最小响应长度, 说明, 严重度)
FILE_TARGETS: list[tuple[str, str, re.Pattern, int, int, str, str]] = [
    ("linux", "etc/passwd",
     re.compile(r"root:[^:\s]{0,4}:\d+:\d+:[^:\r\n]*:"),
     1, 120, "/etc/passwd（系统账户文件）", "critical"),
    ("linux", "proc/self/status",
     re.compile(r"(?mi)^(Name|State|Tgid|Pid|PPid|Uid|Gid|Threads):\s"),
     4, 200, "/proc/self/status（进程运行信息）", "critical"),
    ("java", "WEB-INF/web.xml",
     re.compile(r"<web-app|<servlet-mapping|<security-constraint", re.I),
     1, 80, "WEB-INF/web.xml（Java 部署描述符）", "high"),
    ("java", "META-INF/MANIFEST.MF",
     re.compile(r"(?mi)^(Manifest-Version|Created-By|Main-Class):\s*\S"),
     2, 60, "META-INF/MANIFEST.MF（构建清单）", "medium"),
    ("windows", "Windows/win.ini",
     re.compile(r"\[fonts\]|\[extensions\]", re.I),
     1, 40, "Windows/win.ini（系统配置）", "high"),
    ("windows", "boot.ini",
     re.compile(r"\[boot loader\]", re.I),
     1, 20, "boot.ini（启动配置）", "high"),
]


def _traversal_units() -> list[tuple[str, str]]:
    """穿越序列的「每层写法」，乘上深度即完整序列。

    同一个漏洞在不同服务端实现下需要不同写法，所以这是一张矩阵而不是一个载荷：

    - 「先解码再拼路径」的实现 → 单次百分号编码有效（`%2e%2e%2f`）
    - 「先归一化再用」的实现   → 明文 `../` 有效（会被客户端库吃掉，必须走裸通道）
    - 解一层不够的实现         → 二次编码（`%252e%252e%252f`）
    - 老式 Java / IIS          → 超长 UTF-8 编码（`%c0%ae%c0%ae%2f`）
    - Tomcat / Spring          → `;` 路径参数截断（`..;/`），归一时会丢弃 `;` 之后
    - 只过滤 `../` 字面量的实现 → `....//`、`.%2e/` 绕过
    - Windows 目标             → 反斜杠及其编码形式（`..\\`、`..%5c`）
    """
    return [
        ("明文", "../"),
        ("点号+斜杠编码", "%2e%2e%2f"),
        ("斜杠编码", "..%2f"),
        ("点号编码", "%2e%2e/"),
        ("二次编码", "%252e%252e%252f"),
        ("超长UTF-8编码", "%c0%ae%c0%ae%2f"),
        ("反斜杠", "..\\"),
        ("反斜杠编码", "..%5c"),
        ("路径参数截断", "..;/"),
        ("多点变形", "....//"),
        ("尾随点", ".%2e/"),
    ]


def _param_value_forms(depth: int) -> list[tuple[str, str]]:
    """参数型穿越的取值形态（同一个参数要试多种取值，因为落地实现差异很大）。"""
    d = max(1, int(depth))
    return [
        ("相对穿越", "../" * d + "etc/passwd"),
        ("编码相对穿越", "%2e%2e%2f" * d + "etc/passwd"),
        ("绝对路径", "/etc/passwd"),
        ("file 协议", "file:///etc/passwd"),
        ("Windows 相对穿越", "..\\" * d + "Windows\\win.ini"),
        ("Windows 绝对路径", "C:\\Windows\\win.ini"),
    ]


# 文件读取类参数名。命中率高的排前面，靠前优先测。
_FILE_PARAM_NAMES = [
    "file", "filename", "fileName", "filePath", "filepath", "path", "pathname",
    "download", "downloadUrl", "resource", "template", "include", "src", "url",
    "load", "read", "doc", "document", "attachment", "dir", "folder", "name",
    "image", "img", "content", "data", "key", "id",
]

# 每次调用允许发出的最大探测请求数（按档位缩放，避免轻量档把目标打爆）
_PROBE_BUDGET = {"quick": 40, "standard": 170, "deep": 320}

# 同一个目标文件确认可读之后，最多再记录几种生效写法就收手。
# 不为"把 11 种编码全试一遍"耗预算——预算更该花在还没探过的目标和参数上。
_MAX_FORMS_PER_TARGET = 2


def _match_target(target: tuple, body: bytes) -> tuple[int, str]:
    """在响应体里找该目标文件的特征，返回 (命中次数, 可读证据片段)。

    要处理响应被 JSON 转义的情况：很多接口把文件内容塞进 `{"data":"..."}`，
    里面的换行是字面量 `\\n`，锚定行首的判据（`^Name:`）就永远匹配不上，
    真实命中会被漏掉。所以同时用「原样」和「还原转义后」两个版本去匹配。
    """
    pattern = target[2]
    text = body[:262144].decode("utf-8", "replace")
    variants = [text]
    if text.count("\\n") >= 3:
        variants.append(text.replace("\\n", "\n").replace("\\/", "/"))
    best, needle = 0, ""
    for v in variants:
        found = pattern.findall(v)
        if len(found) > best:
            best = len(found)
            needle = found[0] if isinstance(found[0], str) else str(found[0])
    return best, needle


def _build_raw_path(path: str, query_items: list[tuple[str, str]]) -> str:
    """手工拼出请求行里的 path+query，**不做任何转义**。

    就是要让 `../`、`%2e%2e%2f`、`C:\\Windows` 原样出现在请求行里——
    这些字节形态本身就是被测对象，任何一层自动转义都会改变测试语义。
    """
    if not query_items:
        return path or "/"
    qs = "&".join(f"{k}={v}" for k, v in query_items)
    base = path or "/"
    return f"{base}?{qs}" if "?" not in base else f"{base}&{qs}"


@tool("traversal_probe",
      "目录遍历 / 任意文件读取探测（**只读**）：对静态资源前缀做路径穿越、对文件类参数做取值穿越，"
      "覆盖明文、单/双次编码、超长 UTF-8、反斜杠、`;` 路径参数截断等 11 种绕过形态。"
      "判据是**文件内容特征**（如 /etc/passwd 的账户行、win.ini 的节名）而不是状态码，"
      "因此在「任何路径都返回 200」的端点上同样可靠。",
      {"url": "str，目标 URL（接口地址，或一个已知存在的静态文件地址）",
       "prefixes": "list[str]，可选，额外要测的静态资源前缀，如 ['/assets/', '/download/']",
       "params": "list[str]，可选，优先检测的文件类参数名"},
      phase="scan", category="注入与参数")
def traversal_probe(sess: ScanSession, url: str, prefixes: list | None = None,
                    params: list | None = None) -> dict:
    parsed = urlparse(url)
    path = parsed.path or "/"
    origin = origin_of(url)
    budget = _PROBE_BUDGET.get(sess.depth, 80)
    notes: list[str] = []

    # ---------- 阶段 0：把「本站正常页面里本来就有该特征」的目标剔掉 ----------
    # 安全类站点发布 /etc/passwd 示例、教程页面贴 win.ini 内容都很常见，
    # 不先排除的话，我们会拿着站点自己的公告页当"任意文件读取漏洞"报上去。
    base_bytes = b""
    try:
        base_resp, _err = sess.request("GET", url)
        base_bytes = (base_resp.content or b"") if base_resp is not None else b""
    except (BudgetExceeded, OSError):
        base_bytes = b""
    preexisting = [t[1] for t in FILE_TARGETS if _match_target(t, base_bytes)[0] >= t[3]]
    if preexisting:
        notes.append("以下特征在本站正常页面中已出现，已排除对应目标以免误报："
                     + "、".join(preexisting))
    active = [t for t in FILE_TARGETS if t[1] not in preexisting]

    # ---------- 阶段 0b：软 404 基线 ----------
    # 与路径类工具复用同一套判据。裸 socket 拿不到 Response 对象，
    # 所以调 `matches()` —— 判据只有一份实现，两处各写一套迟早漂移。
    fb = FallbackBaseline(sess, origin)
    snote = soft404_note(fb, origin)
    if snote:
        notes.append(snote)

    # ---------- 阶段 1：静态资源前缀穿越 ----------
    def _dir_prefix(p: str) -> str:
        """把 URL 路径转成「当作起点」的目录前缀。"""
        if p.endswith("/"):
            return p
        seg = p.rsplit("/", 1)[-1]
        return (p.rsplit("/", 1)[0] + "/") if "." in seg else (p + "/")

    cand: list[str] = []
    for extra in (prefixes or []):
        if isinstance(extra, str) and extra.strip():
            cand.append(extra.strip() if extra.strip().startswith("/") else "/" + extra.strip())
    last_seg = path.rsplit("/", 1)[-1]
    if "." in last_seg:
        # URL 指向具体静态文件 → 用它的目录当起点，这是最容易命中的形态
        cand.insert(0, _dir_prefix(path))
        # 再收窄到首段目录（静态资源常集中在一个前缀下）
        head = path.strip("/").split("/")[0]
        if head and head != last_seg:
            cand.append(f"/{head}/")
    else:
        cand.append(_dir_prefix(path))
    seen: set[str] = set()
    prefix_list: list[str] = []
    for p in cand:
        p = re.sub(r"/{2,}", "/", p)
        if p not in seen and p != "//":
            seen.add(p)
            prefix_list.append(p)
    prefix_list = prefix_list[: 2 if sess.depth != "quick" else 1]

    # 阶段预算必须分开留：实测第一版把预算全用在静态前缀矩阵上，
    # 结果参数型穿越一次都没跑到——靶场里"真漏洞 + 零命中"，
    # 这是比误报更危险的一类缺陷（漏报且看不出来）。
    b1 = int(budget * 0.55)
    depths = {"quick": [6], "standard": [6, 8]}.get(sess.depth) or [6, 8, 4, 10]
    targets = active[: {"quick": 2, "standard": 3}.get(sess.depth, 4)]
    units = _traversal_units()
    enc_rank = {name: i for i, (name, _u) in enumerate(units)}
    dep_rank = {d: i for i, d in enumerate(depths)}
    tgt_rank = {t[1]: i for i, t in enumerate(targets)}

    # 计划按「编码 → 深度 → 目标」的优先级排序：先用最可能有效的几种写法
    # 把每个目标都过一遍，命中会尽早出现；预算不足时被砍掉的是最不常见的组合。
    plan: list[tuple[int, str, str, int, tuple]] = []
    for enc_i, (enc_name, unit) in enumerate(units):
        for dep_i, d in enumerate(depths):
            for tgt_i, tgt in enumerate(targets):
                prio = enc_i * 100 + dep_i * 10 + tgt_i
                plan.append((prio, enc_name, unit, d, tgt))
    plan.sort(key=lambda x: x[0])

    sent = 0
    dropped = 0
    hits: dict[str, dict] = {}
    errors: list[str] = []

    def _probe(raw_path: str) -> tuple[bool, dict]:
        """发一次穿越请求；命中返回 (True, 命中信息)。"""
        nonlocal sent
        status, body, ctype, err = sess.request_exact_path(origin, raw_path)
        sent += 1
        if err:
            errors.append(f"{raw_path} → {err}")
            return False, {}
        # 兜底页过滤：与基线同形即视为「站点对任何路径都这样答」，不算命中
        if fb.matches(status, body, ctype):
            return False, {}
        for tgt in active:
            cnt, needle = _match_target(tgt, body)
            if cnt >= tgt[3] and len(body) >= tgt[4]:
                return True, {"target": tgt, "count": cnt, "needle": needle,
                              "body": body, "status": status}
        return False, {}

    def _record(info: dict, how: dict) -> None:
        key = info["target"][1]
        rec = hits.setdefault(key, {"target": info["target"], "works": [],
                                    "body": info["body"], "status": info["status"],
                                    "count": info["count"], "needle": info["needle"]})
        rec["works"].append(how)

    def _done(target_rel: str) -> bool:
        """该目标是否已经记够生效写法，可以不再测它了。"""
        rec = hits.get(target_rel)
        return bool(rec) and len(rec["works"]) >= _MAX_FORMS_PER_TARGET

    for _prio, enc_name, unit, d, tgt in plan:
        if sent >= b1 or _done(tgt[1]):
            dropped += 1
            continue
        payload = unit * d
        for pfx in prefix_list:
            if sent >= b1:
                dropped += 1
                break
            raw_path = f"{pfx}{payload}{tgt[1]}"
            ok, info = _probe(raw_path)
            if ok:
                _record(info, {"kind": "path", "enc": enc_name, "depth": d,
                               "prefix": pfx, "raw": raw_path, "status": info["status"]})
                if _done(tgt[1]) or len(hits[tgt[1]]["works"]) >= 1:
                    break  # 已确认，不再为同一目标试其它前缀

    # ---------- 阶段 2：参数型穿越 ----------
    # 参数值同样手工拼进请求行：`urlencode` 会把已编码的值再编一次，
    # 那样"单次编码"的载荷实际变成了双重编码，测试语义完全变了。
    given = [k for k, _v in parse_qsl(parsed.query, keep_blank_values=True) if k]
    extra = [p for p in (params or []) if isinstance(p, str) and p.strip()]
    # 前端 JS 里出现过的查询参数名优先——比猜 30 个常见名有效得多
    js_names = [n for n in (sess.discovered.get("js_params") or {}).get(origin, [])
                if n.isidentifier() or re.fullmatch(r"[A-Za-z_][\w\-]{1,30}", n or "")]
    names = extra + [n for n in given if n not in extra] + [n for n in js_names if n not in extra]
    names += [n for n in _FILE_PARAM_NAMES if n not in names]
    names = names[: 4 if sess.depth == "quick" else 6]

    base_qs = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)]
    param_sent = 0

    # ---------- 阶段 2a：对真实接口做取值穿越 ----------
    # 对着站点根路径猜参数名，在 SPA 上几乎必然空手而归——真实落点是前端 bundle
    # 里那些接口。`api_surface` 已经把清单缓存下来了，这里直接用。
    discovered = [p for p in (sess.discovered.get("endpoints") or {}).get(origin, [])
                  if p and urlparse(p).path != path]
    disc_cap = {"quick": 6, "standard": 18, "deep": 36}.get(sess.depth, 18)
    disc_sent = 0
    disc_hit = 0
    for ep in discovered[: 2 if sess.depth != "deep" else 4]:
        if sent >= budget or disc_sent >= disc_cap:
            break
        ep_path = urlparse(ep).path
        ep_qs = [(k, v) for k, v in parse_qsl(urlparse(ep).query, keep_blank_values=True)]
        for name in names[:2]:
            if sent >= budget or disc_sent >= disc_cap:
                break
            for form_name, value in _param_value_forms(6):
                if sent >= budget or disc_sent >= disc_cap:
                    break
                qs = [kv for kv in ep_qs if kv[0] != name] + [(name, value)]
                raw_path = _build_raw_path(ep_path, qs)
                ok, info = _probe(raw_path)
                disc_sent += 1
                param_sent += 1
                if ok:
                    disc_hit += 1
                    _record(info, {"kind": "param", "param": name, "form": form_name,
                                   "depth": 6, "prefix": "", "raw": raw_path,
                                   "status": info["status"]})
                    break
    if not discovered:
        notes.append("未取得前端接口清单（api_surface 未运行或站点无 JS bundle），"
                     "参数型穿越只对着入口路径测试，命中率会明显偏低")

    for name in names:
        if sent >= budget:
            dropped += 1
            continue
        for form_name, value in _param_value_forms(6):
            if sent >= budget:
                dropped += 1
                break
            qs = [kv for kv in base_qs if kv[0] != name] + [(name, value)]
            raw_path = _build_raw_path(path, qs)
            ok, info = _probe(raw_path)
            param_sent += 1
            if ok:
                _record(info, {"kind": "param", "param": name, "form": form_name,
                               "depth": 6, "prefix": "", "raw": raw_path,
                               "status": info["status"]})
                break   # 该参数已确认，换下一个参数

    # ---------- 汇总 ----------
    issues: list[dict] = []
    for _rel, rec in hits.items():
        tgt = rec["target"]
        works = rec["works"]
        how = works[0]
        is_param = how.get("kind") == "param"

        if is_param:
            where = f"参数 `{how['param']}`，取值形态：{how['form']}"
            context = f"参数 `{how['param']}` 的取值被直接用于拼接文件路径，未做任何归一化校验。"
            param_field = how["param"]
        else:
            where = f"路径穿越（{how['enc']}，向上 {how['depth']} 层）"
            context = "静态资源处理没有把请求路径限制在预设目录内。"
            param_field = ""

        others = ""
        if len(works) > 1:
            labels = [w["raw"] if w.get("kind") == "param" else f"{w['enc']}@深度{w['depth']}"
                      for w in works[1:5]]
            others = f" 另有 {len(works) - 1} 种写法同样有效：" + "、".join(f"`{x}`" for x in labels) + "。"

        issues.append(_issue(
            "path-traversal", tgt[6], "注入与参数",
            f"目录遍历 / 任意文件读取：{tgt[5]}", url,
            f"可以读取 web 根目录之外的文件，本次读出了 {tgt[5]}"
            f"（匹配到 {rec['count']} 处文件特征）。生效方式：{where}。{context}{others}",
            "禁止把用户输入直接拼进文件路径，改为固定映射表（ID → 文件名）。"
            "Java 侧用 `Path.normalize()` 归一化后再校验 `startsWith(基准目录)`；"
            "Spring 静态资源链路的历史穿越漏洞（CVE-2024-38816 / 38819 等）需升级版本；"
            "Tomcat 建议关闭 `;` 路径参数（`allowPathParams=false`）。",
            cwe="CWE-22", method="GET", param=param_field,
            payload=how["raw"],
            evidence=_snippet(rec["body"], needle=rec["needle"], width=260),
            confidence="high" if tgt[6] == "critical" else "medium"))

    prefix_part = f"静态前缀 {len(prefix_list)} 个（{'、'.join(prefix_list)}）" if prefix_list else "静态前缀（无）"
    summary = (f"{prefix_part}、文件类参数 {len(names)} 个，共 {sent} 次穿越请求"
               f"（其中参数型 {param_sent} 次，含对 {len(discovered[:2 if sess.depth != 'deep' else 4])} 个前端接口的 {disc_sent} 次），"
               f"确认 {len(issues)} 项")
    if dropped:
        summary += f"；受本档位预算（{budget} 次）限制，有 {dropped} 个组合未测试"
    if errors:
        summary += f"；{len(errors)} 次请求失败"
    if not issues and not active:
        summary = "本站正常页面已含全部目标文件特征，无可信的穿越判据，本次未做穿越测试"

    return {"ok": True, "summary": summary,
            "data": {"url": url, "prefixes": prefix_list, "depths": depths,
                     "units": [u[0] for u in units], "params": names,
                     "targets": [t[1] for t in active],
                     "excluded_targets": preexisting,
                     "discovered_endpoints": len(discovered),
                     "discovered_tested": disc_sent,
                     "discovered_hits": disc_hit,
                     "requests": sent, "static_budget": b1, "budget": budget,
                     "dropped": dropped, "param_requests": param_sent,
                     "hits": [{"file": k, "works": v["works"]} for k, v in hits.items()]},
            "issues": issues, "notes": notes}


# ============================================================ 前端接口面与未授权可达性
#
# 为什么需要这个工具：现代站点的真实接口面**不在 HTML 里，在前端 JS bundle 里**。
# 实测一个 Angular 站点，扫描器把根路径翻了个遍只报了 3 个缺安全头，
# 而 bundle 里明明白白写着 `/aiopskit/basic/config/proxy` 这类接口，
# 其中好几个**免 token 就能读到**（含代理用户名/口令字段名与租户 ID）。
# 探测起点只有 `/` 时，参数注入与路径穿越这两类工具根本没有落点，
# 只能用猜的参数名对着首页打——在 SPA 上几乎必然空手而归，然后被误读成"目标干净"。

# JS 里的绝对路径字符串（含模板串 ${e} 这类形态）
_JS_PATH_RE = re.compile(
    r"""["'`](/(?!/)[A-Za-z][A-Za-z0-9_\-]*(?:/[A-Za-z0-9_\-{}:.$]+)+)["'`]""")
# JS 里的查询参数名（`?file=` / `&path=`）
_JS_QUERY_RE = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_\-]{1,30})=")
_SCRIPT_SRC_RE = re.compile(
    r"""<script[^>]+src=["']([^"']+\.js[^"']*)["']""", re.I)

# ---- 传统 HTML 站点的落点采集 ----
#
# 只有 JS bundle 采集是**不够**的，而且不够得很隐蔽：传统站点（PHP/Java/ASP
# 拼页面的那种）根本没有 bundle，接口路径与参数名全在 `<a href>` 和 `<form>` 里。
# 此时 `discovered["endpoints"]` 恒为空，参数注入 / 文件包含 / CRLF 三类工具
# 就只能对着入口路径猜参数名——在「首页无参数、真实功能都在子页面」的站点上
# 命中率趋近于零，报告却只写「未发现」，读起来像是已经检查过并且没问题。
#
# 所以这里把 href / action / src 也当落点来源，并且**专门保留带查询串的 URL**：
# 一个带 `?file=` 的链接本身就证明了「该路径接受 file 参数」，比任何猜名字都准。
_HTML_ATTR_RE = re.compile(
    r"""<(?:a|area|form|iframe|frame|link)\b[^>]*?\b(?:href|action|src)\s*=\s*"""
    r"""["']([^"'#][^"']*)["']""", re.I)
# 表单里可能没有 action（提交到当前页），但 input 的 name 仍是真实参数名
_HTML_INPUT_NAME_RE = re.compile(
    r"""<(?:input|select|textarea)\b[^>]*?\bname\s*=\s*["']([A-Za-z_][\w\-\.]{0,40})["']""",
    re.I)
# 单引号/双引号皆可出现在 JS 里，也允许 <script> 内联写的同源路径
_HTML_PARAM_HINT_RE = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_\-]{1,30})=")
# 整段 form：取 action、method 与其中所有 input 名
_HTML_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
_HTML_ATTR_IN_TAG_RE = re.compile(r"""\b(action|method)\s*=\s*["']([^"']*)["']""", re.I)

# 静态资源不算接口
_STATIC_EXT_RE = re.compile(
    r"\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|html?|webmanifest)$", re.I)
_STATIC_PREFIX = ("/assets/", "/node_modules/", "/static/", "/styles.", "/polyfills",
                  "/main-", "/runtime-", "/scripts.", "/favicon")

# 疑似凭据字段（键名，值非空时才升级等级）
_SECRET_KEY_RE = re.compile(
    r"""["']\w*?(passw\w*|pwd|secret\w*|token\w*|credential\w*|"""
    r"""api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?(?:user|pwd))\w*["']\s*:\s*["']([^"']+)["']""",
    re.I)

_API_PROBE_LIMIT = {"quick": 14, "standard": 44, "deep": 90}

# 文件/上传/下载/导出/模板类接口——任意文件读取与越权访问的主战场
_FILEISH_HINTS = ("file", "files", "path", "dir", "folder", "download", "upload",
                  "attach", "doc", "docs", "export", "import", "template", "report",
                  "resource", "stream", "image", "img", "media", "backup", "log",
                  "logfile", "static", "asset", "content", "print", "preview", "view")


def _endpoint_rank(p: str) -> tuple:
    """接口的探测优先级：文件类最高，其次是网关/接口类，最后是页面类。"""
    low = p.lower()
    fileish = 0 if any(h in low for h in _FILEISH_HINTS) else 1
    apish = 0 if any(h in low for h in ("api", "gateway", "service", "open",
                                        "config", "admin", "manage", "device")) else 1
    return (fileish, apish)


def _clean_js_path(p: str) -> str:
    """把从 JS 里抠出来的字符串整理成可请求的路径；不像接口的返回空串。"""
    p = p.split("?")[0].split("#")[0].strip()
    if not p.startswith("/") or p.startswith("//"):
        return ""
    if len(p) > 120 or "//" in p:
        return ""
    low = p.lower()
    if any(low.startswith(s) for s in _STATIC_PREFIX):
        return ""
    if _STATIC_EXT_RE.search(p):
        return ""
    if not re.search(r"[A-Za-z]", p):
        return ""
    # 全是单字符段（`/a/b`、`/a/i`）——从压缩后的库代码里抠出来的片段，
    # 不是接口。真实接口的首段基本都有语义（`api`、`aio`、`v1`）。
    segs = [s for s in p.strip("/").split("/") if s]
    if segs and all(len(s) <= 1 for s in segs):
        return ""
    return p


def _script_rank(url: str) -> tuple:
    """JS bundle 的抓取优先级。

    实测教训：标准档只抓前 5 个 bundle 时，真正含接口清单的 `main-es2015.js`
    恰好排在第 6 个，于是"接口面发现"跑完只得到 2 个垃圾路径——
    不是没实现，而是**抓错了文件**。所以必须先按重要性排序再截断。

    两条排序依据：
    1. `-es5` 是 `-es2015` 的降级副本，内容等价，抓一个就够；
    2. 名字里带 main / app / chunk / vendor / index 的才是业务代码所在。
    """
    name = url.rsplit("/", 1)[-1].lower()
    es5_dup = 1 if "-es5" in name or ".es5." in name else 0
    mainish = 0 if any(k in name for k in ("main", "app", "chunk", "vendor",
                                           "index", "common")) else 1
    # 压缩过的第三方库（jquery.min.js 之类）排在最后：里面几乎只有代码片段，
    # 硬抠出来的"路径"大多是 `/a/b` 这种噪声。
    if ".min." in name or "/lib/" in url:
        mainish += 1
    return (es5_dup, mainish, -len(name))


@tool("api_surface",
      "前端接口面发现（**只读**）：从页面 HTML 与 JS bundle 中提取后端接口路径与查询参数名，"
      "逐个**不带任何凭据**请求，识别免认证即可访问的接口、以及响应中暴露凭据字段的接口。"
      "提取到的接口会缓存到扫描会话，供参数注入与路径穿越工具当作真实落点使用。",
      {"url": "str，站点入口 URL（通常是首页）"},
      phase="recon", category="信息收集")
def api_surface(sess: ScanSession, url: str) -> dict:
    origin = origin_of(url)
    limit = _API_PROBE_LIMIT.get(sess.depth, 18)
    notes: list[str] = []
    issues: list[dict] = []

    # ---------- 收集脚本地址 ----------
    scripts: list[str] = []
    html = ""
    try:
        page, _err = sess.request("GET", url)
        html = (page.text or "") if page is not None else ""
    except (BudgetExceeded, OSError):
        html = ""
    for m in _SCRIPT_SRC_RE.finditer(html):
        scripts.append(m.group(1))
    # HTML 自身的内联路径也算（有些站把接口前缀直接写在页面上）
    raw_routes = list(_JS_PATH_RE.findall(html)) + list(_JS_QUERY_RE.findall(html))

    # ---------- 抓取脚本并抽取路径 ----------
    max_scripts = {"quick": 3, "standard": 10, "deep": 18}.get(sess.depth, 10)
    ordered = sorted(scripts, key=_script_rank)
    fetched = 0
    for src in ordered[:max_scripts]:
        full = src if src.startswith("http") else f"{origin}/{src.lstrip('/')}"
        if not full.startswith(("http://", "https://")):
            continue          # data: / blob: 之类的 src 直接跳过
        try:
            r, _e = sess.request("GET", full)
        except (BudgetExceeded, OSError):
            break
        if r is None or r.status_code >= 400:
            continue
        fetched += 1
        text = r.text or ""
        raw_routes += _JS_PATH_RE.findall(text)
        raw_routes += _JS_QUERY_RE.findall(text)

    if len(scripts) > max_scripts:
        notes.append(f"页面引用 {len(scripts)} 个 JS bundle，本档位仅解析前 {max_scripts} 个；"
                     f"接口面可能不完整")

    # ---------- 传统 HTML 落点采集（链接 / 表单）----------
    # 这一步与 JS bundle 解析是**互补**关系，不是重复：bundle 解析覆盖 SPA，
    # 这里覆盖「页面里就有 a href / form action」的传统站点。两类都跑，
    # 才不会出现"站点明明是传统架构，却因为没 bundle 而整类漏检"。
    html_param_urls: list[str] = []
    html_params: list[str] = []
    html_paths: list[str] = []

    def _harvest(page_html: str, page_url: str) -> list[str]:
        """从一页 HTML 里采集落点，返回本页发现的同源待抓 URL。"""
        found: list[str] = []
        for raw in _HTML_ATTR_RE.findall(page_html):
            raw = raw.strip()
            if not raw or raw.lower().startswith(("javascript:", "mailto:", "tel:",
                                                  "data:", "blob:", "#")):
                continue
            # 相对路径补成绝对，跨域的直接丢弃（不做站外探测）
            if raw.startswith("//"):
                raw = f"{urlparse(page_url).scheme}:{raw}"
            elif raw.startswith("/"):
                raw = origin + raw
            elif not raw.startswith(("http://", "https://")):
                base_dir = page_url.rsplit("/", 1)[0]
                raw = f"{base_dir}/{raw.lstrip('./')}"
            if not raw.startswith(origin):
                continue
            p = urlparse(raw)
            if p.query:
                # 带查询串 = 已证实的参数落点，最值钱
                if raw not in html_param_urls and len(html_param_urls) < 60:
                    html_param_urls.append(raw)
                for m in _HTML_PARAM_HINT_RE.finditer("?" + p.query):
                    if m.group(1) not in html_params:
                        html_params.append(m.group(1))
            elif p.path and not _STATIC_EXT_RE.search(p.path) and p.path != "/":
                if p.path not in html_paths and len(html_paths) < 80:
                    html_paths.append(p.path)
                found.append(origin + p.path)
        for m in _HTML_INPUT_NAME_RE.finditer(page_html):
            name = m.group(1)
            if name.lower() not in ("submit", "reset", "button", "_method") \
                    and name not in html_params:
                html_params.append(name)
        # 表单：action 本身常常没有查询串（`<form action="/search">`），
        # 于是「参数名采集到了」却没有对应的落点 URL——参数注入工具拿着
        # 名字却不知道往哪条路径投。这里把 action 与它的 input 名合成一个
        # 带查询串的 URL，让下游工具能直接当落点用。
        # 只收 GET 表单：本工具链全部走 GET/HEAD，POST 表单投不进去，
        # 收进来只会变成必然失败的请求，白花预算。
        for fattr, finner in _HTML_FORM_RE.findall(page_html):
            meta = {k.lower(): v for k, v in _HTML_ATTR_IN_TAG_RE.findall(fattr)}
            if (meta.get("method") or "get").strip().lower() != "get":
                continue
            action = (meta.get("action") or "").strip()
            if action.lower().startswith(("javascript:", "mailto:", "tel:", "#")):
                continue
            fnames = [n for n in _HTML_INPUT_NAME_RE.findall(finner)
                      if n.lower() not in ("submit", "reset", "button", "_method",
                                           "_token", "csrfmiddlewaretoken")]
            if not fnames:
                continue
            if action.startswith(("http://", "https://")):
                furl = action
            elif action.startswith("/"):
                furl = origin + action
            else:
                base_dir = page_url.rsplit("/", 1)[0]
                furl = f"{base_dir}/{(action or '').lstrip('./')}"
            if not furl.startswith(origin):
                continue
            fp = urlparse(furl)
            existing = [k for k, _v in
                        parse_qsl(fp.query, keep_blank_values=True) if k]
            allnames = existing + [n for n in fnames if n not in existing]
            synth = (f"{fp.scheme}://{fp.netloc}{fp.path or '/'}"
                     f"?{'&'.join(n + '=' for n in allnames[:6])}")
            if synth not in html_param_urls and len(html_param_urls) < 60:
                html_param_urls.append(synth)
            for n in allnames:
                if n not in html_params:
                    html_params.append(n)
        return found

    # html 是首页（`sess.request` 已抓过，不额外花请求）
    crawl_queue = _harvest(html, url)
    # BFS 扩一层：只抓同源、无查询串的 HTML 页面。再深一层收益下降很快，
    # 而请求预算是所有工具共享的——采落点花超了，后面的检测项就跑不到。
    crawl_cap = {"quick": 4, "standard": 12, "deep": 24}.get(sess.depth, 12)
    crawled = 0
    seen_pages = {urlparse(url).path}
    while crawl_queue and crawled < crawl_cap:
        nxt = crawl_queue.pop(0)
        p = urlparse(nxt)
        if p.path in seen_pages:
            continue
        seen_pages.add(p.path)
        try:
            r, _e = sess.request("GET", nxt)
        except (BudgetExceeded, OSError):
            break
        if r is None or r.status_code >= 400:
            continue
        ctype = (r.headers.get("content-type") or "").lower()
        if "html" not in ctype:
            continue          # 只顺着页面爬，不下钻二进制/JSON
        crawled += 1
        for u in _harvest(r.text or "", nxt):
            uq = urlparse(u)
            if not uq.query and uq.path not in seen_pages:
                crawl_queue.append(u)

    if html_param_urls:
        notes.append(f"从页面链接/表单采集到 {len(html_param_urls)} 个带参数的落点"
                     f"（如 `{urlparse(html_param_urls[0]).path}?{urlparse(html_param_urls[0]).query}`），"
                     f"已作为参数注入/文件包含/CRLF 的注入点")

    # 只有以 `/` 开头的才是接口路径；其余是查询参数名（另存到 js_params）
    endpoints: list[str] = []
    for raw in raw_routes:
        if not raw.startswith("/"):
            continue
        cand = _clean_js_path(raw)
        if cand and cand not in endpoints:
            endpoints.append(cand)
    # 排序按「价值」而不是字母：文件/上传/下载/导出类接口是任意文件读取与
    # 越权的主战场，必须排在前面——按字母排时它们会排在 `/aiopskit/*` 之后，
    # 预算一截断就全被丢掉（实测 `/files/segment`、`/dpt/dev-tool/dw-upload-cc`
    # 就是这样被漏掉的）。
    endpoints.sort(key=lambda p: (_endpoint_rank(p), len(p)))
    # 免凭据可达性探测的额度要给足：每个接口只是一次普通 GET，很便宜；
    # 而「哪些接口不需要鉴权」恰恰是这份清单最有价值的产出，卡太紧会漏掉整类。
    # 额度不足时被丢掉的接口必须写进 notes，不能静默。
    if len(endpoints) > limit:
        notes.append(f"共提取 {len(endpoints)} 个候选接口路径，本档位仅探测前 {limit} 个；"
                     f"未探测：{'、'.join(endpoints[limit:limit + 6])}"
                     f"{' 等' if len(endpoints) > limit + 6 else ''}")

    # 参数名取 JS 与 HTML 两处的并集：两处来源都只增不减，谁有就信谁。
    js_params = sorted({x for x in raw_routes if x and not x.startswith("/")}
                       | set(html_params))
    # 本工具自己只对 JS 抽出的接口做 JSON 可达性探测；HTML 页面路径不是接口，
    # 塞进这个循环纯属浪费预算。它们在本函数返回前才并入共享清单，
    # 供后面的穿越/参数类工具当落点用。
    probe_targets = endpoints[:limit]

    # ---------- 免凭据可达性探测 ----------
    reachable: list[tuple[str, int, list[str]]] = []
    errors = 0
    for path in probe_targets:
        try:
            r, err = sess.request("GET", origin + path)
        except (BudgetExceeded, OSError):
            break
        if r is None:
            errors += 1
            continue
        if not (200 <= r.status_code < 300):
            continue
        ctype = (r.headers.get("content-type") or "").lower()
        if "json" not in ctype:
            continue          # 非 JSON 的 2xx 多半是前端路由兜底，不作为接口
        body = r.text or ""
        secrets = [m.group(0)[:60] for m in _SECRET_KEY_RE.finditer(body)
                   if (m.group(2) or "").strip()]
        reachable.append((path, r.status_code, secrets))

    leaking = [x for x in reachable if x[2]]
    if reachable:
        listed = "、".join(f"`{p}`" for p, _s, _k in reachable[:12])
        more = f"（另有 {len(reachable) - 12} 个）" if len(reachable) > 12 else ""
        issues.append(_issue(
            "api-surface",
            "medium" if leaking else "low",
            "未授权访问",
            f"免认证可访问的后端接口 {len(reachable)} 个"
            + ("（其中含凭据类字段）" if leaking else ""),
            url,
            f"以下接口不带任何凭据即可返回业务数据：{listed}{more}。"
            + (f"其中 {len(leaking)} 个的响应体里出现了凭据类字段名且**值非空**"
               f"（如 {leaking[0][2][0]}），需要立刻确认是否泄漏了真实凭据。"
               if leaking else
               "本次响应中未发现非空的凭据字段值，但接口面本身对外可见，"
               "建议逐个人工确认是否有应当鉴权的接口。"),
            "在网关层统一做鉴权，不要依赖前端不展示；"
            "配置类接口应要求认证并限制来源 IP；"
            "不要把口令类字段写进接口响应体（哪怕当前为空）。",
            cwe="CWE-306", method="GET",
            evidence="\n".join(f"GET {origin}{p} → {s}"
                               + (f"  凭据字段：{', '.join(k[:40] for k in ks)}" if ks else "")
                               for p, s, ks in reachable[:8]),
            confidence="high" if leaking else "medium", source="tool"))

    if errors:
        notes.append(f"{errors} 个接口请求失败，未纳入判定")

    # ---------- 写入跨工具共享清单 ----------
    # 按 origin 分键——一个作业里可能扫多个目标，共用一份缓存会串台。
    # HTML 页面路径排在 JS 接口之后：JS 里的是真接口，优先级更高；
    # 但两者都要留给后续工具，否则传统站点上穿越/参数类工具无落点可用。
    shared_endpoints = list(endpoints)
    for hp in html_paths:
        if hp not in shared_endpoints:
            shared_endpoints.append(hp)
    sess.discovered.setdefault("endpoints", {})[origin] = shared_endpoints
    sess.discovered.setdefault("js_params", {})[origin] = js_params
    # 已证实带参数的 URL —— 参数注入 / 文件包含 / CRLF 的最高价值落点
    sess.discovered.setdefault("param_urls", {})[origin] = html_param_urls

    summary = (f"解析 {fetched} 个 JS bundle，提取 {len(endpoints)} 个候选接口路径"
               + (f"；爬取 {crawled} 个页面，从链接/表单补充 {len(html_paths)} 个路径、"
                  f"{len(html_param_urls)} 个带参数落点" if (html_paths or html_param_urls) else "")
               + f"，探测前 {len(probe_targets)} 个：免凭据可达 {len(reachable)} 个"
               + (f"，其中 {len(leaking)} 个含非空凭据字段" if leaking else ""))
    return {"ok": True, "summary": summary,
            "data": {"url": url, "scripts": scripts[:max_scripts],
                     "fetched_bundles": fetched,
                     "endpoints": shared_endpoints,
                     "html_pages_crawled": crawled,
                     "param_urls": html_param_urls,
                     "probed": len(probe_targets),
                     "unauth_reachable": [{"path": p, "status": s, "secret_keys": k}
                                          for p, s, k in reachable],
                     "param_names": js_params},
            "issues": issues, "notes": notes}
