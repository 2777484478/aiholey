"""目标 → 扫描单元展开（「逐端口扫描」的核心编排）。

为什么要展开
------------
用户输入的是 IP / 域名 / URL，但真实的暴露面在**端口**上：同一台机器上
可能 80 端口跑着网站、9200 跑着 Elasticsearch、6379 跑着 Redis。
只扫 80 端口，后面这些全都看不见。

展开流程
--------
    目标（IP / 域名 / URL）
      ├─ ① 端口发现   按档位选「常见端口」或「1-65535 全端口」
      ├─ ② 服务识别   对每个开放端口做 banner / 协议 / 应用识别
      └─ ③ 分派
           ├─ HTTP 类  → 构造 http(s)://host:port，走完整 Web 检测链（AI 规划）
           ├─ 服务类    → Redis / ES / Docker / K8s … 走未授权访问检测
           └─ 其他      → 仅记录暴露（风险判定已由服务识别给出）

配额与透明性
------------
端点数、服务识别数都有上限，且**超限时会写入 notes 与日志**——
不静默跳过，否则使用者会误以为「这些端口扫过了、没问题」。
"""
from __future__ import annotations

from urllib.parse import urlparse

from backend.config import WEB_DEPTHS
from backend.core.webscan import tools as T

# 端口扫描范围与端点配额的「兜底默认」——真实取值优先从 WEB_DEPTHS 读，
# 保持档位参数只有一处定义，避免两处漂移。
PORT_MODES = {"quick": "common", "standard": "full", "deep": "full"}
ENDPOINT_LIMITS = {"quick": 1, "standard": 4, "deep": 8}


def _port_mode(depth: str) -> str:
    cfg = WEB_DEPTHS.get(depth) or {}
    return str(cfg.get("ports") or PORT_MODES.get(depth, "full"))


def _endpoint_limit(depth: str) -> int:
    cfg = WEB_DEPTHS.get(depth) or {}
    try:
        return int(cfg.get("endpoints") or ENDPOINT_LIMITS.get(depth, 4))
    except (TypeError, ValueError):
        return ENDPOINT_LIMITS.get(depth, 4)

# 最多对多少个开放端口做服务识别（识别本身也要发探针）
PROBE_LIMIT = 40

# 应用层就是 HTTP 的服务 → 适合跑完整 Web 检测链
WEB_SERVICES = {
    "http", "https", "tomcat", "nginx", "spring-boot", "jenkins",
    "swagger", "grafana", "php", "apache", "iis", "weblogic", "jetty",
}

# 数据面/管理面服务 → 走未授权访问检测（比跑 Web 链更精准）
SERVICE_CHECKS = {
    "redis", "memcached", "elasticsearch", "docker", "k8s-api", "kibana", "rabbitmq",
}

# 这些端口按 TLS 处理
TLS_PORTS = {443, 465, 636, 993, 995, 2376, 4443, 6443, 8443, 9443, 10443}


def expand_target(target: str, sess: T.ScanSession, *, depth: str = "standard",
                  say=None) -> dict:
    """把单个目标展开成扫描单元。

    返回 ``{"http": [...], "services": [...], "ports": [...], "issues": [...], "notes": [...]}``：

    - ``http``     需跑完整 Web 检测链的端点，主端点排在最前
    - ``services`` 需跑未授权访问检测的服务端口
    - ``ports``    全部开放端口的概览（含服务识别结果）
    - ``issues``   端口探测阶段自身产出的确定性发现（端口暴露、服务暴露）
    - ``notes``    展开过程中的说明与配额提示
    """
    def log(msg: str, level: str = "info") -> None:
        if say:
            say(msg, level)

    parsed = urlparse(target)
    host = parsed.hostname or ""
    orig_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    notes: list[str] = []
    issues_found: list[dict] = []
    if not host:
        return {"http": [], "services": [], "ports": [], "issues": [],
                "notes": ["无法从目标中解析出主机名"]}

    # ---------- ① 端口发现 ----------
    mode = _port_mode(depth)
    scan = T.run_tool(sess, "port_scan", {"host": host, "mode": mode})
    open_ports: list[int] = []
    if scan.get("ok"):
        open_ports = [int(x["port"]) for x in (scan.get("data") or {}).get("open", [])]
        log(f"  端口发现（{mode}）：{scan.get('summary')}")
    else:
        notes.append(f"端口发现失败：{scan.get('summary')}")
        log(f"  端口发现失败：{scan.get('summary')}", "warn")
    for it in (scan.get("issues") or []):
        it["target"] = target
        issues_found.append(it)

    # ---------- ② 逐端口服务识别 ----------
    probed: list[dict] = []
    for port in open_ports[:PROBE_LIMIT]:
        r = T.run_tool(sess, "service_probe", {"host": host, "port": port})
        d = r.get("data") or {}
        probed.append({
            "port": port,
            "service": str(d.get("service") or "unknown"),
            "version": str(d.get("version") or ""),
            "tls": bool(d.get("tls")),
            "banner": str(d.get("banner") or "")[:160],
            "open": True,
        })
        for it in (r.get("issues") or []):
            it["target"] = target
            issues_found.append(it)
    if len(open_ports) > PROBE_LIMIT:
        notes.append(f"开放端口 {len(open_ports)} 个，仅对前 {PROBE_LIMIT} 个做了服务识别")
        log(f"  开放端口 {len(open_ports)} 个，超出识别配额（{PROBE_LIMIT}），"
            f"其余端口只做连通性记录")

    # ---------- ③ 分派 ----------
    http_eps: list[dict] = []
    svc_ports: list[dict] = []
    for p in probed:
        svc = p["service"]
        port = p["port"]
        if svc in SERVICE_CHECKS:
            svc_ports.append(p)
            continue
        is_http = svc in WEB_SERVICES or (p["tls"] and svc == "unknown")
        if not is_http:
            continue
        scheme = "https" if (p["tls"] or port in TLS_PORTS) else "http"
        http_eps.append({**p, "url": f"{scheme}://{host}:{port}",
                         "is_primary": port == orig_port})

    # 原始端点必须保留：即便端口发现漏了它（例如目标指到非标准端口或扫描配额不足）
    if not any(e["is_primary"] for e in http_eps):
        http_eps.insert(0, {
            "port": orig_port, "service": parsed.scheme or "http", "version": "",
            "tls": parsed.scheme == "https", "banner": "", "open": True,
            "url": target.rstrip("/"), "is_primary": True,
        })

    # ---------- ④ 端点配额 ----------
    limit = _endpoint_limit(depth)
    http_eps.sort(key=lambda e: (not e["is_primary"], e["port"]))
    if len(http_eps) > limit:
        dropped = http_eps[limit:]
        detail = "、".join(f"{e['port']}({e['service']})" for e in dropped)
        notes.append(f"HTTP 端点共 {len(http_eps)} 个，本档位仅展开前 {limit} 个；"
                     f"未展开：{detail}")
        log(f"  HTTP 端点 {len(http_eps)} 个，超出本档位配额（{limit}），未展开：{detail}", "warn")
        http_eps = http_eps[:limit]

    for e in http_eps:
        e["is_primary"] = bool(e["is_primary"])

    return {"http": http_eps, "services": svc_ports, "ports": probed,
            "issues": issues_found, "notes": notes}


def port_summary(ports: list[dict]) -> str:
    """把端口概览压成一行日志。"""
    if not ports:
        return "未发现开放端口"
    return "、".join(f"{p['port']}/{p['service']}" for p in ports[:15]) + (
        f" 等 {len(ports)} 个" if len(ports) > 15 else "")
