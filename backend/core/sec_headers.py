"""安全响应头（供 main.py 的中间件与报告端点共用）。

单独拆一个模块而不是写在 main.py 里，是因为**报告端点需要覆写 CSP**——
而 main.py 导入了这些端点，端点再反过来 import main 就是循环导入了。
"""
from __future__ import annotations

from backend.core.report_html import PRINT_SCRIPT_HASH

# 主站 CSP：前端是零依赖原生实现，index.html / login.html 都只引外部脚本，
# 所以 script-src 能收紧到 'self'，不给 'unsafe-inline'。
# 好处是：即便某处漏了转义导致 HTML 注入，攻击者也执行不了脚本。
# style-src 必须留 'unsafe-inline'——登录页样式是内联的，且前端用 canvas 手绘图、
# 到处设 style 属性；CSS 注入的危害远小于脚本执行。
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",                    # 防点击劫持（旧浏览器）
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    ),
}

# 报告页 CSP：报告正文里嵌着**被扫描项目的代码与响应内容**，是本站最不可信的
# 一块 HTML，所以比主站更严——default-src 直接 'none'，脚本只放行打印按钮那一段
# 固定内联脚本的 sha256（哈希在 report_html 里和脚本本体一同定义，改脚本忘改哈希
# 这种事不可能发生）。内联 <style> 保留在 style-src 里，否则报告会掉样式。
REPORT_CSP = (
    "default-src 'none'; "
    f"script-src 'sha256-{PRINT_SCRIPT_HASH}'; "
    "style-src 'unsafe-inline'; "
    "img-src data:; "
    "font-src data:; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "frame-ancestors 'none'"
)
