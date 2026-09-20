"""Web 漏洞扫描模块（轻量级，独立于代码审计）。

组成：
    tools.py        可被 AI 调用的原子探测能力（HTTP 探测 / 指纹 / 端口 / TLS / 目录 / 配置审计）
    tools_deep.py   深度探测能力（服务识别 / 未授权访问 / 备份泄漏 / 参数型漏洞 / 目录遍历 / 接口面）
    tools_vuln.py   应用层缺陷（XSS 上下文判定 / CSRF / 凭据泄漏 / CRLF 响应头注入）
    tools_expose.py 暴露面与攻击面测绘（组件版本 / 文件包含 / 认证攻击面 / API 审计 / WAF 识别）
    skills_seed.py  Web 漏扫技能库（SKILL.md 形式，描述每个阶段"做什么、调哪个工具、怎么判"）
    agent.py        AI 自主规划渗透流程 + 工具执行循环
    report.py       Markdown / HTML 报告渲染

注意：这里显式 import 各个工具模块，是为了让它们的 ``@tool`` 装饰器在
包被导入时全部执行、注册进同一个工具表——否则工具会「存在但不可调用」。
漏 import 一个模块的表现是：技能提示词里写了这个工具，AI 也照着调了，
但每次都被回「未知工具」。所以新增工具模块时**必须**在这里加一行。
"""
from __future__ import annotations

from backend.core.webscan import tools  # noqa: F401
from backend.core.webscan import tools_deep  # noqa: F401
from backend.core.webscan import tools_vuln  # noqa: F401
from backend.core.webscan import tools_expose  # noqa: F401

__all__ = ["tools", "tools_deep", "tools_vuln", "tools_expose",
           "skills_seed", "agent", "report"]
