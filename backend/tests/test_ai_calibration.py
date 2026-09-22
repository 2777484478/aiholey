"""AI 结论校准（engine._calibrate_ai）的回归测试。

用法：.venv/bin/python -m unittest backend.tests.test_ai_calibration -v

为什么需要它
------------
AI 层的误报和规则层不是一回事：它不是「匹配了错误的字符串」，而是**基于看不到的
代码做保守推断**，并给出 critical/high。历史数据里 run2 的 27 条有 23 条、
run3 的 28 条有 22 条属于这种「假设式结论」。

提示词里已经要求模型自己校准（见 engine.SYS_PROMPT 第 5、6 条），但模型不总是听话，
所以再加一层确定性的兜底：命中假设式措辞就降一级并把 confidence 压到 low。
这里锁住这个行为，避免以后被顺手改掉。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.core.engine import _calibrate_ai  # noqa: E402


class AICalibrationTest(unittest.TestCase):
    def test_evidence_backed_kept(self):
        """有可见证据的结论：严重度与置信度都不动。"""
        for sev in ("critical", "high", "medium", "low"):
            with self.subTest(sev=sev):
                self.assertEqual(
                    _calibrate_ai(sev, "high", "MyBatis 注解 SQL 拼接注入",
                                  "第 12 行把 name 直接拼进 SELECT，可注入 ' or 1=1 --"),
                    (sev, "high"),
                )

    def test_hedged_critical_downgraded(self):
        """「可能 / 若」这类假设式结论不给 critical。"""
        self.assertEqual(
            _calibrate_ai("critical", "high", "硬编码密钥泄露",
                          "若 utils.ts 中 encrypt 函数使用固定密钥，则存在硬编码密钥风险"),
            ("high", "low"),
        )
        self.assertEqual(
            _calibrate_ai("critical", "high", "表达式注入",
                          "虽然当前代码未直接使用 SpEL，但该方法可能触发表达式求值"),
            ("high", "low"),
        )
        self.assertEqual(
            _calibrate_ai("high", "medium", "越权访问",
                          "目标实现未在本次代码中给出，无法确认是否做了权限校验"),
            ("medium", "low"),
        )

    def test_low_never_upgraded(self):
        """已经是 low 的严重度不会被抬高。"""
        self.assertEqual(_calibrate_ai("low", "low", "可能存在问题", "")[0], "low")

    def test_hedge_in_title_alone_is_enough(self):
        """标题里带假设措辞也要降级（模型常把「可能」写进标题）。"""
        self.assertEqual(
            _calibrate_ai("critical", "high", "可能存在 SSRF", "")[1], "low")


if __name__ == "__main__":
    unittest.main(verbosity=2)
