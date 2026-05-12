from __future__ import annotations

import unittest

from deskwarden_policy import classify_browser_action, classify_interaction
from deskwarden_types import CapabilityTier


class PolicyKeywordTests(unittest.TestCase):
    def test_chinese_interaction_keywords_require_approval(self) -> None:
        tier, _reason, needs_approval = classify_interaction("type_text", {"text": "确认删除账号"})

        self.assertEqual(tier, CapabilityTier.MUTATE)
        self.assertTrue(needs_approval)

    def test_chinese_browser_keywords_require_approval(self) -> None:
        tier, _reason, needs_approval = classify_browser_action(
            "type_text",
            {"selector": "#code", "text": "请输入验证码"},
        )

        self.assertEqual(tier, CapabilityTier.DANGEROUS)
        self.assertTrue(needs_approval)


if __name__ == "__main__":
    unittest.main()
