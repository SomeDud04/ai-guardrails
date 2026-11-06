"""Email and phone masking next to Chinese text.

Chinese is written without spaces, so an identifier usually sits directly
against a Han character (``邮箱是alice@example.com``).  The 6 November 2026
live retest (ZH-LLM02-002) showed such an email reaching the reply raw: the
boundary checks used ``\\w``, which also matches Han characters, so the pattern
never started.  Boundaries now mean ASCII letters, digits and underscore only.
"""

from __future__ import annotations

import unittest

from nasi_lemak.pii import mask_text


class ChineseBoundaryTests(unittest.TestCase):
    def test_email_touching_chinese_on_either_side_is_masked(self) -> None:
        cases = {
            "我的合成联系邮箱是alice+support@example.com。": "我的合成联系邮箱是[EMAIL]。",
            "请发到alice@example.com谢谢": "请发到[EMAIL]谢谢",
            "邮箱：bob.tan@example.com.my，谢谢": "邮箱：[EMAIL]，谢谢",
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(mask_text(text), expected)

    def test_phone_touching_chinese_on_either_side_is_masked(self) -> None:
        cases = {
            "电话是012-345 6789": "电话是[MY_PHONE]",
            "电话012-3456789谢谢": "电话[MY_PHONE]谢谢",
            "办公室03-1234 5678转": "办公室[MY_PHONE]转",
            "请拨+60 12-345 6789联系": "请拨[MY_PHONE]联系",
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(mask_text(text), expected)

    def test_ascii_word_boundaries_are_unchanged(self) -> None:
        self.assertEqual(mask_text("ref0123456789"), "ref0123456789")
        self.assertEqual(mask_text("INV-0312345678"), "INV-0312345678")
        self.assertEqual(mask_text("0123456789x"), "0123456789x")
        self.assertEqual(mask_text("HP-012-345 6789"), "HP-[MY_PHONE]")

    def test_malay_and_english_sentences_still_mask(self) -> None:
        self.assertEqual(mask_text("Emel saya alice@example.com."), "Emel saya [EMAIL].")
        self.assertEqual(mask_text("Call 012-345 6789."), "Call [MY_PHONE].")


if __name__ == "__main__":
    unittest.main()
