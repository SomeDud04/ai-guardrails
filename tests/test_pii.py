import unittest

from nasi_lemak.gateway import mask_pii
from nasi_lemak.pii import MASK_TOKENS, find_redactions, mask_text


class SharedPiiSpanTests(unittest.TestCase):
    def test_production_mask_outputs_are_unchanged_regressions(self):
        # Intentional bugfix: this expectation used to preserve the known
        # terminal-period miss. The sentence period is punctuation, so the
        # address is masked and the period remains in the output.
        cases = {
            "mail a.b+c@example.invalid now": "mail [EMAIL] now",
            "call +60123456789 or 0123456789": "call [MY_PHONE] or [MY_PHONE]",
            "id 900101-12-3456 and 900101123456": "id [MYKAD] and [MYKAD]",
            "reach me: a@test.invalid / +60 12-345 6789 / 900101123456":
                "reach me: [EMAIL] / +60 12-345 6789 / [MYKAD]",
            "not phone 0123456 and 012345678901234":
                "not phone 0123456 and 012345678901234",
            "x@y.invalid, 0 1 2 3 4 5 6 7 8 9":
                "[EMAIL], 0 1 2 3 4 5 6 7 8 9",
            "a@example.invalid. and a@example.invalidx":
                "[EMAIL]. and [EMAIL]",
            "123456789012": "[MYKAD]",
            "ABC 123456-78-9012 xyz": "ABC [MYKAD] xyz",
            "user test@example.invalid and order 900101123456":
                "user [EMAIL] and order [MYKAD]",
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(mask_pii(text), expected)
                self.assertEqual(mask_text(text), expected)

    def test_shared_spans_have_original_offsets_and_types(self):
        text = "Email a@example.invalid, phone 012-3456789, IC 900101-12-3456."
        spans = find_redactions(text)
        self.assertEqual(
            [(item.entity_type, text[item.start:item.end]) for item in spans],
            [
                ("EMAIL", "a@example.invalid"),
                ("MY_PHONE", "012-3456789"),
                ("MYKAD", "900101-12-3456"),
            ],
        )

    def test_mask_is_exact_span_replacement_and_spans_do_not_overlap(self):
        texts = [
            "Email a@test.invalid and b@example.invalid.",
            "Call +60123456789 or 012 345 6789 now.",
            "IC 900101-12-3456 / 880202105678.",
            "Order 123456789012 and email ops@test.invalid.",
            "placeholder [EMAIL] stays literal",
        ]
        for text in texts:
            with self.subTest(text=text):
                spans = find_redactions(text)
                rebuilt = []
                last = 0
                for span in spans:
                    self.assertLessEqual(last, span.start)
                    rebuilt.append(text[last:span.start])
                    rebuilt.append(MASK_TOKENS[span.entity_type])
                    last = span.end
                rebuilt.append(text[last:])
                self.assertEqual("".join(rebuilt), mask_text(text))
                for previous, current in zip(spans, spans[1:]):
                    self.assertLessEqual(previous.end, current.start)

    def test_email_terminal_period_is_masked_without_consuming_punctuation(self):
        # Caller review found this real production gap: the old email tail
        # rejected every period, so a normal sentence-final address stayed raw.
        cases = {
            "Contact a@example.invalid.": "Contact [EMAIL].",
            "Contact a@example.invalid. ": "Contact [EMAIL]. ",
            "Contact a@example.invalid.)": "Contact [EMAIL].)",
            "Contact a@example.invalid.,": "Contact [EMAIL].,",
            "Contact a@example.invalid.?": "Contact [EMAIL].?",
            "Contact a@example.invalid,": "Contact [EMAIL],",
            "Contact a@example.invalid?": "Contact [EMAIL]?",
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(mask_text(text), expected)
                self.assertEqual(mask_pii(text), expected)

    def test_email_with_longer_valid_domain_is_fully_masked(self):
        cases = {
            "a@example.invalid.example": "[EMAIL]",
            "a@example.deep.subdomain.invalid": "[EMAIL]",
            "a@example.invalid.example.": "[EMAIL].",
            "a@example.invalid.com": "[EMAIL]",
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(mask_text(text), expected)
                self.assertEqual(mask_pii(text), expected)

    def test_invalid_dotted_suffix_is_not_partially_masked(self):
        # A trailing period followed by another dot or a domain continuation is
        # not sentence punctuation; do not hide only the valid-looking prefix.
        cases = (
            "a@example.invalid..",
            "a@example.invalid.. ",
            "a@example.invalid.-x",
        )
        for text in cases:
            with self.subTest(text=text):
                self.assertEqual(mask_text(text), text)
                self.assertEqual(find_redactions(text), [])

    def test_unicode_digit_behaviour_is_unchanged(self):
        # Preserved Python regex behaviour: ``\d`` is Unicode-aware here.  The
        # measured fixtures remain ASCII, and this is not a non-ASCII claim.
        self.assertEqual(mask_text("id ١٢٣٤٥٦٧٨٩٠١٢"), "id [MYKAD]")

    def test_literal_mask_tokens_are_not_new_detections(self):
        for text in ("Placeholder [EMAIL]", "[MY_PHONE] and [MYKAD]", "already [EMAIL] here"):
            with self.subTest(text=text):
                self.assertEqual(find_redactions(text), [])
                self.assertEqual(mask_text(text), text)

    def test_email_phone_mykad_order_is_preserved(self):
        text = "a@example.invalid 0123456789 900101-12-3456"
        self.assertEqual(mask_pii(text), "[EMAIL] [MY_PHONE] [MYKAD]")
        self.assertEqual([item.entity_type for item in find_redactions(text)],
                         ["EMAIL", "MY_PHONE", "MYKAD"])


if __name__ == "__main__":
    unittest.main()
