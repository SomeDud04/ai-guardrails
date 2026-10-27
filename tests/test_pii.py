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
                "reach me: [EMAIL] / [MY_PHONE] / [MYKAD]",
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

    def test_labelled_order_and_sku_12_digit_values_still_masked(self):
        # Documented format-only tradeoff: any 12-digit MyKad-shaped value is
        # masked even when a nearby label says order/SKU. These are the known
        # MyKad false positives recorded in docs/pii-quality.md; no evaluation
        # label or recognizer changes are made here and no precision claim is
        # repaired.
        cases = {
            "order 900101123456": "order [MYKAD]",
            "order_id=900101123456": "order_id=[MYKAD]",
            "SKU: 900101123456": "SKU: [MYKAD]",
            "sku 880202105678": "sku [MYKAD]",
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(mask_text(text), expected)
                self.assertEqual(mask_pii(text), expected)
                self.assertEqual(
                    [item.entity_type for item in find_redactions(text)],
                    ["MYKAD"],
                )

    def test_malaysian_country_code_with_space_or_dash_is_masked(self):
        # 27 Oct 2026 live defect: the country code had to touch the digits, so
        # the most natural Malaysian mobile format reached the model raw. All
        # six reported formats (two previously leaking, four passing) must now
        # mask, for both the production input and output masking paths.
        cases = {
            "+60 12-000 0000": "[MY_PHONE]",
            "+60-12-000 0000": "[MY_PHONE]",
            "+60120000000": "[MY_PHONE]",
            "60120000000": "[MY_PHONE]",
            "012-000 0000": "[MY_PHONE]",
            "012 000 0000": "[MY_PHONE]",
            "SMS ke +60 12-000 0000 esok": "SMS ke [MY_PHONE] esok",
            "SMS ke +60-12-000 0000 esok": "SMS ke [MY_PHONE] esok",
            "reach me on +60 12 000 0000.": "reach me on [MY_PHONE].",
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(mask_text(text), expected)
                self.assertEqual(mask_pii(text), expected)
                self.assertEqual(
                    [item.entity_type for item in find_redactions(text)],
                    ["MY_PHONE"],
                )

    def test_email_phone_mykad_order_is_preserved(self):
        text = "a@example.invalid 0123456789 900101-12-3456"
        self.assertEqual(mask_pii(text), "[EMAIL] [MY_PHONE] [MYKAD]")
        self.assertEqual([item.entity_type for item in find_redactions(text)],
                         ["EMAIL", "MY_PHONE", "MYKAD"])

    def test_postal_address_positive_forms_keep_surrounding_text(self):
        cases = {
            "No. 12, Jalan Melati 3, Taman Sri Indah, 43000 Kajang, Selangor":
                "[POSTAL_ADDRESS]",
            "Unit 12-3, Jalan Ampang, 50450 Kuala Lumpur":
                "[POSTAL_ADDRESS]",
            "12 Lorong Mawar 2, 11600 George Town, Pulau Pinang":
                "[POSTAL_ADDRESS]",
            "No. 7, Lrg Mawar 2, 11600 George Town, Pulau Pinang":
                "[POSTAL_ADDRESS]",
            "No. 5, Jln Ampang 5, 50450 Kuala Lumpur":
                "[POSTAL_ADDRESS]",
            "No. 9, Persiaran KLCC, 50088 Kuala Lumpur":
                "[POSTAL_ADDRESS]",
            "No. 12, Jalan Melati 3, 43000":
                "[POSTAL_ADDRESS]",
            "Address: No. 12, Jalan Melati 3, 43000 Kajang.":
                "Address: [POSTAL_ADDRESS].",
            "Alamat: No. 12, Jalan Melati 3, 43000 Kajang.":
                "Alamat: [POSTAL_ADDRESS].",
            "地址: No. 12, Jalan Melati 3, 43000 Kajang.":
                "地址: [POSTAL_ADDRESS].",
            "Rumah saya di No. 12, Jalan Melati 3, 43000 Kajang, Selangor. Jumpa esok!":
                "Rumah saya di [POSTAL_ADDRESS]. Jumpa esok!",
            "(No. 12, Jalan Melati 3, 43000 Kajang)":
                "([POSTAL_ADDRESS])",
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(mask_text(text), expected)
                self.assertEqual(mask_pii(text), expected)

    def test_postal_address_span_is_the_full_address(self):
        text = "Rumah saya di No. 12, Jalan Melati 3, Taman Sri Indah, 43000 Kajang, Selangor. Jumpa esok!"
        address = "No. 12, Jalan Melati 3, Taman Sri Indah, 43000 Kajang, Selangor"
        self.assertEqual(
            [(item.entity_type, text[item.start:item.end])
             for item in find_redactions(text)],
            [("POSTAL_ADDRESS", address)],
        )

    def test_postal_address_false_positives_stay_unmasked(self):
        # A street-shaped fragment, a bare postcode or a place-name mention is
        # not an address. The recognizer also requires either a postcode or an
        # explicit label, so broad location prose remains untouched.
        cases = (
            "43000 Kajang",
            "Kajang, Selangor",
            "Jalan Ampang, 50450 Kuala Lumpur",
            "Jalan Melati 3, 43000 Kajang",
            "Taman Sri Indah, 43000 Kajang",
            "No. 12, Jalan Melati 3",
            "No. 12, Jalan Melati 3 is nearby",
            "Meet at Taman Sri Indah, 43000 Kajang.",
        )
        for text in cases:
            with self.subTest(text=text):
                self.assertEqual(mask_text(text), text)
                self.assertEqual(find_redactions(text), [])

    def test_postal_address_selection_off_and_on(self):
        text = "Alamat: No. 12, Jalan Melati 3, 43000 Kajang, Selangor"
        self.assertEqual(
            mask_text(text, ("EMAIL", "MY_PHONE", "MYKAD")), text
        )
        self.assertEqual(mask_text(text, ()), text)
        self.assertEqual(
            mask_text(text, ("POSTAL_ADDRESS",)), "Alamat: [POSTAL_ADDRESS]"
        )
        self.assertEqual(mask_text(text), "Alamat: [POSTAL_ADDRESS]")
        self.assertEqual(mask_pii(text, ("EMAIL", "MY_PHONE", "MYKAD")), text)
        self.assertEqual(
            [item.entity_type for item in find_redactions(text)], ["POSTAL_ADDRESS"]
        )

    def test_labelled_postal_address_without_postcode_is_masked(self):
        # Caller review reproduced this privacy gap: a clearly labelled home
        # address with no postcode reached the model raw. An explicit
        # Address:/Alamat: label now makes the same numbered street shape
        # sufficient; unlabelled postcode-less forms remain conservative.
        cases = {
            "Address: No. 12, Jalan Melati 3": "Address: [POSTAL_ADDRESS]",
            "Alamat: Unit 12-3, Jalan Ampang": "Alamat: [POSTAL_ADDRESS]",
            "address: No. 12, Jalan Melati 3": "address: [POSTAL_ADDRESS]",
            "Alamat: No. 12, Jalan Melati 3, Taman Sri Indah.":
                "Alamat: [POSTAL_ADDRESS].",
            "Address: No. 12, Jalan Melati 3 is nearby":
                "Address: [POSTAL_ADDRESS] is nearby",
            "Alamat: Unit 12-3, Jalan Ampang. Jumpa esok!":
                "Alamat: [POSTAL_ADDRESS]. Jumpa esok!",
            "Rumah: Alamat: No. 12, Jalan Melati 3. Jumpa esok!":
                "Rumah: Alamat: [POSTAL_ADDRESS]. Jumpa esok!",
            "(Address: No. 12, Jalan Melati 3)": "(Address: [POSTAL_ADDRESS])",
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(mask_text(text), expected)
                self.assertEqual(mask_pii(text), expected)
                self.assertEqual(
                    [item.entity_type for item in find_redactions(text)],
                    ["POSTAL_ADDRESS"],
                )

    def test_labelled_postal_address_without_postcode_span_excludes_label(self):
        text = "Rumah: Alamat: Unit 12-3, Jalan Ampang. Jumpa esok!"
        self.assertEqual(
            [(item.entity_type, text[item.start:item.end])
             for item in find_redactions(text)],
            [("POSTAL_ADDRESS", "Unit 12-3, Jalan Ampang")],
        )

    def test_labelled_postal_address_selection_off_and_on(self):
        text = "Address: No. 12, Jalan Melati 3"
        self.assertEqual(
            mask_text(text, ("EMAIL", "MY_PHONE", "MYKAD")), text
        )
        self.assertEqual(mask_text(text, ()), text)
        self.assertEqual(
            mask_text(text, ("POSTAL_ADDRESS",)), "Address: [POSTAL_ADDRESS]"
        )
        self.assertEqual(mask_text(text), "Address: [POSTAL_ADDRESS]")
        self.assertEqual(
            mask_pii(text, ("EMAIL", "MY_PHONE", "MYKAD")), text
        )
        self.assertEqual(
            mask_pii(text, ("POSTAL_ADDRESS",)), "Address: [POSTAL_ADDRESS]"
        )

    def test_labelled_postal_address_false_positives_stay_unmasked(self):
        # The label repair stays narrow: address-shaped fragments without a
        # label, a house number or a street keyword remain untouched, and a
        # bare postcode is still not an address.
        cases = (
            "No. 12, Jalan Melati 3",
            "Unit 12-3, Jalan Ampang",
            "No. 12, Jalan Melati 3 is nearby",
            "Alamat: Jalan Melati 3",
            "Address: No. 12",
            "Address: 12, Ampang",
            "Address: Melati 3",
            "EmailAddress: No. 12, Jalan Melati 3",
            "Address: 12, Jalan Ampang 50450 Kuala Lumpur",
            "43000 Kajang",
        )
        for text in cases:
            with self.subTest(text=text):
                self.assertEqual(mask_text(text), text)
                self.assertEqual(find_redactions(text), [])

    def test_postal_address_does_not_change_existing_entity_regression(self):
        text = (
            "No. 12, Jalan Melati 3, 43000 Kajang "
            "a@example.invalid 0123456789 900101-12-3456"
        )
        self.assertEqual(
            mask_text(text),
            "[POSTAL_ADDRESS] [EMAIL] [MY_PHONE] [MYKAD]",
        )
        self.assertEqual(
            [item.entity_type for item in find_redactions(text)],
            ["POSTAL_ADDRESS", "EMAIL", "MY_PHONE", "MYKAD"],
        )


if __name__ == "__main__":
    unittest.main()
