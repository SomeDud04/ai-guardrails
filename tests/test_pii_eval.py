import hashlib
import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from nasi_lemak.gateway import mask_pii
from nasi_lemak.pii import Redaction, find_redactions
from nasi_lemak.pii_eval import (
    MAX_CASES,
    MAX_FIXTURE_BYTES,
    MAX_SPANS_PER_CASE,
    MAX_TEXT_LENGTH,
    FixtureError,
    evaluate_corpus,
    load_corpus,
    main,
    parse_corpus,
)

REAL_ROOT = Path(__file__).resolve().parents[1] / "evals" / "pii"
REVIEWED_V2_ROOT = REAL_ROOT / "reviewed-labels-v2"
CALLER_REVIEW_ROOT = REAL_ROOT / "caller-review-v1"
CALLER_REVIEW_BASELINE = (
    CALLER_REVIEW_ROOT / "results" / "before-email-fix-evaluation-report.json"
)


def annotate(text, entity_type, needle, occurrence=0):
    start = -1
    for _ in range(occurrence + 1):
        start = text.index(needle, start + 1)
    return {"type": entity_type, "start": start, "end": start + len(needle), "text": needle}


def make_case(case_id, text, gold=(), focus="EMAIL", scope="in_scope", label="test_case", notes=""):
    return {
        "id": case_id,
        "focus": focus,
        "scope": scope,
        "label": label,
        "notes": notes,
        "text": text,
        "gold": list(gold),
    }


def payload(cases, corpus_id="unit-corpus", split="evaluation"):
    return {
        "schema_version": 1,
        "split": split,
        "corpus_id": corpus_id,
        "cases": cases,
    }


class PiiMetricMathTests(unittest.TestCase):
    def test_known_tp_fp_fn_and_null_denominators(self):
        text = "aaa bbb ccc"
        case = make_case(
            "M-1",
            text,
            gold=[
                {"type": "EMAIL", "start": 0, "end": 3, "text": "aaa"},
                {"type": "EMAIL", "start": 4, "end": 7, "text": "bbb"},
                {"type": "MY_PHONE", "start": 8, "end": 11, "text": "ccc"},
            ],
        )
        corpus = parse_corpus(payload([case]))
        report = evaluate_corpus(
            corpus,
            recognizer=lambda _text: [
                Redaction("EMAIL", 0, 3),
                Redaction("EMAIL", 8, 11),
                Redaction("MY_PHONE", 4, 7),
            ],
        )
        email = report["per_entity"]["EMAIL"]
        self.assertEqual((email["gold_count"], email["predicted_count"], email["tp"], email["fp"], email["fn"]),
                         (2, 2, 1, 1, 1))
        self.assertEqual((email["precision"], email["recall"], email["f1"]), (0.5, 0.5, 0.5))
        phone = report["per_entity"]["MY_PHONE"]
        self.assertEqual((phone["gold_count"], phone["predicted_count"], phone["tp"], phone["fp"], phone["fn"]),
                         (1, 1, 0, 1, 1))
        self.assertEqual((phone["precision"], phone["recall"]), (0.0, 0.0))
        self.assertEqual(phone["f1"], 0.0)
        mykad = report["per_entity"]["MYKAD"]
        self.assertEqual((mykad["gold_count"], mykad["predicted_count"]), (0, 0))
        self.assertIsNone(mykad["precision"])
        self.assertIsNone(mykad["recall"])
        self.assertIsNone(mykad["f1"])
        self.assertFalse(mykad["gate_applicable"])
        self.assertFalse(report["gates"]["overall_pass"])
        self.assertEqual(len(report["errors"]), 4)

    def test_f1_zero_from_fp_and_fn_even_when_precision_and_recall_are_zero(self):
        text = "abc def"
        case = make_case(
            "M-F1",
            text,
            gold=[{"type": "EMAIL", "start": 0, "end": 3, "text": "abc"}],
        )
        report = evaluate_corpus(
            parse_corpus(payload([case])),
            recognizer=lambda _text: [Redaction("EMAIL", 4, 7)],
        )
        email = report["per_entity"]["EMAIL"]
        self.assertEqual((email["tp"], email["fp"], email["fn"]), (0, 1, 1))
        self.assertEqual((email["precision"], email["recall"], email["f1"]), (0.0, 0.0, 0.0))

        empty_case = make_case("M-F1-EMPTY", "no pii here", gold=[], focus="MYKAD")
        empty_report = evaluate_corpus(
            parse_corpus(payload([empty_case])),
            recognizer=lambda _text: [],
        )
        mykad = empty_report["per_entity"]["MYKAD"]
        self.assertIsNone(mykad["precision"])
        self.assertIsNone(mykad["recall"])
        self.assertIsNone(mykad["f1"])

    def test_strict_span_mismatch_is_not_a_match(self):
        text = "test"
        case = make_case("M-2", text,
                         gold=[{"type": "EMAIL", "start": 0, "end": 4, "text": "test"}])
        report = evaluate_corpus(parse_corpus(payload([case])),
                                 recognizer=lambda _text: [Redaction("EMAIL", 0, 3)])
        email = report["per_entity"]["EMAIL"]
        self.assertEqual((email["tp"], email["fp"], email["fn"]), (0, 1, 1))
        self.assertEqual({error["kind"] for error in report["errors"]},
                         {"false_positive", "false_negative"})

    def test_same_offsets_wrong_type_is_not_a_match(self):
        text = "test"
        case = make_case("M-3", text,
                         gold=[{"type": "EMAIL", "start": 0, "end": 4, "text": "test"}])
        report = evaluate_corpus(parse_corpus(payload([case])),
                                 recognizer=lambda _text: [Redaction("MYKAD", 0, 4)])
        self.assertEqual(report["per_entity"]["EMAIL"]["fn"], 1)
        self.assertEqual(report["per_entity"]["MYKAD"]["fp"], 1)
        self.assertEqual(report["per_entity"]["EMAIL"]["tp"], 0)

    def test_empty_denominators_are_null_and_never_vacuously_pass(self):
        case = make_case("M-4", "no pii here", gold=[], focus="MYKAD")
        report = evaluate_corpus(parse_corpus(payload([case])), recognizer=lambda _text: [])
        mykad = report["per_entity"]["MYKAD"]
        self.assertIsNone(mykad["precision"])
        self.assertIsNone(mykad["recall"])
        self.assertIsNone(mykad["f1"])
        self.assertEqual(mykad["gate_status"], "not_applicable")
        self.assertFalse(report["gates"]["overall_pass"])


class PiiGateAggregationTests(unittest.TestCase):
    """Frozen splits have no POSTAL_ADDRESS gold; absence must not fail them."""

    def test_not_applicable_postal_gate_does_not_fail_overall(self):
        positive = "Email a@example.invalid for details"
        negative = "Email a@example is incomplete"
        corpus = parse_corpus(payload([
            make_case("G-EMAIL-P", positive,
                      gold=[annotate(positive, "EMAIL", "a@example.invalid")]),
            make_case("G-EMAIL-N", negative, focus="EMAIL"),
        ]))
        report = evaluate_corpus(corpus)

        email = report["per_entity"]["EMAIL"]
        self.assertEqual(email["gate_status"], "pass")
        postal = report["per_entity"]["POSTAL_ADDRESS"]
        self.assertEqual((postal["gold_count"], postal["predicted_count"]), (0, 0))
        self.assertEqual(postal["gate_status"], "not_applicable")
        self.assertEqual(report["gates"]["applicable_entities"], ["EMAIL"])
        self.assertEqual(
            report["gates"]["not_applicable_entities"],
            ["MY_PHONE", "MYKAD", "POSTAL_ADDRESS"],
        )
        self.assertTrue(report["gates"]["overall_pass"])
        self.assertEqual(report["gates"]["overall_status"], "pass")

    def test_all_gates_not_applicable_never_passes(self):
        report = evaluate_corpus(parse_corpus(payload([
            make_case("G-NONE", "Nothing to see here", focus="EMAIL"),
        ])))
        self.assertEqual(report["gates"]["applicable_entities"], [])
        self.assertFalse(any(
            gate["applicable"] for gate in report["gates"]["entities"].values()
        ))
        self.assertEqual(report["gates"]["overall_status"], "fail")
        self.assertFalse(report["gates"]["overall_pass"])

    def test_applicable_failing_gate_still_fails_overall(self):
        email_positive = "Email a@example.invalid"
        email_negative = "Email a@example"
        mykad_positive = "IC 900101-12-3456"
        mykad_negative = "Ref 900101-12-3457"
        corpus = parse_corpus(payload([
            make_case("G-FAIL-EMAIL-P", email_positive,
                      gold=[annotate(email_positive, "EMAIL", "a@example.invalid")]),
            make_case("G-FAIL-EMAIL-N", email_negative, focus="EMAIL"),
            make_case("G-FAIL-MYKAD-P", mykad_positive,
                      gold=[annotate(mykad_positive, "MYKAD", "900101-12-3456")],
                      focus="MYKAD"),
            make_case("G-FAIL-MYKAD-N", mykad_negative, focus="MYKAD"),
        ]))

        def recognizer(text):
            if text == email_positive:
                return [Redaction("EMAIL", 6, 23)]
            if text == mykad_positive:
                return [Redaction("MYKAD", 3, 17)]
            if text == mykad_negative:
                return [Redaction("MYKAD", 4, 18)]
            return []

        report = evaluate_corpus(corpus, recognizer=recognizer)
        self.assertEqual(report["per_entity"]["EMAIL"]["gate_status"], "pass")
        self.assertEqual(report["per_entity"]["MYKAD"]["gate_status"], "fail")
        self.assertEqual(report["per_entity"]["POSTAL_ADDRESS"]["gate_status"], "not_applicable")
        self.assertEqual(
            report["gates"]["applicable_entities"], ["EMAIL", "MYKAD"]
        )
        self.assertEqual(
            report["gates"]["not_applicable_entities"], ["MY_PHONE", "POSTAL_ADDRESS"]
        )
        self.assertEqual(report["gates"]["overall_status"], "fail")
        self.assertFalse(report["gates"]["overall_pass"])

    def test_frozen_corpora_report_postal_as_not_applicable_without_address_metrics(self):
        expected_overall = {
            REAL_ROOT: False,
            REVIEWED_V2_ROOT: False,
            CALLER_REVIEW_ROOT: True,
        }
        for root, expected in expected_overall.items():
            with self.subTest(root=root.name):
                corpus, _ = load_corpus(root / "evaluation.json", root / "manifest.json")
                report = evaluate_corpus(corpus)
                postal = report["per_entity"]["POSTAL_ADDRESS"]
                self.assertEqual(postal["gold_count"], 0)
                self.assertEqual(postal["positive_cases"], 0)
                self.assertEqual(postal["gate_status"], "not_applicable")
                self.assertIn("POSTAL_ADDRESS", report["gates"]["not_applicable_entities"])
                self.assertEqual(report["gates"]["overall_pass"], expected)
                # No address quality metric is asserted or claimed from these splits.
                self.assertIsNone(postal["precision"])
                self.assertIsNone(postal["recall"])
                self.assertIsNone(postal["f1"])


class PiiFixtureValidationTests(unittest.TestCase):
    def base_case(self):
        text = "Email a@example.invalid"
        return make_case("V-1", text, gold=[annotate(text, "EMAIL", "a@example.invalid")])

    def test_invalid_offsets_types_duplicates_overlaps_and_bounds(self):
        variants = []
        base = self.base_case()

        missing = json.loads(json.dumps(base))
        missing["gold"][0]["end"] = len(missing["text"]) + 1
        variants.append(("out of file/text bounds", [missing]))

        negative = json.loads(json.dumps(base))
        negative["gold"][0]["start"] = -1
        variants.append(("negative offset", [negative]))

        empty = json.loads(json.dumps(base))
        empty["gold"][0]["end"] = empty["gold"][0]["start"]
        variants.append(("empty span", [empty]))

        boolean = json.loads(json.dumps(base))
        boolean["gold"][0]["start"] = True
        variants.append(("bool offset", [boolean]))

        wrong_type = json.loads(json.dumps(base))
        wrong_type["gold"][0]["type"] = "PASSPORT"
        variants.append(("unsupported type", [wrong_type]))

        duplicate = json.loads(json.dumps(base))
        duplicate["gold"].append(dict(duplicate["gold"][0]))
        variants.append(("duplicate span", [duplicate]))

        overlap_text = "abcde"
        overlap = make_case(
            "V-2",
            overlap_text,
            gold=[
                {"type": "EMAIL", "start": 0, "end": 3, "text": "abc"},
                {"type": "MY_PHONE", "start": 2, "end": 5, "text": "cde"},
            ],
        )
        variants.append(("overlap", [overlap]))

        mismatch = json.loads(json.dumps(base))
        mismatch["gold"][0]["text"] = "wrong"
        variants.append(("text mismatch", [mismatch]))

        duplicate_id = [self.base_case(), self.base_case()]
        variants.append(("duplicate case id", duplicate_id))

        for label, cases in variants:
            with self.subTest(label=label):
                with self.assertRaises(FixtureError) as caught:
                    parse_corpus(payload(cases))
                self.assertNotIn("a@example.invalid", str(caught.exception))

    def test_top_level_and_cases_shape_are_validated(self):
        for bad in (None, [], {"schema_version": 1, "split": "evaluation", "corpus_id": "x", "cases": []}):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(FixtureError):
                    parse_corpus(bad)

    def test_case_count_text_length_and_span_count_are_bounded(self):
        with self.assertRaises(FixtureError):
            parse_corpus(payload([{} for _ in range(MAX_CASES + 1)]))

        with self.assertRaises(FixtureError):
            parse_corpus(payload([make_case("B-LONG", "a" * (MAX_TEXT_LENGTH + 1))]))

        span_text = "a" * (MAX_SPANS_PER_CASE * 2)
        spans = [
            {"type": "EMAIL", "start": index * 2, "end": index * 2 + 1, "text": "a"}
            for index in range(MAX_SPANS_PER_CASE + 1)
        ]
        with self.assertRaises(FixtureError):
            parse_corpus(payload([make_case("B-SPANS", span_text, gold=spans)]))

    def assert_cli_rejects(self, raw, *, forbidden=None):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            root = Path(tmp)
            (root / "evaluation.json").write_bytes(raw)
            manifest = {"schema_version": 1, "files": {
                "evaluation.json": hashlib.sha256(raw).hexdigest()}}
            (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                code = main(["--root", str(root), "--out-dir", str(root / "results")])
            self.assertEqual(code, 2)
            self.assertIn("malformed fixture", stderr.getvalue())
            self.assertFalse((root / "results").exists())
            if forbidden is not None:
                self.assertNotIn(forbidden, stderr.getvalue())

    def test_cli_rejects_oversized_and_deeply_nested_json(self):
        self.assert_cli_rejects(b" " * (MAX_FIXTURE_BYTES + 1))
        self.assert_cli_rejects(b"[" * 20000 + b"]" * 20000)

    def test_cli_rejects_case_count_and_text_length_without_echoing_text(self):
        too_many = json.dumps(
            {
                "schema_version": 1,
                "split": "evaluation",
                "corpus_id": "too-many-cases",
                "cases": [{} for _ in range(MAX_CASES + 1)],
            },
            separators=(",", ":"),
        ).encode("utf-8")
        self.assert_cli_rejects(too_many)

        marker = "LEAKMARKER" * 2000
        self.assertGreater(len(marker), MAX_TEXT_LENGTH)
        raw = json.dumps(payload([make_case("B-LONG", marker)])).encode("utf-8")
        self.assert_cli_rejects(raw, forbidden=marker)

    def test_manifest_mismatch_and_missing_entry_fail_closed(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            root = Path(tmp)
            corpus_payload = payload([self.base_case()], corpus_id="manifest-test")
            raw = (json.dumps(corpus_payload, indent=2) + "\n").encode("utf-8")
            (root / "evaluation.json").write_bytes(raw)
            good = hashlib.sha256(raw).hexdigest()

            manifest = {"schema_version": 1, "files": {"evaluation.json": "0" * 64}}
            (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(FixtureError):
                load_corpus(root / "evaluation.json", root / "manifest.json")

            manifest["files"]["evaluation.json"] = good
            (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            corpus, _ = load_corpus(root / "evaluation.json", root / "manifest.json")
            self.assertEqual(corpus.split, "evaluation")

            manifest["files"] = {}
            (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(FixtureError):
                load_corpus(root / "evaluation.json", root / "manifest.json")

    def test_frozen_fixtures_have_declared_coverage_and_distinct_splits(self):
        evaluation, _ = load_corpus(REAL_ROOT / "evaluation.json", REAL_ROOT / "manifest.json")
        development, _ = load_corpus(REAL_ROOT / "development.json", REAL_ROOT / "manifest.json")
        self.assertGreaterEqual(len(evaluation.cases), 60)
        self.assertGreaterEqual(len(development.cases), 10)
        self.assertTrue({case.case_id for case in evaluation.cases}.isdisjoint(
            {case.case_id for case in development.cases}))
        self.assertTrue({case.text for case in evaluation.cases}.isdisjoint(
            {case.text for case in development.cases}))

        for case in evaluation.cases:
            for span in case.gold:
                self.assertEqual(span.end - span.start, len(case.text[span.start:span.end]))
        raw_evaluation = json.loads((REAL_ROOT / "evaluation.json").read_text(encoding="utf-8"))
        for case in raw_evaluation["cases"]:
            for span in case["gold"]:
                self.assertEqual(case["text"][span["start"]:span["end"]], span["text"])
        for entity_type in ("EMAIL", "MY_PHONE", "MYKAD"):
            positives = sum(
                1 for case in evaluation.cases
                if case.scope == "in_scope" and any(span.entity_type == entity_type for span in case.gold)
            )
            negatives = sum(
                1 for case in evaluation.cases
                if case.scope == "in_scope" and case.focus == entity_type
                and not any(span.entity_type == entity_type for span in case.gold)
            )
            self.assertGreaterEqual(positives, 5, entity_type)
            self.assertGreaterEqual(negatives, 5, entity_type)

    def test_evaluation_contains_only_synthetic_domains(self):
        evaluation, _ = load_corpus(REAL_ROOT / "evaluation.json", REAL_ROOT / "manifest.json")
        for case in evaluation.cases:
            for span in case.gold:
                if span.entity_type == "EMAIL":
                    address = case.text[span.start:span.end].lower()
                    self.assertTrue(address.endswith(("@example.invalid", "@test.invalid")), address)


class PiiEvaluatorIntegrationTests(unittest.TestCase):
    def test_actual_mask_and_evaluation_use_the_same_spans(self):
        text = "Email a@example.invalid, phone 012-3456789, IC 900101-12-3456."
        case = make_case(
            "I-1",
            text,
            gold=[
                annotate(text, "EMAIL", "a@example.invalid"),
                annotate(text, "MY_PHONE", "012-3456789"),
                annotate(text, "MYKAD", "900101-12-3456"),
            ],
        )
        report = evaluate_corpus(parse_corpus(payload([case])))
        for entity_type in ("EMAIL", "MY_PHONE", "MYKAD"):
            self.assertEqual(report["per_entity"][entity_type]["tp"], 1)
            self.assertEqual(report["per_entity"][entity_type]["fp"], 0)
            self.assertEqual(report["per_entity"][entity_type]["fn"], 0)
        self.assertEqual(len(find_redactions(text)), 3)
        self.assertEqual(mask_pii(text), "Email [EMAIL], phone [MY_PHONE], IC [MYKAD].")

    def test_ambiguous_sku_is_honestly_counted_as_mykad_false_positive(self):
        corpus, _ = load_corpus(REAL_ROOT / "evaluation.json", REAL_ROOT / "manifest.json")
        report = evaluate_corpus(corpus)
        errors = {(error["case_id"], error["kind"], error["type"]) for error in report["errors"]}
        self.assertIn(("EV-MYKAD-017", "false_positive", "MYKAD"), errors)
        self.assertIn(("EV-MYKAD-016", "false_positive", "MYKAD"), errors)
        mykad = report["per_entity"]["MYKAD"]
        self.assertEqual(mykad["fp"], 4)
        self.assertLess(mykad["precision"], 0.95)
        self.assertEqual(mykad["gate_status"], "fail")
        self.assertFalse(report["gates"]["overall_pass"])

    def test_v1_frozen_trailing_dot_label_is_annotation_conflicted_raw_fp(self):
        # The old v1 fixture labelled a sentence-final address as a negative
        # near-match because the recognizer missed it. This is a disclosed
        # annotation defect, not the correct gold: the address is PII. The
        # narrow repair exposes the bad label as one raw FP; v1 is kept frozen
        # and its EMAIL score must not be presented as reliable current quality.
        corpus, _ = load_corpus(REAL_ROOT / "evaluation.json", REAL_ROOT / "manifest.json")
        report = evaluate_corpus(corpus)
        errors = {(error["case_id"], error["kind"], error["type"]) for error in report["errors"]}
        self.assertIn(("EV-EMAIL-014", "false_positive", "EMAIL"), errors)
        email = report["per_entity"]["EMAIL"]
        self.assertEqual(
            (email["gold_count"], email["predicted_count"], email["tp"], email["fp"], email["fn"]),
            (16, 17, 16, 1, 0),
        )
        self.assertLess(email["precision"], 0.95)
        self.assertEqual(email["gate_status"], "fail")
        self.assertEqual(report["per_entity"]["MYKAD"]["fp"], 4)
        self.assertEqual(report["per_entity"]["MYKAD"]["gate_status"], "fail")
        self.assertFalse(report["gates"]["overall_pass"])

    def test_evaluator_cannot_pass_with_always_none_or_always_mask(self):
        corpus, _ = load_corpus(REAL_ROOT / "evaluation.json", REAL_ROOT / "manifest.json")
        always_none = evaluate_corpus(corpus, recognizer=lambda _text: [])
        self.assertFalse(always_none["gates"]["overall_pass"])
        self.assertEqual(always_none["per_entity"]["EMAIL"]["recall"], 0.0)

        always_mask = evaluate_corpus(
            corpus,
            recognizer=lambda text: [Redaction("EMAIL", 0, len(text))],
        )
        self.assertFalse(always_mask["gates"]["overall_pass"])
        self.assertGreater(always_mask["per_entity"]["EMAIL"]["fp"], 0)

    def test_literal_mask_tokens_do_not_create_errors_or_predictions(self):
        corpus, _ = load_corpus(REAL_ROOT / "evaluation.json", REAL_ROOT / "manifest.json")
        report = evaluate_corpus(corpus)
        error_ids = {error["case_id"] for error in report["errors"]}
        self.assertNotIn("EV-EMAIL-020", error_ids)
        self.assertNotIn("EV-MYKAD-019", error_ids)
        for case in corpus.cases:
            if "[EMAIL]" in case.text:
                self.assertEqual(find_redactions(case.text), [])

    def test_unsupported_cases_are_reported_and_excluded(self):
        corpus, _ = load_corpus(REAL_ROOT / "evaluation.json", REAL_ROOT / "manifest.json")
        report = evaluate_corpus(corpus)
        excluded_ids = {item["case_id"] for item in report["excluded_cases"]}
        self.assertEqual(excluded_ids, {"EV-EMAIL-019", "EV-PHONE-021", "EV-MYKAD-020"})
        self.assertEqual(report["counts"]["excluded_cases"], 3)


class CallerReviewCorpusTests(unittest.TestCase):
    def test_frozen_edge_corpus_now_masks_terminal_period_email(self):
        corpus, _ = load_corpus(
            CALLER_REVIEW_ROOT / "evaluation.json",
            CALLER_REVIEW_ROOT / "manifest.json",
        )
        self.assertEqual(corpus.corpus_id, "pii-caller-review-edge-v1")
        self.assertEqual(corpus.split, "evaluation")
        self.assertEqual(len(corpus.cases), 6)
        self.assertEqual(len({case.case_id for case in corpus.cases}), 6)
        self.assertEqual(
            corpus.sha256,
            "6ec81452e320ac03517eed894f1cd416f73f54736335c04eca49153465aa7e14",
        )

        # Preserved before-fix artifact: the original failure remains visible
        # evidence and is not rewritten to match the repaired runtime.
        baseline = json.loads(CALLER_REVIEW_BASELINE.read_text(encoding="utf-8"))
        self.assertEqual(baseline["corpus_sha256"], corpus.sha256)
        self.assertEqual(
            (baseline["per_entity"]["EMAIL"]["tp"], baseline["per_entity"]["EMAIL"]["fn"]),
            (0, 1),
        )
        self.assertFalse(baseline["gates"]["overall_pass"])

        report = evaluate_corpus(corpus)
        email = report["per_entity"]["EMAIL"]
        self.assertEqual(
            (email["gold_count"], email["predicted_count"], email["tp"], email["fp"], email["fn"]),
            (1, 1, 1, 0, 0),
        )
        self.assertEqual((email["precision"], email["recall"], email["f1"]), (1.0, 1.0, 1.0))
        self.assertEqual(email["gate_status"], "pass")

        for entity_type in ("MY_PHONE", "MYKAD"):
            result = report["per_entity"][entity_type]
            self.assertEqual(
                (result["gold_count"], result["predicted_count"], result["tp"],
                 result["fp"], result["fn"]),
                (1, 1, 1, 0, 0),
            )
            self.assertEqual((result["precision"], result["recall"], result["f1"]), (1.0, 1.0, 1.0))
            self.assertEqual(result["gate_status"], "pass")

        self.assertEqual(report["errors"], [])
        self.assertTrue(report["gates"]["overall_pass"])

        self.assertEqual(mask_pii("Contact a@example.invalid."), "Contact [EMAIL].")
        self.assertEqual(
            [(item.entity_type, item.start, item.end)
             for item in find_redactions("Contact a@example.invalid.")],
            [("EMAIL", 8, 25)],
        )

    def test_cli_writes_a_separate_reproducible_report_and_exits_zero(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            root = Path(tmp)
            for name in ("evaluation.json", "manifest.json"):
                shutil.copy(CALLER_REVIEW_ROOT / name, root / name)
            out_dir = root / "results"

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = main(["--root", str(root), "--out-dir", str(out_dir)])

            self.assertEqual(code, 0)
            self.assertIn("provisional quality gates: PASS", stdout.getvalue())
            report = json.loads((out_dir / "evaluation-report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["corpus_id"], "pii-caller-review-edge-v1")
            self.assertEqual(report["per_entity"]["EMAIL"]["tp"], 1)
            self.assertEqual(report["per_entity"]["EMAIL"]["fn"], 0)
            self.assertEqual(report["per_entity"]["EMAIL"]["f1"], 1.0)
            self.assertTrue(report["gates"]["overall_pass"])
            self.assertEqual(
                report["corpus_sha256"],
                "6ec81452e320ac03517eed894f1cd416f73f54736335c04eca49153465aa7e14",
            )

            baseline = json.loads(CALLER_REVIEW_BASELINE.read_text(encoding="utf-8"))
            self.assertEqual(baseline["per_entity"]["EMAIL"]["fn"], 1)
            self.assertFalse(baseline["gates"]["overall_pass"])

            corpus_payload = json.loads((root / "evaluation.json").read_text(encoding="utf-8"))
            blob = (out_dir / "evaluation-report.json").read_text(encoding="utf-8")
            blob += (out_dir / "evaluation-summary.md").read_text(encoding="utf-8")
            blob += stdout.getvalue()
            for case in corpus_payload["cases"]:
                self.assertNotIn(case["text"], blob)


class ReviewedLabelAdjudicationTests(unittest.TestCase):
    def test_v2_corrects_only_the_annotation_conflicted_email_case(self):
        # The frozen v1 bytes and manifest stay exactly as published.
        v1_raw = (REAL_ROOT / "evaluation.json").read_bytes()
        v1_manifest_raw = (REAL_ROOT / "manifest.json").read_bytes()
        self.assertEqual(
            hashlib.sha256(v1_raw).hexdigest(),
            "fa644f708df31e182a1e64ff1f9eb891dc3d99800c10ff81cea026e73ea55381",
        )
        self.assertEqual(
            hashlib.sha256(v1_manifest_raw).hexdigest(),
            "309f65fbb979cc703a11b668322441c2a803786c9c9bedfcdb41fd6bcf6cf982",
        )

        v1 = json.loads(v1_raw)
        v2_path = REVIEWED_V2_ROOT / "evaluation.json"
        v2 = json.loads(v2_path.read_text(encoding="utf-8"))
        self.assertEqual(v2["corpus_id"], "pii-synthetic-evaluation-v2-adjudicated")
        self.assertEqual(len(v1["cases"]), 61)
        self.assertEqual(len(v2["cases"]), 61)
        self.assertEqual(
            [case["id"] for case in v2["cases"]],
            [case["id"] for case in v1["cases"]],
        )

        # Only EV-EMAIL-014 may differ. Every original text is byte-for-byte
        # the same, and all other case objects are unchanged.
        changed_ids = []
        for before, after in zip(v1["cases"], v2["cases"]):
            self.assertEqual(before["text"], after["text"])
            if before != after:
                changed_ids.append(before["id"])
        self.assertEqual(changed_ids, ["EV-EMAIL-014"])

        corrected = next(case for case in v2["cases"] if case["id"] == "EV-EMAIL-014")
        self.assertEqual(
            corrected["text"], "Tulis kepada nama@example.invalid. untuk maklumat."
        )
        self.assertEqual(corrected["label"], "positive_trailing_dot")
        self.assertIn("caller-agent", corrected["notes"].lower())
        self.assertEqual(
            corrected["gold"],
            [{"type": "EMAIL", "start": 13, "end": 33, "text": "nama@example.invalid"}],
        )
        # The terminal sentence period remains punctuation, outside the span.
        self.assertEqual(corrected["text"][corrected["gold"][0]["end"]], ".")

        corpus, _ = load_corpus(v2_path, REVIEWED_V2_ROOT / "manifest.json")
        self.assertEqual(
            corpus.sha256,
            "aa4879f2c7a678781498f514bdfd9d38213c15b6eb11c559f3df3824b5b7b4db",
        )
        report = evaluate_corpus(corpus)
        email = report["per_entity"]["EMAIL"]
        self.assertEqual(
            (email["gold_count"], email["predicted_count"], email["tp"],
             email["fp"], email["fn"]),
            (17, 17, 17, 0, 0),
        )
        self.assertEqual(email["gate_status"], "pass")
        self.assertEqual(report["per_entity"]["MYKAD"]["fp"], 4)
        self.assertEqual(report["per_entity"]["MYKAD"]["gate_status"], "fail")
        self.assertFalse(report["gates"]["overall_pass"])
        self.assertNotIn(
            ("EV-EMAIL-014", "false_positive", "EMAIL"),
            {(error["case_id"], error["kind"], error["type"]) for error in report["errors"]},
        )


class PiiCliTests(unittest.TestCase):
    def test_real_evaluation_exit_is_nonzero_and_report_is_reproducible_without_raw_text(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            root = Path(tmp)
            for name in ("evaluation.json", "development.json", "manifest.json"):
                shutil.copy(REAL_ROOT / name, root / name)
            out_dir = root / "results"

            first_stdout = io.StringIO()
            with redirect_stdout(first_stdout):
                first_code = main(["--root", str(root), "--out-dir", str(out_dir)])
            first_json = (out_dir / "evaluation-report.json").read_bytes()
            first_markdown = (out_dir / "evaluation-summary.md").read_bytes()

            second_stdout = io.StringIO()
            with redirect_stdout(second_stdout):
                second_code = main(["--root", str(root), "--out-dir", str(out_dir)])
            second_json = (out_dir / "evaluation-report.json").read_bytes()
            second_markdown = (out_dir / "evaluation-summary.md").read_bytes()

            self.assertEqual(first_code, 1)
            self.assertEqual(second_code, 1)
            self.assertEqual(first_json, second_json)
            self.assertEqual(first_markdown, second_markdown)
            self.assertEqual(first_stdout.getvalue(), second_stdout.getvalue())

            report = json.loads(first_json)
            raw_corpus = (root / "evaluation.json").read_bytes()
            self.assertEqual(report["corpus_sha256"], hashlib.sha256(raw_corpus).hexdigest())
            self.assertEqual(report["runtime_sha256"]["nasi_lemak/pii.py"],
                             hashlib.sha256((REAL_ROOT.parents[1] / "nasi_lemak" / "pii.py").read_bytes()).hexdigest())
            for key in ("timestamp", "created_at", "generated_at", "wall_clock"):
                self.assertNotIn(key, report)

            corpus_payload = json.loads(raw_corpus)
            blob = first_json.decode("utf-8") + first_markdown.decode("utf-8") + first_stdout.getvalue()
            for case in corpus_payload["cases"]:
                self.assertNotIn(case["text"], blob)

    def test_controlled_passing_fixture_exits_zero(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            root = Path(tmp)
            cases = [
                make_case("P-E", "Email me@example.invalid", gold=[
                    annotate("Email me@example.invalid", "EMAIL", "me@example.invalid")]),
                make_case("P-EN", "Not an email me@example", focus="EMAIL"),
                make_case("P-P", "Call 0123456789", gold=[
                    annotate("Call 0123456789", "MY_PHONE", "0123456789")], focus="MY_PHONE"),
                make_case("P-PN", "Call 0123456", focus="MY_PHONE"),
                make_case("P-M", "IC 900101-12-3456", gold=[
                    annotate("IC 900101-12-3456", "MYKAD", "900101-12-3456")], focus="MYKAD"),
                make_case("P-MN", "Ref 900101-12-345", focus="MYKAD"),
            ]
            raw = (json.dumps(payload(cases, corpus_id="controlled-passing"), indent=2) + "\n").encode("utf-8")
            (root / "evaluation.json").write_bytes(raw)
            manifest = {"schema_version": 1, "files": {
                "evaluation.json": hashlib.sha256(raw).hexdigest()}}
            (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = main(["--root", str(root), "--out-dir", str(root / "results")])
            self.assertEqual(code, 0)
            self.assertIn("provisional quality gates: PASS", stdout.getvalue())
            report = json.loads((root / "results" / "evaluation-report.json").read_text(encoding="utf-8"))
            self.assertTrue(report["gates"]["overall_pass"])
            for entity_type, result in report["per_entity"].items():
                if result["gate_applicable"]:
                    self.assertEqual((result["precision"], result["recall"]), (1.0, 1.0), entity_type)
            self.assertEqual(report["gates"]["not_applicable_entities"], ["POSTAL_ADDRESS"])

    def test_malformed_fixture_exits_two_without_raw_text(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            root = Path(tmp)
            raw = b'{"schema_version": 1, "split": "evaluation", "corpus_id": "bad", "cases": ['
            (root / "evaluation.json").write_bytes(raw)
            manifest = {"schema_version": 1, "files": {
                "evaluation.json": hashlib.sha256(raw).hexdigest()}}
            (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                code = main(["--root", str(root), "--out-dir", str(root / "results")])
            self.assertEqual(code, 2)
            self.assertIn("malformed fixture", stderr.getvalue())
            self.assertFalse((root / "results").exists())


if __name__ == "__main__":
    unittest.main()
