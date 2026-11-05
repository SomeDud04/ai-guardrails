"""Build the Malay and Chinese mirror of the OWASP LLM Top 10 (2026) corpus.

Each output row mirrors one English corpus row: every field is copied from the
English row except ``id``, ``language``, ``mirror_of`` and the message text.
Message text comes from one of two sources:

* **reused** - the existing guard-lane translations (v2 Malay attacks, v3
  Malay controls, v3 Chinese mirrors), so a case reads the same in every
  dataset that holds it;
* **authored** - ``translations.json`` beside the payloads, for rows the guard
  lanes never covered.

The English corpus under ``evals/owasp/llm-top10-2026`` is frozen and is only
read.  This script writes ``schema.json``, ``payloads/*.jsonl`` and
``MANIFEST.sha256`` under ``evals/owasp/llm-top10-2026-ml``.  It performs no
network access.

Usage:
    python scripts/build_owasp_ml_corpus.py
    python scripts/build_owasp_ml_corpus.py --check
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_owasp_checklist as english  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
EN_ROOT = ROOT / "evals" / "owasp" / "llm-top10-2026"
EN_PAYLOADS = EN_ROOT / "payloads"
EN_SCHEMA = EN_ROOT / "schema.json"
ML_ROOT = ROOT / "evals" / "owasp" / "llm-top10-2026-ml"
ML_PAYLOADS = ML_ROOT / "payloads"
ML_SCHEMA = ML_ROOT / "schema.json"
ML_MANIFEST = ML_ROOT / "MANIFEST.sha256"
TRANSLATIONS = ML_ROOT / "translations.json"
GUARDS = ROOT / "evals" / "guards"

LANGUAGES = ("bm", "zh")
ML_FIELDS = ("language", "mirror_of")
# Guard-lane files whose mirrors are reused, per language.
REUSED_SOURCES = {
    "bm": ("owasp-llm-top10-2026-v2-bm.json", "owasp-llm-top10-2026-v3-bm-ctrl.json"),
    "zh": ("owasp-llm-top10-2026-v3-zh.json",),
}
ID_PATTERN = r"^(BM|ZH)-(LLM(0[1-9]|10)|CTRL)-[0-9]{3}$"
MIRROR_PATTERN = r"^(LLM(0[1-9]|10)|CTRL)-[0-9]{3}$"


class MlCorpusError(Exception):
    """The mirror corpus or one of its sources failed validation."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise MlCorpusError(message)


def ml_id(language: str, english_id: str) -> str:
    return f"{language.upper()}-{english_id}"


def guard_to_english_id(guard_id: str, language: str) -> str | None:
    """``bm-llm01-002`` -> ``LLM01-002``; ``None`` for a guard-only case."""
    prefix = f"{language}-"
    if not guard_id.startswith(prefix):
        return None
    rest = guard_id[len(prefix):]
    if not rest.startswith(("llm", "ctrl")):
        return None  # for example bm-ben-*: hard negatives with no corpus row
    return rest.upper()


def english_records() -> list[dict[str, Any]]:
    return english.load_corpus(EN_PAYLOADS)


def english_files() -> dict[str, str]:
    """English row id -> the payload file name it lives in."""
    where: dict[str, str] = {}
    for path in sorted(EN_PAYLOADS.glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                where[json.loads(line)["id"]] = path.name
    return where


def reused_messages() -> dict[str, dict[str, list[dict[str, str]]]]:
    """language -> English id -> messages, from the guard-lane datasets."""
    found: dict[str, dict[str, list[dict[str, str]]]] = {lang: {} for lang in LANGUAGES}
    for language, names in REUSED_SOURCES.items():
        for name in names:
            payload = json.loads((GUARDS / name).read_text(encoding="utf-8"))
            for case in payload["cases"]:
                english_id = guard_to_english_id(case["id"], language)
                if english_id is None:
                    continue
                _require(case["language"] == language,
                         f"{name}: {case['id']} is labelled {case['language']}")
                _require(english_id not in found[language],
                         f"{name}: {case['id']} duplicates another reused mirror")
                found[language][english_id] = case["messages"]
    return found


def authored_messages(path: Path = TRANSLATIONS) -> dict[str, dict[str, list[dict[str, str]]]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    _require(payload.get("schema_version") == 1, f"{path.name}: schema_version must be 1")
    rows = payload.get("rows")
    _require(isinstance(rows, dict) and set(rows) == set(LANGUAGES),
             f"{path.name}: rows must hold exactly {list(LANGUAGES)}")
    return rows


def build_schema() -> dict[str, Any]:
    schema = json.loads(EN_SCHEMA.read_text(encoding="utf-8"))
    schema["$id"] = "https://example.com/nasi-lemak/owasp-llm-top10-2026-ml/record.schema.json"
    schema["title"] = "OWASP LLM Top 10 2026 synthetic payload record, Malay and Chinese mirror"
    schema["description"] = (
        "One JSONL record mirroring an English corpus row in Malay (bm) or Chinese (zh). "
        "Every field except id, language, mirror_of and the message text equals the "
        "English row named by mirror_of. " + schema["description"]
    )
    properties = schema["properties"]
    properties["id"] = {"type": "string", "pattern": ID_PATTERN}
    rebuilt: dict[str, Any] = {}
    for key, value in properties.items():
        rebuilt[key] = value
        if key == "id":
            rebuilt["language"] = {"type": "string", "enum": list(LANGUAGES)}
            rebuilt["mirror_of"] = {"type": "string", "pattern": MIRROR_PATTERN}
    schema["properties"] = rebuilt
    required = list(schema["required"])
    position = required.index("id") + 1
    schema["required"] = required[:position] + list(ML_FIELDS) + required[position:]
    return schema


def mirror_row(english_row: dict[str, Any], language: str,
               messages: list[dict[str, str]], source: str) -> dict[str, Any]:
    roles = [message["role"] for message in english_row["messages"]]
    _require([m.get("role") for m in messages] == roles,
             f"{source}: {language} mirror of {english_row['id']} changes the message roles")
    row: dict[str, Any] = {}
    for key, value in english_row.items():
        if key == "id":
            row["id"] = ml_id(language, english_row["id"])
            row["language"] = language
            row["mirror_of"] = english_row["id"]
        elif key == "messages":
            row["messages"] = [{"role": m["role"], "content": m["content"]} for m in messages]
        else:
            row[key] = copy.deepcopy(value)
    return row


def validate_mirror(row: dict[str, Any], english_by_id: dict[str, dict[str, Any]]) -> None:
    source = row.get("id", "<no id>")
    _require(row.get("language") in LANGUAGES, f"{source}: invalid language")
    mirror_of = row.get("mirror_of")
    _require(mirror_of in english_by_id, f"{source}: mirror_of {mirror_of!r} is not an English row")
    _require(row["id"] == ml_id(row["language"], mirror_of), f"{source}: id does not match language/mirror_of")
    stripped = {key: value for key, value in row.items() if key not in ML_FIELDS}
    stripped["id"] = mirror_of
    english.validate_record(stripped, source=source)
    reference = english_by_id[mirror_of]
    for key, value in reference.items():
        if key != "messages" and key != "id":
            _require(stripped.get(key) == value, f"{source}: field {key} differs from {mirror_of}")
    _require(set(stripped) == set(reference), f"{source}: field set differs from {mirror_of}")


def build_rows() -> dict[str, list[dict[str, Any]]]:
    """payload file name -> mirror rows, in English order, Malay before Chinese."""
    records = english_records()
    by_id = {record["id"]: record for record in records}
    where = english_files()
    reused = reused_messages()
    authored = authored_messages()
    for language in LANGUAGES:
        for english_id in reused[language]:
            _require(english_id in by_id, f"reused {language} mirror of unknown row {english_id}")
        for english_id in authored[language]:
            _require(english_id in by_id, f"translations.json: unknown row {english_id}")
            _require(english_id not in reused[language],
                     f"translations.json: {language} {english_id} is already a reused mirror")
    files: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        for language in LANGUAGES:
            if record["id"] in reused[language]:
                messages, source = reused[language][record["id"]], "guard lane"
            elif record["id"] in authored[language]:
                messages, source = authored[language][record["id"]], "translations.json"
            else:
                continue
            row = mirror_row(record, language, messages, source)
            validate_mirror(row, by_id)
            files.setdefault(where[record["id"]], []).append(row)
    return files


def render_jsonl(rows: list[dict[str, Any]]) -> str:
    return "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)


def render_schema(schema: dict[str, Any]) -> str:
    return json.dumps(schema, indent=2, ensure_ascii=False) + "\n"


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def render_outputs() -> dict[str, str]:
    """Relative path under ML_ROOT -> exact file text."""
    outputs = {"schema.json": render_schema(build_schema())}
    for name, rows in sorted(build_rows().items()):
        outputs[f"payloads/{name}"] = render_jsonl(rows)
    hashed = dict(outputs)
    # Hash the exact bytes on disk; read_text would fold CRLF line endings.
    hashed["translations.json"] = TRANSLATIONS.read_bytes().decode("utf-8")
    outputs["MANIFEST.sha256"] = "".join(
        f"{_sha256(text)}  {path}\n" for path, text in sorted(hashed.items())
    )
    return outputs


def build() -> list[str]:
    outputs = render_outputs()
    ML_PAYLOADS.mkdir(parents=True, exist_ok=True)
    stale = {f"payloads/{p.name}" for p in ML_PAYLOADS.glob("*.jsonl")} - set(outputs)
    for path in sorted(stale):
        (ML_ROOT / path).unlink()
    for path, text in outputs.items():
        (ML_ROOT / path).write_bytes(text.encode("utf-8"))
    return sorted(outputs)


def check() -> list[str]:
    """Differences between the committed files and a fresh build."""
    outputs = render_outputs()
    problems: list[str] = []
    committed = {f"payloads/{p.name}" for p in ML_PAYLOADS.glob("*.jsonl")}
    for path in sorted(committed - set(outputs)):
        problems.append(f"{path}: stale file, not produced by the builder")
    for path, text in sorted(outputs.items()):
        target = ML_ROOT / path
        if not target.exists():
            problems.append(f"{path}: missing")
        elif target.read_bytes() != text.encode("utf-8"):
            problems.append(f"{path}: differs from a fresh build")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="verify committed files, write nothing")
    args = parser.parse_args(argv)
    try:
        if args.check:
            problems = check()
            for problem in problems:
                print(problem, file=sys.stderr)
            print("ok" if not problems else f"{len(problems)} problem(s)")
            return 1 if problems else 0
        for path in build():
            print(f"wrote {ML_ROOT.relative_to(ROOT).as_posix()}/{path}")
        return 0
    except (MlCorpusError, english.CorpusError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
