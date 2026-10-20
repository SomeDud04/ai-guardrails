"""Shared ASCII PII redaction spans.

This module is the single source of truth for the three format recognizers used
by the runtime gateway.  ``mask_text`` is the production masking path and
``find_redactions`` exposes the same spans to the offline evaluator, so the
evaluation cannot drift from the gateway with a cloned regex.

The recognizers are deliberately narrow ASCII structured-format heuristics.
They do not validate identity documents, phone reachability or email
deliverability, and they do not detect semantic PII in free text.
"""

from __future__ import annotations

import re
from typing import NamedTuple

ENTITY_TYPES = ("EMAIL", "MY_PHONE", "MYKAD")

MASK_TOKENS = {
    "EMAIL": "[EMAIL]",
    "MY_PHONE": "[MY_PHONE]",
    "MYKAD": "[MYKAD]",
}

# Preserved literals and order from the original gateway implementation.
# Narrow reviewed repair: a period may terminate a sentence, but it may not
# continue a domain/hyphenated suffix or start a double-dot suffix.
_EMAIL = re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w-]|\.[\w.-])", re.I)
_PHONE = re.compile(r"(?<!\w)(?:\+?60|0)1[0-9](?:[ -]?\d){7,8}(?!\w)")
_MYKAD = re.compile(r"(?<!\d)\d{6}-?\d{2}-?\d{4}(?!\d)")

_RECOGNIZERS = (
    ("EMAIL", _EMAIL),
    ("MY_PHONE", _PHONE),
    ("MYKAD", _MYKAD),
)


class Redaction(NamedTuple):
    """One exact span in the original text."""

    entity_type: str
    start: int
    end: int


def find_redactions(text: str) -> list[Redaction]:
    """Return production redaction spans in original-text coordinates.

    The recognizers run in the same order as ``mask_text`` (email, phone, MyKad).
    Earlier replacements become mask tokens, which contain no characters the
    later recognizers match, so later spans still lie in untouched regions.
    """

    current = text
    mapping = list(range(len(text)))
    redactions: list[Redaction] = []
    for entity_type, pattern in _RECOGNIZERS:
        matches = list(pattern.finditer(current))
        if not matches:
            continue
        pieces: list[str] = []
        new_mapping: list[int] = []
        last = 0
        token = MASK_TOKENS[entity_type]
        for match in matches:
            pieces.append(current[last:match.start()])
            new_mapping.extend(mapping[last:match.start()])
            pieces.append(token)
            new_mapping.extend([-1] * len(token))
            start = mapping[match.start()]
            end = mapping[match.end() - 1] + 1
            redactions.append(Redaction(entity_type, start, end))
            last = match.end()
        pieces.append(current[last:])
        new_mapping.extend(mapping[last:])
        current = "".join(pieces)
        mapping = new_mapping
    redactions.sort(key=lambda item: (item.start, item.end, item.entity_type))
    return redactions


def mask_text(text: str) -> str:
    """Replace every detected span with its fixed placeholder."""

    pieces: list[str] = []
    last = 0
    for redaction in find_redactions(text):
        pieces.append(text[last:redaction.start])
        pieces.append(MASK_TOKENS[redaction.entity_type])
        last = redaction.end
    pieces.append(text[last:])
    return "".join(pieces)
