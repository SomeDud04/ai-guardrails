"""Shared ASCII PII redaction spans.

This module is the single source of truth for the format recognizers used by the
runtime gateway.  ``mask_text`` is the production masking path and
``find_redactions`` exposes the same spans to the offline evaluator, so the
evaluation cannot drift from the gateway with a cloned regex.

The recognizers are deliberately narrow ASCII structured-format heuristics.
They do not validate identity documents, phone reachability or email
deliverability, and they do not detect semantic PII in free text.

``POSTAL_ADDRESS`` recognises two bounded Malaysian single-line address shapes.
The first requires a house/unit number, a Jalan/Jln, Lorong/Lrg, Persiaran or
similar street keyword, a capitalised street name and a five-digit postcode,
with optional comma-separated locality/state words.  The second is the same
body without a postcode but only when it follows an explicit ``Address:`` or
``Alamat:`` label; the label itself stays outside the masked span.  It is not
comprehensive semantic address detection: street-first addresses without a
house number and *unlabelled* addresses without a postcode are left untouched.
"""

from __future__ import annotations

import re
from typing import NamedTuple

ENTITY_TYPES = ("EMAIL", "MY_PHONE", "MYKAD", "POSTAL_ADDRESS")

MASK_TOKENS = {
    "EMAIL": "[EMAIL]",
    "MY_PHONE": "[MY_PHONE]",
    "MYKAD": "[MYKAD]",
    "POSTAL_ADDRESS": "[POSTAL_ADDRESS]",
}

# Preserved literals and order from the original gateway implementation.
# Narrow reviewed repair: a period may terminate a sentence, but it may not
# continue a domain/hyphenated suffix or start a double-dot suffix.
_EMAIL = re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w-]|\.[\w.-])", re.I)
_PHONE = re.compile(r"(?<!\w)(?:\+?60[ -]?|0)1[0-9](?:[ -]?\d){7,8}(?!\w)")
_MYKAD = re.compile(r"(?<!\d)\d{6}-?\d{2}-?\d{4}(?!\d)")

# Postcode-bearing bounded Malaysian single-line address shape.  It requires a
# house/unit number, a street keyword and a five-digit postcode, so bare
# postcodes, place-name mentions and ordinary numbered prose stay raw.
_ADDRESS_NAME = r"(?:[A-Z][A-Za-z']*|\d{1,3}[A-Za-z]?)"
_ADDRESS_STREET_NAME = rf"{_ADDRESS_NAME}(?:\s+{_ADDRESS_NAME}){{0,3}}"
_ADDRESS_PLACE = rf"{_ADDRESS_NAME}(?:\s+{_ADDRESS_NAME}){{0,3}}"
_ADDRESS_NUMBER = (
    r"(?:(?i:No|Unit|Blok|Block|Lot|Level|Floor)\.?\s*)?"
    r"\d{1,4}[A-Z]?(?:-\d{1,4}[A-Z]?)?"
)
_ADDRESS_STREET = (
    r"(?i:Jalan|Jln|Lorong|Lrg|Persiaran|Pesiaran|Lebuh|Lbh|Changkat)\.?"
)
_POSTAL_ADDRESS = re.compile(
    rf"(?<![\w]){_ADDRESS_NUMBER}\s*,?\s*{_ADDRESS_STREET}\s+{_ADDRESS_STREET_NAME}"
    rf"(?:\s*,\s*{_ADDRESS_PLACE}){{0,3}}\s*,\s*\d{{5}}(?!\d)"
    rf"(?:(?:\s*,\s*|\s+){_ADDRESS_PLACE}){{0,3}}(?![\w])"
)

# Narrow reviewed repair: an explicit ``Address:``/``Alamat:`` label makes the
# postcode optional for the same numbered street shape.  Only the body (group
# 1) is masked; the label and any surrounding punctuation/prose stay outside.
# The street name remains bounded to four short tokens and the trailing
# locality groups still require commas, so ordinary following words are not
# swallowed.  A comma-less trailing postcode is excluded so the recognizer
# cannot mask half of an address shape the postcode pattern does not accept.
_LABELLED_ADDRESS = re.compile(
    rf"(?<![\w])(?i:Address|Alamat)\s*:\s*"
    rf"(?P<address>{_ADDRESS_NUMBER}\s*,?\s*{_ADDRESS_STREET}\s+{_ADDRESS_STREET_NAME}"
    rf"(?:\s*,\s*{_ADDRESS_PLACE}){{0,3}})"
    rf"(?![\w])(?!\s*,?\s*\d{{5}}(?!\d))"
)

# (entity type, compiled pattern, group holding the exact span).  Most
# recognizers match the whole pattern; the labelled address masks only its
# body so the label survives.
_RECOGNIZERS = (
    ("EMAIL", _EMAIL, 0),
    ("MY_PHONE", _PHONE, 0),
    ("MYKAD", _MYKAD, 0),
    ("POSTAL_ADDRESS", _POSTAL_ADDRESS, 0),
    ("POSTAL_ADDRESS", _LABELLED_ADDRESS, 1),
)


class Redaction(NamedTuple):
    """One exact span in the original text."""

    entity_type: str
    start: int
    end: int


def _selected_recognizers(entity_types: tuple[str, ...] | list[str] | None):
    if entity_types is None:
        return _RECOGNIZERS
    if isinstance(entity_types, str):
        raise ValueError("entity type selection is invalid")
    selected = tuple(entity_types)
    if any(item not in ENTITY_TYPES for item in selected):
        raise ValueError("entity type selection is invalid")
    if len(set(selected)) != len(selected):
        raise ValueError("entity type selection is invalid")
    wanted = set(selected)
    return tuple(item for item in _RECOGNIZERS if item[0] in wanted)


def find_redactions(
    text: str, entity_types: tuple[str, ...] | list[str] | None = None
) -> list[Redaction]:
    """Return production redaction spans in original-text coordinates.

    The recognizers run in the same order as ``mask_text`` (email, phone,
    MyKad, postal address with postcode, labelled postal address without
    postcode).  Earlier replacements become mask tokens, which contain no
    characters the later recognizers match, so later spans still lie in
    untouched regions.
    ``entity_types`` optionally narrows the recognizers for an explicit
    administrator-selected mask policy; ``None`` preserves the original
    all-recognizer behaviour.
    """

    current = text
    mapping = list(range(len(text)))
    redactions: list[Redaction] = []
    for entity_type, pattern, span_group in _selected_recognizers(entity_types):
        matches = list(pattern.finditer(current))
        if not matches:
            continue
        pieces: list[str] = []
        new_mapping: list[int] = []
        last = 0
        token = MASK_TOKENS[entity_type]
        for match in matches:
            span_start = match.start(span_group)
            span_end = match.end(span_group)
            pieces.append(current[last:span_start])
            new_mapping.extend(mapping[last:span_start])
            pieces.append(token)
            new_mapping.extend([-1] * len(token))
            start = mapping[span_start]
            end = mapping[span_end - 1] + 1
            redactions.append(Redaction(entity_type, start, end))
            last = span_end
        pieces.append(current[last:])
        new_mapping.extend(mapping[last:])
        current = "".join(pieces)
        mapping = new_mapping
    redactions.sort(key=lambda item: (item.start, item.end, item.entity_type))
    return redactions


def mask_text(
    text: str, entity_types: tuple[str, ...] | list[str] | None = None
) -> str:
    """Replace every detected span with its fixed placeholder.

    ``entity_types`` is optional and defaults to all four recognizers.  An
    empty selection is a deliberate no-op.
    """

    pieces: list[str] = []
    last = 0
    for redaction in find_redactions(text, entity_types):
        pieces.append(text[last:redaction.start])
        pieces.append(MASK_TOKENS[redaction.entity_type])
        last = redaction.end
    pieces.append(text[last:])
    return "".join(pieces)
