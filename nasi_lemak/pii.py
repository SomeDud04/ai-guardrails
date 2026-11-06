"""Shared ASCII PII redaction spans.

This module is the single source of truth for the format recognizers used by the
runtime gateway.  ``mask_text`` is the production masking path and
``find_redactions`` exposes the same spans to the offline evaluator, so the
evaluation cannot drift from the gateway with a cloned regex.

The recognizers are deliberately narrow structured-format heuristics.  They
also accept a small reviewed set of Unicode dash/space separators in MyKad and
phone groupings, but they do not validate identity documents, phone
reachability or email deliverability, and they do not detect semantic PII in
free text.

``CARD_NUMBER`` recognises 13-19 digit payment-card candidates only when the
Luhn checksum passes.  ``BANK_ACCOUNT`` and ``PASSPORT`` require an explicit
account/passport label and mask only the value, never the label.  These are
format heuristics: unlabelled bank/passport values stay raw, and a Luhn-valid
number is masked even when it is not a real card.

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

ENTITY_TYPES = (
    "EMAIL",
    "MY_PHONE",
    "MYKAD",
    "POSTAL_ADDRESS",
    "CARD_NUMBER",
    "BANK_ACCOUNT",
    "PASSPORT",
)

MASK_TOKENS = {
    "EMAIL": "[EMAIL]",
    "MY_PHONE": "[MY_PHONE]",
    "MYKAD": "[MYKAD]",
    "POSTAL_ADDRESS": "[POSTAL_ADDRESS]",
    "CARD_NUMBER": "[CARD_NUMBER]",
    "BANK_ACCOUNT": "[BANK_ACCOUNT]",
    "PASSPORT": "[PASSPORT]",
}

# Word boundaries for EMAIL and MY_PHONE mean ASCII letters, digits and
# underscore only.  ``\w`` also matches Han characters, and Chinese is written
# without spaces, so ``邮箱是alice@example.com`` would never start a match.
_W = "A-Za-z0-9_"

# Preserved literals and order from the original gateway implementation.
# Narrow reviewed repair: a period may terminate a sentence, but it may not
# continue a domain/hyphenated suffix or start a double-dot suffix.
_EMAIL = re.compile(
    rf"(?<![{_W}.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{{2,}}(?![{_W}-]|\.[{_W}.-])", re.I
)

# Structural group separators.  MyKad groups accept exactly zero or one of the
# reviewed dash/space variants; phone groups additionally accept a period
# (``012.345.6789``) and an en dash.  Keeping the sets here preserves the
# single-source-of-truth contract for the gateway and offline evaluator.
_MYKAD_SEP = r"[ \u2013\u2014\u2212\u2011-]"
_PHONE_SEP = r"[ .\u2013-]"

# Optional Malaysian country code (the leading local zero is omitted) or the
# local leading zero.
_PHONE_CODE = rf"(?:\+?60{_PHONE_SEP}?|0)"


def _phone_with_brackets(body: str) -> str:
    """Allow one paired set of brackets around a phone prefix/area code."""

    return rf"(?:\({body}\)|{body})"


_PHONE_MOBILE = (
    _phone_with_brackets(rf"{_PHONE_CODE}1\d")
    + rf"(?:{_PHONE_SEP}?\d){{7,8}}"
)
# Full national landline lengths: 03 + 8 digits, 04/05/06/07/09 + 7 digits and
# 08x + 6 digits.  The country-code forms use the same subscriber counts
# without the leading zero.
_PHONE_LANDLINE = "|".join(
    _phone_with_brackets(rf"{_PHONE_CODE}{area}")
    + rf"(?:{_PHONE_SEP}?\d){{{digits}}}"
    for area, digits in (("3", 8), ("[45679]", 7), (r"8\d", 6))
)
# A hyphen-prefixed identifier such as ``INV-0312345678`` is not a landline, so
# that boundary also rejects a preceding hyphen.  Mobile numbers keep the plain
# word boundary: ``HP-012-345 6789`` must stay masked.  A trailing period followed
# by a digit is left to a larger numeric literal (for example a decimal), and the
# right word boundary prevents matching inside a longer run.
_PHONE = re.compile(
    rf"(?:(?<![{_W}])(?:{_PHONE_MOBILE})|(?<![{_W}-])(?:{_PHONE_LANDLINE}))(?![{_W}])(?!\.\d)"
)
_MYKAD = re.compile(
    rf"(?<!\d)\d{{6}}{_MYKAD_SEP}?\d{{2}}{_MYKAD_SEP}?\d{{4}}(?!\d)"
)

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

# Payment-card candidates: 13-19 ASCII digits, contiguous or grouped by single
# spaces/hyphens.  The surrounding lookarounds reject any span that is only part
# of a longer digit run, including one joined by a separator.  Candidates are
# kept only when the Luhn checksum passes.
_CARD_CANDIDATE = re.compile(
    r"(?<![0-9])(?<![0-9][ -])(?:[0-9][ -]?){12,18}[0-9](?![ -]?[0-9])"
)


def _luhn_valid(value: str) -> bool:
    """Return whether a digit/space/hyphen value passes the Luhn checksum."""

    total = 0
    digits = value.replace(" ", "").replace("-", "")
    for index, char in enumerate(reversed(digits)):
        digit = ord(char) - ord("0")
        if index % 2:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


class _LuhnPattern:
    """Regex wrapper that yields only matches whose text passes Luhn."""

    def __init__(self, pattern: re.Pattern[str]) -> None:
        self._pattern = pattern

    def finditer(self, text: str):
        for match in self._pattern.finditer(text):
            if _luhn_valid(match.group(0)):
                yield match


_CARD = _LuhnPattern(_CARD_CANDIDATE)

# Labelled account/passport values.  A label may be followed by up to three
# filler tokens (``no``/``no.``/``number``/``#``/``is``/``:``) before the value.
# Only the value is captured, so the label and punctuation stay in the output.
_LABEL_FILLER = r"(?:\s*(?:(?i:no\.?|number|is)|[#:])){0,3}"

_BANK_ACCOUNT = re.compile(
    rf"(?<![\w])(?i:bank\s+account|account|acct|acc|a/c|akaun)(?![\w])"
    rf"{_LABEL_FILLER}\s*"
    rf"(?P<bank>[0-9](?:[ -]?[0-9]){{7,16}})(?![ -]?[0-9])"
)

_PASSPORT = re.compile(
    rf"(?<![\w])(?i:passport|pasport)(?![\w])"
    rf"{_LABEL_FILLER}\s*"
    rf"(?P<passport>[A-Za-z]{{1,2}}[0-9]{{6,9}})(?![0-9A-Za-z])"
)

# (entity type, compiled pattern, group holding the exact span).  Most
# recognizers match the whole pattern; the labelled address, bank account and
# passport mask only their value group so the label survives.
_RECOGNIZERS = (
    ("EMAIL", _EMAIL, 0),
    ("CARD_NUMBER", _CARD, 0),
    ("MY_PHONE", _PHONE, 0),
    ("MYKAD", _MYKAD, 0),
    ("POSTAL_ADDRESS", _POSTAL_ADDRESS, 0),
    ("POSTAL_ADDRESS", _LABELLED_ADDRESS, 1),
    ("BANK_ACCOUNT", _BANK_ACCOUNT, "bank"),
    ("PASSPORT", _PASSPORT, "passport"),
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

    The recognizers run in the same order as ``mask_text`` (email, card number,
    phone, MyKad, postal address with postcode, labelled postal address without
    postcode, labelled bank account, labelled passport).  Earlier replacements
    become mask tokens, which contain no characters the later recognizers match,
    so later spans still lie in untouched regions.
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

    ``entity_types`` is optional and defaults to all recognizers.  An empty
    selection is a deliberate no-op.
    """

    pieces: list[str] = []
    last = 0
    for redaction in find_redactions(text, entity_types):
        pieces.append(text[last:redaction.start])
        pieces.append(MASK_TOKENS[redaction.entity_type])
        last = redaction.end
    pieces.append(text[last:])
    return "".join(pieces)
