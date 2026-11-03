"""Candidate texts that may hide a deny phrase behind a light encoding.

``Policy.denies`` checks the message as written and then every candidate this
module produces.  The transformations are deliberately conservative: each one
only adds text that a person could reasonably read as the same phrase, so normal
prose, URLs, JSON and binary blobs do not become false positives.

The module is standard-library only and has no knowledge of the configured
phrases.  Callers must treat the returned texts as untrusted candidates and
never log them.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re

# A run of three or more single letters separated by spaces spells one word.
_SINGLE_LETTER_RUN = re.compile(
    r"(?<![A-Za-z])(?:[A-Za-z] +){2,}[A-Za-z](?![A-Za-z])"
)
# Maximal Base64-looking runs, so a substring of a longer token is never
# decoded on its own.  Padding is part of the token.
_BASE64_TOKEN = re.compile(
    r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]+={0,2}(?![A-Za-z0-9+/=])"
)
_MIN_TOKEN_LENGTH = 16
_MAX_TOKEN_LENGTH = 4096
_MAX_DECODED_TOKENS = 8
_MAX_VARIANT_BYTES = 16 * 1024


def _collapse_single_letters(match: re.Match[str]) -> str:
    return "".join(match.group(0).split())


def _decode_printable_token(token: str) -> str | None:
    """Decode one Base64 token, or return ``None`` when it is not text."""
    if not _MIN_TOKEN_LENGTH <= len(token) <= _MAX_TOKEN_LENGTH:
        return None
    padding = (-len(token)) % 4
    if padding == 3:
        # A remainder of one is not a valid Base64 length.
        return None
    try:
        raw = base64.b64decode(token + "=" * padding, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not decoded:
        return None
    # Newlines and tabs are ordinary textual layout; every other control or
    # unprintable character means this is data (an image header, for example),
    # not a hidden phrase.
    if not all(
        character.isprintable() or character in "\t\n\r" for character in decoded
    ):
        return None
    return decoded


def variants(text: str) -> list[str]:
    """Return candidate texts derived from ``text``.

    Three independent variants are produced: single letters collapsed into a
    word, the whole text ROT13-decoded, and up to eight Base64 tokens that
    decode to printable UTF-8.  Variant text is capped at 16 KiB in total;
    anything beyond the cap is silently ignored.
    """
    if not isinstance(text, str) or not text:
        return []

    found: list[str] = []
    seen: set[str] = set()
    used_bytes = 0

    def add(candidate: str) -> None:
        nonlocal used_bytes
        if not candidate or candidate == text or candidate in seen:
            return
        size = len(candidate.encode("utf-8"))
        if used_bytes + size > _MAX_VARIANT_BYTES:
            return
        seen.add(candidate)
        used_bytes += size
        found.append(candidate)

    collapsed = _SINGLE_LETTER_RUN.sub(_collapse_single_letters, text)
    if collapsed != text:
        add(collapsed)

    add(codecs.decode(text, "rot13"))

    decoded_count = 0
    for match in _BASE64_TOKEN.finditer(text):
        decoded = _decode_printable_token(match.group(0))
        if decoded is None:
            continue
        add(decoded)
        decoded_count += 1
        if decoded_count >= _MAX_DECODED_TOKENS:
            break

    return found
