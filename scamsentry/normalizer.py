"""Normalise text for matching without rewriting the original message."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from scamsentry.models import DEFAULT_MAX_BYTES, InputError


INVISIBLE_CODEPOINTS = frozenset(
    {
        0x00AD,  # soft hyphen
        0x034F,  # combining grapheme joiner
        0x061C,  # Arabic letter mark
        0x115F,  # Hangul filler
        0x1160,
        0x17B4,
        0x17B5,
        0x180B,
        0x180C,
        0x180D,
        0x180E,
        0x200B,  # zero-width space
        0x200C,  # ZWNJ
        0x200D,  # ZWJ
        0x200E,  # LRM
        0x200F,  # RLM
        0x202A,
        0x202B,
        0x202C,
        0x202D,
        0x202E,
        0x2060,  # word joiner
        0x2061,
        0x2062,
        0x2063,
        0x2064,
        0x2066,
        0x2067,
        0x2068,
        0x2069,
        0x206A,
        0x206B,
        0x206C,
        0x206D,
        0x206E,
        0x206F,
        0x3164,  # Hangul filler
        0xFE00,
        0xFE01,
        0xFE02,
        0xFE03,
        0xFE04,
        0xFE05,
        0xFE06,
        0xFE07,
        0xFE08,
        0xFE09,
        0xFE0A,
        0xFE0B,
        0xFE0C,
        0xFE0D,
        0xFE0E,
        0xFE0F,
        0xFEFF,  # BOM / ZWNBSP
        0xFFA0,
        0xFFF9,
        0xFFFA,
        0xFFFB,
    }
)

_WHITESPACE_RE = re.compile(r"\s+")


@dataclass(frozen=True)
class InvisibleSpan:
    start: int
    end: int
    codepoint: str
    name: str


@dataclass(frozen=True)
class NormalisationResult:
    original: str
    normalised: str
    invisible_spans: tuple[InvisibleSpan, ...]


def utf8_byte_length(text: str) -> int:
    return len(text.encode("utf-8"))


def validate_message(message: str, *, max_bytes: int = DEFAULT_MAX_BYTES) -> None:
    if not isinstance(message, str):
        raise InputError("Message must be a Unicode string.")
    if message.strip() == "":
        raise InputError("Message is empty or whitespace-only.")
    size = utf8_byte_length(message)
    if size > max_bytes:
        raise InputError(
            f"Message exceeds the configured maximum of {max_bytes} UTF-8 bytes "
            f"(received {size})."
        )


def _is_invisible(ch: str) -> bool:
    code = ord(ch)
    if code in INVISIBLE_CODEPOINTS:
        return True
    if 0xE0000 <= code <= 0xE007F:  # language tags
        return True
    category = unicodedata.category(ch)
    if category in {"Cf", "Cc"} and ch not in {"\n", "\r", "\t"}:
        return True
    return False


def find_invisible_spans(original: str) -> tuple[InvisibleSpan, ...]:
    spans: list[InvisibleSpan] = []
    for index, char in enumerate(original):
        if _is_invisible(char):
            try:
                name = unicodedata.name(char)
            except ValueError:
                name = f"U+{ord(char):04X}"
            spans.append(
                InvisibleSpan(
                    start=index,
                    end=index + 1,
                    codepoint=f"U+{ord(char):04X}",
                    name=name,
                )
            )
    return tuple(spans)


def normalise_for_matching(original: str) -> str:
    """NFKC + strip invisible formatting + collapse whitespace.

    Used only for matching. The original message is never rewritten.
    """

    nfkc = unicodedata.normalize("NFKC", original)
    without_invisible: list[str] = []
    for char in nfkc:
        if _is_invisible(char) or char in {"\u00a0"}:
            without_invisible.append(" ")
            continue
        without_invisible.append(char)
    collapsed = _WHITESPACE_RE.sub(" ", "".join(without_invisible))
    return collapsed.strip().lower()


def normalise_message(original: str) -> NormalisationResult:
    return NormalisationResult(
        original=original,
        normalised=normalise_for_matching(original),
        invisible_spans=find_invisible_spans(original),
    )


def locate_in_original(original: str, snippet: str) -> tuple[int, int] | None:
    """Map a snippet onto the original message when the mapping is unique and exact."""

    if not snippet:
        return None
    start = original.find(snippet)
    if start < 0:
        return None
    if original.find(snippet, start + 1) >= 0:
        return None
    return start, start + len(snippet)
