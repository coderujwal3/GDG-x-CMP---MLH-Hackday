from __future__ import annotations

import pytest

from scamsentry.models import InputError
from scamsentry.normalizer import (
    locate_in_original,
    normalise_message,
    utf8_byte_length,
    validate_message,
)


def test_empty_rejected() -> None:
    with pytest.raises(InputError, match="empty"):
        validate_message("")


def test_whitespace_only_rejected() -> None:
    with pytest.raises(InputError, match="whitespace"):
        validate_message("  \n\t  ")


def test_size_limit() -> None:
    message = "a" * 100
    with pytest.raises(InputError, match="exceeds"):
        validate_message(message, max_bytes=10)
    validate_message(message, max_bytes=utf8_byte_length(message))


def test_original_preserved_when_normalising() -> None:
    original = "Hello\u200bWORLD   team"
    result = normalise_message(original)
    assert result.original == original
    assert "\u200b" not in result.normalised
    assert "helloworld" in result.normalised.replace(" ", "")
    assert result.invisible_spans
    assert result.invisible_spans[0].start == original.index("\u200b")


def test_invisible_unicode_detected() -> None:
    original = "act\u200bnow"
    result = normalise_message(original)
    assert any(span.codepoint == "U+200B" for span in result.invisible_spans)


def test_locate_in_original_unique() -> None:
    original = "Please confirm your password today."
    located = locate_in_original(original, "password")
    assert located == (original.index("password"), original.index("password") + 8)


def test_locate_in_original_ambiguous_returns_none() -> None:
    original = "password then password"
    assert locate_in_original(original, "password") is None
