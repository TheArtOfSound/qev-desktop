from __future__ import annotations

from typing import Iterable

from bry_nfet_sx.bry.alphabet import SORTED_TOKENS, TOKEN_TO_CHAR
from bry_nfet_sx.bry.canonical import BryDecodingError, encode_to_bry

HUMAN_SEPARATOR = "|"


def tokenize_bry(code: str) -> list[str]:
    """
    Tokenize compact Bry using strict longest-match parsing.

    Whitespace is ignored for readability.
    """
    compact = "".join(ch for ch in code if not ch.isspace())
    out: list[str] = []
    i = 0

    while i < len(compact):
        matched = False

        for token in SORTED_TOKENS:
            if compact.startswith(token, i):
                out.append(token)
                i += len(token)
                matched = True
                break

        if not matched:
            raise BryDecodingError(
                f"Invalid Bry token stream near position {i}: {compact[i:i+12]!r}"
            )

    return out


def untokenize_bry(tokens: Iterable[str]) -> str:
    items = list(tokens)
    invalid = [tok for tok in items if tok not in TOKEN_TO_CHAR]
    if invalid:
        raise BryDecodingError(f"Unknown Bry tokens: {invalid!r}")
    return "".join(items)


def plaintext_to_bry_tokens(text: str) -> list[str]:
    return tokenize_bry(encode_to_bry(text))


def render_human_bry(tokens: Iterable[str], separator: str = HUMAN_SEPARATOR) -> str:
    items = list(tokens)
    invalid = [tok for tok in items if tok not in TOKEN_TO_CHAR]
    if invalid:
        raise BryDecodingError(f"Unknown Bry tokens: {invalid!r}")
    return separator.join(items)


def parse_human_bry(text: str, separator: str = HUMAN_SEPARATOR) -> list[str]:
    stripped = text.strip()
    if not stripped:
        return []

    raw_items = [part.strip() for part in stripped.split(separator)]
    if any(item == "" for item in raw_items):
        raise BryDecodingError(
            "Human-safe Bry contains an empty token segment. "
            "Check for duplicated separators or trailing separators."
        )

    invalid = [tok for tok in raw_items if tok not in TOKEN_TO_CHAR]
    if invalid:
        raise BryDecodingError(f"Unknown Bry tokens in human-safe input: {invalid!r}")

    return raw_items


def parse_bry_input(text: str) -> list[str]:
    """
    Accept either:
    - compact Bry (longest-match parsed)
    - human-safe Bry (pipe-delimited exact token mode)
    """
    if HUMAN_SEPARATOR in text:
        return parse_human_bry(text)
    return tokenize_bry(text)


def canonicalize_bry_input(text: str) -> str:
    return untokenize_bry(parse_bry_input(text))
