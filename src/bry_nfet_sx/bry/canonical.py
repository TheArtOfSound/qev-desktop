from __future__ import annotations

from dataclasses import dataclass

from bry_nfet_sx.bry.alphabet import CHAR_TO_TOKEN, SORTED_TOKENS, TOKEN_TO_CHAR


class BryEncodingError(ValueError):
    """Raised when plaintext cannot be canonically encoded."""


class BryDecodingError(ValueError):
    """Raised when Bry text cannot be canonically decoded."""


@dataclass(frozen=True)
class BryMessage:
    plaintext: str
    canonical_bry: str


def normalize_plaintext(text: str) -> str:
    """
    Canonicalize plaintext into the current Bry v1 domain.

    Rules:
    - convert to uppercase
    - convert tabs/newlines/carriage returns to spaces
    - preserve repeated spaces
    - reject unsupported characters
    """
    out: list[str] = []

    for ch in text:
        if ch in "\t\r\n":
            out.append(" ")
            continue

        up = ch.upper()
        if up in CHAR_TO_TOKEN:
            out.append(up)
            continue

        raise BryEncodingError(
            f"Unsupported character {ch!r}. "
            "Bry v1 currently supports A-Z, space, . , ? ! and apostrophe."
        )

    return "".join(out)


def encode_to_bry(text: str) -> str:
    normalized = normalize_plaintext(text)
    return "".join(CHAR_TO_TOKEN[ch] for ch in normalized)


def decode_from_bry(code: str) -> str:
    """
    Decode Bry using strict longest-match parsing.

    Non-token whitespace is ignored for human readability, but canonical
    output never emits raw whitespace.
    """
    compact = "".join(ch for ch in code if not ch.isspace())
    out: list[str] = []
    i = 0

    while i < len(compact):
        matched = False

        for token in SORTED_TOKENS:
            if compact.startswith(token, i):
                out.append(TOKEN_TO_CHAR[token])
                i += len(token)
                matched = True
                break

        if not matched:
            raise BryDecodingError(
                f"Invalid Bry stream near position {i}: {compact[i:i+12]!r}"
            )

    return "".join(out)


def roundtrip(text: str) -> BryMessage:
    canonical_plaintext = normalize_plaintext(text)
    canonical_bry = encode_to_bry(canonical_plaintext)
    decoded = decode_from_bry(canonical_bry)

    if decoded != canonical_plaintext:
        raise AssertionError(
            "Roundtrip invariant failed. "
            f"decoded={decoded!r}, expected={canonical_plaintext!r}"
        )

    return BryMessage(
        plaintext=canonical_plaintext,
        canonical_bry=canonical_bry,
    )
