from __future__ import annotations

import pytest

from bry_nfet_sx.bry import (
    BryDecodingError,
    BryEncodingError,
    decode_from_bry,
    encode_to_bry,
    normalize_plaintext,
    roundtrip,
)


def test_roundtrip_examples() -> None:
    samples = [
        "MY NAME IS BRYAN.",
        "WHAT'S UP?",
        "GOOD MORNING, BRYAN!",
    ]

    for sample in samples:
        msg = roundtrip(sample)
        assert msg.plaintext == normalize_plaintext(sample)
        assert decode_from_bry(msg.canonical_bry) == normalize_plaintext(sample)


def test_longest_match_for_z() -> None:
    assert encode_to_bry("Z") == "++6"
    assert decode_from_bry("++6") == "Z"


def test_whitespace_is_ignored_on_decode() -> None:
    encoded = encode_to_bry("HI")
    spaced = " ".join(encoded)
    assert decode_from_bry(spaced) == "HI"


def test_reject_unsupported_character() -> None:
    with pytest.raises(BryEncodingError):
        encode_to_bry("HELLO🙂")


def test_reject_invalid_bry_stream() -> None:
    with pytest.raises(BryDecodingError):
        decode_from_bry("@@@")
