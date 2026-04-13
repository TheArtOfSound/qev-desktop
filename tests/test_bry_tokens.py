from __future__ import annotations

from bry_nfet_sx.bry import encode_to_bry, plaintext_to_bry_tokens, tokenize_bry, untokenize_bry


def test_tokenize_and_untokenize() -> None:
    code = encode_to_bry("MY NAME.")
    tokens = tokenize_bry(code)
    assert untokenize_bry(tokens) == code


def test_plaintext_to_bry_tokens() -> None:
    tokens = plaintext_to_bry_tokens("HI!")
    assert tokens == ["8", "9", "--e"]
