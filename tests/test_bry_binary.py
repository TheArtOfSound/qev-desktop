from __future__ import annotations

from bry_nfet_sx.bry import bytes_to_tokens, parse_bry_input, render_human_bry, tokens_to_bytes


def test_binary_token_roundtrip() -> None:
    tokens = parse_bry_input("+3|++5|-|+4|1|+3|5|--p")
    data = tokens_to_bytes(tokens)
    recovered = bytes_to_tokens(data)

    assert recovered == tokens
    assert render_human_bry(recovered) == "+3|++5|-|+4|1|+3|5|--p"
