from __future__ import annotations

from bry_nfet_sx.bry import (
    canonicalize_bry_input,
    parse_bry_input,
    render_human_bry,
)


def test_compact_and_human_forms_canonicalize_to_same_stream() -> None:
    compact = "+3++5-+41+35-9+9-2+8++51+4--p"
    human = "+3|++5|-|+4|1|+3|5|-|9|+9|-|2|+8|++5|1|+4|--p"

    assert canonicalize_bry_input(compact) == canonicalize_bry_input(human)


def test_render_human_bry_is_reversible() -> None:
    tokens = ["+3", "++5", "-", "+4", "1", "--p"]
    human = render_human_bry(tokens)

    assert human == "+3|++5|-|+4|1|--p"
    assert parse_bry_input(human) == tokens
