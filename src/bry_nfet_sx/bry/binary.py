from __future__ import annotations

from bry_nfet_sx.bry.alphabet import TOKEN_TO_CHAR
from bry_nfet_sx.bry.tokens import parse_bry_input, render_human_bry, untokenize_bry
from bry_nfet_sx.bry.canonical import BryDecodingError

TOKEN_ORDER: tuple[str, ...] = tuple(TOKEN_TO_CHAR.keys())
TOKEN_TO_ID: dict[str, int] = {token: idx for idx, token in enumerate(TOKEN_ORDER)}
ID_TO_TOKEN: dict[int, str] = {idx: token for token, idx in TOKEN_TO_ID.items()}


def tokens_to_bytes(tokens: list[str]) -> bytes:
    invalid = [tok for tok in tokens if tok not in TOKEN_TO_ID]
    if invalid:
        raise BryDecodingError(f"Unknown tokens for binary serialization: {invalid!r}")
    return bytes(TOKEN_TO_ID[tok] for tok in tokens)


def bytes_to_tokens(data: bytes) -> list[str]:
    out: list[str] = []
    invalid: list[int] = []

    for value in data:
        token = ID_TO_TOKEN.get(value)
        if token is None:
            invalid.append(value)
        else:
            out.append(token)

    if invalid:
        raise BryDecodingError(f"Unknown token IDs in binary payload: {invalid!r}")

    return out


def bry_text_to_token_bytes(text: str) -> bytes:
    tokens = parse_bry_input(text)
    return tokens_to_bytes(tokens)


def token_bytes_to_human_bry(data: bytes) -> str:
    return render_human_bry(bytes_to_tokens(data))


def token_bytes_to_compact_bry(data: bytes) -> str:
    return untokenize_bry(bytes_to_tokens(data))
