from __future__ import annotations

TOKEN_TO_CHAR: dict[str, str] = {
    "1": "A",
    "2": "B",
    "3": "C",
    "4": "D",
    "5": "E",
    "6": "F",
    "7": "G",
    "8": "H",
    "9": "I",
    "+": "J",
    "+1": "K",
    "+2": "L",
    "+3": "M",
    "+4": "N",
    "+5": "O",
    "+6": "P",
    "+7": "Q",
    "+8": "R",
    "+9": "S",
    "++": "T",
    "++1": "U",
    "++2": "V",
    "++3": "W",
    "++4": "X",
    "++5": "Y",
    "++6": "Z",
    "-": " ",
    "--p": ".",
    "--c": ",",
    "--q": "?",
    "--e": "!",
    "--a": "'",
}

CHAR_TO_TOKEN: dict[str, str] = {char: token for token, char in TOKEN_TO_CHAR.items()}

# Longest-match is mandatory because tokens overlap heavily.
SORTED_TOKENS: tuple[str, ...] = tuple(
    sorted(TOKEN_TO_CHAR.keys(), key=len, reverse=True)
)

SUPPORTED_CHARS: tuple[str, ...] = tuple(CHAR_TO_TOKEN.keys())
