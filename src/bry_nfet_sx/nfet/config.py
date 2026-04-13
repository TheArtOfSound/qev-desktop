from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class NFETConfig:
    state_bytes: int = 32
    transform_bucket_count: int = 16
    dummy_insertion_modulus: int = 7

    def validate(self) -> None:
        if not (16 <= self.state_bytes <= 64):
            raise ValueError("state_bytes must be between 16 and 64")
        if not (4 <= self.transform_bucket_count <= 256):
            raise ValueError("transform_bucket_count must be between 4 and 256")
        if not (2 <= self.dummy_insertion_modulus <= 64):
            raise ValueError("dummy_insertion_modulus must be between 2 and 64")
