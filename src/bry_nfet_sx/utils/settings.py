from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class LabSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="BRY_NFET_SX_",
        env_file=".env",
        extra="ignore",
    )

    state_bytes: int = Field(default=32, ge=16, le=64)
    transform_bucket_count: int = Field(default=16, ge=4, le=256)
    dummy_insertion_modulus: int = Field(default=7, ge=2, le=64)
    dashboard_title: str = "BRY-NFET-SX Local Lab"


settings = LabSettings()
