"""
XScan Settings
==============
Loaded once at startup. Sources (highest → lowest priority):
  1. Environment variables  (XSCAN_*)
  2. ~/.xscan/config.toml
  3. Defaults in this file

Uses pydantic-settings for env-var binding and validation.
"""
from __future__ import annotations

import functools
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from xscan.config.defaults import (
    CONFIG_FILE,
    DB_PATH,
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_LLM_MODEL,
    DEFAULT_LLM_TIMEOUT,
    DEFAULT_PROFILE,
    LOG_DIR,
    OLLAMA_BASE_URL,
    XSCAN_HOME,
)

Profile = Literal["fast", "balanced", "deep"]


class LLMSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="XSCAN_LLM_", extra="ignore")

    model: str = DEFAULT_LLM_MODEL
    provider: str = "ollama"
    base_url: str = OLLAMA_BASE_URL
    timeout: int = DEFAULT_LLM_TIMEOUT
    temperature: float = 0.1
    max_tokens: int = 2048


class StorageSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="XSCAN_STORAGE_", extra="ignore")

    db_path: Path = DB_PATH
    log_dir: Path = LOG_DIR


class ScanSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="XSCAN_SCAN_", extra="ignore")

    default_profile: Profile = DEFAULT_PROFILE  # type: ignore[assignment]
    http_timeout: int = DEFAULT_HTTP_TIMEOUT
    verify_ssl: bool = False
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/125.0.0.0 Safari/537.36"
    )


class RuntimeSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="XSCAN_RUNTIME_", extra="ignore")

    # "windows" | "linux" | "wsl" — auto-detected if not set
    execution_env: str | None = None
    wsl_distro: str = "Ubuntu"
    xscan_bin_dir: Path = XSCAN_HOME / "bin"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="XSCAN_",
        env_nested_delimiter="__",
        extra="ignore",
        case_sensitive=False,
    )

    xscan_home: Path = XSCAN_HOME
    debug: bool = False
    telemetry_enabled: bool = False

    llm: LLMSettings = Field(default_factory=LLMSettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    scan: ScanSettings = Field(default_factory=ScanSettings)
    runtime: RuntimeSettings = Field(default_factory=RuntimeSettings)

    @field_validator("xscan_home", mode="before")
    @classmethod
    def expand_home(cls, v: object) -> Path:
        return Path(str(v)).expanduser()

    @model_validator(mode="after")
    def _load_toml_overrides(self) -> Settings:
        """Merge ~/.xscan/config.toml on top of env/defaults."""
        if CONFIG_FILE.exists():
            try:
                import tomllib  # Python 3.11+
            except ImportError:
                try:
                    import tomli as tomllib  # type: ignore[no-redef]
                except ImportError:
                    return self

            with open(CONFIG_FILE, "rb") as f:
                data = tomllib.load(f)

            llm_data = data.get("llm", {})
            if llm_data:
                for k, v in llm_data.items():
                    if hasattr(self.llm, k):
                        object.__setattr__(self.llm, k, v)

        return self


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the singleton Settings instance."""
    return Settings()
