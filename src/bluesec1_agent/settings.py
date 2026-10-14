from pathlib import Path
from typing import Literal, Self

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_ENV_FILE = Path(__file__).resolve().parents[2] / ".env"


class Settings(BaseSettings):
    """Scenario-runtime and OpenAI-compatible provider settings."""

    model_config = SettingsConfigDict(
        env_file=_ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    scenario_runtime_endpoint: str = Field(
        default="127.0.0.1:50051",
        validation_alias="SCENARIO_RUNTIME_ENDPOINT",
        min_length=1,
    )
    scenario_runtime_token: SecretStr = Field(
        validation_alias="SCENARIO_RUNTIME_TOKEN",
        min_length=1,
    )
    scenario_runtime_verify_tls: bool = Field(
        default=True,
        validation_alias="SCENARIO_RUNTIME_VERIFY_TLS",
    )
    scenario_runtime_arena: str | None = Field(
        default=None,
        validation_alias="SCENARIO_RUNTIME_ARENA",
        min_length=1,
        max_length=64,
    )
    remote_run_label: str = Field(
        default="bluesec1-agent",
        validation_alias="REMOTE_RUN_LABEL",
        min_length=1,
    )
    agent_name: str = Field(
        default="bluesec1-agent",
        validation_alias="AGENT_NAME",
        min_length=1,
        max_length=255,
    )

    llm_backend: Literal["openai", "codex"] = Field(
        default="openai",
        validation_alias="LLM_BACKEND",
    )
    llm_base_url: str | None = Field(default=None, validation_alias="LLM_BASE_URL", min_length=1)
    llm_api_key: SecretStr | None = Field(
        default=None, validation_alias="LLM_API_KEY", min_length=1
    )
    llm_default_model: str | None = Field(
        default=None, validation_alias="LLM_DEFAULT_MODEL", min_length=1
    )
    codex_reasoning_effort: str | None = Field(
        default="low",
        validation_alias="CODEX_REASONING_EFFORT",
        min_length=1,
    )
    llm_timeout_seconds: float = Field(
        default=120.0,
        validation_alias="LLM_TIMEOUT_SECONDS",
        gt=0,
    )
    llm_max_completion_tokens: int = Field(
        default=16_384,
        validation_alias="LLM_MAX_COMPLETION_TOKENS",
        gt=0,
    )
    llm_max_step_retries: int = Field(
        default=3,
        validation_alias="LLM_MAX_STEP_RETRIES",
        ge=1,
        le=5,
    )
    typesafe_api_key: SecretStr | None = Field(
        default=None,
        validation_alias="TYPESAFE_API_KEY",
    )
    typesafe_model: str | None = Field(
        default=None,
        validation_alias="TYPESAFE_MODEL",
        min_length=1,
    )
    agent_max_assessments: int = Field(
        default=4,
        validation_alias="BLUESEC_AGENT_MAX_ASSESSMENTS",
        ge=0,
    )
    agent_max_steps: int = Field(
        default=100,
        validation_alias="BLUESEC_AGENT_MAX_STEPS",
        ge=1,
        le=100,
    )

    @model_validator(mode="after")
    def require_openai_credentials(self) -> Self:
        """Require provider settings only for the OpenAI-compatible backend."""
        if self.llm_backend == "openai":
            missing = [
                name
                for name, value in (
                    ("LLM_BASE_URL", self.llm_base_url),
                    ("LLM_API_KEY", self.llm_api_key),
                    ("LLM_DEFAULT_MODEL", self.llm_default_model),
                )
                if value is None
            ]
            if missing:
                raise ValueError(f"LLM_BACKEND=openai requires {', '.join(missing)}")
        return self
