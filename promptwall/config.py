"""Configuration, loaded from the environment (and optionally a .env file).

Hand-rolled rather than pydantic-settings so the only hard dependency is
pydantic itself. Validation is strict: a bad value fails at startup rather
than at the first request that happens to touch it.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator
from pydantic import ValidationError as PydanticValidationError

from .constants import FailMode, Mode
from .exceptions import ConfigError

ENV_PREFIX = "PW_"
_TRUE = {"1", "true", "yes", "on", "t", "y"}
_FALSE = {"0", "false", "no", "off", "f", "n"}


def _env(key: str, default: Any = None) -> Any:
    return os.environ.get(ENV_PREFIX + key, default)


def _env_bool(key: str, default: bool) -> bool:
    raw = _env(key)
    if raw is None or raw == "":
        return default
    low = str(raw).strip().lower()
    if low in _TRUE:
        return True
    if low in _FALSE:
        return False
    raise ConfigError(f"{ENV_PREFIX}{key} must be a boolean, got {raw!r}")


def _env_num(key: str, default: float, cast: type) -> Any:
    raw = _env(key)
    if raw is None or raw == "":
        return default
    try:
        return cast(raw)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{ENV_PREFIX}{key} must be a number, got {raw!r}") from exc


def _env_list(key: str, default: list[str] | None = None) -> list[str]:
    raw = _env(key)
    if raw is None or str(raw).strip() == "":
        return list(default or [])
    return [item.strip() for item in str(raw).split(",") if item.strip()]


def load_dotenv(path: str | Path = ".env", *, override: bool = False) -> int:
    """Minimal .env loader. Returns the number of keys applied.

    Deliberately tiny: KEY=value lines, hash comments, optional quotes.
    Existing environment variables win unless override is set, so a real
    deployment secrets manager is never clobbered by a stray file.
    """
    p = Path(path)
    if not p.is_file():
        return 0
    applied = 0
    for raw_line in p.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and (override or key not in os.environ):
            os.environ[key] = value
            applied += 1
    return applied


class UpstreamConfig(BaseModel):
    provider: str = "openai_compat"
    base_url: str = "https://api.openai.com/v1"
    api_key: str = ""
    timeout_s: float = Field(default=60.0, gt=0)
    max_retries: int = Field(default=2, ge=0, le=5)

    @field_validator("provider")
    @classmethod
    def _known_provider(cls, v: str) -> str:
        allowed = {"openai_compat", "anthropic", "echo"}
        if v not in allowed:
            raise ValueError(f"provider must be one of {sorted(allowed)}")
        return v

    @field_validator("base_url")
    @classmethod
    def _strip_slash(cls, v: str) -> str:
        return v.rstrip("/")


class JudgeConfig(BaseModel):
    """The L3 LLM judge. Off by default: it costs money and adds latency."""

    enabled: bool = False
    model: str = "gpt-4o-mini"
    base_url: str = ""
    api_key: str = ""
    max_input_chars: int = Field(default=6000, gt=0)
    min_score: float = Field(default=0.55, ge=0.0, le=1.0)
    max_score: float = Field(default=0.90, ge=0.0, le=1.0)


class ClassifierConfig(BaseModel):
    model_config = {"protected_namespaces": ()}

    enabled: bool = True
    model_path: str = "models/artifacts/classifier.onnx"
    # When the ONNX artifact is missing we fall back to the built-in feature
    # scorer rather than failing. Set false to make a missing model fatal.
    allow_fallback: bool = True


class ThresholdConfig(BaseModel):
    block: float = Field(default=0.90, ge=0.0, le=1.0)
    review: float = Field(default=0.55, ge=0.0, le=1.0)

    @field_validator("review")
    @classmethod
    def _ordered(cls, v: float, info: Any) -> float:
        block = info.data.get("block")
        if block is not None and v > block:
            raise ValueError("review threshold must be <= block threshold")
        return v


class BudgetConfig(BaseModel):
    input_ms: float = Field(default=120.0, gt=0)
    output_ms: float = Field(default=80.0, gt=0)
    judge_ms: float = Field(default=2500.0, gt=0)


class SessionConfig(BaseModel):
    backend: str = "memory"
    redis_url: str = "redis://localhost:6379/0"
    ttl_s: int = Field(default=3600, gt=0)
    max_turns: int = Field(default=200, gt=0)

    @field_validator("backend")
    @classmethod
    def _known_backend(cls, v: str) -> str:
        if v not in {"memory", "redis"}:
            raise ValueError("session backend must be memory or redis")
        return v


class TelemetryConfig(BaseModel):
    metrics_enabled: bool = True
    audit_enabled: bool = True
    audit_path: str = "./audit.log"
    # Off by default. The audit log of an LLM gateway is a high-value target
    # and contains user data by definition.
    audit_store_content: bool = False
    audit_hmac_key: str = ""
    tracing_enabled: bool = False
    otlp_endpoint: str = "http://localhost:4318"


class Settings(BaseModel):
    """Root settings object. Build with build_settings()."""

    host: str = "0.0.0.0"
    port: int = Field(default=8080, gt=0, lt=65536)
    log_level: str = "INFO"
    log_format: str = "json"

    mode: Mode = Mode.MONITOR
    fail_mode: FailMode = FailMode.OPEN

    api_keys: list[str] = Field(default_factory=list)
    admin_api_keys: list[str] = Field(default_factory=list)
    auth_required: bool = True

    policy_dir: str = ""
    upstream: UpstreamConfig = Field(default_factory=UpstreamConfig)
    classifier: ClassifierConfig = Field(default_factory=ClassifierConfig)
    judge: JudgeConfig = Field(default_factory=JudgeConfig)
    thresholds: ThresholdConfig = Field(default_factory=ThresholdConfig)
    budgets: BudgetConfig = Field(default_factory=BudgetConfig)
    session: SessionConfig = Field(default_factory=SessionConfig)
    telemetry: TelemetryConfig = Field(default_factory=TelemetryConfig)

    rate_limit_rps: float = Field(default=20.0, gt=0)
    rate_limit_burst: int = Field(default=40, gt=0)
    max_input_chars: int = Field(default=512_000, gt=0)

    @field_validator("log_format")
    @classmethod
    def _known_format(cls, v: str) -> str:
        if v not in {"json", "console"}:
            raise ValueError("log_format must be json or console")
        return v

    @field_validator("log_level")
    @classmethod
    def _known_level(cls, v: str) -> str:
        v = v.upper()
        if v not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("log_level must be a standard logging level name")
        return v

    @property
    def enforcing(self) -> bool:
        return self.mode is Mode.ENFORCE

    @property
    def fail_closed(self) -> bool:
        return self.fail_mode is FailMode.CLOSED

    def redacted(self) -> dict[str, Any]:
        """Config safe to log or serve from /admin/config: secrets stripped."""
        data = self.model_dump(mode="json")
        data["api_keys"] = [fingerprint(k) for k in self.api_keys]
        data["admin_api_keys"] = [fingerprint(k) for k in self.admin_api_keys]
        data["upstream"]["api_key"] = fingerprint(self.upstream.api_key)
        data["judge"]["api_key"] = fingerprint(self.judge.api_key)
        data["telemetry"]["audit_hmac_key"] = fingerprint(self.telemetry.audit_hmac_key)
        return data


def fingerprint(secret: str) -> str:
    """Enough to tell two keys apart in a log, not enough to use one."""
    if not secret:
        return ""
    import hashlib

    return "sha256:" + hashlib.sha256(secret.encode()).hexdigest()[:12]


def build_settings() -> Settings:
    """Read the environment into a Settings. Raises ConfigError on bad input."""
    try:
        settings = Settings(
            host=_env("HOST", "0.0.0.0"),
            port=int(_env_num("PORT", 8080, int)),
            log_level=_env("LOG_LEVEL", "INFO"),
            log_format=_env("LOG_FORMAT", "json"),
            mode=Mode(_env("MODE", "monitor")),
            fail_mode=FailMode(_env("FAIL_MODE", "open")),
            api_keys=_env_list("API_KEYS"),
            admin_api_keys=_env_list("ADMIN_API_KEYS"),
            auth_required=_env_bool("AUTH_REQUIRED", True),
            policy_dir=_env("POLICY_DIR", ""),
            upstream=UpstreamConfig(
                provider=_env("UPSTREAM_PROVIDER", "openai_compat"),
                base_url=_env("UPSTREAM_BASE_URL", "https://api.openai.com/v1"),
                api_key=_env("UPSTREAM_API_KEY", ""),
                timeout_s=_env_num("UPSTREAM_TIMEOUT_S", 60.0, float),
                max_retries=int(_env_num("UPSTREAM_MAX_RETRIES", 2, int)),
            ),
            classifier=ClassifierConfig(
                enabled=_env_bool("L2_ENABLED", True),
                model_path=_env("L2_MODEL_PATH", "models/artifacts/classifier.onnx"),
                allow_fallback=_env_bool("L2_ALLOW_FALLBACK", True),
            ),
            judge=JudgeConfig(
                enabled=_env_bool("L3_ENABLED", False),
                model=_env("L3_MODEL", "gpt-4o-mini"),
                base_url=_env("L3_BASE_URL", ""),
                api_key=_env("L3_API_KEY", ""),
                min_score=_env_num("THRESHOLD_REVIEW", 0.55, float),
                max_score=_env_num("THRESHOLD_BLOCK", 0.90, float),
            ),
            thresholds=ThresholdConfig(
                block=_env_num("THRESHOLD_BLOCK", 0.90, float),
                review=_env_num("THRESHOLD_REVIEW", 0.55, float),
            ),
            budgets=BudgetConfig(
                input_ms=_env_num("BUDGET_INPUT_MS", 120.0, float),
                output_ms=_env_num("BUDGET_OUTPUT_MS", 80.0, float),
                judge_ms=_env_num("BUDGET_JUDGE_MS", 2500.0, float),
            ),
            session=SessionConfig(
                backend=_env("SESSION_BACKEND", "memory"),
                redis_url=_env("REDIS_URL", "redis://localhost:6379/0"),
                ttl_s=int(_env_num("SESSION_TTL_S", 3600, int)),
            ),
            telemetry=TelemetryConfig(
                metrics_enabled=_env_bool("METRICS_ENABLED", True),
                audit_enabled=_env_bool("AUDIT_ENABLED", True),
                audit_path=_env("AUDIT_PATH", "./audit.log"),
                audit_store_content=_env_bool("AUDIT_STORE_CONTENT", False),
                audit_hmac_key=_env("AUDIT_HMAC_KEY", ""),
                tracing_enabled=_env_bool("TRACING_ENABLED", False),
                otlp_endpoint=_env("OTLP_ENDPOINT", "http://localhost:4318"),
            ),
            rate_limit_rps=_env_num("RATE_LIMIT_RPS", 20.0, float),
            rate_limit_burst=int(_env_num("RATE_LIMIT_BURST", 40, int)),
            max_input_chars=int(_env_num("MAX_INPUT_CHARS", 512_000, int)),
        )
    except PydanticValidationError as exc:
        raise ConfigError(f"invalid configuration: {exc}") from exc
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc

    if settings.auth_required and not settings.api_keys:
        raise ConfigError(
            "PW_AUTH_REQUIRED is true but PW_API_KEYS is empty. Set PW_API_KEYS, "
            "or set PW_AUTH_REQUIRED=false for local development."
        )
    return settings


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings singleton."""
    return build_settings()


def reset_settings_cache() -> None:
    """Drop the singleton. Used by tests and the admin config-reload path."""
    get_settings.cache_clear()
