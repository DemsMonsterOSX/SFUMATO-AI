"""Central configuration loaded from environment variables (and `.env`)."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]


def _default_repo_dir() -> Path:
    # In the container the repo content is copied under /srv; locally it is the parent of backend/.
    candidate = BACKEND_DIR.parent
    return candidate if (candidate / "examples").exists() else BACKEND_DIR


class Settings(BaseSettings):
    # Later files win: backend/.env (local development) overrides the repository .env used by Docker.
    model_config = SettingsConfigDict(env_file=("../.env", ".env"), extra="ignore", case_sensitive=False)

    app_name: str = "Sfumato Autonomous SOC"
    app_version: str = "1.0.0"
    environment: Literal["development", "production", "test"] = "development"
    deployment_mode: Literal["lite", "full"] = "lite"

    # Persistence
    database_url: str = "sqlite:///./sfumato.db"
    redis_url: str | None = None

    # Security
    api_keys: str = "sfumato-dev-key-change-me"
    secret_key: str = "change-this-secret-key-for-credential-encryption"
    max_request_bytes: int = 256 * 1024
    rate_limit_per_minute: int = 120
    cors_origins: str = "http://localhost:3000"

    # Workers
    embedded_worker: bool = True
    worker_concurrency: int = 2
    worker_poll_interval: float = 0.5
    job_stale_after_seconds: int = 300
    max_job_attempts: int = 3

    # Threat intelligence
    cti_mode: Literal["live", "demo"] = "demo"
    cti_timeout_seconds: float = 8.0
    cti_max_retries: int = 2
    cti_cache_ttl_seconds: int = 3600
    abusech_auth_key: str | None = None
    otx_api_key: str | None = None
    opencti_url: str | None = None
    opencti_token: str | None = None
    cisa_kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    internal_domain_suffixes: str = ".local,.lan,.corp,.internal,.intranet,.home.arpa,.localdomain"

    # AI investigator
    ai_provider: Literal["auto", "anthropic", "openai", "ollama", "deterministic"] = "auto"
    ai_timeout_seconds: float = 180.0
    ai_max_concurrency: int = 1  # a single local GPU serves one generation at a time
    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-sonnet-5-5"
    openai_api_key: str | None = None
    openai_base_url: str = "https://api.openai.com/v1"
    openai_model: str = "gpt-4o-mini"
    ollama_url: str | None = None
    ollama_model: str = "qwen2.5:7b-instruct"
    ai_allow_external: bool = False  # must be explicitly enabled to send (redacted) data to an external LLM

    # Knowledge base (RAG) built from the Hugging Face dataset by ml/knowledge/build_kb.py
    kb_enabled: bool = True
    kb_hf_repo: str | None = None  # private HF dataset repo holding the built knowledge base
    kb_hf_revision: str = "main"
    kb_local_path: str | None = None  # alternatively: a local folder containing a built knowledge base
    kb_dir: str = Field(default_factory=lambda: str(_default_repo_dir() / "ml" / "knowledge_base"))
    kb_model_cache: str | None = None  # fastembed model cache (pre-filled in the Docker image)
    kb_embed_model: str = "BAAI/bge-small-en-v1.5"
    kb_store: Literal["auto", "pgvector", "memory"] = "auto"
    kb_top_k: int = 5
    kb_min_score: float = 0.55
    hf_token: str | None = None
    kb_artifact_uri: str | None = None  # gs://bucket/prefix (or hf://, folder): knowledge base published by build_kb.py

    # Reference triage model trained on Microsoft GUIDE, served from a bucket
    ml_artifact_uri: str | None = None  # gs://bucket/prefix | hf://user/repo | local folder
    ml_artifact_name: str = "guide_triage"
    ml_artifact_require_signature: bool = True  # remote artifacts are pickles: verify HMAC + sha256
    artifact_signing_key: str | None = None
    google_application_credentials: str | None = None  # path to a read-only service-account key (GCS)

    # Machine learning
    ml_model_dir: str = Field(default_factory=lambda: str(_default_repo_dir() / "ml" / "models"))
    ml_eval_dir: str = Field(default_factory=lambda: str(_default_repo_dir() / "ml" / "evaluation"))
    ml_auto_train: bool = True

    # Content
    repo_dir: str = Field(default_factory=lambda: str(_default_repo_dir()))
    seed_demo_incidents: bool = True

    @field_validator("redis_url", "abusech_auth_key", "otx_api_key", "opencti_url", "opencti_token",
                     "anthropic_api_key", "openai_api_key", "ollama_url", "kb_hf_repo", "kb_local_path",
                     "kb_model_cache", "hf_token", "kb_artifact_uri", "ml_artifact_uri", "artifact_signing_key",
                     "google_application_credentials", mode="before")
    @classmethod
    def _empty_to_none(cls, v):
        if isinstance(v, str) and not v.strip():
            return None
        return v

    @property
    def api_key_list(self) -> list[str]:
        return [k.strip() for k in self.api_keys.split(",") if k.strip()]

    @property
    def internal_suffixes(self) -> list[str]:
        return [s.strip().lower() for s in self.internal_domain_suffixes.split(",") if s.strip()]

    @property
    def examples_dir(self) -> Path:
        return Path(self.repo_dir) / "examples"

    @property
    def playbooks_dir(self) -> Path:
        return Path(self.repo_dir) / "playbooks"

    @property
    def config_dir(self) -> Path:
        return Path(self.repo_dir) / "config"


@lru_cache
def get_settings() -> Settings:
    return Settings()
