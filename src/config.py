"""Service configuration, read from environment variables prefixed ``POLARYS_`` (or a ``.env`` file)."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="POLARYS_", env_file=".env", extra="ignore")

    # Ledger
    database_url: str = Field("sqlite:///polarys-ledger.db", description="postgresql://… (production) or sqlite:///path (development)")
    db_pool_size: int = 8

    # Keys
    keystore_dir: Path = Path("keystore")
    key_passphrase: SecretStr | None = None
    key_passphrase_file: Path | None = None

    # Object store
    store: Literal["local", "s3"] = "local"
    local_store_dir: Path = Path("objects")
    spool_dir: Path | None = Path("spool")
    s3_bucket: str | None = None
    s3_region: str = "us-east-1"
    s3_endpoint_url: str | None = None
    s3_access_key_id: str | None = None
    s3_secret_access_key: SecretStr | None = None
    s3_session_token: str | None = None
    s3_prefix: str = ""
    s3_path_style: bool | None = None
    s3_object_lock: bool = True

    # Limits
    max_record_bytes: int = 1 << 20  # one log record's payload
    max_submission_bytes: int = 50 << 20  # all documents of one business submission
    max_request_bytes: int = 64 << 20
    max_batch: int = 1000
    tx_batch: int = 500

    # HTTP
    host: str = "127.0.0.1"
    port: int = 8080
    public_base_url: str | None = None
    trusted_proxies: list[str] = Field(default_factory=list, description="CIDRs whose X-Forwarded-For is trusted")
    client_cache_seconds: float = 30.0

    # Sealer
    seal_interval_seconds: int = Field(300, description="block interval; boundaries are multiples of this since midnight UTC")
    restamp_after_seconds: int = 120
    max_clock_skew_seconds: int = 60
    tsa_mode: Literal["public", "dev"] = "public"
    tsa_urls: list[str] = Field(default_factory=list, description='override the TSA order, e.g. ["Sectigo=http://timestamp.sectigo.com"]')
    tsa_attempts_per_tsa: int = 2
    tsa_timeout_seconds: float = 10.0
    tsa_trust_roots: Path | None = Field(None, description="PEM bundle of TSA root certificates to verify token chains")
    dev_tsa_dir: Path = Path("dev-tsa")

    # Receipt webhooks
    webhook_timeout_seconds: float = 10.0
    webhook_retry_hours: float = 24.0
    allow_http_webhooks: bool = False

    @model_validator(mode="after")
    def _check(self):
        if self.store == "s3" and not self.s3_bucket:
            raise ValueError("POLARYS_S3_BUCKET is required when POLARYS_STORE=s3")
        if self.tx_batch < 1 or self.max_batch < 1:
            raise ValueError("batch sizes must be positive")
        if self.seal_interval_seconds < 10 or 86400 % self.seal_interval_seconds:
            raise ValueError("POLARYS_SEAL_INTERVAL_SECONDS must divide a day evenly and be at least 10")
        return self

    def passphrase(self) -> str:
        if self.key_passphrase:
            return self.key_passphrase.get_secret_value()
        if self.key_passphrase_file:
            return self.key_passphrase_file.read_text().rstrip("\n")
        raise ValueError("set POLARYS_KEY_PASSPHRASE or POLARYS_KEY_PASSPHRASE_FILE to unlock the keystore")
