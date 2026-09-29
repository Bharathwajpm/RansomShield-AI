"""
RansomShield AI — Backend Configuration Settings
Phase 3A: Backend Foundation

Defines strongly typed application settings using Pydantic Settings v2.
"""

from typing import List, Optional, Union
from functools import lru_cache
from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application configuration loaded from environment variables and .env file.
    """
    app_name: str = "RansomShield AI Backend"
    app_version: str = "0.1.0"
    environment: str = "development"
    debug: bool = False
    host: str = "0.0.0.0"
    port: int = 8000
    api_v1_prefix: str = "/api/v1"
    log_level: str = "INFO"

    # Database Settings (MongoDB)
    database_backend: str = "auto"  # "auto", "mongodb", "memory"
    mongodb_uri: Optional[str] = None
    mongodb_database: str = "ransomshield_db"
    mongodb_server_selection_timeout_ms: int = 2000
    mongodb_connect_timeout_ms: int = 2000

    # CORS Settings
    cors_origins: Union[List[str], str] = [
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:5175",
        "http://localhost:3000",
        "http://localhost:4173",
        "http://localhost:8080",
        "http://localhost:8000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
        "http://127.0.0.1:5175",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:4173",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:8000",
        "http://10.243.216.187:8080",
        "http://10.243.216.187:8000",
        "http://10.243.216.187:5173",
        "http://10.243.216.187:4173",
        "http://10.243.216.187:3000",
    ]

    # Authentication & Security Settings
    jwt_secret_key: str = "ransomshield-super-secret-jwt-key-change-in-production"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 480
    agent_api_key: str = "rs-agent-secret-key-prod"
    enforce_agent_auth_in_test: bool = False

    # Agent & Record Limits
    agent_heartbeat_timeout_seconds: int = 60
    max_in_memory_records: int = 1000

    # Phase 4: Defensive Response & Containment
    response_dry_run: bool = True
    require_two_person_approval: bool = True
    quarantine_directory: str = "data/quarantine"

    # Phase 5: Production Hardening & Resource Limits
    rate_limit_enabled: bool = True
    rate_limit_general_per_minute: int = 120
    rate_limit_auth_per_minute: int = 10
    rate_limit_response_per_minute: int = 30
    max_request_body_bytes: int = 10 * 1024 * 1024  # 10 MB

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    @model_validator(mode="after")
    def validate_production_security(self) -> "Settings":
        """Enforces enterprise security guardrails when running in production environment."""
        if self.environment.lower() == "production":
            if (
                self.jwt_secret_key == "ransomshield-super-secret-jwt-key-change-in-production"
                or len(self.jwt_secret_key) < 32
            ):
                raise ValueError(
                    "Production security failure: JWT_SECRET_KEY must be explicitly set to a high-entropy secret with at least 32 characters."
                )
            if (
                self.agent_api_key == "rs-agent-secret-key-prod"
                or len(self.agent_api_key) < 16
            ):
                raise ValueError(
                    "Production security failure: AGENT_API_KEY must be configured with at least 16 characters in production."
                )
            if any(origin == "*" for origin in self.cors_origins):
                raise ValueError(
                    "Production security failure: Wildcard origin '*' in CORS_ORIGINS is strictly prohibited in production."
                )
        return self

    def __repr__(self) -> str:
        """Sanitized string representation masking sensitive secrets."""
        return (
            f"Settings(app_name='{self.app_name}', env='{self.environment}', "
            f"database='{self.database_backend}', jwt_secret='***', agent_key='***')"
        )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache()
def get_settings() -> Settings:
    """Returns cached application settings instance."""
    return Settings()
