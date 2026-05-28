"""Global configuration and engagement scope definitions.

``ScopeConfig`` is the single source of truth for what HYDRA is authorized to
touch. It is consumed by ``hydra.utils.scope.ScopeValidator`` and enforced at
the HTTP-client level so that no module can send a request out of scope.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from hydra.core.schemas import Aggressiveness

DEFAULT_WEB_PORTS: tuple[int, ...] = (80, 443)


class ScopeConfig(BaseModel):
    """Defines the authorized testing boundary for an engagement.

    Anything not explicitly permitted here is denied. This is a deny-by-default
    safety boundary — do not weaken it.
    """

    domains: list[str] = Field(
        default_factory=list,
        description="Exact ('api.target.com') or wildcard ('*.target.com') host patterns.",
    )
    ip_ranges: list[str] = Field(
        default_factory=list,
        description="CIDR ranges authorized for IP-based targets, e.g. '192.168.1.0/24'.",
    )
    ports: list[int] = Field(
        default_factory=lambda: list(DEFAULT_WEB_PORTS),
        description="Whitelisted ports. Empty list means 'any port'.",
    )
    exclude_paths: list[str] = Field(
        default_factory=list,
        description="Regex patterns for paths that must never be requested.",
    )
    block_third_party: bool = Field(
        default=True,
        description="Flag/deny requests to hosts not matching the scope (CDNs, analytics).",
    )

    @field_validator("domains", mode="after")
    @classmethod
    def _normalize_domains(cls, v: list[str]) -> list[str]:
        return [d.strip().lower().rstrip(".") for d in v if d.strip()]

    @classmethod
    def auto_from_target(cls, target: str, include_subdomains: bool = True) -> ScopeConfig:
        """Derive a minimal scope from a single target URL.

        Authorizes the exact host (and its subdomains when requested), honoring
        an explicit port and routing IP-literal targets to ``ip_ranges``. Used
        for ``--scope auto``; a real engagement should pass an explicit scope.
        """
        parts = urlsplit(target if "://" in target else f"//{target}")
        host = (parts.hostname or target).lower().rstrip(".")

        domains: list[str] = []
        ip_ranges: list[str] = []
        try:
            ip = ipaddress.ip_address(host)
            ip_ranges.append(f"{host}/{ip.max_prefixlen}")
        except ValueError:
            domains.append(host)
            if include_subdomains and host.count(".") >= 1:
                domains.append(f"*.{host}")

        if parts.port:
            ports = [parts.port]
        elif parts.scheme == "https":
            ports = [443]
        elif parts.scheme == "http":
            ports = [80]
        else:
            ports = list(DEFAULT_WEB_PORTS)

        return cls(domains=domains, ip_ranges=ip_ranges, ports=ports)


class RateLimitConfig(BaseModel):
    requests_per_second: float = 50.0
    burst: int = 10
    jitter: float = Field(default=0.0, description="Random 0..jitter seconds added per request.")


class ScanConfig(BaseModel):
    """Full configuration for a single scan run, populated from the CLI."""

    scan_id: str | None = None
    target: str
    scope: ScopeConfig
    modules: list[str] = Field(default_factory=lambda: ["all"])
    aggressiveness: Aggressiveness = Aggressiveness.NORMAL

    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    crawl_depth: int = 10
    max_pages: int = 5000
    timeout: float = 30.0
    concurrency: int = 10

    proxy: str | None = None
    user_agent: str = "random"
    extra_headers: dict[str, str] = Field(default_factory=dict)

    auth_cookie: str | None = None
    auth_script: str | None = None

    callback: str | None = None
    no_exploit: bool = False
    verify_tls: bool = False  # pentest default: tolerate self-signed/expired certs

    output: str = "hydra_report"
    report_format: str = "html"


class Settings(BaseSettings):
    """Process-wide settings sourced from environment / .env file.

    Secrets (API keys) and infra endpoints live here, never in ScanConfig.
    """

    model_config = SettingsConfigDict(env_prefix="HYDRA_", env_file=".env", extra="ignore")

    db_url: str = "sqlite+aiosqlite:///./hydra.sqlite3"
    data_dir: str = "./scan_data"
    log_level: str = "info"

    # Deferred external-integration credentials (optional until those modules land).
    shodan_api_key: str | None = None
    censys_api_id: str | None = None
    censys_api_secret: str | None = None
    virustotal_api_key: str | None = None
    nvd_api_key: str | None = None
    github_token: str | None = None


def get_settings() -> Settings:
    return Settings()


__all__ = ["ScopeConfig", "RateLimitConfig", "ScanConfig", "Settings", "get_settings"]
