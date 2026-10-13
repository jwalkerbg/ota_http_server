"""SSL configuration and database driver mapping for MySQL and PostgreSQL."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping


class SSLMode(StrEnum):
    DISABLED = "disabled"
    PREFER = "prefer"
    REQUIRED = "required"
    VERIFY_CA = "verify_ca"
    VERIFY_FULL = "verify_full"


# Normalization aliases map user inputs (e.g. kebab-case or postgres/mysql naming)
# to canonical SSLMode values.
_SSL_MODE_ALIASES: dict[str, SSLMode] = {
    "disabled": SSLMode.DISABLED,
    "disable": SSLMode.DISABLED,
    "off": SSLMode.DISABLED,
    "false": SSLMode.DISABLED,
    "none": SSLMode.DISABLED,
    "prefer": SSLMode.PREFER,
    "preferred": SSLMode.PREFER,
    "required": SSLMode.REQUIRED,
    "require": SSLMode.REQUIRED,
    "on": SSLMode.REQUIRED,
    "true": SSLMode.REQUIRED,
    "verify_ca": SSLMode.VERIFY_CA,
    "verify-ca": SSLMode.VERIFY_CA,
    "verify_identity": SSLMode.VERIFY_FULL,
    "verify-identity": SSLMode.VERIFY_FULL,
    "verify_full": SSLMode.VERIFY_FULL,
    "verify-full": SSLMode.VERIFY_FULL,
}


def normalize_ssl_mode(mode: str | SSLMode | None) -> SSLMode:
    """Normalize input string to canonical SSLMode."""
    if mode is None:
        return SSLMode.DISABLED
    if isinstance(mode, SSLMode):
        return mode
    cleaned = str(mode).strip().lower()
    if not cleaned:
        return SSLMode.DISABLED
    if cleaned in _SSL_MODE_ALIASES:
        return _SSL_MODE_ALIASES[cleaned]
    allowed = ", ".join(f"'{m.value}'" for m in SSLMode)
    raise ValueError(f"Invalid ssl_mode '{mode}'. Allowed modes: {allowed}")


@dataclass(frozen=True)
class DatabaseSSLConfig:
    """Abstract SSL settings for database connections."""

    ssl_mode: SSLMode = SSLMode.DISABLED
    ssl_ca: str | None = None
    ssl_cert: str | None = None
    ssl_key: str | None = None

    @classmethod
    def from_dict(cls, cfg: Mapping[str, Any] | None) -> "DatabaseSSLConfig":
        """Construct a validated DatabaseSSLConfig from a configuration mapping."""
        if not cfg:
            return cls()

        raw_mode = cfg.get("ssl_mode")
        mode = normalize_ssl_mode(raw_mode)

        def _clean_str(val: Any) -> str | None:
            if val is None:
                return None
            s = str(val).strip()
            return s if s else None

        ca = _clean_str(cfg.get("ssl_ca"))
        cert = _clean_str(cfg.get("ssl_cert"))
        key = _clean_str(cfg.get("ssl_key"))

        if mode in (SSLMode.VERIFY_CA, SSLMode.VERIFY_FULL) and not ca:
            raise ValueError(
                f"ssl_ca must be provided when ssl_mode is '{mode.value}'"
            )

        if bool(cert) != bool(key):
            raise ValueError(
                "Both ssl_cert and ssl_key must be specified for client certificate authentication"
            )

        return cls(
            ssl_mode=mode,
            ssl_ca=ca,
            ssl_cert=cert,
            ssl_key=key,
        )

    def to_mysql_kwargs(self) -> dict[str, Any]:
        """Map abstract SSL config to mysql.connector connection arguments."""
        if self.ssl_mode == SSLMode.DISABLED:
            return {"ssl_disabled": True}

        kwargs: dict[str, Any] = {
            "ssl_disabled": False,
        }

        if self.ssl_mode in (SSLMode.PREFER, SSLMode.REQUIRED):
            kwargs["ssl_verify_cert"] = False
            kwargs["ssl_verify_identity"] = False
            if self.ssl_ca:
                kwargs["ssl_ca"] = self.ssl_ca
        elif self.ssl_mode == SSLMode.VERIFY_CA:
            kwargs["ssl_verify_cert"] = True
            kwargs["ssl_verify_identity"] = False
            kwargs["ssl_ca"] = self.ssl_ca
        elif self.ssl_mode == SSLMode.VERIFY_FULL:
            kwargs["ssl_verify_cert"] = True
            kwargs["ssl_verify_identity"] = True
            kwargs["ssl_ca"] = self.ssl_ca

        if self.ssl_cert and self.ssl_key:
            kwargs["ssl_cert"] = self.ssl_cert
            kwargs["ssl_key"] = self.ssl_key

        return kwargs

    def to_postgres_kwargs(self) -> dict[str, Any]:
        """Map abstract SSL config to psycopg connection arguments."""
        if self.ssl_mode == SSLMode.DISABLED:
            return {"sslmode": "disable"}

        mode_map = {
            SSLMode.PREFER: "prefer",
            SSLMode.REQUIRED: "require",
            SSLMode.VERIFY_CA: "verify-ca",
            SSLMode.VERIFY_FULL: "verify-full",
        }

        kwargs: dict[str, Any] = {
            "sslmode": mode_map[self.ssl_mode],
        }

        if self.ssl_ca:
            kwargs["sslrootcert"] = self.ssl_ca

        if self.ssl_cert and self.ssl_key:
            kwargs["sslcert"] = self.ssl_cert
            kwargs["sslkey"] = self.ssl_key

        return kwargs


def get_mysql_ssl_kwargs(cfg: Mapping[str, Any] | None) -> dict[str, Any]:
    """Helper to convert a configuration mapping directly to MySQL SSL kwargs."""
    return DatabaseSSLConfig.from_dict(cfg).to_mysql_kwargs()


def get_postgres_ssl_kwargs(cfg: Mapping[str, Any] | None) -> dict[str, Any]:
    """Helper to convert a configuration mapping directly to PostgreSQL SSL kwargs."""
    return DatabaseSSLConfig.from_dict(cfg).to_postgres_kwargs()
