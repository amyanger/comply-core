"""Configuration loading, saving, and validation for ComplyCore."""

from __future__ import annotations

import base64
import os
import platform
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from cryptography.fernet import Fernet, InvalidToken

from comply_core.exceptions import ComplyConfigError
from comply_core.utils.logging import get_logger

logger = get_logger("config")

DEFAULT_CONFIG_DIR = Path.home() / ".comply-core"
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.yaml"


def _derive_machine_key() -> bytes:
    """Derive a Fernet key from machine-specific identifiers."""
    import hashlib

    node = platform.node()
    user = os.getenv("USERNAME") or os.getenv("USER") or "comply-core"
    seed = f"comply-core:{node}:{user}".encode()
    raw = hashlib.sha256(seed).digest()
    return base64.urlsafe_b64encode(raw)


def _encrypt_secret(plaintext: str) -> str:
    """Encrypt a secret using a machine-derived Fernet key."""
    f = Fernet(_derive_machine_key())
    return f.encrypt(plaintext.encode()).decode()


def _decrypt_secret(ciphertext: str) -> str:
    """Decrypt a secret using a machine-derived Fernet key."""
    f = Fernet(_derive_machine_key())
    try:
        return f.decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise ComplyConfigError(
            "Failed to decrypt client secret. Config may have been created on a different machine."
        ) from exc


@dataclass
class ComplyConfig:
    """ComplyCore configuration."""

    tenant_id: str = ""
    client_id: str = ""
    client_secret_encrypted: str = ""
    evidence_dir: str = str(DEFAULT_CONFIG_DIR / "evidence")
    database_path: str = str(DEFAULT_CONFIG_DIR / "evidence.db")
    collection_frequency: str = "weekly"
    redact_upns: bool = False

    @property
    def client_secret(self) -> str:
        """Decrypt and return the client secret."""
        if not self.client_secret_encrypted:
            raise ComplyConfigError("No client secret configured. Run 'comply-core init'.")
        return _decrypt_secret(self.client_secret_encrypted)

    @client_secret.setter
    def client_secret(self, value: str) -> None:
        """Encrypt and store the client secret."""
        self.client_secret_encrypted = _encrypt_secret(value)

    def validate(self) -> list[str]:
        """Validate configuration, returning a list of error messages."""
        errors: list[str] = []
        if not self.tenant_id:
            errors.append("tenant_id is required")
        if not self.client_id:
            errors.append("client_id is required")
        if not self.client_secret_encrypted:
            errors.append("client_secret is required")
        return errors


def load_config(config_path: Path | None = None) -> ComplyConfig:
    """Load configuration from YAML file."""
    path = config_path or DEFAULT_CONFIG_FILE

    if not path.exists():
        raise ComplyConfigError(
            f"Config file not found at {path}. Run 'comply-core init' to create one."
        )

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ComplyConfigError(f"Invalid YAML in config file: {exc}") from exc

    if not isinstance(raw, dict):
        raise ComplyConfigError("Config file must contain a YAML mapping.")

    config = ComplyConfig(
        tenant_id=raw.get("tenant_id", ""),
        client_id=raw.get("client_id", ""),
        client_secret_encrypted=raw.get("client_secret_encrypted", ""),
        evidence_dir=raw.get("evidence_dir", str(DEFAULT_CONFIG_DIR / "evidence")),
        database_path=raw.get("database_path", str(DEFAULT_CONFIG_DIR / "evidence.db")),
        collection_frequency=raw.get("collection_frequency", "weekly"),
        redact_upns=raw.get("redact_upns", False),
    )

    errors = config.validate()
    if errors:
        raise ComplyConfigError(f"Config validation failed: {'; '.join(errors)}")

    logger.info("Configuration loaded from %s", path)
    return config


def save_config(config: ComplyConfig, config_path: Path | None = None) -> None:
    """Save configuration to YAML file."""
    path = config_path or DEFAULT_CONFIG_FILE
    path.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "tenant_id": config.tenant_id,
        "client_id": config.client_id,
        "client_secret_encrypted": config.client_secret_encrypted,
        "evidence_dir": config.evidence_dir,
        "database_path": config.database_path,
        "collection_frequency": config.collection_frequency,
        "redact_upns": config.redact_upns,
    }

    path.write_text(yaml.dump(data, default_flow_style=False), encoding="utf-8")

    # Restrict permissions on config file (contains encrypted secret)
    try:
        path.chmod(0o600)
    except OSError:
        logger.warning("Could not restrict config file permissions (Windows?)")

    logger.info("Configuration saved to %s", path)
