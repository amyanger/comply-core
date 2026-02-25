"""Shared test fixtures for ComplyCore."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"
GRAPH_RESPONSES_DIR = FIXTURES_DIR / "graph_responses"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES_DIR


@pytest.fixture
def graph_responses_dir() -> Path:
    return GRAPH_RESPONSES_DIR


@pytest.fixture
def mfa_registration_response() -> list[dict]:
    data = json.loads((GRAPH_RESPONSES_DIR / "mfa_registration.json").read_text())
    return data["value"]


@pytest.fixture
def conditional_access_response() -> list[dict]:
    data = json.loads((GRAPH_RESPONSES_DIR / "conditional_access.json").read_text())
    return data["value"]


@pytest.fixture
def directory_roles_response() -> list[dict]:
    data = json.loads((GRAPH_RESPONSES_DIR / "directory_roles.json").read_text())
    return data["value"]


@pytest.fixture
def users_response() -> list[dict]:
    data = json.loads((GRAPH_RESPONSES_DIR / "users.json").read_text())
    return data["value"]


@pytest.fixture
def devices_response() -> list[dict]:
    data = json.loads((GRAPH_RESPONSES_DIR / "devices.json").read_text())
    return data["value"]


@pytest.fixture
def tmp_evidence_dir(tmp_path: Path) -> Path:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    return evidence_dir


@pytest.fixture
def tmp_db_path(tmp_path: Path) -> Path:
    return tmp_path / "evidence.db"


@pytest.fixture
def sample_framework_path() -> Path:
    return Path(__file__).parent.parent / "mappings" / "iso27001-2022.yaml"
