"""Tests for evidence integrity verification."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from comply_core.store.evidence_store import (
    ComplianceStatus,
    EvidenceRecord,
    EvidenceStore,
    Finding,
    Severity,
)
from comply_core.store.integrity import compute_hash, verify_chain


def _make_record(control_id: str = "A.5.17") -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id="",
        control_id=control_id,
        control_name="Test",
        collected_at=datetime.now(timezone.utc),
        source="test",
        collector_version="0.1.0",
        summary={"test": True},
        finding=Finding(
            status=ComplianceStatus.COMPLIANT,
            severity=Severity.NONE,
            note="Test",
        ),
        raw_data=None,
    )


@pytest.fixture
def store(tmp_db_path: Path, tmp_evidence_dir: Path) -> EvidenceStore:
    s = EvidenceStore(db_path=tmp_db_path, evidence_dir=tmp_evidence_dir)
    s.initialise()
    return s


class TestComputeHash:
    def test_deterministic(self, tmp_path: Path) -> None:
        f = tmp_path / "test.json"
        f.write_text('{"hello": "world"}')
        h1 = compute_hash(f)
        h2 = compute_hash(f)
        assert h1 == h2

    def test_different_content_different_hash(self, tmp_path: Path) -> None:
        f1 = tmp_path / "a.json"
        f2 = tmp_path / "b.json"
        f1.write_text('{"a": 1}')
        f2.write_text('{"b": 2}')
        assert compute_hash(f1) != compute_hash(f2)


class TestVerifyChain:
    def test_valid_chain(self, store: EvidenceStore) -> None:
        store.save(_make_record("A.5.17"))
        store.save(_make_record("A.5.17"))
        issues = verify_chain(store)
        assert issues == []

    def test_empty_store(self, store: EvidenceStore) -> None:
        issues = verify_chain(store)
        assert issues == []

    def test_tampered_file_detected(
        self, store: EvidenceStore, tmp_evidence_dir: Path
    ) -> None:
        store.save(_make_record("A.5.17"))

        # Tamper with the evidence file
        json_files = list(tmp_evidence_dir.rglob("*.json"))
        non_raw = [f for f in json_files if ".raw." not in f.name]
        assert len(non_raw) == 1
        non_raw[0].write_text('{"tampered": true}')

        issues = verify_chain(store)
        assert len(issues) >= 1
        assert "Hash mismatch" in issues[0]
