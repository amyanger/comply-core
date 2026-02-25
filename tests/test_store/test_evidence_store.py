"""Tests for the evidence store."""

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


def _make_record(
    control_id: str = "A.5.17",
    status: ComplianceStatus = ComplianceStatus.COMPLIANT,
) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id="",
        control_id=control_id,
        control_name="Test Control",
        collected_at=datetime.now(timezone.utc),
        source="test",
        collector_version="0.1.0",
        summary={"test_field": 42},
        finding=Finding(status=status, severity=Severity.NONE, note="Test"),
        raw_data={"raw": "data"},
    )


@pytest.fixture
def store(tmp_db_path: Path, tmp_evidence_dir: Path) -> EvidenceStore:
    s = EvidenceStore(db_path=tmp_db_path, evidence_dir=tmp_evidence_dir)
    s.initialise()
    return s


class TestEvidenceStore:
    def test_save_and_retrieve(self, store: EvidenceStore) -> None:
        record = _make_record()
        saved = store.save(record)

        assert saved.evidence_id != ""
        assert saved.content_hash != ""

        results = store.get_by_control("A.5.17")
        assert len(results) == 1
        assert results[0].evidence_id == saved.evidence_id

    def test_auto_generates_id(self, store: EvidenceStore) -> None:
        record = _make_record()
        saved = store.save(record)
        assert saved.evidence_id.startswith("ev-")

    def test_hash_chain(self, store: EvidenceStore) -> None:
        rec1 = _make_record()
        saved1 = store.save(rec1)
        assert saved1.previous_hash == ""

        rec2 = _make_record()
        saved2 = store.save(rec2)
        assert saved2.previous_hash == saved1.content_hash

    def test_latest_by_control(self, store: EvidenceStore) -> None:
        store.save(_make_record("A.5.17"))
        store.save(_make_record("A.5.17"))
        store.save(_make_record("A.8.2"))

        latest = store.latest_by_control()
        assert "A.5.17" in latest
        assert "A.8.2" in latest

    def test_get_all(self, store: EvidenceStore) -> None:
        store.save(_make_record("A.5.17"))
        store.save(_make_record("A.8.2"))

        all_records = store.get_all()
        assert len(all_records) == 2

    def test_get_by_id(self, store: EvidenceStore) -> None:
        saved = store.save(_make_record())
        fetched = store.get_by_id(saved.evidence_id)
        assert fetched is not None
        assert fetched.control_id == "A.5.17"

    def test_get_by_id_not_found(self, store: EvidenceStore) -> None:
        assert store.get_by_id("nonexistent") is None

    def test_raw_data_file_created(
        self, store: EvidenceStore, tmp_evidence_dir: Path
    ) -> None:
        store.save(_make_record())
        raw_files = list(tmp_evidence_dir.rglob("*.raw.json"))
        assert len(raw_files) == 1

    def test_no_raw_data_no_file(
        self, store: EvidenceStore, tmp_evidence_dir: Path
    ) -> None:
        record = _make_record()
        record.raw_data = None
        store.save(record)
        raw_files = list(tmp_evidence_dir.rglob("*.raw.json"))
        assert len(raw_files) == 0
