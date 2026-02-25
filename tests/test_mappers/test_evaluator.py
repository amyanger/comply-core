"""Tests for the compliance evaluator."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from comply_core.mappers.evaluator import Evaluator
from comply_core.mappers.framework import load_framework
from comply_core.store.evidence_store import (
    ComplianceStatus,
    EvidenceRecord,
    Finding,
    Severity,
)


@pytest.fixture
def evaluator(sample_framework_path: Path) -> Evaluator:
    framework = load_framework(sample_framework_path)
    return Evaluator(framework)


def _make_record(control_id: str, summary: dict) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id="test-001",
        control_id=control_id,
        control_name="Test",
        collected_at=datetime.now(timezone.utc),
        source="test",
        collector_version="0.1.0",
        summary=summary,
        finding=Finding(
            status=ComplianceStatus.NOT_COLLECTED,
            severity=Severity.NONE,
            note="Pending",
        ),
        raw_data=None,
    )


class TestMFAEvaluation:
    def test_100_percent_compliant(self, evaluator: Evaluator) -> None:
        record = _make_record("A.5.17", {"mfa_coverage": 100})
        result = evaluator.evaluate("A.5.17", record)
        assert result.finding.status == ComplianceStatus.COMPLIANT

    def test_96_percent_partial(self, evaluator: Evaluator) -> None:
        record = _make_record("A.5.17", {"mfa_coverage": 96})
        result = evaluator.evaluate("A.5.17", record)
        assert result.finding.status == ComplianceStatus.PARTIAL

    def test_below_95_non_compliant(self, evaluator: Evaluator) -> None:
        record = _make_record("A.5.17", {"mfa_coverage": 80})
        result = evaluator.evaluate("A.5.17", record)
        assert result.finding.status == ComplianceStatus.NON_COMPLIANT
        assert result.finding.severity == Severity.HIGH


class TestConditionalAccessEvaluation:
    def test_enough_policies_compliant(self, evaluator: Evaluator) -> None:
        record = _make_record("A.5.15", {"enabled": 5, "total_policies": 6})
        result = evaluator.evaluate("A.5.15", record)
        assert result.finding.status == ComplianceStatus.COMPLIANT

    def test_few_policies_partial(self, evaluator: Evaluator) -> None:
        record = _make_record("A.5.15", {"enabled": 2, "total_policies": 3})
        result = evaluator.evaluate("A.5.15", record)
        assert result.finding.status == ComplianceStatus.PARTIAL

    def test_no_policies_non_compliant(self, evaluator: Evaluator) -> None:
        record = _make_record("A.5.15", {"enabled": 0, "total_policies": 0})
        result = evaluator.evaluate("A.5.15", record)
        assert result.finding.status == ComplianceStatus.NON_COMPLIANT


class TestPrivilegedAccessEvaluation:
    def test_few_admins_compliant(self, evaluator: Evaluator) -> None:
        record = _make_record("A.8.2", {"global_admin_count": 2})
        result = evaluator.evaluate("A.8.2", record)
        assert result.finding.status == ComplianceStatus.COMPLIANT

    def test_many_admins_non_compliant(self, evaluator: Evaluator) -> None:
        record = _make_record("A.8.2", {"global_admin_count": 10})
        result = evaluator.evaluate("A.8.2", record)
        assert result.finding.status == ComplianceStatus.NON_COMPLIANT


class TestNoRulesControl:
    def test_unknown_control_unchanged(self, evaluator: Evaluator) -> None:
        record = _make_record("Z.99.99", {"anything": 42})
        result = evaluator.evaluate("Z.99.99", record)
        assert result.finding.status == ComplianceStatus.NOT_COLLECTED
