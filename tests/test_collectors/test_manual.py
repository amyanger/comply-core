"""Tests for the manual evidence collector."""

from __future__ import annotations

import pytest

from comply_core.collectors.manual import ManualCollector
from comply_core.store.evidence_store import ComplianceStatus


@pytest.fixture
def collector() -> ManualCollector:
    return ManualCollector()


class TestManualCollector:
    @pytest.mark.asyncio
    async def test_returns_manual_required(self, collector: ManualCollector) -> None:
        record = await collector.collect("A.5.1", {
            "id": "manual_security_policy",
            "description": "Information security policy document",
        })

        assert record.control_id == "A.5.1"
        assert record.source == "manual"
        assert record.finding.status == ComplianceStatus.MANUAL_REQUIRED

    @pytest.mark.asyncio
    async def test_no_raw_data(self, collector: ManualCollector) -> None:
        record = await collector.collect("A.5.1", {"description": "Test"})
        assert record.raw_data is None

    def test_source_id(self, collector: ManualCollector) -> None:
        assert collector.source_id == "manual"

    def test_display_name(self, collector: ManualCollector) -> None:
        assert collector.display_name == "Manual Evidence"

    @pytest.mark.asyncio
    async def test_healthcheck(self, collector: ManualCollector) -> None:
        assert await collector.healthcheck() is True
