"""Manual evidence tracking for controls that cannot be automated."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from comply_core import __version__
from comply_core.collectors.base import BaseCollector
from comply_core.store.evidence_store import (
    ComplianceStatus,
    EvidenceRecord,
    Finding,
    Severity,
)
from comply_core.utils.logging import get_logger

logger = get_logger("collectors.manual")


class ManualCollector(BaseCollector):
    """Tracks controls that require manual evidence upload."""

    @property
    def source_id(self) -> str:
        return "manual"

    @property
    def display_name(self) -> str:
        return "Manual Evidence"

    async def collect(self, control_id: str, collector_config: dict) -> EvidenceRecord:
        """Create a placeholder record for manual evidence collection."""
        description = collector_config.get("description", "Manual evidence required")

        return EvidenceRecord(
            evidence_id="",
            control_id=control_id,
            control_name=description,
            collected_at=datetime.now(timezone.utc),
            source=self.source_id,
            collector_version=__version__,
            summary={
                "description": description,
                "status": "Awaiting manual upload",
            },
            finding=Finding(
                status=ComplianceStatus.MANUAL_REQUIRED,
                severity=Severity.NONE,
                note=f"Manual evidence required: {description}",
            ),
            raw_data=None,
        )

    async def healthcheck(self) -> bool:
        """Manual collector is always available."""
        return True
