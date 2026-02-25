"""Abstract base class for all evidence collectors."""

from __future__ import annotations

from abc import ABC, abstractmethod

from comply_core.store.evidence_store import EvidenceRecord


class BaseCollector(ABC):
    """Base class for all evidence collectors."""

    @property
    @abstractmethod
    def source_id(self) -> str:
        """Unique identifier for this collector source (e.g., 'microsoft_graph')."""
        ...

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable name for CLI output."""
        ...

    @abstractmethod
    async def collect(self, control_id: str, collector_config: dict) -> EvidenceRecord:
        """Collect evidence for a specific control.

        Args:
            control_id: ISO 27001 control ID (e.g., 'A.5.17').
            collector_config: Collector-specific config from the YAML mapping.

        Returns:
            EvidenceRecord with raw data, summary, and finding.

        Raises:
            ComplyCollectionError: If the API call fails.
            ComplyAuthError: If authentication/permissions fail.
        """
        ...

    async def healthcheck(self) -> bool:
        """Test connectivity and permissions. Called during `comply-core init`."""
        return True
