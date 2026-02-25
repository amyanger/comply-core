"""Maps evidence records to ISO 27001 controls."""

from __future__ import annotations

from comply_core.mappers.framework import Framework, Control
from comply_core.store.evidence_store import EvidenceRecord
from comply_core.utils.logging import get_logger

logger = get_logger("mappers.control_mapper")


class ControlMapper:
    """Maps evidence to framework controls."""

    def __init__(self, framework: Framework) -> None:
        self._framework = framework

    def get_control(self, control_id: str) -> Control | None:
        """Look up a control definition by ID."""
        return self._framework.controls.get(control_id)

    def get_required_collectors(self, control_id: str) -> list[dict]:
        """Get the list of collector tasks required for a control."""
        control = self.get_control(control_id)
        if not control:
            return []
        return [
            {
                "id": ct.id,
                "description": ct.description,
                "api": ct.api,
                "endpoint": ct.endpoint,
                "evidence_type": ct.evidence_type,
            }
            for ct in control.collectors
        ]

    def get_all_control_ids(self) -> list[str]:
        """Return all control IDs in the framework."""
        return sorted(self._framework.controls.keys())

    def get_controls_by_category(self) -> dict[str, list[Control]]:
        """Group controls by their Annex A category."""
        by_cat: dict[str, list[Control]] = {}
        for ctrl in self._framework.controls.values():
            by_cat.setdefault(ctrl.category, []).append(ctrl)
        return by_cat

    def get_required_permissions(self) -> set[str]:
        """Get the full set of Graph API permissions required by all collectors."""
        perms: set[str] = set()
        for ctrl in self._framework.controls.values():
            for ct in ctrl.collectors:
                perms.update(ct.graph_permissions)
        return perms
