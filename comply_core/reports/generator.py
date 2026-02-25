"""Report builder — generates HTML reports from evidence and framework data."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from comply_core.mappers.framework import Framework
from comply_core.store.evidence_store import EvidenceStore
from comply_core.utils.logging import get_logger

logger = get_logger("reports.generator")

TEMPLATE_DIR = Path(__file__).parent / "templates"


class ReportGenerator:
    """Generates audit-ready HTML reports."""

    def __init__(self, store: EvidenceStore, framework: Framework) -> None:
        self._store = store
        self._framework = framework
        self._env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=True,
        )

    def generate(self, template_name: str, output_path: Path) -> None:
        """Generate a report using the specified template."""
        template = self._env.get_template(f"{template_name}.html")

        # Gather data
        latest = self._store.latest_by_control()
        all_records = self._store.get_all()
        controls = self._framework.controls

        # Compute stats
        total_controls = len(controls)
        assessed = len(latest)
        compliant = sum(
            1 for r in latest.values() if r.finding.status.value == "COMPLIANT"
        )
        partial = sum(
            1 for r in latest.values() if r.finding.status.value == "PARTIAL"
        )
        non_compliant = sum(
            1 for r in latest.values() if r.finding.status.value == "NON_COMPLIANT"
        )
        errors = sum(
            1 for r in latest.values() if r.finding.status.value == "COLLECTION_ERROR"
        )
        manual = sum(
            1 for r in latest.values() if r.finding.status.value == "MANUAL_REQUIRED"
        )
        not_collected = total_controls - assessed

        # Group controls by category
        by_category: dict[str, list[dict]] = {}
        for cid in sorted(controls.keys()):
            ctrl = controls[cid]
            rec = latest.get(cid)
            entry = {
                "id": cid,
                "name": ctrl.name,
                "category": ctrl.category,
                "description": ctrl.description,
                "status": rec.finding.status.value if rec else "NOT_COLLECTED",
                "severity": rec.finding.severity.value if rec else "NONE",
                "note": rec.finding.note if rec else "No evidence collected",
                "collected_at": rec.collected_at.strftime("%Y-%m-%d %H:%M") if rec else "—",
                "source": rec.source if rec else "—",
            }
            by_category.setdefault(ctrl.category, []).append(entry)

        context = {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "framework_name": self._framework.name,
            "framework_version": self._framework.version,
            "total_controls": total_controls,
            "assessed": assessed,
            "compliant": compliant,
            "partial": partial,
            "non_compliant": non_compliant,
            "errors": errors,
            "manual": manual,
            "not_collected": not_collected,
            "by_category": by_category,
            "latest": latest,
            "all_records": all_records,
        }

        html = template.render(**context)
        output_path.write_text(html, encoding="utf-8")
        logger.info("Report generated: %s", output_path)
