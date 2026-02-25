"""Evaluates compliance status for evidence records using YAML rules."""

from __future__ import annotations

import re
from typing import Any

from comply_core.mappers.framework import Framework, EvaluationRule
from comply_core.store.evidence_store import (
    ComplianceStatus,
    EvidenceRecord,
    Finding,
    Severity,
)
from comply_core.utils.logging import get_logger

logger = get_logger("mappers.evaluator")

# Pattern to match simple numeric comparisons like "mfa_coverage >= 95"
_CONDITION_PATTERN = re.compile(
    r"^(\w+)\s*(>=|<=|>|<|==|!=)\s*(\d+(?:\.\d+)?)$"
)


class Evaluator:
    """Evaluates evidence records against framework rules."""

    def __init__(self, framework: Framework) -> None:
        self._framework = framework

    def evaluate(self, control_id: str, record: EvidenceRecord) -> EvidenceRecord:
        """Evaluate an evidence record and update its finding."""
        control = self._framework.controls.get(control_id)
        if not control or not control.evaluation_rules:
            logger.debug("No evaluation rules for %s", control_id)
            return record

        summary = record.summary

        for rule in control.evaluation_rules:
            if self._check_condition(rule.condition, summary):
                record.finding = Finding(
                    status=ComplianceStatus(rule.status),
                    severity=Severity(rule.severity),
                    note=rule.note,
                )
                logger.info(
                    "Control %s evaluated as %s: %s",
                    control_id,
                    rule.status,
                    rule.note,
                )
                return record

        # No rule matched — leave as NOT_COLLECTED
        logger.warning("No evaluation rule matched for %s", control_id)
        return record

    def _check_condition(self, condition: str, summary: dict[str, Any]) -> bool:
        """Evaluate a simple condition string against the evidence summary.

        Supports conditions like:
            mfa_coverage >= 100
            global_admin_count <= 5
            enabled_policies > 0
            total_devices == 0
        """
        match = _CONDITION_PATTERN.match(condition.strip())
        if not match:
            logger.warning("Could not parse condition: %s", condition)
            return False

        field_name = match.group(1)
        operator = match.group(2)
        threshold = float(match.group(3))

        # Look up the field value in the summary
        value = self._resolve_field(field_name, summary)
        if value is None:
            logger.warning("Field '%s' not found in evidence summary", field_name)
            return False

        try:
            numeric_value = float(value)
        except (TypeError, ValueError):
            logger.warning("Field '%s' value '%s' is not numeric", field_name, value)
            return False

        match operator:
            case ">=":
                return numeric_value >= threshold
            case "<=":
                return numeric_value <= threshold
            case ">":
                return numeric_value > threshold
            case "<":
                return numeric_value < threshold
            case "==":
                return numeric_value == threshold
            case "!=":
                return numeric_value != threshold
            case _:
                return False

    def _resolve_field(self, field_name: str, summary: dict[str, Any]) -> Any:
        """Resolve a field name from the evidence summary, supporting nested keys."""
        if field_name in summary:
            return summary[field_name]

        # Try common prefixes/mappings
        for key, val in summary.items():
            if isinstance(val, dict) and field_name in val:
                return val[field_name]

        return None
