"""Framework definition loader — reads YAML control mappings."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from comply_core.exceptions import ComplyConfigError
from comply_core.utils.logging import get_logger

logger = get_logger("mappers.framework")


@dataclass
class EvaluationRule:
    """A single evaluation rule from the YAML mapping."""

    condition: str
    status: str
    severity: str
    note: str


@dataclass
class CollectorTask:
    """A collector task definition from the YAML mapping."""

    id: str
    description: str
    api: str
    endpoint: str
    frequency: str = "weekly"
    evidence_type: str = "snapshot"
    graph_permissions: list[str] = field(default_factory=list)


@dataclass
class Control:
    """An ISO 27001 control definition."""

    id: str
    name: str
    category: str
    description: str
    collectors: list[CollectorTask] = field(default_factory=list)
    evaluation_rules: list[EvaluationRule] = field(default_factory=list)


@dataclass
class Framework:
    """A compliance framework loaded from YAML."""

    name: str
    version: str
    controls: dict[str, Control] = field(default_factory=dict)


def load_framework(yaml_path: Path) -> Framework:
    """Load a compliance framework from a YAML file."""
    if not yaml_path.exists():
        raise ComplyConfigError(f"Framework mapping not found: {yaml_path}")

    try:
        raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ComplyConfigError(f"Invalid YAML in framework file: {exc}") from exc

    if not isinstance(raw, dict):
        raise ComplyConfigError("Framework file must contain a YAML mapping.")

    framework = Framework(
        name=raw.get("name", "Unknown"),
        version=raw.get("version", ""),
    )

    for cid, cdata in raw.get("controls", {}).items():
        collectors = []
        for ct in cdata.get("collectors", []):
            collectors.append(CollectorTask(
                id=ct.get("id", ""),
                description=ct.get("description", ""),
                api=ct.get("api", ""),
                endpoint=ct.get("endpoint", ""),
                frequency=ct.get("frequency", "weekly"),
                evidence_type=ct.get("evidence_type", "snapshot"),
                graph_permissions=ct.get("graph_permissions", []),
            ))

        eval_rules = []
        evaluation = cdata.get("evaluation", {})
        for rule in evaluation.get("rules", []):
            eval_rules.append(EvaluationRule(
                condition=rule.get("condition", ""),
                status=rule.get("status", "NOT_COLLECTED"),
                severity=rule.get("severity", "NONE"),
                note=rule.get("note", ""),
            ))

        framework.controls[str(cid)] = Control(
            id=str(cid),
            name=cdata.get("name", ""),
            category=cdata.get("category", ""),
            description=cdata.get("description", ""),
            collectors=collectors,
            evaluation_rules=eval_rules,
        )

    logger.info("Loaded framework '%s' with %d controls", framework.name, len(framework.controls))
    return framework
