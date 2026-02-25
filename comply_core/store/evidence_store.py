"""SQLite metadata store and JSON evidence file management."""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path

from comply_core.store.integrity import compute_hash
from comply_core.utils.logging import get_logger

logger = get_logger("evidence_store")


class ComplianceStatus(StrEnum):
    COMPLIANT = "COMPLIANT"
    PARTIAL = "PARTIAL"
    NON_COMPLIANT = "NON_COMPLIANT"
    NOT_COLLECTED = "NOT_COLLECTED"
    COLLECTION_ERROR = "COLLECTION_ERROR"
    MANUAL_REQUIRED = "MANUAL_REQUIRED"


class Severity(StrEnum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Finding:
    status: ComplianceStatus
    severity: Severity
    note: str


@dataclass
class EvidenceRecord:
    evidence_id: str
    control_id: str
    control_name: str
    collected_at: datetime
    source: str
    collector_version: str
    summary: dict
    finding: Finding
    raw_data: dict | list | None
    content_hash: str = ""
    previous_hash: str = ""


_SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    control_id TEXT NOT NULL,
    control_name TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    source TEXT NOT NULL,
    collector_version TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    note TEXT,
    content_hash TEXT NOT NULL,
    previous_hash TEXT,
    file_path TEXT NOT NULL,
    raw_data_path TEXT
);

CREATE INDEX IF NOT EXISTS idx_control ON evidence(control_id);
CREATE INDEX IF NOT EXISTS idx_collected ON evidence(collected_at);
CREATE INDEX IF NOT EXISTS idx_status ON evidence(status);

CREATE TABLE IF NOT EXISTS manual_evidence (
    id TEXT PRIMARY KEY,
    control_id TEXT NOT NULL,
    uploaded_at TEXT NOT NULL,
    uploaded_by TEXT,
    file_path TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    note TEXT
);
"""


class EvidenceStore:
    """Manages evidence storage: SQLite index + JSON files."""

    def __init__(self, db_path: Path, evidence_dir: Path) -> None:
        self._db_path = db_path
        self._evidence_dir = evidence_dir

    def initialise(self) -> None:
        """Create database tables and evidence directory."""
        self._evidence_dir.mkdir(parents=True, exist_ok=True)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
        logger.info("Evidence store initialised at %s", self._db_path)

    def _connect(self) -> sqlite3.Connection:
        """Open a connection to the SQLite database."""
        return sqlite3.connect(str(self._db_path))

    def _get_previous_hash(self, control_id: str) -> str:
        """Get the content_hash of the most recent evidence for a control."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT content_hash FROM evidence WHERE control_id = ? "
                "ORDER BY collected_at DESC LIMIT 1",
                (control_id,),
            ).fetchone()
        return row[0] if row else ""

    def save(self, record: EvidenceRecord) -> EvidenceRecord:
        """Save an evidence record: write JSON file, compute hash, insert into DB."""
        # Generate ID if empty
        if not record.evidence_id:
            date_str = record.collected_at.strftime("%Y-%m-%d")
            short_id = uuid.uuid4().hex[:6]
            safe_control = record.control_id.replace(".", "")
            record.evidence_id = f"ev-{date_str}-{safe_control}-{short_id}"

        # Build date-based directory
        date_dir = self._evidence_dir / record.collected_at.strftime("%Y-%m-%d")
        date_dir.mkdir(parents=True, exist_ok=True)

        # Write evidence JSON
        safe_control_file = record.control_id.replace(".", "_")
        evidence_file = date_dir / f"{safe_control_file}_{record.evidence_id[-6:]}.json"
        evidence_data = {
            "evidence_id": record.evidence_id,
            "control_id": record.control_id,
            "control_name": record.control_name,
            "collected_at": record.collected_at.isoformat(),
            "source": record.source,
            "collector_version": record.collector_version,
            "summary": record.summary,
            "finding": {
                "status": record.finding.status.value,
                "severity": record.finding.severity.value,
                "note": record.finding.note,
            },
        }
        evidence_file.write_text(
            json.dumps(evidence_data, indent=2, default=str),
            encoding="utf-8",
        )

        # Write raw data separately if present
        raw_path: str | None = None
        if record.raw_data is not None:
            raw_file = date_dir / f"{safe_control_file}_{record.evidence_id[-6:]}.raw.json"
            raw_file.write_text(
                json.dumps(record.raw_data, indent=2, default=str),
                encoding="utf-8",
            )
            raw_path = str(raw_file.relative_to(self._evidence_dir))

        # Compute hash chain
        record.previous_hash = self._get_previous_hash(record.control_id)
        record.content_hash = compute_hash(evidence_file)

        # Insert into database
        file_path = str(evidence_file.relative_to(self._evidence_dir))
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO evidence
                   (id, control_id, control_name, collected_at, source, collector_version,
                    status, severity, note, content_hash, previous_hash, file_path, raw_data_path)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    record.evidence_id,
                    record.control_id,
                    record.control_name,
                    record.collected_at.isoformat(),
                    record.source,
                    record.collector_version,
                    record.finding.status.value,
                    record.finding.severity.value,
                    record.finding.note,
                    record.content_hash,
                    record.previous_hash,
                    file_path,
                    raw_path,
                ),
            )

        logger.info("Saved evidence %s for %s", record.evidence_id, record.control_id)
        return record

    def get_by_control(self, control_id: str) -> list[EvidenceRecord]:
        """Get all evidence records for a given control, ordered by collection time."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM evidence WHERE control_id = ? ORDER BY collected_at",
                (control_id,),
            ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def get_all(self) -> list[EvidenceRecord]:
        """Get all evidence records."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM evidence ORDER BY collected_at DESC"
            ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def latest_by_control(self) -> dict[str, EvidenceRecord]:
        """Get the most recent evidence record for each control."""
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT e.* FROM evidence e
                   INNER JOIN (
                       SELECT control_id, MAX(collected_at) as max_date
                       FROM evidence GROUP BY control_id
                   ) latest ON e.control_id = latest.control_id
                   AND e.collected_at = latest.max_date"""
            ).fetchall()
        return {row[1]: self._row_to_record(row) for row in rows}

    def get_by_id(self, evidence_id: str) -> EvidenceRecord | None:
        """Get a specific evidence record by ID."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM evidence WHERE id = ?", (evidence_id,)
            ).fetchone()
        return self._row_to_record(row) if row else None

    def _row_to_record(self, row: tuple) -> EvidenceRecord:
        """Convert a database row to an EvidenceRecord."""
        return EvidenceRecord(
            evidence_id=row[0],
            control_id=row[1],
            control_name=row[2],
            collected_at=datetime.fromisoformat(row[3]),
            source=row[4],
            collector_version=row[5],
            summary={},
            finding=Finding(
                status=ComplianceStatus(row[6]),
                severity=Severity(row[7]),
                note=row[8] or "",
            ),
            raw_data=None,
            content_hash=row[9],
            previous_hash=row[10] or "",
        )
