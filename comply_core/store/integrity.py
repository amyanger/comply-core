"""SHA-256 hashing and hash chain verification."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import TYPE_CHECKING

from comply_core.exceptions import ComplyIntegrityError
from comply_core.utils.logging import get_logger

if TYPE_CHECKING:
    from comply_core.store.evidence_store import EvidenceStore

logger = get_logger("integrity")


def compute_hash(file_path: Path) -> str:
    """Compute SHA-256 hash of a file's contents."""
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    return sha.hexdigest()


def verify_chain(store: EvidenceStore) -> list[str]:
    """Walk the hash chain for all controls and return a list of issues.

    Each control maintains its own chain: the most recent record's
    previous_hash should equal the prior record's content_hash.
    """
    issues: list[str] = []

    # Group evidence by control
    all_records = store.get_all()
    by_control: dict[str, list] = {}
    for rec in all_records:
        by_control.setdefault(rec.control_id, []).append(rec)

    for control_id, records in sorted(by_control.items()):
        # Sort by collection time ascending
        records.sort(key=lambda r: r.collected_at)

        for i, rec in enumerate(records):
            # Verify file hash matches stored hash
            evidence_dir = store._evidence_dir
            # Reconstruct file path
            with store._connect() as conn:
                row = conn.execute(
                    "SELECT file_path FROM evidence WHERE id = ?",
                    (rec.evidence_id,),
                ).fetchone()

            if not row:
                issues.append(f"{control_id}/{rec.evidence_id}: DB record missing")
                continue

            file_path = evidence_dir / row[0]
            if not file_path.exists():
                issues.append(f"{control_id}/{rec.evidence_id}: Evidence file missing at {file_path}")
                continue

            actual_hash = compute_hash(file_path)
            if actual_hash != rec.content_hash:
                issues.append(
                    f"{control_id}/{rec.evidence_id}: Hash mismatch — "
                    f"expected {rec.content_hash[:16]}..., got {actual_hash[:16]}..."
                )

            # Verify chain link
            if i > 0:
                expected_prev = records[i - 1].content_hash
                if rec.previous_hash != expected_prev:
                    issues.append(
                        f"{control_id}/{rec.evidence_id}: Chain break — "
                        f"previous_hash {rec.previous_hash[:16]}... != "
                        f"expected {expected_prev[:16]}..."
                    )
            elif rec.previous_hash:
                # First record should have empty previous_hash
                issues.append(
                    f"{control_id}/{rec.evidence_id}: First record has non-empty previous_hash"
                )

    logger.info("Integrity check complete: %d issue(s)", len(issues))
    return issues
