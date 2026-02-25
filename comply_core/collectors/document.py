"""Document-based evidence collector for governance controls.

Reads PDF/MD/TXT files from a directory, matches them to the 9 manual
controls via keyword scoring, and optionally uses an LLM for deeper
quality assessment when ANTHROPIC_API_KEY is set.
"""

from __future__ import annotations

import os
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

logger = get_logger("collectors.document")

# ---------------------------------------------------------------------------
# Keyword map: task_id -> {keywords, topic}
# ---------------------------------------------------------------------------

_TASK_KEYWORDS: dict[str, dict] = {
    "manual_security_policy": {
        "keywords": [
            "information security policy", "security policy", "isms",
            "information security management", "iso 27001", "security objectives",
            "security governance", "acceptable use",
        ],
        "topic": "Information security policy",
    },
    "manual_roles_responsibilities": {
        "keywords": [
            "roles and responsibilities", "security roles", "raci",
            "information security responsibilities", "ciso", "security officer",
            "security organisation", "security organization", "accountability",
        ],
        "topic": "Roles and responsibilities for information security",
    },
    "manual_incident_plan": {
        "keywords": [
            "incident response", "incident management", "security incident",
            "incident handling", "incident plan", "breach notification",
            "escalation procedure", "incident playbook",
        ],
        "topic": "Incident response plan",
    },
    "manual_bcp": {
        "keywords": [
            "business continuity", "disaster recovery", "bcp", "drp",
            "continuity plan", "recovery plan", "resilience",
            "backup and recovery", "rto", "rpo",
        ],
        "topic": "Business continuity plan",
    },
    "manual_screening": {
        "keywords": [
            "screening", "background check", "pre-employment",
            "employee vetting", "hiring process", "reference check",
            "criminal record", "employment verification",
        ],
        "topic": "Employee screening process",
    },
    "manual_training": {
        "keywords": [
            "security awareness", "security training", "awareness training",
            "phishing training", "training record", "training completion",
            "security education", "training programme", "training program",
        ],
        "topic": "Security awareness training records",
    },
    "manual_physical_security": {
        "keywords": [
            "physical security", "physical access", "cctv", "access control",
            "visitor management", "secure area", "perimeter security",
            "data centre security", "data center security", "entry control",
        ],
        "topic": "Physical security assessment",
    },
    "manual_cryptography_policy": {
        "keywords": [
            "cryptography", "encryption", "encryption policy", "key management",
            "tls", "certificate management", "cryptographic controls",
            "data protection", "encryption standard",
        ],
        "topic": "Cryptography and encryption policy",
    },
    "manual_sdlc": {
        "keywords": [
            "secure development", "sdlc", "secure coding", "code review",
            "development lifecycle", "application security", "sast", "dast",
            "security testing", "devsecops", "secure software",
        ],
        "topic": "Secure development lifecycle",
    },
}

_MAX_CONTENT_CHARS = 50_000
_FILENAME_WEIGHT = 2
_KEYWORD_MATCH_THRESHOLD = 2  # minimum weighted score to count as a match


# ---------------------------------------------------------------------------
# File readers
# ---------------------------------------------------------------------------


def _read_pdf_file(path: Path) -> str:
    """Extract text from a PDF using pypdf.  Returns '' if pypdf is missing."""
    try:
        from pypdf import PdfReader  # type: ignore[import-untyped]
    except ImportError:
        logger.warning(
            "pypdf not installed — skipping %s (pip install 'comply-core[docs]')",
            path.name,
        )
        return ""

    try:
        reader = PdfReader(str(path))
        pages = [page.extract_text() or "" for page in reader.pages]
        text = "\n".join(pages)
        return text[:_MAX_CONTENT_CHARS]
    except Exception:
        logger.warning("Failed to read PDF %s", path.name, exc_info=True)
        return ""


def _read_text_file(path: Path) -> str:
    """Read a .md or .txt file as UTF-8."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        return text[:_MAX_CONTENT_CHARS]
    except Exception:
        logger.warning("Failed to read %s", path.name, exc_info=True)
        return ""


_READERS: dict[str, callable] = {  # type: ignore[type-arg]
    ".pdf": _read_pdf_file,
    ".md": _read_text_file,
    ".txt": _read_text_file,
}


def _load_documents(docs_dir: Path) -> list[dict]:
    """Scan *docs_dir* for supported files and return their content."""
    docs: list[dict] = []
    for child in sorted(docs_dir.iterdir()):
        if child.is_file() and child.suffix.lower() in _READERS:
            reader = _READERS[child.suffix.lower()]
            content = reader(child)
            if content:
                docs.append({
                    "filename": child.name,
                    "path": str(child),
                    "content": content,
                })
            else:
                logger.info("Skipped empty/unreadable file: %s", child.name)
    return docs


# ---------------------------------------------------------------------------
# DocumentCollector
# ---------------------------------------------------------------------------


class DocumentCollector(BaseCollector):
    """Assess governance documents against manual controls.

    When ``ANTHROPIC_API_KEY`` is set, sends pre-filtered docs to Claude for
    quality assessment.  Otherwise uses keyword matching (offline, free).
    """

    def __init__(self, docs_dir: Path) -> None:
        self._docs_dir = docs_dir
        self._documents: list[dict] | None = None  # lazy-loaded

    @property
    def source_id(self) -> str:
        # Same as ManualCollector so YAML routing picks it up with zero changes.
        return "manual"

    @property
    def display_name(self) -> str:
        return "Document Audit"

    # -- public API ----------------------------------------------------------

    async def collect(self, control_id: str, collector_config: dict) -> EvidenceRecord:
        if self._documents is None:
            self._documents = _load_documents(self._docs_dir)
            logger.info("Loaded %d documents from %s", len(self._documents), self._docs_dir)

        task_id = collector_config.get("id", "")
        description = collector_config.get("description", "")

        if task_id not in _TASK_KEYWORDS:
            # Not a manual task we know about — fall back to manual placeholder
            return self._manual_placeholder(control_id, description)

        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if api_key:
            try:
                return await self._llm_assess(control_id, task_id, description, api_key)
            except Exception:
                logger.warning(
                    "LLM assessment failed for %s — falling back to keyword matching",
                    task_id,
                    exc_info=True,
                )

        return self._keyword_match(control_id, task_id, description)

    async def healthcheck(self) -> bool:
        return self._docs_dir.is_dir()

    # -- keyword matching ----------------------------------------------------

    def _keyword_match(
        self, control_id: str, task_id: str, description: str
    ) -> EvidenceRecord:
        task_info = _TASK_KEYWORDS[task_id]
        keywords: list[str] = task_info["keywords"]

        matched_files: list[dict] = []

        for doc in self._documents or []:
            score = 0
            filename_lower = doc["filename"].lower()
            content_lower = doc["content"].lower()
            hits: list[str] = []

            for kw in keywords:
                kw_lower = kw.lower()
                if kw_lower in filename_lower:
                    score += _FILENAME_WEIGHT
                    hits.append(f"{kw} (filename)")
                if kw_lower in content_lower:
                    score += 1
                    hits.append(f"{kw} (content)")

            if score >= _KEYWORD_MATCH_THRESHOLD:
                matched_files.append({
                    "filename": doc["filename"],
                    "score": score,
                    "hits": hits,
                })

        matched_files.sort(key=lambda m: m["score"], reverse=True)
        doc_exists = 1 if matched_files else 0

        if matched_files:
            top = matched_files[0]
            quality = min(100, top["score"] * 15)
            note = (
                f"Document found: {top['filename']} "
                f"(score {top['score']}, keyword match)"
            )
        else:
            quality = 0
            note = f"No matching document found for: {description}"

        return EvidenceRecord(
            evidence_id="",
            control_id=control_id,
            control_name=description,
            collected_at=datetime.now(timezone.utc),
            source=self.source_id,
            collector_version=__version__,
            summary={
                "description": description,
                "document_exists": doc_exists,
                "document_quality": quality,
                "matched_files": [
                    {"filename": m["filename"], "score": m["score"]}
                    for m in matched_files
                ],
                "assessment_mode": "keyword",
            },
            finding=Finding(
                status=ComplianceStatus.COMPLIANT if doc_exists else ComplianceStatus.MANUAL_REQUIRED,
                severity=Severity.NONE if doc_exists else Severity.MEDIUM,
                note=note,
            ),
            raw_data=None,
        )

    # -- LLM assessment ------------------------------------------------------

    async def _llm_assess(
        self, control_id: str, task_id: str, description: str, api_key: str
    ) -> EvidenceRecord:
        task_info = _TASK_KEYWORDS[task_id]
        keywords: list[str] = task_info["keywords"]
        topic: str = task_info["topic"]

        # Pre-filter documents using keywords (at least 1 keyword hit)
        candidates: list[dict] = []
        for doc in self._documents or []:
            combined = (doc["filename"] + " " + doc["content"]).lower()
            if any(kw.lower() in combined for kw in keywords):
                candidates.append(doc)

        if not candidates:
            return self._keyword_match(control_id, task_id, description)

        # Truncate content to fit in context
        doc_texts: list[str] = []
        for doc in candidates[:5]:  # max 5 documents
            snippet = doc["content"][:10_000]
            doc_texts.append(f"--- {doc['filename']} ---\n{snippet}")
        combined_text = "\n\n".join(doc_texts)

        prompt = (
            f"You are an ISO 27001 auditor. Assess whether the following documents "
            f"adequately cover the topic: '{topic}'.\n\n"
            f"Documents:\n{combined_text}\n\n"
            f"Respond with ONLY a JSON object (no markdown fences):\n"
            f'{{"document_quality": <0-100>, "reasoning": "<1-2 sentences>", '
            f'"gaps": ["<gap1>", ...]}}'
        )

        import json as _json

        try:
            from anthropic import Anthropic  # type: ignore[import-untyped]
        except ImportError:
            logger.warning(
                "anthropic package not installed — falling back to keyword matching "
                "(pip install 'comply-core[llm]')"
            )
            return self._keyword_match(control_id, task_id, description)

        client = Anthropic(api_key=api_key)
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
        )

        raw_text = message.content[0].text.strip()
        result = _json.loads(raw_text)

        quality = int(result.get("document_quality", 0))
        reasoning = result.get("reasoning", "")
        gaps = result.get("gaps", [])
        doc_exists = 1 if quality >= 30 else 0

        best_file = candidates[0]["filename"] if candidates else "unknown"
        note = f"LLM assessed '{best_file}': quality {quality}/100 — {reasoning}"

        return EvidenceRecord(
            evidence_id="",
            control_id=control_id,
            control_name=description,
            collected_at=datetime.now(timezone.utc),
            source=self.source_id,
            collector_version=__version__,
            summary={
                "description": description,
                "document_exists": doc_exists,
                "document_quality": quality,
                "matched_files": [{"filename": d["filename"]} for d in candidates[:5]],
                "assessment_mode": "llm",
                "reasoning": reasoning,
                "gaps": gaps,
            },
            finding=Finding(
                status=ComplianceStatus.COMPLIANT if doc_exists else ComplianceStatus.MANUAL_REQUIRED,
                severity=Severity.NONE if doc_exists else Severity.MEDIUM,
                note=note,
            ),
            raw_data={"llm_response": raw_text},
        )

    # -- fallback ------------------------------------------------------------

    def _manual_placeholder(
        self, control_id: str, description: str
    ) -> EvidenceRecord:
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
