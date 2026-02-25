"""Microsoft Graph API collectors for Azure AD, M365, and Intune evidence."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from comply_core import __version__
from comply_core.collectors.base import BaseCollector
from comply_core.exceptions import ComplyCollectionError
from comply_core.store.evidence_store import (
    ComplianceStatus,
    EvidenceRecord,
    Finding,
    Severity,
)
from comply_core.utils.graph_client import GraphClient
from comply_core.utils.logging import get_logger

logger = get_logger("collectors.microsoft_graph")


class MicrosoftGraphCollector(BaseCollector):
    """Collects evidence from Microsoft Graph API."""

    def __init__(self, graph_client: GraphClient) -> None:
        self._client = graph_client

    @property
    def source_id(self) -> str:
        return "microsoft_graph"

    @property
    def display_name(self) -> str:
        return "Microsoft Graph"

    async def collect(self, control_id: str, collector_config: dict) -> EvidenceRecord:
        """Collect evidence for a control using the Graph API."""
        task_id = collector_config.get("id", "")
        endpoint = collector_config.get("endpoint", "")
        description = collector_config.get("description", "")
        evidence_type = collector_config.get("evidence_type", "snapshot")

        # Dispatch to specialised handlers by task ID
        handler = self._HANDLERS.get(task_id)
        if handler:
            return await handler(self, control_id, collector_config)

        # Generic endpoint collection
        return await self._generic_collect(control_id, collector_config)

    async def healthcheck(self) -> bool:
        """Test Graph API connectivity."""
        result = await self._client.test_connection()
        return result.get("authenticated", False)

    # -- Specialised collection handlers --

    async def _collect_mfa_enrollment(
        self, control_id: str, config: dict
    ) -> EvidenceRecord:
        """Collect MFA enrollment status for all users (A.5.17)."""
        endpoint = config.get(
            "endpoint",
            "/reports/authenticationMethods/userRegistrationDetails",
        )

        try:
            data = await self._client.paginated_get(endpoint)
        except Exception as exc:
            raise ComplyCollectionError(f"Failed to collect MFA enrollment: {exc}") from exc

        total_users = len(data)
        mfa_registered = sum(
            1
            for user in data
            if user.get("isMfaRegistered", False)
            or user.get("methodsRegistered")
        )
        mfa_capable = sum(
            1
            for user in data
            if user.get("isMfaCapable", False)
        )

        mfa_coverage = (mfa_registered / total_users * 100) if total_users > 0 else 0

        summary = {
            "total_users": total_users,
            "mfa_registered": mfa_registered,
            "mfa_capable": mfa_capable,
            "mfa_coverage": round(mfa_coverage, 1),
            "users_without_mfa": [
                {
                    "userPrincipalName": u.get("userPrincipalName", "unknown"),
                    "isMfaRegistered": u.get("isMfaRegistered", False),
                }
                for u in data
                if not u.get("isMfaRegistered", False)
                and not u.get("methodsRegistered")
            ][:50],  # Cap at 50 to limit output size
        }

        return EvidenceRecord(
            evidence_id="",
            control_id=control_id,
            control_name="Authentication information",
            collected_at=datetime.now(timezone.utc),
            source=self.source_id,
            collector_version=__version__,
            summary=summary,
            finding=Finding(
                status=ComplianceStatus.NOT_COLLECTED,
                severity=Severity.NONE,
                note="Pending evaluation",
            ),
            raw_data=data,
        )

    async def _collect_conditional_access(
        self, control_id: str, config: dict
    ) -> EvidenceRecord:
        """Collect Conditional Access policies (A.5.15)."""
        endpoint = config.get(
            "endpoint",
            "/identity/conditionalAccess/policies",
        )

        try:
            data = await self._client.paginated_get(endpoint)
        except Exception as exc:
            raise ComplyCollectionError(
                f"Failed to collect Conditional Access policies: {exc}"
            ) from exc

        total_policies = len(data)
        enabled = [p for p in data if p.get("state") == "enabled"]
        report_only = [p for p in data if p.get("state") == "enabledForReportingButNotEnforced"]
        disabled = [p for p in data if p.get("state") == "disabled"]

        summary = {
            "total_policies": total_policies,
            "enabled": len(enabled),
            "report_only": len(report_only),
            "disabled": len(disabled),
            "policies": [
                {
                    "displayName": p.get("displayName", "Unknown"),
                    "state": p.get("state", "unknown"),
                    "createdDateTime": p.get("createdDateTime", ""),
                    "modifiedDateTime": p.get("modifiedDateTime", ""),
                }
                for p in data
            ],
        }

        return EvidenceRecord(
            evidence_id="",
            control_id=control_id,
            control_name="Access control",
            collected_at=datetime.now(timezone.utc),
            source=self.source_id,
            collector_version=__version__,
            summary=summary,
            finding=Finding(
                status=ComplianceStatus.NOT_COLLECTED,
                severity=Severity.NONE,
                note="Pending evaluation",
            ),
            raw_data=data,
        )

    async def _collect_privileged_roles(
        self, control_id: str, config: dict
    ) -> EvidenceRecord:
        """Collect privileged role assignments (A.8.2)."""
        try:
            # Get directory role assignments
            roles_data = await self._client.paginated_get(
                "/directoryRoles"
            )

            privileged_roles: list[dict[str, Any]] = []
            for role in roles_data:
                role_id = role.get("id", "")
                role_name = role.get("displayName", "Unknown")

                # Get members of this role
                try:
                    members = await self._client.paginated_get(
                        f"/directoryRoles/{role_id}/members"
                    )
                    privileged_roles.append({
                        "role": role_name,
                        "roleId": role_id,
                        "memberCount": len(members),
                        "members": [
                            {
                                "displayName": m.get("displayName", "Unknown"),
                                "userPrincipalName": m.get("userPrincipalName", ""),
                                "accountEnabled": m.get("accountEnabled", True),
                            }
                            for m in members
                        ],
                    })
                except Exception:
                    logger.warning("Could not fetch members for role %s", role_name)
                    privileged_roles.append({
                        "role": role_name,
                        "roleId": role_id,
                        "memberCount": -1,
                        "members": [],
                        "error": "Could not fetch members",
                    })

        except Exception as exc:
            raise ComplyCollectionError(
                f"Failed to collect privileged role assignments: {exc}"
            ) from exc

        # Find Global Administrator role specifically
        global_admins = [
            r for r in privileged_roles
            if "global administrator" in r["role"].lower()
        ]
        global_admin_count = sum(r["memberCount"] for r in global_admins if r["memberCount"] >= 0)

        total_privileged = sum(r["memberCount"] for r in privileged_roles if r["memberCount"] >= 0)

        summary = {
            "total_privileged_roles": len(privileged_roles),
            "total_privileged_users": total_privileged,
            "global_admin_count": global_admin_count,
            "roles": privileged_roles,
        }

        return EvidenceRecord(
            evidence_id="",
            control_id=control_id,
            control_name="Privileged access rights",
            collected_at=datetime.now(timezone.utc),
            source=self.source_id,
            collector_version=__version__,
            summary=summary,
            finding=Finding(
                status=ComplianceStatus.NOT_COLLECTED,
                severity=Severity.NONE,
                note="Pending evaluation",
            ),
            raw_data=roles_data,
        )

    async def _collect_users(
        self, control_id: str, config: dict
    ) -> EvidenceRecord:
        """Collect user listing for access reviews."""
        endpoint = config.get(
            "endpoint",
            "/users?$select=id,displayName,userPrincipalName,accountEnabled,createdDateTime,userType",
        )

        try:
            data = await self._client.paginated_get(endpoint)
        except Exception as exc:
            raise ComplyCollectionError(f"Failed to collect users: {exc}") from exc

        total = len(data)
        enabled = sum(1 for u in data if u.get("accountEnabled", False))
        disabled = total - enabled
        guests = sum(1 for u in data if u.get("userType", "").lower() == "guest")

        summary = {
            "total_users": total,
            "enabled": enabled,
            "disabled": disabled,
            "guests": guests,
            "members": total - guests,
        }

        return EvidenceRecord(
            evidence_id="",
            control_id=control_id,
            control_name="User access management",
            collected_at=datetime.now(timezone.utc),
            source=self.source_id,
            collector_version=__version__,
            summary=summary,
            finding=Finding(
                status=ComplianceStatus.NOT_COLLECTED,
                severity=Severity.NONE,
                note="Pending evaluation",
            ),
            raw_data=data,
        )

    async def _collect_devices(
        self, control_id: str, config: dict
    ) -> EvidenceRecord:
        """Collect managed device information."""
        endpoint = config.get(
            "endpoint",
            "/deviceManagement/managedDevices",
        )

        try:
            data = await self._client.paginated_get(endpoint)
        except Exception as exc:
            raise ComplyCollectionError(f"Failed to collect device info: {exc}") from exc

        total = len(data)
        compliant = sum(
            1 for d in data if d.get("complianceState", "") == "compliant"
        )
        noncompliant = sum(
            1 for d in data if d.get("complianceState", "") == "noncompliant"
        )

        summary = {
            "total_devices": total,
            "compliant": compliant,
            "noncompliant": noncompliant,
            "unknown": total - compliant - noncompliant,
            "os_breakdown": _count_by_field(data, "operatingSystem"),
        }

        return EvidenceRecord(
            evidence_id="",
            control_id=control_id,
            control_name="Endpoint device management",
            collected_at=datetime.now(timezone.utc),
            source=self.source_id,
            collector_version=__version__,
            summary=summary,
            finding=Finding(
                status=ComplianceStatus.NOT_COLLECTED,
                severity=Severity.NONE,
                note="Pending evaluation",
            ),
            raw_data=data,
        )

    async def _collect_secure_score(
        self, control_id: str, config: dict
    ) -> EvidenceRecord:
        """Collect Microsoft Secure Score."""
        endpoint = config.get("endpoint", "/security/secureScores?$top=1")

        try:
            result = await self._client.get(endpoint)
            data = result.get("value", [])
        except Exception as exc:
            raise ComplyCollectionError(f"Failed to collect Secure Score: {exc}") from exc

        if data:
            score = data[0]
            current = score.get("currentScore", 0)
            max_score = score.get("maxScore", 0)
            pct = (current / max_score * 100) if max_score > 0 else 0
            summary = {
                "current_score": current,
                "max_score": max_score,
                "percentage": round(pct, 1),
                "created_date": score.get("createdDateTime", ""),
            }
        else:
            summary = {"current_score": 0, "max_score": 0, "percentage": 0}

        return EvidenceRecord(
            evidence_id="",
            control_id=control_id,
            control_name="Security monitoring",
            collected_at=datetime.now(timezone.utc),
            source=self.source_id,
            collector_version=__version__,
            summary=summary,
            finding=Finding(
                status=ComplianceStatus.NOT_COLLECTED,
                severity=Severity.NONE,
                note="Pending evaluation",
            ),
            raw_data=data,
        )

    async def _collect_audit_logs(
        self, control_id: str, config: dict
    ) -> EvidenceRecord:
        """Collect audit log entries."""
        endpoint = config.get(
            "endpoint",
            "/auditLogs/directoryAudits?$top=100&$orderby=activityDateTime desc",
        )

        try:
            result = await self._client.get(endpoint)
            data = result.get("value", [])
        except Exception as exc:
            raise ComplyCollectionError(f"Failed to collect audit logs: {exc}") from exc

        categories = _count_by_field(data, "category")
        results_breakdown = _count_by_field(data, "result")

        summary = {
            "entries_sampled": len(data),
            "categories": categories,
            "results": results_breakdown,
        }

        return EvidenceRecord(
            evidence_id="",
            control_id=control_id,
            control_name="Logging and monitoring",
            collected_at=datetime.now(timezone.utc),
            source=self.source_id,
            collector_version=__version__,
            summary=summary,
            finding=Finding(
                status=ComplianceStatus.NOT_COLLECTED,
                severity=Severity.NONE,
                note="Pending evaluation",
            ),
            raw_data=data,
        )

    async def _generic_collect(
        self, control_id: str, config: dict
    ) -> EvidenceRecord:
        """Fallback: collect raw data from an arbitrary endpoint."""
        endpoint = config.get("endpoint", "")
        description = config.get("description", "Generic collection")

        if not endpoint:
            raise ComplyCollectionError(f"No endpoint configured for {control_id}")

        try:
            if "$top=" in endpoint or "?" not in endpoint:
                result = await self._client.get(endpoint)
                data = result.get("value", result) if isinstance(result, dict) else result
            else:
                data = await self._client.paginated_get(endpoint)
        except Exception as exc:
            raise ComplyCollectionError(
                f"Failed generic collection for {control_id}: {exc}"
            ) from exc

        record_count = len(data) if isinstance(data, list) else 1
        summary = {
            "description": description,
            "record_count": record_count,
        }

        return EvidenceRecord(
            evidence_id="",
            control_id=control_id,
            control_name=description,
            collected_at=datetime.now(timezone.utc),
            source=self.source_id,
            collector_version=__version__,
            summary=summary,
            finding=Finding(
                status=ComplianceStatus.NOT_COLLECTED,
                severity=Severity.NONE,
                note="Pending evaluation",
            ),
            raw_data=data if isinstance(data, (dict, list)) else {"data": data},
        )

    # Handler dispatch table — maps collector task IDs to methods
    _HANDLERS: dict[str, Any] = {}


# Populate handler dispatch table after class definition
MicrosoftGraphCollector._HANDLERS = {
    "azure_ad_mfa_enrollment": MicrosoftGraphCollector._collect_mfa_enrollment,
    "azure_ad_conditional_access": MicrosoftGraphCollector._collect_conditional_access,
    "azure_ad_privileged_roles": MicrosoftGraphCollector._collect_privileged_roles,
    "azure_ad_users": MicrosoftGraphCollector._collect_users,
    "intune_managed_devices": MicrosoftGraphCollector._collect_devices,
    "intune_device_compliance": MicrosoftGraphCollector._collect_devices,
    "ms_secure_score": MicrosoftGraphCollector._collect_secure_score,
    "azure_ad_audit_logs": MicrosoftGraphCollector._collect_audit_logs,
}


def _count_by_field(items: list[dict], field: str) -> dict[str, int]:
    """Count occurrences of each value for a given field."""
    counts: dict[str, int] = {}
    for item in items:
        val = str(item.get(field, "unknown"))
        counts[val] = counts.get(val, 0) + 1
    return counts
