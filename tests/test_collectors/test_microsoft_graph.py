"""Tests for the Microsoft Graph collector."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from comply_core.collectors.microsoft_graph import MicrosoftGraphCollector
from comply_core.store.evidence_store import ComplianceStatus


@pytest.fixture
def mock_graph_client() -> MagicMock:
    client = MagicMock()
    client.paginated_get = AsyncMock()
    client.get = AsyncMock()
    return client


@pytest.fixture
def collector(mock_graph_client: MagicMock) -> MicrosoftGraphCollector:
    return MicrosoftGraphCollector(mock_graph_client)


class TestMFAEnrollment:
    @pytest.mark.asyncio
    async def test_full_mfa_coverage(
        self, collector: MicrosoftGraphCollector, mock_graph_client: MagicMock
    ) -> None:
        mock_graph_client.paginated_get.return_value = [
            {"userPrincipalName": "alice@contoso.com", "isMfaRegistered": True, "isMfaCapable": True, "methodsRegistered": ["push"]},
            {"userPrincipalName": "bob@contoso.com", "isMfaRegistered": True, "isMfaCapable": True, "methodsRegistered": ["fido2"]},
        ]

        record = await collector.collect("A.5.17", {
            "id": "azure_ad_mfa_enrollment",
            "endpoint": "/reports/authenticationMethods/userRegistrationDetails",
            "evidence_type": "snapshot",
        })

        assert record.control_id == "A.5.17"
        assert record.source == "microsoft_graph"
        assert record.summary["mfa_coverage"] == 100.0
        assert record.summary["total_users"] == 2
        assert record.summary["mfa_registered"] == 2

    @pytest.mark.asyncio
    async def test_partial_mfa_coverage(
        self, collector: MicrosoftGraphCollector, mock_graph_client: MagicMock
    ) -> None:
        mock_graph_client.paginated_get.return_value = [
            {"userPrincipalName": "alice@contoso.com", "isMfaRegistered": True, "isMfaCapable": True, "methodsRegistered": ["push"]},
            {"userPrincipalName": "charlie@contoso.com", "isMfaRegistered": False, "isMfaCapable": False, "methodsRegistered": []},
        ]

        record = await collector.collect("A.5.17", {
            "id": "azure_ad_mfa_enrollment",
            "endpoint": "/reports/authenticationMethods/userRegistrationDetails",
            "evidence_type": "snapshot",
        })

        assert record.summary["mfa_coverage"] == 50.0
        assert record.summary["mfa_registered"] == 1
        assert len(record.summary["users_without_mfa"]) == 1

    @pytest.mark.asyncio
    async def test_no_users(
        self, collector: MicrosoftGraphCollector, mock_graph_client: MagicMock
    ) -> None:
        mock_graph_client.paginated_get.return_value = []

        record = await collector.collect("A.5.17", {
            "id": "azure_ad_mfa_enrollment",
            "endpoint": "/reports/authenticationMethods/userRegistrationDetails",
            "evidence_type": "snapshot",
        })

        assert record.summary["mfa_coverage"] == 0
        assert record.summary["total_users"] == 0


class TestConditionalAccess:
    @pytest.mark.asyncio
    async def test_policies_counted(
        self, collector: MicrosoftGraphCollector, mock_graph_client: MagicMock
    ) -> None:
        mock_graph_client.paginated_get.return_value = [
            {"displayName": "Require MFA", "state": "enabled"},
            {"displayName": "Block legacy", "state": "enabled"},
            {"displayName": "Test", "state": "enabledForReportingButNotEnforced"},
            {"displayName": "Old", "state": "disabled"},
        ]

        record = await collector.collect("A.5.15", {
            "id": "azure_ad_conditional_access",
            "endpoint": "/identity/conditionalAccess/policies",
            "evidence_type": "configuration",
        })

        assert record.summary["total_policies"] == 4
        assert record.summary["enabled"] == 2
        assert record.summary["report_only"] == 1
        assert record.summary["disabled"] == 1


class TestPrivilegedRoles:
    @pytest.mark.asyncio
    async def test_role_members(
        self, collector: MicrosoftGraphCollector, mock_graph_client: MagicMock
    ) -> None:
        mock_graph_client.paginated_get.side_effect = [
            # First call: directory roles
            [
                {"id": "role-1", "displayName": "Global Administrator"},
                {"id": "role-2", "displayName": "User Administrator"},
            ],
            # Second call: members of Global Administrator
            [
                {"displayName": "Alice", "userPrincipalName": "alice@contoso.com", "accountEnabled": True},
                {"displayName": "Bob", "userPrincipalName": "bob@contoso.com", "accountEnabled": True},
            ],
            # Third call: members of User Administrator
            [
                {"displayName": "Charlie", "userPrincipalName": "charlie@contoso.com", "accountEnabled": True},
            ],
        ]

        record = await collector.collect("A.8.2", {
            "id": "azure_ad_privileged_roles",
            "endpoint": "/directoryRoles",
            "evidence_type": "snapshot",
        })

        assert record.summary["global_admin_count"] == 2
        assert record.summary["total_privileged_users"] == 3
        assert record.summary["total_privileged_roles"] == 2


class TestSourceProperties:
    def test_source_id(self, collector: MicrosoftGraphCollector) -> None:
        assert collector.source_id == "microsoft_graph"

    def test_display_name(self, collector: MicrosoftGraphCollector) -> None:
        assert collector.display_name == "Microsoft Graph"
