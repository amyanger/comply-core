# Azure AD App Registration Setup

This guide walks you through creating an Azure AD app registration for ComplyCore.

## Prerequisites

- An Azure AD tenant (comes with any Microsoft 365 subscription)
- Global Administrator or Application Administrator role in Azure AD

## Steps

### 1. Navigate to App Registrations

1. Go to [Azure Portal](https://portal.azure.com)
2. Search for "App registrations" in the top search bar
3. Click **New registration**

### 2. Register the Application

- **Name:** ComplyCore Evidence Collector
- **Supported account types:** Accounts in this organizational directory only (Single tenant)
- **Redirect URI:** Leave blank (we use client credentials, not interactive login)
- Click **Register**

### 3. Note the IDs

On the app's Overview page, note:
- **Application (client) ID** — you'll need this for `comply-core init`
- **Directory (tenant) ID** — you'll need this too

### 4. Create a Client Secret

1. Go to **Certificates & secrets**
2. Click **New client secret**
3. Description: "ComplyCore"
4. Expiry: 24 months (set a calendar reminder to rotate)
5. Click **Add**
6. **Copy the secret value immediately** — it won't be shown again

### 5. Grant API Permissions

1. Go to **API permissions**
2. Click **Add a permission** → **Microsoft Graph** → **Application permissions**
3. Add the following permissions:

| Permission | Purpose |
|-----------|---------|
| `User.Read.All` | List all users for access reviews |
| `Directory.Read.All` | Read directory roles and memberships |
| `Policy.Read.All` | Read Conditional Access policies |
| `Reports.Read.All` | Read authentication methods reports |
| `AuditLog.Read.All` | Read audit log entries |
| `SecurityEvents.Read.All` | Read Microsoft Secure Score |
| `DeviceManagementManagedDevices.Read.All` | Read Intune managed devices |

4. Click **Grant admin consent for [Your Org]**
5. Verify all permissions show a green tick

### 6. Configure ComplyCore

```bash
comply-core init
```

Enter:
- **Tenant ID:** from step 3
- **Client ID:** from step 3
- **Client Secret:** from step 4

ComplyCore will test the connection and confirm which permissions are granted.

## Security Considerations

- The app registration has **read-only** access — it cannot modify your tenant
- The client secret is encrypted on disk using a machine-derived key
- Consider restricting the app's access using Conditional Access if your tenant supports it
- Rotate the client secret annually and update via `comply-core init`

## Troubleshooting

### "Insufficient privileges"
The admin consent step was missed or didn't complete. Go back to API permissions and click "Grant admin consent."

### "Invalid client secret"
The secret may have expired or been copied incorrectly. Create a new one and run `comply-core init` again.

### "AADSTS700016: Application not found"
Double-check the Client ID. It should be the Application (client) ID, not the Object ID.
