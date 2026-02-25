# ComplyCore

**If you're a one-person IT team at a charity and ISO 27001 audit prep makes you want to cry — this is for you.**

ComplyCore is an open-source evidence collection engine for ISO 27001:2022. It connects to your Microsoft 365 tenant, automatically pulls compliance evidence, maps it to Annex A controls, and produces audit-ready reports.

No more screenshots. No more spreadsheets. No more manually proving you have MFA enabled for the third year running.

## What it does

- Connects to Microsoft Graph API (Azure AD, Intune, Defender)
- Collects evidence automatically: MFA status, Conditional Access policies, privileged roles, device compliance, audit logs, Secure Score
- Maps evidence to ISO 27001:2022 Annex A controls
- Evaluates compliance status using configurable YAML rules
- Generates audit-ready HTML reports
- Maintains an integrity chain (SHA-256) so evidence is tamper-evident

## What it doesn't do

ComplyCore is **not** a GRC platform. No risk registers, no policy management, no workflow approvals. It's the plumbing that feeds into whatever GRC tool you already use — CISO Assistant, Eramba, or just a well-organised folder.

## Quick Start

### 1. Install

```bash
pip install comply-core
```

### 2. Register an Azure AD App

You need an app registration in Azure AD with **application permissions**. See [docs/setup.md](docs/setup.md) for a step-by-step walkthrough.

Required permissions:
- `User.Read.All`
- `Directory.Read.All`
- `Policy.Read.All`
- `Reports.Read.All`
- `AuditLog.Read.All`
- `SecurityEvents.Read.All`
- `DeviceManagementManagedDevices.Read.All`

### 3. Configure

```bash
comply-core init
```

This prompts for your Tenant ID, Client ID, and Client Secret. The secret is encrypted and stored locally.

### 4. Collect Evidence

```bash
# Collect evidence for all mapped controls
comply-core collect

# Collect specific controls only
comply-core collect --controls A.5.17 A.8.2

# Dry run — see what would be collected
comply-core collect --dry-run
```

### 5. Review Gaps

```bash
# Table view
comply-core gaps

# JSON output for piping to other tools
comply-core gaps --format json
```

### 6. Generate Reports

```bash
# Full evidence pack
comply-core report --template evidence_pack --output ./audit-pack/

# Gap report
comply-core report --template gap_report --output ./audit-pack/

# Executive summary
comply-core report --template executive_summary --output ./audit-pack/
```

### 7. Verify Integrity

```bash
comply-core verify
```

## How It Works

```
Microsoft 365          ComplyCore                     Output
┌──────────┐     ┌──────────────────┐          ┌─────────────┐
│ Azure AD │────▶│ Collectors       │──────────▶│ HTML Reports│
│ Intune   │     │ Evidence Store   │          │ Gap Analysis│
│ Defender │     │ Control Mapper   │          │ JSON Export │
│ Secure   │     │ Evaluator        │          │ Audit Pack  │
│ Score    │     └──────────────────┘          └─────────────┘
└──────────┘            │
                        ▼
                  ~/.comply-core/
                  ├── config.yaml
                  ├── evidence.db
                  └── evidence/
                      └── 2026-02-25/
                          ├── A_5_17_*.json
                          └── A_8_2_*.json
```

Evidence is immutable — once collected, files are never modified. A SHA-256 hash chain links each collection run, making tampering detectable.

## Customisation

### Adjust compliance thresholds

Edit `mappings/iso27001-2022.yaml` to change evaluation rules:

```yaml
# Example: require 98% MFA coverage instead of 95%
evaluation:
  rules:
    - condition: "mfa_coverage >= 98"
      status: COMPLIANT
      severity: NONE
      note: "MFA coverage meets organisational threshold"
```

### Add a new framework

Create a YAML file in `mappings/` following the same structure. ComplyCore will load it.

## Development

```bash
# Clone and install dev dependencies
git clone https://github.com/amyanger/comply-core.git
cd comply-core
pip install -e ".[dev]"

# Run tests
pytest

# Lint and format
ruff check .
ruff format .

# Type check
mypy comply_core/
```

## Why not Vanta/Drata/etc?

Those tools are excellent — if you can afford them. At £15,000–£80,000 per year, they're priced for well-funded startups and enterprises. ComplyCore exists for the 50-person charity running Microsoft 365 where one person does IT, compliance, and probably facilities management too.

## Licence

Apache 2.0 — use it, modify it, contribute back if you can.
