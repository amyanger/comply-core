# ComplyCore

Open-source evidence collection engine for **ISO 27001:2022** compliance. ComplyCore connects to your Microsoft 365 tenant via the Graph API, automatically collects compliance evidence, maps it to Annex A controls, evaluates compliance status, and generates audit-ready reports.

## ✨ Features

- 🔄 **Automated evidence collection** from Azure AD, Intune, Defender, and Microsoft Secure Score via the Microsoft Graph API
- 🗺️ **ISO 27001:2022 Annex A mapping** across 21+ controls covering MFA enrollment, Conditional Access, privileged roles, device compliance, audit logs, and more
- ⚙️ **Configurable evaluation rules** defined in YAML — adjust compliance thresholds without changing code
- 📊 **Audit-ready HTML reports** — evidence packs, gap reports, and executive summaries in a single static file
- 🔒 **Tamper-evident evidence chain** — SHA-256 hash chain ensures integrity of collected evidence
- 🧩 **Extensible collector architecture** — add new evidence sources by adding a single Python file
- 🏠 **Self-hosted and offline** — all data stays on your infrastructure, no external SaaS dependencies

## 🚀 Quick Start

### 1. Install

```bash
pip install comply-core
```

Requires Python 3.11+.

### 2. Register an Azure AD App

Create an app registration in Azure AD with **application permissions**. See [docs/setup.md](docs/setup.md) for a full walkthrough.

Required Microsoft Graph permissions:

| Permission | Purpose |
|------------|---------|
| `User.Read.All` | User account inventory |
| `Directory.Read.All` | Privileged role assignments |
| `Policy.Read.All` | Conditional Access and auth policies |
| `Reports.Read.All` | MFA enrollment status |
| `AuditLog.Read.All` | Directory audit logs |
| `SecurityEvents.Read.All` | Microsoft Secure Score |
| `DeviceManagementManagedDevices.Read.All` | Device compliance status |

### 3. Configure

```bash
comply-core init
```

Prompts for your Tenant ID, Client ID, and Client Secret. Credentials are encrypted locally using Fernet symmetric encryption.

### 4. Collect Evidence

```bash
# Collect evidence for all mapped controls
comply-core collect

# Collect specific controls only
comply-core collect --controls A.5.17 A.8.2

# Preview what will be collected without making API calls
comply-core collect --dry-run
```

### 5. Review Compliance Gaps

```bash
# Table output
comply-core gaps

# JSON output for integration with other tools
comply-core gaps --format json
```

### 6. Generate Reports

```bash
# Full evidence pack for auditors
comply-core report --template evidence_pack --output ./audit-pack/

# Gap analysis report
comply-core report --template gap_report --output ./audit-pack/

# Executive summary with compliance overview
comply-core report --template executive_summary --output ./audit-pack/
```

### 7. Verify Evidence Integrity

```bash
comply-core verify
```

Walks the SHA-256 hash chain for all collected evidence and flags any tampering or chain breaks.

## 🏗️ Architecture

```
Microsoft 365            ComplyCore                       Output
┌──────────────┐   ┌─────────────────────┐   ┌────────────────────┐
│ Azure AD     │──>│ Collectors          │──>│ HTML Reports       │
│ Intune       │   │ Evaluator           │   │ Gap Analysis       │
│ Defender     │   │ Control Mapper      │   │ Executive Summary  │
│ Secure Score │   │ Evidence Store      │   │ JSON Export        │
└──────────────┘   └─────────────────────┘   └────────────────────┘
                           │
                           v
                     ~/.comply-core/
                     ├── config.yaml          # Encrypted credentials
                     ├── evidence.db          # SQLite metadata index
                     └── evidence/
                         └── 2026-02-25/
                             ├── A_5_17_mfa_enrollment.json
                             └── A_8_2_privileged_access.json
```

Evidence files are immutable — once written, they are never modified. Each record includes a `content_hash` (SHA-256 of the file) and a `previous_hash` linking to the prior collection for the same control, forming a per-control hash chain.

## 🔧 Customisation

### Compliance Thresholds

Evaluation rules are defined in `mappings/iso27001-2022.yaml` and can be adjusted without modifying source code:

```yaml
evaluation:
  rules:
    - condition: "mfa_coverage >= 100"
      status: COMPLIANT
      severity: NONE
      note: "All users enrolled in MFA"
    - condition: "mfa_coverage >= 95"
      status: PARTIAL
      severity: LOW
      note: "MFA coverage above 95% — review exceptions"
    - condition: "mfa_coverage < 95"
      status: NON_COMPLIANT
      severity: HIGH
      note: "MFA coverage below 95% — remediation required"
```

### Adding Frameworks

Create a new YAML file in `mappings/` following the same structure as `iso27001-2022.yaml`. See [docs/mappings.md](docs/mappings.md) for the schema reference.

### Writing Custom Collectors

Implement a subclass of `BaseCollector` in `comply_core/collectors/`. See [docs/collectors.md](docs/collectors.md) for the collector API.

## 🛠️ Development

```bash
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

## 📦 Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.11+ |
| CLI | Click |
| Auth | MSAL (client credentials flow) |
| HTTP | httpx (async) |
| Data | SQLite + JSON |
| Templates | Jinja2 |
| Testing | pytest + pytest-asyncio |
| Linting | ruff |
| Type checking | mypy |

## 📄 Licence

[Apache 2.0](LICENSE)
