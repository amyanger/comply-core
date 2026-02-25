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

## 🎮 Demo Mode

Don't have an Azure AD tenant? Use `--demo` to run the full pipeline with realistic simulated data — no credentials or configuration needed.

```bash
# Collect evidence using simulated Microsoft 365 data
comply-core collect --demo

# Review gaps, verify integrity, and generate reports — all from demo data
comply-core gaps --demo
comply-core verify --demo
comply-core report --demo --template evidence_pack
comply-core report --demo --template gap_report
comply-core report --demo --template executive_summary
```

Demo data is stored in `~/.comply-core-demo/` and is completely separate from any real evidence.

## 📄 Document Audit Mode

Use `--docs` to assess governance documents offline — no Azure connection needed. Point ComplyCore at a folder of policy documents and it will match them to the 9 manual controls that normally return `MANUAL_REQUIRED`.

```bash
# Keyword matching (default, offline, no API key needed)
comply-core collect --demo --docs ./governance-docs/

# LLM-powered assessment — set any supported provider's API key
export ANTHROPIC_API_KEY=sk-ant-...   # Claude
# or: export OPENAI_API_KEY=sk-...    # ChatGPT
# or: export GEMINI_API_KEY=...       # Gemini
comply-core collect --demo --docs ./governance-docs/
```

**Supported formats:** `.pdf` (requires `pip install 'comply-core[docs]'`), `.md`, `.txt`

**Install the LLM provider you want:**

```bash
pip install 'comply-core[llm-anthropic]'   # Claude
pip install 'comply-core[llm-openai]'      # ChatGPT / GPT-4o
pip install 'comply-core[llm-gemini]'      # Gemini
```

**How it works:**
- **Keyword mode (default):** Scans filenames (weighted 2x) and content for control-specific keywords. Free, fully offline.
- **LLM mode (when an API key is set):** Pre-filters docs with keywords, then sends relevant ones to your chosen AI provider for quality assessment. Returns a quality score (0-100), reasoning, and gap identification. Falls back to keyword mode on any error. Supports Claude, ChatGPT, and Gemini — the first API key found is used. Override the default model with `COMPLY_LLM_MODEL=<model-name>`.

**Matched controls produce `COMPLIANT`** instead of `MANUAL_REQUIRED`. Unmatched controls remain `MANUAL_REQUIRED`.

| Flags | Graph controls | Manual controls |
|-------|---------------|-----------------|
| (none) | Real Azure API | `MANUAL_REQUIRED` |
| `--demo` | Demo fixtures | `MANUAL_REQUIRED` |
| `--docs ./dir` | Real Azure API | Document assessment |
| `--demo --docs ./dir` | Demo fixtures | Document assessment |

### Example Output

```
$ comply-core collect --demo

DEMO MODE — using simulated data (no Azure connection)

Collecting evidence for 24 controls...

  [A.5.1] Policies for information security
    MANUAL_REQUIRED — Manual evidence required: Information security policy document
  [A.5.15] Access control
    COMPLIANT — Adequate Conditional Access policies in place
  [A.5.16] Identity management
    COMPLIANT — Disabled account count is low — identity lifecycle well managed
  [A.5.17] Authentication information
    NON_COMPLIANT — MFA coverage below 95% — remediation required
  [A.5.18] Access rights
    COMPLIANT — Privileged access appropriately limited
  [A.5.2] Information security roles and responsibilities
    MANUAL_REQUIRED — Manual evidence required: Roles and responsibilities documentation
  [A.5.23] Information security for use of cloud services
    PARTIAL — Secure Score between 50-80% — improvement recommended
  [A.5.24] Information security incident management planning and preparation
    MANUAL_REQUIRED — Manual evidence required: Incident response plan documentation
  [A.5.29] Information security during disruption
    MANUAL_REQUIRED — Manual evidence required: Business continuity plan documentation
  [A.5.3] Segregation of duties
    COMPLIANT — Global admin count within acceptable range
  [A.6.1] Screening
    MANUAL_REQUIRED — Manual evidence required: Employee screening process documentation
  [A.6.3] Information security awareness, education and training
    MANUAL_REQUIRED — Manual evidence required: Security awareness training records
  [A.7.1] Physical security perimeters
    MANUAL_REQUIRED — Manual evidence required: Physical security assessment documentation
  [A.8.1] User endpoint devices
    PARTIAL — A few non-compliant devices — review and remediate
  [A.8.15] Logging
    COMPLIANT — Active audit logging with recent entries
  [A.8.16] Monitoring activities
    COMPLIANT — Strong security monitoring posture
  [A.8.2] Privileged access rights
    PARTIAL — Global Admin count slightly elevated
  [A.8.20] Networks security
    COMPLIANT — Network-level access controls in place
  [A.8.24] Use of cryptography
    MANUAL_REQUIRED — Manual evidence required: Cryptography policy documentation
  [A.8.25] Secure development life cycle
    MANUAL_REQUIRED — Manual evidence required: Secure development lifecycle documentation
  [A.8.3] Information access restriction
    PARTIAL — Some access restriction policies — consider adding more
  [A.8.5] Secure authentication
    PARTIAL — MFA coverage above 90% but not universal
  [A.8.7] Protection against malware
    PARTIAL — Device compliance between 80-95%
  [A.8.9] Configuration management
    COMPLIANT — Adequate security configuration policies defined

Collection complete.
  COMPLIANT: 8
  MANUAL_REQUIRED: 9
  NON_COMPLIANT: 1
  PARTIAL: 6
```

### Simulated Data

The demo fixtures model a realistic mid-size organisation with some compliance gaps:

| Data Source | Simulated Scenario | Key Numbers |
|---|---|---|
| **MFA Enrollment** | 20 users, 18 enrolled in MFA | 90% coverage — triggers NON_COMPLIANT for A.5.17 (threshold: 95%), PARTIAL for A.8.5 (threshold: 90%) |
| **Conditional Access** | 5 policies: 3 enabled, 1 report-only, 1 disabled | 3 active policies — COMPLIANT for most controls, PARTIAL for A.8.3 (needs 5) |
| **Privileged Roles** | 3 roles: Global Admin (4 members), User Admin (3), Security Admin (2) | 4 Global Admins — COMPLIANT for A.5.3 (limit: 5), PARTIAL for A.8.2 (limit: 3) |
| **Users** | 25 users: 22 enabled, 3 disabled, 2 guests | 3 disabled accounts — COMPLIANT for A.5.16 (limit: 10) |
| **Devices** | 100 managed devices: 85 compliant, 3 noncompliant, 12 unknown | PARTIAL for A.8.1 (3 noncompliant) and A.8.7 (85 compliant, needs 95) |
| **Secure Score** | 72 out of 100 | 72% — PARTIAL for A.5.23 (needs 80%), COMPLIANT for A.8.16 (needs 70%) |
| **Audit Logs** | 75 entries across 5 categories | COMPLIANT for A.8.15 (needs 50+ entries) |
| **Manual Controls** | 9 controls (policy docs, training, physical security, etc.) | All return MANUAL_REQUIRED — upload evidence via future manual workflow |

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
