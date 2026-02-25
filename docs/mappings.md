# Adding and Editing Framework Mappings

Framework mappings define which controls exist, what evidence is needed, and how to evaluate compliance. They are YAML files in the `mappings/` directory.

## Structure

```yaml
name: "Framework Name"
version: "2022"

controls:
  CONTROL_ID:
    name: "Control name"
    category: "Category"
    description: "What this control requires..."
    collectors:
      - id: unique_task_id
        description: "What this collection task does"
        api: collector_source_id
        endpoint: /api/endpoint
        frequency: weekly
        evidence_type: snapshot
        graph_permissions:
          - Permission.Read.All
    evaluation:
      rules:
        - condition: "field_name >= threshold"
          status: COMPLIANT
          severity: NONE
          note: "Human-readable explanation"
```

## Evaluation Rules

Rules are evaluated **top-to-bottom** — the first matching rule wins.

### Supported Conditions

Simple numeric comparisons against fields in the evidence summary:

```yaml
- condition: "mfa_coverage >= 100"      # greater than or equal
- condition: "global_admin_count <= 5"   # less than or equal
- condition: "enabled > 0"              # greater than
- condition: "noncompliant < 3"         # less than
- condition: "total_devices == 0"       # equal to
- condition: "errors != 0"             # not equal to
```

### Status Values

| Status | Meaning |
|--------|---------|
| `COMPLIANT` | Control is fully met |
| `PARTIAL` | Partially met — minor improvements needed |
| `NON_COMPLIANT` | Not met — remediation required |
| `NOT_COLLECTED` | No evidence gathered |
| `COLLECTION_ERROR` | Collection attempt failed |
| `MANUAL_REQUIRED` | Cannot be automated — needs manual evidence |

### Severity Values

`NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

## Adding a New Framework

1. Create a YAML file in `mappings/` (e.g., `cyber-essentials.yaml`)
2. Follow the structure above
3. Use existing collector `api` values or create new collectors
4. ComplyCore will automatically pick up the new framework

## Tips

- Put the strictest rules first (COMPLIANT), least strict last (NON_COMPLIANT)
- Use `MANUAL_REQUIRED` for controls that can't be verified via API
- Keep `note` messages actionable — they appear in reports for auditors
- Test evaluation rules by running `comply-core collect` with mock data
