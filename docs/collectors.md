# Writing Custom Collectors

ComplyCore is designed to be extended with custom collectors. Each collector is a Python class that knows how to pull evidence from a specific source.

## The BaseCollector Interface

All collectors inherit from `BaseCollector`:

```python
from comply_core.collectors.base import BaseCollector
from comply_core.store.evidence_store import EvidenceRecord

class MyCollector(BaseCollector):

    @property
    def source_id(self) -> str:
        return "my_source"

    @property
    def display_name(self) -> str:
        return "My Custom Source"

    async def collect(self, control_id: str, collector_config: dict) -> EvidenceRecord:
        # Your collection logic here
        ...

    async def healthcheck(self) -> bool:
        # Test connectivity
        return True
```

## Key Concepts

### source_id
A unique string identifying this collector. It must match the `api` field in the YAML mapping.

### collector_config
A dictionary passed from the YAML mapping, containing:
- `id`: unique task identifier
- `description`: human-readable description
- `endpoint`: API endpoint or resource path
- `evidence_type`: `snapshot`, `configuration`, or `log`

### EvidenceRecord
Your collector must return an `EvidenceRecord` with:
- **summary**: A structured dict with key findings (e.g., `{"mfa_coverage": 95.5}`)
- **finding**: Set to `NOT_COLLECTED` — the evaluator will set the final status
- **raw_data**: The full API response for audit trail purposes

## Adding to the Framework

1. Create your collector file in `comply_core/collectors/`
2. Add control definitions to `mappings/iso27001-2022.yaml` with `api: your_source_id`
3. Add evaluation rules to determine compliance status

## Example: AWS Collector

```python
class AWSCollector(BaseCollector):

    @property
    def source_id(self) -> str:
        return "aws"

    @property
    def display_name(self) -> str:
        return "AWS"

    async def collect(self, control_id: str, config: dict) -> EvidenceRecord:
        # Use boto3 to pull evidence from AWS
        ...
```

Then in the YAML mapping:

```yaml
A.5.17:
  collectors:
    - id: aws_iam_mfa
      description: "IAM MFA status"
      api: aws
      endpoint: iam/credential-report
```
