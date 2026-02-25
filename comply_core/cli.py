"""ComplyCore CLI — all commands defined here."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click

from comply_core import __version__
from comply_core.config import ComplyConfig, DEFAULT_CONFIG_DIR, load_config, save_config
from comply_core.exceptions import ComplyConfigError, ComplyIntegrityError
from comply_core.utils.logging import get_logger

logger = get_logger("cli")


@click.group()
@click.version_option(version=__version__, prog_name="comply-core")
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to config file (default: ~/.comply-core/config.yaml).",
)
@click.pass_context
def cli(ctx: click.Context, config_path: Path | None) -> None:
    """ComplyCore — automated evidence collection for ISO 27001:2022."""
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config_path


def _load_config_or_exit(ctx: click.Context) -> ComplyConfig:
    """Load config or exit with a helpful message."""
    try:
        return load_config(ctx.obj.get("config_path"))
    except ComplyConfigError as exc:
        click.echo(click.style(f"Error: {exc}", fg="red"), err=True)
        raise SystemExit(1) from exc


# -- init command --


@cli.command()
@click.pass_context
def init(ctx: click.Context) -> None:
    """Set up ComplyCore configuration (Azure AD app credentials)."""
    click.echo(click.style("ComplyCore Setup", fg="cyan", bold=True))
    click.echo(
        "You'll need an Azure AD app registration with application permissions.\n"
        "See docs/setup.md for a walkthrough.\n"
    )

    tenant_id = click.prompt("Azure AD Tenant ID")
    client_id = click.prompt("Application (client) ID")
    client_secret = click.prompt("Client secret value", hide_input=True)

    config = ComplyConfig(tenant_id=tenant_id, client_id=client_id)
    config.client_secret = client_secret

    evidence_dir = Path(config.evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    config_path = ctx.obj.get("config_path")
    save_config(config, config_path)

    click.echo(click.style("\nConfiguration saved.", fg="green"))
    click.echo(f"  Config:   {config_path or DEFAULT_CONFIG_DIR / 'config.yaml'}")
    click.echo(f"  Evidence: {evidence_dir}")

    # Test connection
    click.echo(click.style("\nTesting connection to Microsoft Graph...", fg="yellow"))
    try:
        from comply_core.utils.graph_client import GraphClient

        client = GraphClient(config)
        result = asyncio.run(client.test_connection())
        if result["authenticated"]:
            click.echo(click.style("  Authentication successful!", fg="green"))
            if result.get("permissions"):
                click.echo("  Granted permissions:")
                for perm in sorted(result["permissions"]):
                    click.echo(f"    - {perm}")
        else:
            click.echo(click.style("  Authentication failed.", fg="red"))
            if result.get("error"):
                click.echo(f"  Error: {result['error']}")
    except Exception as exc:
        click.echo(click.style(f"  Connection test failed: {exc}", fg="red"))
        click.echo("  You can still use ComplyCore — fix credentials and run 'comply-core init' again.")


# -- collect command --


@cli.command()
@click.option(
    "--controls",
    multiple=True,
    help="Specific control IDs to collect (e.g., A.5.17 A.8.2). Collects all if omitted.",
)
@click.option("--dry-run", is_flag=True, help="Show what would be collected without running.")
@click.pass_context
def collect(ctx: click.Context, controls: tuple[str, ...], dry_run: bool) -> None:
    """Collect compliance evidence from configured sources."""
    config = _load_config_or_exit(ctx)

    from comply_core.mappers.framework import load_framework
    from comply_core.mappers.control_mapper import ControlMapper
    from comply_core.mappers.evaluator import Evaluator
    from comply_core.store.evidence_store import EvidenceStore
    from comply_core.collectors.microsoft_graph import MicrosoftGraphCollector
    from comply_core.utils.graph_client import GraphClient

    mappings_dir = Path(__file__).parent.parent / "mappings"
    framework = load_framework(mappings_dir / "iso27001-2022.yaml")
    mapper = ControlMapper(framework)

    target_controls = list(controls) if controls else list(framework.controls.keys())

    if dry_run:
        click.echo(click.style("Dry run — would collect evidence for:", fg="yellow"))
        for cid in sorted(target_controls):
            ctrl = framework.controls.get(cid)
            if ctrl:
                click.echo(f"  {cid}: {ctrl.name}")
                for task in ctrl.collectors:
                    click.echo(f"    - {task.description} (via {task.api})")
        return

    click.echo(click.style(f"Collecting evidence for {len(target_controls)} controls...\n", fg="cyan"))

    store = EvidenceStore(
        db_path=Path(config.database_path),
        evidence_dir=Path(config.evidence_dir),
    )
    store.initialise()

    graph_client = GraphClient(config)
    graph_collector = MicrosoftGraphCollector(graph_client)
    evaluator = Evaluator(framework)

    results = asyncio.run(_run_collection(
        target_controls, framework, graph_collector, evaluator, store, mapper,
    ))

    # Summary
    click.echo(click.style("\nCollection complete.", fg="green", bold=True))
    statuses: dict[str, int] = {}
    for rec in results:
        s = rec.finding.status.value
        statuses[s] = statuses.get(s, 0) + 1
    for status, count in sorted(statuses.items()):
        colour = {
            "COMPLIANT": "green",
            "PARTIAL": "yellow",
            "NON_COMPLIANT": "red",
            "COLLECTION_ERROR": "magenta",
            "NOT_COLLECTED": "white",
            "MANUAL_REQUIRED": "cyan",
        }.get(status, "white")
        click.echo(f"  {click.style(status, fg=colour)}: {count}")


async def _run_collection(
    target_controls: list[str],
    framework: object,
    graph_collector: object,
    evaluator: object,
    store: object,
    mapper: object,
) -> list:
    """Run evidence collection for all target controls."""
    from comply_core.store.evidence_store import EvidenceRecord, EvidenceStore
    from comply_core.mappers.framework import Framework, Control
    from comply_core.mappers.evaluator import Evaluator
    from comply_core.collectors.microsoft_graph import MicrosoftGraphCollector
    from comply_core.collectors.base import BaseCollector
    from comply_core.exceptions import ComplyCollectionError, ComplyAuthError

    fw: Framework = framework  # type: ignore[assignment]
    gc: MicrosoftGraphCollector = graph_collector  # type: ignore[assignment]
    ev: Evaluator = evaluator  # type: ignore[assignment]
    st: EvidenceStore = store  # type: ignore[assignment]

    results: list[EvidenceRecord] = []
    for cid in sorted(target_controls):
        ctrl = fw.controls.get(cid)
        if not ctrl:
            click.echo(click.style(f"  [{cid}] Unknown control — skipped", fg="white"))
            continue

        click.echo(click.style(f"  [{cid}] {ctrl.name}", fg="cyan"))

        for task in ctrl.collectors:
            try:
                record = await gc.collect(cid, {
                    "id": task.id,
                    "description": task.description,
                    "endpoint": task.endpoint,
                    "evidence_type": task.evidence_type,
                })
                record = ev.evaluate(cid, record)
                st.save(record)
                results.append(record)

                colour = {
                    "COMPLIANT": "green",
                    "PARTIAL": "yellow",
                    "NON_COMPLIANT": "red",
                }.get(record.finding.status.value, "white")
                click.echo(
                    f"    {click.style(record.finding.status.value, fg=colour)} — "
                    f"{record.finding.note}"
                )
            except (ComplyCollectionError, ComplyAuthError) as exc:
                click.echo(click.style(f"    COLLECTION_ERROR — {exc}", fg="magenta"))
                from comply_core.store.evidence_store import Finding, ComplianceStatus, Severity
                from datetime import datetime, timezone

                err_record = EvidenceRecord(
                    evidence_id="",
                    control_id=cid,
                    control_name=ctrl.name,
                    collected_at=datetime.now(timezone.utc),
                    source=gc.source_id,
                    collector_version=__version__,
                    summary={"error": str(exc)},
                    finding=Finding(
                        status=ComplianceStatus.COLLECTION_ERROR,
                        severity=Severity.HIGH,
                        note=str(exc),
                    ),
                    raw_data=None,
                )
                st.save(err_record)
                results.append(err_record)
            except Exception as exc:
                logger.exception("Unexpected error collecting %s", cid)
                click.echo(click.style(f"    ERROR — {exc}", fg="red"))

    return results


# -- gaps command --


@cli.command()
@click.option("--format", "output_format", type=click.Choice(["table", "json"]), default="table")
@click.pass_context
def gaps(ctx: click.Context, output_format: str) -> None:
    """Show compliance gap report — controls that are not fully compliant."""
    config = _load_config_or_exit(ctx)

    from comply_core.store.evidence_store import EvidenceStore
    from comply_core.mappers.framework import load_framework

    store = EvidenceStore(
        db_path=Path(config.database_path),
        evidence_dir=Path(config.evidence_dir),
    )

    mappings_dir = Path(__file__).parent.parent / "mappings"
    framework = load_framework(mappings_dir / "iso27001-2022.yaml")

    records = store.latest_by_control()

    if output_format == "json":
        import json

        gaps_list = []
        for cid, rec in sorted(records.items()):
            if rec.finding.status.value != "COMPLIANT":
                gaps_list.append({
                    "control_id": cid,
                    "control_name": rec.control_name,
                    "status": rec.finding.status.value,
                    "severity": rec.finding.severity.value,
                    "note": rec.finding.note,
                    "collected_at": rec.collected_at.isoformat(),
                })
        # Include controls with no evidence
        for cid, ctrl in framework.controls.items():
            if cid not in records:
                gaps_list.append({
                    "control_id": cid,
                    "control_name": ctrl.name,
                    "status": "NOT_COLLECTED",
                    "severity": "NONE",
                    "note": "No evidence collected",
                    "collected_at": None,
                })
        click.echo(json.dumps(gaps_list, indent=2))
        return

    # Table format
    click.echo(click.style("\nCompliance Gap Report", fg="cyan", bold=True))
    click.echo(click.style("=" * 80, fg="cyan"))

    gap_count = 0
    for cid in sorted(framework.controls.keys()):
        ctrl = framework.controls[cid]
        rec = records.get(cid)

        if rec and rec.finding.status.value == "COMPLIANT":
            continue

        gap_count += 1
        if rec:
            colour = {
                "PARTIAL": "yellow",
                "NON_COMPLIANT": "red",
                "COLLECTION_ERROR": "magenta",
                "MANUAL_REQUIRED": "cyan",
            }.get(rec.finding.status.value, "white")
            status = rec.finding.status.value
            note = rec.finding.note
            severity = rec.finding.severity.value
        else:
            colour = "white"
            status = "NOT_COLLECTED"
            note = "No evidence collected"
            severity = "—"

        click.echo(
            f"  {click.style(cid, bold=True):20s} "
            f"{click.style(status, fg=colour):24s} "
            f"{severity:10s} "
            f"{ctrl.name}"
        )
        click.echo(f"  {'':20s} {note}")

    if gap_count == 0:
        click.echo(click.style("  No gaps found — all controls compliant!", fg="green"))
    else:
        click.echo(click.style(f"\n  {gap_count} gap(s) identified.", fg="yellow"))


# -- verify command --


@cli.command()
@click.pass_context
def verify(ctx: click.Context) -> None:
    """Verify evidence integrity by walking the hash chain."""
    config = _load_config_or_exit(ctx)

    from comply_core.store.evidence_store import EvidenceStore
    from comply_core.store.integrity import verify_chain

    store = EvidenceStore(
        db_path=Path(config.database_path),
        evidence_dir=Path(config.evidence_dir),
    )

    click.echo(click.style("Verifying evidence integrity...\n", fg="cyan"))

    try:
        issues = verify_chain(store)
    except ComplyIntegrityError as exc:
        click.echo(click.style(f"Integrity verification failed: {exc}", fg="red"))
        raise SystemExit(1) from exc

    if not issues:
        click.echo(click.style("All evidence integrity checks passed.", fg="green"))
    else:
        click.echo(click.style(f"{len(issues)} issue(s) found:\n", fg="red"))
        for issue in issues:
            click.echo(f"  {click.style('!', fg='red')} {issue}")
        raise SystemExit(1)


# -- report command --


@cli.command()
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["html"]),
    default="html",
    help="Report format.",
)
@click.option(
    "--output",
    "output_dir",
    type=click.Path(path_type=Path),
    default=Path("./audit-pack"),
    help="Output directory for reports.",
)
@click.option(
    "--template",
    type=click.Choice(["evidence_pack", "gap_report", "executive_summary"]),
    default="evidence_pack",
    help="Report template to use.",
)
@click.pass_context
def report(
    ctx: click.Context,
    output_format: str,
    output_dir: Path,
    template: str,
) -> None:
    """Generate an audit-ready HTML report."""
    config = _load_config_or_exit(ctx)

    from comply_core.reports.generator import ReportGenerator
    from comply_core.store.evidence_store import EvidenceStore
    from comply_core.mappers.framework import load_framework

    store = EvidenceStore(
        db_path=Path(config.database_path),
        evidence_dir=Path(config.evidence_dir),
    )

    mappings_dir = Path(__file__).parent.parent / "mappings"
    framework = load_framework(mappings_dir / "iso27001-2022.yaml")

    generator = ReportGenerator(store=store, framework=framework)

    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / f"{template}.html"

    click.echo(click.style(f"Generating {template} report...", fg="cyan"))
    generator.generate(template_name=template, output_path=output_file)
    click.echo(click.style(f"Report saved to {output_file}", fg="green"))


# Import __version__ for use in error records
from comply_core import __version__
