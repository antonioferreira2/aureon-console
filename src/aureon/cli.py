"""Command line entry point.

``aureon`` with no arguments starts the interactive console. Sub-commands exist
for scripting and CI; every command is read-only with respect to the audited
host. Ingestion and database maintenance only write AUREON's local state.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from . import APP_NAME, __version__
from .config import Config, load_config
from .export import export_period_summary
from .periods import BUILTIN_PERIODS, PERIOD_CUSTOM
from .security import SecurityService
from .util import human_bytes


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aureon",
        description=f"{APP_NAME} - read-only Linux server monitoring and Fail2ban insights.",
        epilog="Author: Antonio Lourenco Ferreira. License: MIT.",
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    parser.add_argument("--config", type=Path, help="path to config file")
    parser.add_argument("--state-dir", type=Path, help="override the state directory")
    parser.add_argument("--tz", help="timezone name (default: server local time)")
    parser.add_argument("--refresh", type=float, help="refresh interval in seconds")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("console", help="start the interactive TUI (default)")
    sub.add_parser("doctor", help="environment and requirement check")

    stats = sub.add_parser("stats", help="print Fail2ban statistics for a period")
    stats.add_argument("--period", default="today", choices=list(BUILTIN_PERIODS) + [PERIOD_CUSTOM])
    stats.add_argument("--from", dest="start", help="custom range start (ISO-8601)")
    stats.add_argument("--to", dest="end", help="custom range end (ISO-8601)")
    stats.add_argument("--json", action="store_true", help="machine readable output")
    stats.add_argument("--top", type=int, default=10, help="how many IPs to list")

    ingest = sub.add_parser("ingest", help="collect events into the local store")
    ingest.add_argument("--import-history", action="store_true", help="import the whole existing fail2ban log")
    ingest.add_argument("--json", action="store_true")

    db = sub.add_parser("db", help="database maintenance")
    db.add_argument("action", choices=["info", "backup", "integrity", "vacuum", "prune"])
    db.add_argument("--path", type=Path, help="backup destination directory")

    export = sub.add_parser("export", help="export statistics to CSV")
    export.add_argument("--output", type=Path, default=Path("aureon-security-summary.csv"))

    f2b = sub.add_parser("f2b", help="Fail2ban status and assisted configuration")
    f2b_sub = f2b.add_subparsers(dest="f2b_command", required=True)
    f2b_sub.add_parser("status", help="show Fail2ban detection results")
    plan = f2b_sub.add_parser("plan", help="show the configuration proposal (no changes)")
    plan.add_argument("--policy", default="balanced", choices=["conservative", "balanced", "strict"])
    plan.add_argument("--ignoreip", action="append", default=[], help="address or CIDR to never ban")
    plan.add_argument("--diff", action="store_true", help="print a unified diff")
    # Deprecated, compatibility-only arguments. The command always refuses
    # writes; retained so older scripts fail safely with an explanatory error.
    plan.add_argument("--apply", action="store_true", help="deprecated: all audited-host writes are refused")
    plan.add_argument("--yes", action="store_true", help="deprecated: no host changes are supported")

    modules = sub.add_parser("modules", help="probe every collector and print availability")
    modules.add_argument("--json", action="store_true")

    firewall = sub.add_parser("firewall", help="inspect local firewall tools and rules (read-only)")
    firewall.add_argument("--json", action="store_true", help="machine-readable output")

    assess = sub.add_parser("assess", help="run and record evidence-based hardening checks")
    assess.add_argument("--json", action="store_true", help="machine-readable output")
    assess.add_argument("--format", choices=("json", "csv"), default="json", help="assessment export format when --output is used")
    assess.add_argument("--output", type=Path, help="write a complete assessment report to this path")

    history = sub.add_parser("assess-history", help="list locally stored hardening assessments")
    history.add_argument("--limit", type=int, default=20)
    history.add_argument("--json", action="store_true")

    compare = sub.add_parser("assess-compare", help="compare two locally stored assessment IDs")
    compare.add_argument("previous", type=int)
    compare.add_argument("current", type=int)
    compare.add_argument("--json", action="store_true")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    config = load_config(args.config)
    overrides = {}
    if args.state_dir:
        overrides["state_dir"] = str(args.state_dir)
    if args.tz:
        overrides["timezone"] = args.tz
    if args.refresh:
        overrides["refresh_seconds"] = float(args.refresh)
    config.apply_overrides(overrides)
    config.ensure_dirs()

    command = args.command or "console"
    if command == "console":
        return _run_console(config)
    if command == "doctor":
        return _cmd_doctor(config)
    if command == "stats":
        return _cmd_stats(config, args)
    if command == "ingest":
        return _cmd_ingest(config, args)
    if command == "db":
        return _cmd_db(config, args)
    if command == "export":
        return _cmd_export(config, args)
    if command == "f2b":
        return _cmd_f2b(config, args)
    if command == "modules":
        return _cmd_modules(config, args)
    if command == "firewall":
        return _cmd_firewall(config, args)
    if command == "assess":
        return _cmd_assess(config, args)
    if command == "assess-history":
        return _cmd_assessment_history(config, args)
    if command == "assess-compare":
        return _cmd_assessment_compare(config, args)
    parser.print_help()  # pragma: no cover
    return 2  # pragma: no cover


# ---------------------------------------------------------------------------
def _run_console(config: Config) -> int:
    try:
        from .tui.app import AureonApp
    except ImportError as exc:
        print(
            f"{APP_NAME}: the Textual UI is not available ({exc}).\n"
            "Install dependencies:  pip install textual rich\n"
            "The headless commands (stats, ingest, doctor, db) work without it.",
            file=sys.stderr,
        )
        return 3
    app = AureonApp(config)
    app.run()
    return 0


def _cmd_doctor(config: Config) -> int:
    print(f"{APP_NAME} {__version__} - environment check")
    print(f"  python        : {sys.version.split()[0]}")
    print(f"  state dir     : {config.state_dir}")
    print(f"  database      : {config.db_path}")
    print(f"  config file   : {config.config_file}")
    try:
        import textual  # noqa: F401

        print("  textual       : available")
    except ImportError:
        print("  textual       : MISSING (headless commands only)")
    from .collectors.base import CollectionContext
    from .collectors import COLLECTORS

    ctx = CollectionContext(config)
    print("  collectors    :")
    for key, klass in COLLECTORS.items():
        collector = klass(ctx)
        print(f"    - {key:<10} {'available' if collector.available() else 'not available'}")
    service = SecurityService(config)
    status = service.refresh_status()
    print(f"  fail2ban      : {'installed ' + status.version if status.installed else 'not installed'}")
    print(f"  ssh jail      : {status.ssh_jail.name if status.ssh_jail else 'none'}")
    return 0


def _cmd_stats(config: Config, args) -> int:
    from datetime import datetime

    service = SecurityService(config)
    stats_service = service.stats()
    kwargs = {}
    if args.period == PERIOD_CUSTOM:
        try:
            kwargs["custom_start"] = datetime.fromisoformat(args.start) if args.start else None
            kwargs["custom_end"] = datetime.fromisoformat(args.end) if args.end else None
        except ValueError:
            print("--from/--to must be ISO-8601 (e.g. 2026-03-01T00:00:00)", file=sys.stderr)
            return 2
    stats = stats_service.period(args.period, **kwargs)

    if args.json:
        payload = {
            "period": stats.period,
            "start": stats.start.isoformat(),
            "end": stats.end.isoformat(),
            "timezone": stats.timezone,
            "unique_banned_ips": stats.unique_banned_ips,
            "ban_events": stats.ban_events,
            "unban_events": stats.unban_events,
            "unbanned_ips": stats.unbanned_ips,
            "currently_banned": stats.currently_banned,
            "failed_auth_attempts": stats.failed_auth_attempts,
            "recurrent_ips": stats.recurrent_ips,
            "data_available": stats.data_available,
            "coverage_start": stats.coverage_start.isoformat() if stats.coverage_start else None,
            "coverage_end": stats.coverage_end.isoformat() if stats.coverage_end else None,
            "warnings": stats.warnings,
            "top_ips": stats.top_ips[: args.top],
        }
        print(json.dumps(payload, indent=2))
        return 0

    print(f"period                 : {stats.period}")
    print(f"window                 : {stats.start.isoformat()} -> {stats.end.isoformat()}")
    print(f"timezone               : {stats.timezone}")
    print(f"unique banned IPs      : {stats.unique_banned_ips}")
    print(f"ban events             : {stats.ban_events}")
    print(f"unban events           : {stats.unban_events}")
    print(f"IPs with unban events  : {stats.unbanned_ips}")
    print(f"currently banned (live): {stats.currently_banned if stats.currently_banned is not None else 'unverified'}")
    print(f"failed SSH auth (logs) : {stats.failed_auth_attempts if stats.failed_auth_attempts is not None else 'unavailable'}")
    print(f"recurrent IPs          : {stats.recurrent_ips}")
    print(f"data available         : {stats.data_available}")
    if stats.coverage_start:
        print(f"data coverage          : {stats.coverage_start.isoformat()} .. {stats.coverage_end.isoformat() if stats.coverage_end else '?'}")
    if stats.top_ips:
        print("top IPs:")
        for entry in stats.top_ips[: args.top]:
            print(f"  {entry['ip']:<40} events={entry['events']:<5} bans={entry['bans']}")
    for warning in stats.warnings:
        print(f"  ! {warning}")
    return 0


def _cmd_ingest(config: Config, args) -> int:
    service = SecurityService(config)
    report = service.ingest(import_history=args.import_history)
    if args.json:
        print(
            json.dumps(
                {
                    "source": report.source,
                    "seen": report.seen,
                    "added": report.added,
                    "duplicates": report.duplicates,
                    "state": report.state,
                    "notes": report.notes,
                },
                indent=2,
            )
        )
    else:
        print(f"source     : {report.source}")
        print(f"events seen: {report.seen}")
        print(f"events new : {report.added}")
        print(f"duplicates : {report.duplicates}")
        print(f"state      : {report.state}")
        for note in report.notes:
            print(f"  - {note}")
    return 0 if report.state in ("ok", "partial") else 1


def _cmd_db(config: Config, args) -> int:
    from .db.repo import Repository
    from datetime import timedelta

    repo = Repository(config.db_path)
    repo.open()
    action = args.action
    if action == "info":
        lo, hi, total = repo.coverage()
        print(f"database    : {config.db_path}")
        print(f"size        : {human_bytes(repo.db_size())}")
        print(f"events      : {total}")
        if lo and hi:
            print(f"coverage    : {lo.isoformat()} .. {hi.isoformat()}")
        last = repo.last_run()
        if last:
            print(f"last ingest : {last['started_at']} ({last['state']}, +{last['events_added']} events)")
    elif action == "backup":
        destination = (args.path or config.backup_dir) / "aureon-backup.db"
        repo.backup(destination)
        print(f"backup written: {destination}")
    elif action == "integrity":
        result = repo.integrity_check()
        print(result.value if result.available else f"FAILED: {result.error}")
        return 0 if result.available else 1
    elif action == "vacuum":
        repo.vacuum()
        print("vacuum complete")
    elif action == "prune":
        cutoff = datetime.now().astimezone() - timedelta(days=config.retention_days)
        removed = repo.purge_older_than(cutoff)
        print(f"removed {removed} events older than {cutoff.isoformat()}")
    repo.close()
    return 0


def _cmd_export(config: Config, args) -> int:
    from .db.repo import Repository

    repo = Repository(config.db_path)
    repo.open()
    target = export_period_summary(repo, tz=None, path=args.output)
    repo.close()
    print(f"written: {target}")
    return 0


def _cmd_f2b(config: Config, args) -> int:
    service = SecurityService(config)
    status = service.refresh_status()
    if args.f2b_command == "status":
        print(f"installed       : {status.installed} {status.version}")
        print(f"service         : {status.service_state} (enabled: {status.service_enabled})")
        print(f"client access   : {'root' if not status.root_required else 'requires root'}")
        print(f"log source      : {status.log_file or 'none'}")
        print(f"config files    : {', '.join(status.config_files) or 'none'}")
        if status.ssh_jail:
            jail = status.ssh_jail
            print(f"ssh jail        : {jail.name} ({jail.status}) port={jail.port or 'n/a'} "
                  f"bantime={jail.bantime} findtime={jail.findtime} maxretry={jail.maxretry}")
            print(f"  ignoreip      : {' '.join(jail.ignoreip) or '(none)'}")
            print(f"  currently ban : {jail.currently_banned if jail.runtime else 'unverified'}")
        else:
            print("ssh jail        : none")
        for problem in status.problems:
            print(f"  ! {problem}")
        for warning in status.warnings:
            print(f"  ~ {warning}")
        return 0 if status.installed and not status.problems else (1 if status.installed else 0)

    plan = service.plan(policy=args.policy, ignoreip=args.ignoreip)
    print("=== AUREON Fail2ban configuration proposal ===")
    print(f"distribution    : {plan.distro}")
    print(f"package manager : {plan.package_manager}")
    print(f"ssh port        : {plan.ssh_port} ({plan.ssh_port_source})")
    print(f"log backend     : {plan.log_backend}")
    print(f"policy          : {plan.policy}")
    print(f"values          : {plan.values}")
    print(f"drop-in file    : {plan.dropin_path}")
    print(f"admin address   : {plan.admin_ip or 'UNKNOWN'} ({plan.admin_ip_warning})")
    print("--- current configuration ---")
    print(_current_snippet(plan))
    print("--- proposed drop-in ---")
    print(plan.content)
    if args.diff:
        print("--- diff ---")
        print(service.plan_diff(plan))
    print("--- steps ---")
    for index, step in enumerate(plan.steps, start=1):
        print(f"  {index}. {step.description}  [{step.risk} risk]")
        if step.command:
            print(f"     $ {step.command}")
    for warning in plan.warnings:
        print(f"  ! {warning}")
    for blocker in plan.blockers:
        print(f"  x {blocker}")

    if not args.apply:
        print("\nNothing was changed. AUREON is read-only; apply any reviewed recommendation separately.")
        return 0

    result = service.apply(plan, confirmed=args.yes)
    print(result.error or "refused: AUREON is read-only")
    print("No files or audited-host services were changed. Review the proposal and apply any change separately.")
    return 1


def _current_snippet(plan) -> str:
    from .fail2ban.wizard import DROPIN_NAME  # noqa: F401 - documents intent

    jail = plan.current_jail
    if jail is None:
        return "(no SSH jail currently defined)"
    lines = [
        f"[{jail.name}] enabled={jail.enabled} port={jail.port or '(default)'} "
        f"backend={jail.backend or '(default)'} bantime={jail.bantime} "
        f"findtime={jail.findtime} maxretry={jail.maxretry}",
        f"    logpath   = {' '.join(jail.logpath) or '(default)'}",
        f"    ignoreip  = {' '.join(jail.ignoreip) or '(none)'}",
        f"    action    = {' '.join(jail.action) or '(default)'}",
        f"    origin    = {jail.file_origin or '(unknown)'}",
    ]
    return "\n".join(lines)


def _cmd_modules(config: Config, args) -> int:
    from .collectors import COLLECTORS
    from .collectors.base import CollectionContext

    ctx = CollectionContext(config)
    payload = {}
    for key, klass in COLLECTORS.items():
        collector = klass(ctx)
        entry = {"available": collector.available(), "title": collector.title}
        try:
            result = collector.collect()
            entry["state"] = result.availability
            entry["source"] = result.source
            if result.error:
                entry["error"] = result.error
        except Exception as exc:  # noqa: BLE001 - report, never crash
            entry["state"] = "error"
            entry["error"] = str(exc)
        payload[key] = entry
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        for key, entry in payload.items():
            print(f"{key:<10} {entry.get('state', '?'):<12} {entry.get('source', '')}"
                  f"{'  ' + entry['error'] if entry.get('error') else ''}")
    return 0


def _cmd_firewall(config: Config, args) -> int:
    from .collectors.base import CollectionContext
    from .collectors.firewall import FirewallCollector

    result = FirewallCollector(CollectionContext(config)).collect()
    if args.json:
        payload = {
            "state": result.availability,
            "source": result.source,
            "error": result.error,
            "detected": result.value.detected if result.available else [],
            "warnings": result.value.warnings if result.available else [],
            "evidence": [
                {
                    "technology": item.technology,
                    "query": item.query,
                    "availability": item.availability,
                    "output": item.output,
                    "error": item.error,
                    "truncated": item.truncated,
                }
                for item in result.value.evidence
            ] if result.available else [],
        }
        print(json.dumps(payload, indent=2))
    elif not result.available:
        print(f"Firewall inspection unavailable: {result.error or result.availability}")
        return 1
    else:
        print("Firewall tools detected: " + (", ".join(result.value.detected) or "none"))
        for warning in result.value.warnings:
            print(f"! {warning}")
        for item in result.value.evidence:
            print(f"\n[{item.technology}] {item.query}: {item.availability}")
            if item.output:
                print(item.output, end="" if item.output.endswith("\n") else "\n")
            if item.error:
                print(f"  error: {item.error}")
            if item.truncated:
                print("  output truncated at the configured safety limit")
    return 0 if result.available else 1


def _cmd_assess(config: Config, args) -> int:
    from .db.repo import Repository
    from .hardening import run_assessment
    from .hardening_reports import export_assessment_csv, export_assessment_json

    assessment = run_assessment(_AssessmentContext(config), __version__)
    payload = assessment.as_dict()
    repo = Repository(config.db_path)
    repo.open()
    assessment_id = repo.save_assessment(payload)
    repo.close()
    payload["id"] = assessment_id
    if args.output:
        target = (export_assessment_csv(payload, args.output) if args.format == "csv"
                  else export_assessment_json(payload, args.output))
        if args.json:
            print(json.dumps({"assessment_id": payload["id"], "output": str(target)}, indent=2))
        else:
            print(f"assessment {payload['id']} exported: {target}")
        return 0
    if args.json:
        print(json.dumps(payload, indent=2))
        return 0
    print(f"Assessment #{payload['id']}: {assessment.assessed_at} (definition v{assessment.definition_version})")
    print(f"Hardening score: {assessment.score if assessment.score is not None else 'unavailable'} / 100")
    print(assessment.scoring_method)
    for check in assessment.checks:
        print(f"\n{check.outcome.value}: {check.check.id} — {check.check.title}")
        if check.reason:
            print(f"  {check.reason}")
        for evidence in check.evidence:
            print(f"  evidence: {evidence}")
        if check.outcome.value == "FAIL":
            print(f"  recommendation: {check.check.remediation}")
            print(f"  verification: {check.check.verification}")
    return 0


def _cmd_assessment_history(config: Config, args) -> int:
    from .db.repo import Repository

    repo = Repository(config.db_path)
    repo.open()
    rows = repo.assessments(args.limit)
    repo.close()
    if args.json:
        print(json.dumps(rows, indent=2))
    elif not rows:
        print("No assessments have been stored yet.")
    else:
        for row in reversed(rows):
            score = row["score"] if row["score"] is not None else "unavailable"
            print(f"#{row['id']} {row['assessed_at']} score={score} definition=v{row['definition_version']}")
    return 0


def _cmd_assessment_compare(config: Config, args) -> int:
    from .db.repo import Repository
    from .hardening_reports import compare_assessments

    repo = Repository(config.db_path)
    repo.open()
    records = {row["id"]: row for row in repo.assessments(500)}
    repo.close()
    if args.previous not in records or args.current not in records:
        print("Assessment ID not found in local history.", file=sys.stderr)
        return 2
    report = compare_assessments(records[args.previous], records[args.current])
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        delta = report["score_delta"]
        print(f"Assessment {args.previous} -> {args.current}; score delta: {delta if delta is not None else 'not comparable'}")
        if not report["changed_checks"]:
            print("No outcome changes in the stored check set.")
        for item in report["changed_checks"]:
            print(f"{item['check_id']} {item['previous'] or '—'} -> {item['current'] or '—'} ({item['change']})")
        print(report["limitations"])
    return 0


class _AssessmentContext:
    def __init__(self, config: Config) -> None:
        self.config = config

    def run(self, argv, timeout=None):
        from .util import run

        return run(argv, timeout=timeout or self.config.command_timeout)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
