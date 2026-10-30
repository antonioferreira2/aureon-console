"""Regression tests for extended read-only assessment and history features."""

from __future__ import annotations

import csv
import json

from aureon.hardening import CHECKS, Outcome
from aureon.hardening_reports import compare_assessments, export_assessment_csv, export_assessment_json
from aureon.i18n import SUPPORTED_LANGUAGES, navigation, normalize_language, tr


def test_assessment_definitions_have_stable_unique_ids_and_required_metadata():
    ids = [item.id for item in CHECKS]
    assert ids
    assert len(ids) == len(set(ids))
    for item in CHECKS:
        assert item.domain and item.title and item.description and item.data_sources
        assert item.expected_state and item.severity and item.weight > 0
        assert item.remediation and item.verification and item.limitations


def test_assessment_collects_independent_local_domains(config, monkeypatch):
    from aureon import assessment_engine
    from aureon.collectors.firewall import FirewallInfo
    from aureon.util import Availability, Result

    monkeypatch.setattr(assessment_engine, "_sshd_settings", lambda _ctx: ({}, "permission denied"))
    monkeypatch.setattr(assessment_engine, "_account_checks", lambda: [
        assessment_engine._simple("ACCOUNT-UID0", Outcome.UNKNOWN, reason="fixture"),
        assessment_engine._simple("SUDOERS-PERMISSIONS", Outcome.UNKNOWN, reason="fixture"),
        assessment_engine._simple("ACCOUNT-PASSWORD-AGING", Outcome.UNKNOWN, reason="fixture"),
    ])
    monkeypatch.setattr(assessment_engine, "_filesystem_checks", lambda: [
        assessment_engine._simple("FILESYSTEM-SECRET-PERMISSIONS", Outcome.UNKNOWN, reason="fixture"),
        assessment_engine._simple("FILESYSTEM-TMP-MOUNT", Outcome.UNKNOWN, reason="fixture"),
    ])
    monkeypatch.setattr(assessment_engine, "_logging_checks", lambda _ctx: [
        assessment_engine._simple("LOG-PERSISTENT-JOURNAL", Outcome.UNKNOWN, reason="fixture"),
        assessment_engine._simple("LOG-AUDIT-SUBSYSTEM", Outcome.UNKNOWN, reason="fixture"),
    ])
    monkeypatch.setattr(assessment_engine, "_os_checks", lambda: [
        assessment_engine._simple("OS-SECURITY-UPDATES", Outcome.UNKNOWN, reason="fixture"),
        assessment_engine._simple("OS-REBOOT-REQUIRED", Outcome.UNKNOWN, reason="fixture"),
    ])
    monkeypatch.setattr(assessment_engine, "_host_protection_checks", lambda: [
        assessment_engine._simple("HOST-SELINUX", Outcome.NOT_APPLICABLE),
        assessment_engine._simple("HOST-APPARMOR", Outcome.NOT_APPLICABLE),
    ])
    monkeypatch.setattr(assessment_engine, "_network_checks", lambda _ctx: [assessment_engine._simple("NETWORK-WILDCARD-LISTENERS", Outcome.UNKNOWN)])
    monkeypatch.setattr(assessment_engine, "_kernel_checks", lambda: [assessment_engine._simple("KERNEL-SECURITY-SYSCTLS", Outcome.UNKNOWN)])
    monkeypatch.setattr(assessment_engine, "_time_sync_check", lambda _ctx: assessment_engine._simple("TIME-SYNCHRONIZATION", Outcome.UNKNOWN))
    monkeypatch.setattr(assessment_engine, "_logging_retention_check", lambda: assessment_engine._simple("LOG-ROTATION", Outcome.UNKNOWN))
    monkeypatch.setattr(assessment_engine, "_fail2ban_check", lambda _ctx: assessment_engine._simple("F2B-SSH-JAIL", Outcome.UNKNOWN))
    monkeypatch.setattr(assessment_engine, "_container_check", lambda _ctx: assessment_engine._simple("CONTAINERS-PRIVILEGED", Outcome.UNKNOWN))
    monkeypatch.setattr(assessment_engine, "_backup_check", lambda: assessment_engine._simple("BACKUP-RECOVERY-EVIDENCE", Outcome.UNKNOWN))
    class Firewall:
        def __init__(self, _ctx): pass
        def collect(self): return Result.ok_result(FirewallInfo(detected=["nftables"]), "test")
    monkeypatch.setattr("aureon.collectors.firewall.FirewallCollector", Firewall)

    results = assessment_engine.collect_checks(type("Ctx", (), {"config": config})())
    assert len(results) == len(CHECKS)
    assert len({item.check.id for item in results}) == len(CHECKS)
    assert all(item.outcome in set(Outcome) for item in results)
    assert next(item for item in results if item.check.id == "SSH-ROOT-LOGIN").outcome == Outcome.UNKNOWN


def test_assessment_history_repository_roundtrip(tmp_path):
    from aureon.db.repo import Repository

    repo = Repository(tmp_path / "history.db")
    repo.open()
    sample = {"assessed_at": "2026-10-29T00:00:00+00:00", "tool_version": "0.1.0",
              "definition_version": "3", "score": None, "checks": []}
    record_id = repo.save_assessment(sample)
    rows = repo.assessments()
    repo.close()
    assert rows[0]["id"] == record_id
    assert rows[0]["assessment"] == sample


def test_collector_duplicate_check_ids_fail_closed(monkeypatch):
    from aureon import assessment_engine
    from aureon.collectors.firewall import FirewallInfo
    from aureon.util import Result

    monkeypatch.setattr(assessment_engine, "_ssh_checks", lambda _ctx: [
        assessment_engine._simple("SSH-ROOT-LOGIN", Outcome.PASS),
        assessment_engine._simple("SSH-ROOT-LOGIN", Outcome.FAIL),
    ])
    monkeypatch.setattr(assessment_engine, "_account_checks", lambda: [])
    monkeypatch.setattr(assessment_engine, "_filesystem_checks", lambda: [])
    monkeypatch.setattr(assessment_engine, "_logging_checks", lambda _ctx: [])
    monkeypatch.setattr(assessment_engine, "_os_checks", lambda: [])
    monkeypatch.setattr(assessment_engine, "_network_checks", lambda _ctx: [])
    monkeypatch.setattr(assessment_engine, "_kernel_checks", lambda: [])
    monkeypatch.setattr(assessment_engine, "_time_sync_check", lambda _ctx: assessment_engine._simple("TIME-SYNCHRONIZATION", Outcome.UNKNOWN))
    monkeypatch.setattr(assessment_engine, "_logging_retention_check", lambda: assessment_engine._simple("LOG-ROTATION", Outcome.UNKNOWN))
    monkeypatch.setattr(assessment_engine, "_host_protection_checks", lambda: [])
    monkeypatch.setattr(assessment_engine, "_fail2ban_check", lambda _ctx: assessment_engine._simple("F2B-SSH-JAIL", Outcome.UNKNOWN))
    monkeypatch.setattr(assessment_engine, "_container_check", lambda _ctx: assessment_engine._simple("CONTAINERS-PRIVILEGED", Outcome.UNKNOWN))
    monkeypatch.setattr(assessment_engine, "_backup_check", lambda: assessment_engine._simple("BACKUP-RECOVERY-EVIDENCE", Outcome.UNKNOWN))
    class Firewall:
        def __init__(self, _ctx): pass
        def collect(self): return Result.ok_result(FirewallInfo(), "test")
    monkeypatch.setattr("aureon.collectors.firewall.FirewallCollector", Firewall)
    config = type("Config", (), {"command_timeout": 1})()
    ctx = type("Ctx", (), {"config": config})()
    result = assessment_engine.collect_checks(ctx)
    root = next(item for item in result if item.check.id == "SSH-ROOT-LOGIN")
    assert root.outcome == Outcome.ERROR
    assert "more than once" in root.reason


def test_comparison_does_not_infer_from_missing_scores_or_checks():
    old = {"assessed_at": "old", "score": None, "checks": []}
    new = {"assessed_at": "new", "score": 80, "checks": [
        {"check": {"id": "X", "domain": "SSH", "title": "Example"}, "outcome": "PASS"}
    ]}
    report = compare_assessments(old, new)
    assert report["score_delta"] is None
    assert report["score_comparable"] is False
    assert report["changed_checks"][0]["change"] == "added"


def test_full_assessment_exports_are_private_and_complete(tmp_path):
    payload = {"id": 7, "assessed_at": "now", "tool_version": "0.1", "definition_version": "3",
               "score": None, "checks": [{"outcome": "UNKNOWN", "reason": "missing data", "evidence": ["source"],
               "check": {"id": "X", "domain": "SSH", "title": "Policy", "description": "desc", "severity": "high", "weight": 4,
                         "expected_state": "secure", "data_sources": ["sshd -T"], "limitations": "limited", "remediation": "review", "verification": "query"}}]}
    json_path = export_assessment_json(payload, tmp_path / "nested" / "report.json")
    csv_path = export_assessment_csv(payload, tmp_path / "report.csv")
    assert json.loads(json_path.read_text())["checks"][0]["evidence"] == ["source"]
    assert json_path.stat().st_mode & 0o077 == 0
    with csv_path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["check_id"] == "X"
    assert rows[0]["remediation"] == "review"
    assert csv_path.stat().st_mode & 0o077 == 0


def test_seven_language_catalogue_and_fallback():
    assert SUPPORTED_LANGUAGES == ("en", "pt", "es", "fr", "de", "it", "nl")
    for language in SUPPORTED_LANGUAGES:
        items = navigation(language)
        assert len(items) == 17
        assert dict(items)["assessment-history"]
        assert dict(items)["system"]
        assert tr("assessment.title", language)
        assert tr("assessment.scoring_method", language)
        for key in ("help_intro", "keys", "proposal_readonly", "no_operational_changes", "filesystems", "firewall_local", "f2b_status"):
            assert tr("ui." + key, language)
            if language != "en":
                assert tr("ui." + key, language) != tr("ui." + key, "en")


def test_every_static_panel_label_has_a_translation_for_each_locale():
    import ast
    from pathlib import Path

    from aureon.i18n import _CATALOG

    keys = set()
    for filename in ("src/aureon/tui/panels.py", "src/aureon/tui/app.py"):
        tree = ast.parse(Path(filename).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            if node.func.id not in {"_t", "tr", "_ui"} or not node.args:
                continue
            argument = node.args[0]
            if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                key = argument.value
                keys.add(key if key.startswith(("ui.", "nav.", "assessment.", "outcome.", "status.")) else "ui." + key)
    assert keys
    for language in SUPPORTED_LANGUAGES:
        assert keys <= _CATALOG[language].keys()
    for language in SUPPORTED_LANGUAGES[1:]:
        untranslated = [key for key in keys if _CATALOG[language][key] == _CATALOG["en"].get(key)]
        assert not untranslated, f"{language} still uses English for panel labels: {sorted(untranslated)}"
    assert normalize_language("pt-PT") == "pt"
    assert tr("assessment.title", "xx") == tr("assessment.title", "en")
    assert tr("missing.key", "en") == "missing.key"
