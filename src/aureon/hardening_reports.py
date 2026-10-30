"""Historical assessment comparison and private, complete report exports."""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path
from typing import Dict, List, Optional


def compare_assessments(previous: Dict[str, object], current: Dict[str, object]) -> Dict[str, object]:
    """Compare stable check IDs and scores without inventing missing outcomes."""
    before = previous.get("assessment", previous)
    after = current.get("assessment", current)
    previous_checks = {
        item.get("check", {}).get("id"): item
        for item in before.get("checks", [])
        if isinstance(item, dict) and isinstance(item.get("check"), dict)
    }
    current_checks = {
        item.get("check", {}).get("id"): item
        for item in after.get("checks", [])
        if isinstance(item, dict) and isinstance(item.get("check"), dict)
    }
    changes = []
    for check_id in sorted(set(previous_checks) | set(current_checks)):
        old, new = previous_checks.get(check_id), current_checks.get(check_id)
        old_state = old.get("outcome") if old else None
        new_state = new.get("outcome") if new else None
        if old_state != new_state:
            definition = (new or old).get("check", {})
            changes.append({
                "check_id": check_id,
                "domain": definition.get("domain", ""),
                "title": definition.get("title", ""),
                "previous": old_state,
                "current": new_state,
                "change": "added" if old is None else "removed" if new is None else "changed",
            })
    old_score, new_score = before.get("score"), after.get("score")
    delta = new_score - old_score if isinstance(new_score, int) and isinstance(old_score, int) else None
    return {
        "previous_assessed_at": before.get("assessed_at"),
        "current_assessed_at": after.get("assessed_at"),
        "previous_score": old_score,
        "current_score": new_score,
        "score_delta": delta,
        "score_comparable": delta is not None,
        "changed_checks": changes,
        "limitations": "Only checks with stable IDs and stored results are compared. Missing check results and unavailable scores are not treated as improvement or regression.",
    }


def export_assessment_json(assessment: Dict[str, object], path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(assessment, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    _restrict(path)
    return path


def export_assessment_csv(assessment: Dict[str, object], path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    checks = assessment.get("checks", [])
    fields = ("assessment_id", "assessed_at", "tool_version", "definition_version", "score",
              "check_id", "domain", "title", "description", "outcome", "severity", "weight",
              "reason", "evidence", "expected_state", "data_sources", "limitations",
              "remediation", "verification")
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for item in checks:
            check = item.get("check", {})
            writer.writerow({
                "assessment_id": assessment.get("id", ""),
                "assessed_at": assessment.get("assessed_at", ""),
                "tool_version": assessment.get("tool_version", ""),
                "definition_version": assessment.get("definition_version", ""),
                "score": assessment.get("score") if assessment.get("score") is not None else "",
                "check_id": check.get("id", ""), "domain": check.get("domain", ""),
                "title": check.get("title", ""), "description": check.get("description", ""),
                "outcome": item.get("outcome", ""), "severity": check.get("severity", ""),
                "weight": check.get("weight", ""), "reason": item.get("reason", ""),
                "evidence": " | ".join(str(value) for value in item.get("evidence", [])),
                "expected_state": check.get("expected_state", ""),
                "data_sources": " | ".join(str(value) for value in check.get("data_sources", [])),
                "limitations": check.get("limitations", ""), "remediation": check.get("remediation", ""),
                "verification": check.get("verification", ""),
            })
    _restrict(path)
    return path


def _restrict(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


__all__ = ["compare_assessments", "export_assessment_csv", "export_assessment_json"]
