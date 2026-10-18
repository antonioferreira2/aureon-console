"""GitHub Actions workflow validation.

A YAML syntax error in a workflow makes the whole run fail *before any job is
created*, which is invisible locally and wastes CI minutes. These tests parse
every workflow so the mistake is caught by pytest instead.
"""

from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

WORKFLOWS = sorted((Path(__file__).resolve().parents[1] / ".github" / "workflows").glob("*.yml"))


def test_workflows_exist():
    assert WORKFLOWS, "no workflows found"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_workflow_is_valid_yaml(path: Path):
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    assert "jobs" in document, "a workflow needs jobs"
    assert document.get("on") or document.get(True), "a workflow needs an on: trigger"
    for name, job in document["jobs"].items():
        assert "runs-on" in job, f"job {name} is missing runs-on"
        assert "steps" in job and job["steps"], f"job {name} has no steps"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_step_has_a_name_or_uses(path: Path):
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    for job_name, job in document["jobs"].items():
        for step in job["steps"]:
            assert "uses" in step or "run" in step, f"{job_name}: step without uses/run"
