"""Assisted Fail2ban configuration wizard.

The wizard is **advisory by default**. It never edits files, never restarts a
service and never touches sshd_config or the firewall unless *all* of these are
true:

  1. ``AUREON_ALLOW_F2B_WRITES=1`` (or ``allow_fail2ban_writes = true``)
  2. the caller passes ``confirmed=True``
  3. the proposed file validates with ``fail2ban-client -t``

Writes are restricted to a dedicated, distribution-appropriate drop-in file
(``jail.d/aureon-sshd.local``) so existing configuration is preserved and the
change is trivially reversible by removing one file.
"""

from __future__ import annotations

import difflib
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import shutil

from ..util import Result, which
from .detect import Fail2banStatus, JailInfo

DROPIN_NAME = "aureon-sshd.local"

POLICY_PRESETS: Dict[str, Dict[str, object]] = {
    "conservative": {"maxretry": 6, "findtime": 600, "bantime": 3600},
    "balanced": {"maxretry": 5, "findtime": 600, "bantime": 3600},
    "strict": {"maxretry": 3, "findtime": 600, "bantime": 86400},
}

POLICY_NOTES = {
    "conservative": "fewer false positives on busy networks; longer ban for a single offender",
    "balanced": "fail2ban upstream defaults, a sensible starting point",
    "strict": "short bantime escalates to recidive; may block legitimate mistyped credentials faster",
}


@dataclass
class PlanStep:
    description: str
    command: str = ""
    reversible: bool = True
    risk: str = "low"


@dataclass
class WizardPlan:
    generated_at: datetime
    distro: str
    package_manager: str
    ssh_port: str
    ssh_port_source: str
    backend: str
    log_backend: str
    current_jail: Optional[JailInfo]
    policy: str
    ignoreip: List[str]
    admin_ip: Optional[str]
    admin_ip_warning: str
    values: Dict[str, object]
    dropin_path: str
    content: str
    steps: List[PlanStep]
    warnings: List[str] = field(default_factory=list)
    blockers: List[str] = field(default_factory=list)

    @property
    def safe_to_apply(self) -> bool:
        return not self.blockers


@dataclass
class ApplyResult:
    applied: bool
    changed_files: List[str] = field(default_factory=list)
    backups: List[str] = field(default_factory=list)
    validation: str = ""
    errors: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# environment detection
# ---------------------------------------------------------------------------
def detect_package_manager() -> Tuple[str, str]:
    for candidate, manager in (
        ("apt-get", "apt (Debian/Ubuntu)"),
        ("dnf", "dnf (RHEL/Fedora/Rocky)"),
        ("yum", "yum (RHEL/CentOS legacy)"),
        ("pacman", "pacman (Arch)"),
        ("zypper", "zypper (openSUSE)"),
        ("apk", "apk (Alpine)"),
    ):
        if which(candidate):
            return candidate, manager
    return "", "unknown"


def detect_distro() -> str:
    try:
        with open("/etc/os-release", "r", encoding="utf-8", errors="replace") as handle:
            values = {}
            for line in handle:
                if "=" in line:
                    key, _, value = line.partition("=")
                    values[key.strip()] = value.strip().strip('"')
            return values.get("PRETTY_NAME") or values.get("NAME") or "unknown"
    except OSError:
        return "unknown"


def detect_ssh_port() -> Tuple[str, str]:
    """Find the real SSH port, including non-standard setups.

    Order of preference: explicit ``Port`` in sshd_config (last one wins, as
    sshd does), then the effective sshd socket (``ss``/systemd), then 22.
    """
    candidates = ("/etc/ssh/sshd_config", "/usr/local/etc/ssh/sshd_config")
    for candidate in candidates:
        path = Path(candidate)
        if not path.exists():
            continue
        port = None
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                for raw in handle:
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(None, 1)
                    if len(parts) == 2 and parts[0].lower() == "port":
                        value = parts[1].split("#")[0].strip()
                        if value.isdigit():
                            port = value
        except OSError:
            continue
        if port:
            return port, candidate
    return "22", "default (no explicit Port directive found)"


def detect_admin_ip() -> Tuple[Optional[str], str]:
    """Best-effort detection of the current SSH client address.

    Fails closed: when the address cannot be determined the caller is warned,
    because an unknown address is exactly the situation where a wrong
    ``ignoreip`` can lock an administrator out.
    """
    env_client = os.environ.get("SSH_CLIENT") or os.environ.get("SSH_CONNECTION")
    if env_client:
        return env_client.split()[0], "SSH_CLIENT environment variable"
    return None, (
        "could not determine the originating client address (SSH_CLIENT not set); "
        "verify manually before applying"
    )


def detect_log_backend(status: Optional[Fail2banStatus]) -> str:
    if status and status.journal_available and not status.log_readable:
        return "systemd"
    if os.path.exists("/var/log/fail2ban.log"):
        return "auto"
    if status and status.log_file.startswith("journal"):
        return "systemd"
    return "auto"


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------
def render_dropin(
    jail: str,
    backend: str,
    port: str,
    logpath: str,
    values: Dict[str, object],
    ignoreip: List[str],
) -> str:
    lines = [
        "# Managed by AUREON Console (António Lourenço Ferreira)",
        "# Created with the assisted configuration wizard. Remove this file to revert.",
        f"[{jail}]",
        "enabled  = true",
        f"backend  = {backend}",
        f"port     = {port}",
        f"logpath  = {logpath}",
        f"maxretry = {values['maxretry']}",
        f"findtime = {values['findtime']}",
        f"bantime  = {values['bantime']}",
    ]
    if ignoreip:
        lines.append(f"ignoreip = {' '.join(ignoreip)}")
    lines.append("")
    return "\n".join(lines)


def build_plan(
    status: Fail2banStatus,
    policy: str = "balanced",
    ignoreip: Optional[List[str]] = None,
    ssh_port: Optional[str] = None,
    backend: Optional[str] = None,
) -> WizardPlan:
    now = datetime.now().astimezone()
    binary, manager = detect_package_manager()
    detected_port, port_source = detect_ssh_port()
    port = ssh_port or detected_port or status.ssh_port
    admin_ip, admin_source = detect_admin_ip()

    jail_name = status.ssh_jail.name if status.ssh_jail else "sshd"
    log_backend = backend or detect_log_backend(status)
    logpath = _resolve_logpath(status, jail_name)

    ignore = list(ignoreip or [])
    if status.ssh_jail and status.ssh_jail.ignoreip and not ignore:
        ignore = [item for item in status.ssh_jail.ignoreip]
    if "127.0.0.1/8" not in ignore and "::1/128" not in ignore:
        ignore = ignore + ["127.0.0.1/8", "::1/128"]

    preset = dict(POLICY_PRESETS.get(policy, POLICY_PRESETS["balanced"]))
    if status.ssh_jail:
        if status.ssh_jail.maxretry is not None and not ssh_port:
            preset["maxretry"] = status.ssh_jail.maxretry
        if status.ssh_jail.findtime is not None:
            preset["findtime"] = status.ssh_jail.findtime
        if status.ssh_jail.bantime is not None:
            preset["bantime"] = status.ssh_jail.bantime

    dropin_dir = Path(status.config_dir or "/etc/fail2ban") / "jail.d"
    dropin_path = dropin_dir / DROPIN_NAME
    content = render_dropin(jail_name, log_backend, port, logpath, preset, ignore)

    warnings: List[str] = []
    blockers: List[str] = []

    if admin_ip is None:
        warnings.append(
            "The originating client address could not be determined. Add your own public address "
            "to ignoreip manually if you are certain of it; never add a whole network."
        )
    else:
        warnings.append(f"Detected admin address {admin_ip} ({admin_source}). It is NOT added automatically.")
    if _is_network_like(ignore):
        warnings.append("ignoreip contains broad entries; every excluded address is never blocked by this jail.")
    if policy not in POLICY_PRESETS:
        warnings.append(f"unknown policy {policy!r}; falling back to 'balanced'")
    if not status.installed:
        blockers.append("Fail2ban is not installed: install it first (no change is performed automatically).")
    if status.service_state == "failed":
        warnings.append("fail2ban.service is currently failed; investigate before applying changes.")
    if port_source.startswith("default"):
        warnings.append("No explicit Port directive found in sshd_config: assuming 22. Verify the real port.")

    steps = [
        PlanStep(
            description=f"Write drop-in {dropin_path}",
            command=f"install -m 0644 <generated> {dropin_path}",
            risk="low",
        ),
        PlanStep(
            description="Validate configuration",
            command="fail2ban-client -t",
            risk="low",
        ),
        PlanStep(
            description="Reload Fail2ban (applies new jail without dropping existing bans)",
            command="systemctl reload fail2ban  # or: fail2ban-client reload",
            risk="medium",
        ),
        PlanStep(
            description="Verify final state",
            command="fail2ban-client status sshd",
            risk="low",
        ),
    ]
    if not status.installed and binary:
        steps.insert(
            0,
            PlanStep(
                description=f"Install Fail2ban via {manager}",
                command=f"{binary} install fail2ban",
                reversible=False,
                risk="high",
            ),
        )

    return WizardPlan(
        generated_at=now,
        distro=detect_distro(),
        package_manager=manager,
        ssh_port=port,
        ssh_port_source=port_source,
        backend=log_backend,
        log_backend=log_backend,
        current_jail=status.ssh_jail,
        policy=policy if policy in POLICY_PRESETS else "balanced",
        ignoreip=ignore,
        admin_ip=admin_ip,
        admin_ip_warning=admin_source,
        values=preset,
        dropin_path=str(dropin_path),
        content=content,
        steps=steps,
        warnings=warnings,
        blockers=blockers,
    )


def _resolve_logpath(status: Fail2banStatus, jail: str) -> str:
    if status.ssh_jail and status.ssh_jail.logpath:
        return " ".join(status.ssh_jail.logpath)
    if os.path.exists("/var/log/auth.log"):
        return "/var/log/auth.log"
    if os.path.exists("/var/log/secure"):
        return "/var/log/secure"
    if status.log_readable:
        return status.log_file
    return "/var/log/auth.log"


def _is_network_like(entries: List[str]) -> bool:
    """True when ignoreip contains CIDRs wider than a single host."""
    for entry in entries:
        if "/" not in entry:
            continue
        prefix = entry.split("/", 1)[0]
        if prefix in ("127.0.0.1", "::1"):
            continue
        if ":" in prefix:            # IPv6 network
            return True
        if prefix.count(".") == 3:    # IPv4 /24 or wider
            return True
    return False


def diff_plan(plan: WizardPlan) -> str:
    """Unified diff between the effective state and the proposal.

    For a drop-in file the "current" content is the existing file when present,
    otherwise an empty file - i.e. the diff shows exactly what would be added.
    """
    path = Path(plan.dropin_path)
    current = ""
    if path.exists():
        try:
            current = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            current = ""
    diff = difflib.unified_diff(
        current.splitlines(),
        plan.content.splitlines(),
        fromfile=f"{path} (current)",
        tofile=f"{path} (proposed)",
        lineterm="",
    )
    return "\n".join(diff)


# ---------------------------------------------------------------------------
# application (opt-in, validated, backed up)
# ---------------------------------------------------------------------------
def apply_plan(plan: WizardPlan, confirmed: bool = False, allow_writes: bool = False) -> ApplyResult:
    result = ApplyResult(applied=False)
    if not confirmed:
        result.errors.append("refused: no explicit confirmation was provided")
        return result
    if not allow_writes:
        result.errors.append(
            "refused: writes are disabled. Set allow_fail2ban_writes = true in the AUREON config "
            "or AUREON_ALLOW_F2B_WRITES=1, then re-run."
        )
        return result
    if not plan.safe_to_apply:
        result.errors.append("refused: the plan has unresolved blockers")
        result.errors.extend(plan.blockers)
        return result

    target = Path(plan.dropin_path)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_dir = Path("/var/backups/aureon")
    try:
        backup_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        result.errors.append(f"cannot create backup directory: {exc}")
        return result

    if target.exists():
        backup = backup_dir / f"{target.name}.{stamp}.bak"
        try:
            shutil.copy2(target, backup)
            os.chmod(backup, 0o600)
            result.backups.append(str(backup))
        except OSError as exc:
            result.errors.append(f"cannot back up {target}: {exc}")
            return result

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(plan.content, encoding="utf-8")
        os.chmod(target, 0o644)
        result.changed_files.append(str(target))
    except OSError as exc:
        result.errors.append(f"cannot write {target}: {exc}")
        return result

    validation = validate_config()
    result.validation = validation.value or "" if validation.available else (validation.error or "not run")
    if not validation.available or (validation.value or "").strip() != "OK":
        result.errors.append(f"configuration validation failed: {result.validation}")
        result.notes.append(f"restore with: cp {result.backups[-1] if result.backups else '(no backup)'} {target}")
        return result

    reload_result = reload_service()
    if not reload_result.available:
        result.notes.append(f"service reload not performed: {reload_result.error}")
    result.applied = True
    result.notes.append("verify with: fail2ban-client status sshd")
    return result


def validate_config() -> Result:
    binary = which("fail2ban-client")
    if not binary:
        return Result.unavailable("fail2ban-client", "fail2ban-client not installed")
    from ..util import run

    res = run([binary, "-t"], timeout=25.0)
    if res.ok:
        text = res.stdout.strip() or "OK"
        return Result.ok_result(text.splitlines()[-1][:120], "fail2ban-client -t")
    return Result(None, "fail2ban-client -t", "error", (res.stderr or "validation failed").strip()[:200])


def reload_service() -> Result:
    systemctl = which("systemctl")
    if not systemctl:
        return Result.unavailable("systemctl", "systemctl not available")
    from ..util import run

    res = run([systemctl, "reload", "fail2ban"], timeout=20.0)
    if res.ok:
        return Result.ok_result("reloaded", "systemctl reload fail2ban")
    return Result(None, "systemctl reload fail2ban", "error", (res.stderr or res.stdout).strip()[:200])


def rollback(plan: WizardPlan, result: ApplyResult) -> ApplyResult:
    """Restore the file captured before the change."""
    out = ApplyResult(applied=False)
    if not result.backups:
        out.errors.append("no backup recorded for this change")
        return out
    backup = Path(result.backups[-1])
    if not backup.exists():
        out.errors.append(f"backup missing: {backup}")
        return out
    try:
        shutil.copy2(backup, Path(plan.dropin_path))
        out.applied = True
        out.notes.append(f"restored {plan.dropin_path} from {backup}")
    except OSError as exc:
        out.errors.append(str(exc))
    return out
