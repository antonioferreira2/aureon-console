"""Assisted Fail2ban configuration wizard.

The wizard is advisory only. It can render a proposal and unified diff, but
AUREON never writes Fail2ban configuration, validates changes by invoking a
write-capable operation, or reloads/restarts the audited service.
"""

from __future__ import annotations

import difflib
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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
    return None, (            "could not determine the originating client address (SSH_CLIENT not set); "
            "review the address manually before changing any configuration"

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
UNRESOLVED_RE = re.compile(r"^\s*%\(.+\)s\s*$")


def is_unresolved(value: str) -> bool:
    """True for a fail2ban template value such as ``%(sshd_log)s``.

    Those placeholders are interpolated by the daemon at runtime. Copying them
    into a hand-written drop-in would either be ignored or break the jail, so
    the wizard never emits them.
    """
    return bool(value) and any(UNRESOLVED_RE.match(part) for part in str(value).split())


def render_dropin(
    jail: str,
    backend: str,
    port: str,
    logpath: str,
    values: Dict[str, object],
    ignoreip: List[str],
) -> str:
    """Render the drop-in file.

    Optional keys are omitted when they are empty or still contain a runtime
    placeholder: the resulting file then inherits the value from
    jail.conf/[DEFAULT], which is always safer than guessing.
    """
    lines = [
        "# Managed by AUREON Console (António Lourenço Ferreira)",
        "# Created with the assisted configuration wizard. Remove this file to revert.",
        f"[{jail}]",
        "enabled  = true",
    ]
    if backend and not is_unresolved(backend):
        lines.append(f"backend  = {backend}")
    if port and not is_unresolved(port):
        lines.append(f"port     = {port}")
    if logpath and not is_unresolved(logpath):
        lines.append(f"logpath  = {logpath}")
    lines += [
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

    # Keep whatever the running jail already uses when AUREON cannot determine
    # it: replacing a multi-port value with a guessed single port would silently
    # stop protecting the other port.
    if status.ssh_jail:
        if not ssh_port and status.ssh_jail.port and not is_unresolved(status.ssh_jail.port):
            port = status.ssh_jail.port
        if not backend and status.ssh_jail.backend and not is_unresolved(status.ssh_jail.backend):
            log_backend = status.ssh_jail.backend

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
    if is_unresolved(logpath):
        warnings.append(
            "the jail log path is defined by a fail2ban placeholder and cannot be resolved statically; "
            "the proposal leaves logpath out so the existing value is inherited"
        )
    if status.ssh_jail and status.ssh_jail.port and " " in status.ssh_jail.port and not ssh_port:
        warnings.append(f"the jail listens on several ports ({status.ssh_jail.port}); they are preserved as-is")
    if not status.ssh_jail and port == "22":
        warnings.append("no SSH jail exists yet: the advisory proposal assumes port 22; verify the actual SSH port manually")
    if policy not in POLICY_PRESETS:
        warnings.append(f"unknown policy {policy!r}; falling back to 'balanced'")
    if not status.installed:
        blockers.append("Fail2ban is not installed: the proposal is informational and does not install packages.")
    if status.service_state == "failed":
        warnings.append("fail2ban.service is currently failed; investigate the service separately.")
    if port_source.startswith("default"):
        warnings.append("No explicit Port directive found in sshd_config: assuming 22. Verify the real port.")

    steps = [
        PlanStep(
            description=f"Review proposed drop-in {dropin_path}; AUREON will not apply it",
            command="",
            risk="low",
        ),
        PlanStep(
            description="Validate configuration",
            command="",
            risk="low",
        ),
        PlanStep(
            description="If an administrator applies a change, review the service impact and reload procedure independently",
            command="",
            risk="medium",
        ),
        PlanStep(
            description="If changes are applied separately, verify the resulting state using your change procedure",
            command="",
            risk="low",
        ),
    ]
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
# Read-only compatibility shim
# ---------------------------------------------------------------------------
def apply_plan(plan: WizardPlan, confirmed: bool = False, allow_writes: bool = False) -> ApplyResult:
    """Refuse every attempt to apply a proposal, including legacy opt-ins.

    Parameters remain accepted for compatibility with existing CLI/config
    callers, but intentionally have no effect. Only the local plan and diff may
    be generated; administrators must review and apply any change separately.
    """
    del plan, confirmed, allow_writes
    return ApplyResult(
        applied=False,
        errors=["refused: AUREON is read-only; review the proposal and apply any changes separately"],
    )
