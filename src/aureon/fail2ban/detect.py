"""Fail2ban detection and status inspection.

Everything here is read-only. The distinction that matters, and that AUREON
always surfaces, is between:

  * *installed*  - the package/files exist
  * *active*     - the daemon is running
  * *enabled*    - it will start at boot
  * *operational*- jails exist, a log backend can be read and bans are visible

A running service with no working jail is reported as a problem, not as
success.
"""

from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..util import Result, read_text, which

F2B_BINARIES = ("fail2ban-client", "fail2ban-server")
F2B_CONFIG_DIRS = ("/etc/fail2ban", "/usr/local/etc/fail2ban", "/usr/local/fail2ban", "/etc/fail2ban.d")
VERSION_FILES = ("/etc/fail2ban/version", "/usr/local/etc/fail2ban/version")
LOG_CANDIDATES = (
    "/var/log/fail2ban.log",
    "/usr/local/var/log/fail2ban.log",
)
AUTH_LOG_CANDIDATES = (
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/messages",
)

_SECTION_RE = re.compile(r"^\[(?P<name>[A-Za-z0-9_.+-]+)\]\s*$")
_INI_LINE_RE = re.compile(r"^\s*(?P<key>[A-Za-z0-9_]+)\s*=\s*(?P<value>.*?)\s*$")


@dataclass
class JailInfo:
    name: str
    enabled: Optional[bool] = None
    backend: str = ""
    logpath: List[str] = field(default_factory=list)
    port: str = ""
    filter: str = ""
    maxretry: Optional[int] = None
    findtime: Optional[int] = None
    bantime: Optional[int] = None
    ignoreip: List[str] = field(default_factory=list)
    action: List[str] = field(default_factory=list)
    file_origin: str = ""
    runtime: bool = False       # seen by the running daemon
    currently_banned: int = 0
    currently_failed: Optional[int] = None
    total_banned: Optional[int] = None

    @property
    def status(self) -> str:
        if self.enabled is False:
            return "disabled"
        if self.runtime:
            return "running"
        if self.enabled:
            return "configured but not active"
        return "unknown"


@dataclass
class Fail2banStatus:
    installed: bool = False
    version: str = ""
    client_path: str = ""
    service_state: str = "unknown"      # active | inactive | failed | not-found | unknown
    service_enabled: Optional[bool] = None
    service_known: bool = False
    backend: str = ""
    dbfile: str = ""
    config_files: List[str] = field(default_factory=list)
    config_dir: str = ""
    jails: List[JailInfo] = field(default_factory=list)
    banned_ips: Dict[str, List[Dict[str, str]]] = field(default_factory=dict)
    banned_total: int = 0
    log_file: str = ""
    log_readable: bool = False
    journal_available: bool = False
    warnings: List[str] = field(default_factory=list)
    problems: List[str] = field(default_factory=list)
    root_required: bool = False
    client_error: str = ""

    _ssh_jail: Optional[JailInfo] = field(default=None, repr=False)

    @property
    def ssh_jail(self) -> Optional[JailInfo]:
        """The jail that protects SSH, resolved from the loaded jail list."""
        if self._ssh_jail is not None:
            return self._ssh_jail
        return _find_ssh_jail(self.jails)

    @ssh_jail.setter
    def ssh_jail(self, value: Optional[JailInfo]) -> None:
        self._ssh_jail = value

    @property
    def ssh_port(self) -> str:
        jail = self.ssh_jail
        return jail.port if jail and jail.port else "22"

    def jail(self, name: str) -> Optional[JailInfo]:
        for item in self.jails:
            if item.name == name:
                return item
        return None


# ---------------------------------------------------------------------------
# configuration parsing
# ---------------------------------------------------------------------------
def parse_jail_config(path: Path) -> Tuple[Dict[str, Dict[str, object]], List[str]]:
    """Parse a fail2ban INI file into ``{section: {key: value}}``.

    Only the first value of a repeated key is kept (fail2ban itself resolves
    the effective value through include files; AUREON reports what it can see
    and names the file it came from).
    """
    sections: Dict[str, Dict[str, object]] = {}
    includes: List[str] = []
    current: Optional[str] = None
    text = read_text(path)
    if text is None:
        return sections, includes
    pending = ""
    for raw in text.splitlines():
        line = pending + raw
        pending = ""
        if line.rstrip().endswith("\\"):
            pending = line.rstrip()[:-1]
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        match = _SECTION_RE.match(stripped)
        if match:
            current = match.group("name")
            sections.setdefault(current, {})
            continue
        if current is None:
            continue
        if stripped.lower().startswith(("include", "reader")) and "=" in stripped:
            key, _, value = stripped.partition("=")
            includes.extend(_split_list(value))
            continue
        match = _INI_LINE_RE.match(stripped)
        if not match:
            continue
        key = match.group("key").lower()
        value = match.group("value")
        if key in sections[current]:
            existing = sections[current][key]
            if isinstance(existing, list):
                existing.append(value)
            else:
                sections[current][key] = [existing, value]
        else:
            sections[current][key] = value
    return sections, includes


def _split_list(value: str) -> List[str]:
    value = value.strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    return [item.strip().strip("'\"") for item in re.split(r"[,\s]+", value) if item.strip()]


_DURATION_RE = re.compile(r"^\s*(-?\d+)\s*([smhdw]?)\s*$", re.IGNORECASE)
_DURATION_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def _as_int(value) -> Optional[int]:
    """Parse an ini value as a number of seconds.

    Fail2ban accepts plain seconds (``600``) and durations (``10m``, ``1h``,
    ``7d``); ``-1`` means "permanent". Anything unparsable returns None so the UI
    says "default" instead of showing a wrong number.
    """
    if value is None:
        return None
    if isinstance(value, list):      # repeated key: keep the last value seen
        value = value[-1] if value else None
        if value is None:
            return None
    match = _DURATION_RE.match(str(value).split("#")[0])
    if not match:
        return None
    number, unit = match.groups()
    seconds = int(number) * _DURATION_UNITS[unit.lower()]
    return None if seconds < 0 else seconds


def _as_bool(value) -> Optional[bool]:
    text = str(value).strip().lower()
    if text in ("true", "yes", "1", "on"):
        return True
    if text in ("false", "no", "0", "off"):
        return False
    return None


def load_jails(config_dir: Optional[str] = None) -> Tuple[List[JailInfo], List[str], str]:
    """Load jail definitions honouring fail2ban's include order.

    Order used (fail2ban default): ``jail.conf`` then, alphabetically, every
    ``*.conf``/``*.local`` inside ``jail.d``. ``.local`` files override the
    defaults, which is exactly the documented behaviour.
    """
    candidates = [config_dir] if config_dir else list(F2B_CONFIG_DIRS)
    for base in candidates:
        base_path = Path(base)
        if not base_path.is_dir():
            continue
        jail_conf = base_path / "jail.conf"
        jail_local = base_path / "jail.local"
        jail_d = base_path / "jail.d"
        files: List[Tuple[Path, str]] = []
        if jail_conf.exists():
            files.append((jail_conf, "jail.conf"))
        if jail_local.exists():
            files.append((jail_local, "jail.local"))
        if jail_d.is_dir():
            for entry in sorted(jail_d.iterdir(), key=lambda p: p.name):
                if entry.suffix in (".conf", ".local") and entry.is_file():
                    files.append((entry, f"jail.d/{entry.name}"))

        if not files:
            continue

        merged: Dict[str, Dict[str, object]] = {}
        origins: Dict[str, str] = {}
        for path, label in files:
            sections, includes = parse_jail_config(path)
            if includes:
                for include in includes:
                    inc_path = (path.parent / include).resolve()
                    if inc_path.exists() and str(inc_path) not in [str(p) for p, _ in files]:
                        inc_sections, _ = parse_jail_config(inc_path)
                        for name, values in inc_sections.items():
                            merged.setdefault(name, {}).update(values)
                            origins[name] = f"jail.conf -> {include}"
            for name, values in sections.items():
                merged.setdefault(name, {}).update(values)
                origins[name] = label

        # Fail2ban inherits every unset key from [DEFAULT]; doing the same here
        # makes the reported bantime/findtime/maxretry the *effective* values
        # instead of "unknown".
        defaults = dict(merged.get("DEFAULT", {}))

        jails: List[JailInfo] = []
        for name, values in merged.items():
            if not name or name == "DEFAULT":
                continue
            effective = dict(defaults)
            effective.update(values)
            values = effective
            enabled = _as_bool(values.get("enabled"))
            if enabled is None:
                continue  # a jail definition without `enabled` is a template
            logpath = _split_list(values.get("logpath", "")) if values.get("logpath") else []
            if isinstance(values.get("logpath"), list):
                logpath = [item for value in values["logpath"] for item in _split_list(value)]
            jails.append(
                JailInfo(
                    name=name,
                    enabled=enabled,
                    backend=str(values.get("backend", "") or ""),
                    logpath=logpath,
                    port=str(values.get("port", "") or ""),
                    filter=str(values.get("filter", "") or ""),
                    maxretry=_as_int(values.get("maxretry")),
                    findtime=_as_int(values.get("findtime")),
                    bantime=_as_int(values.get("bantime")),
                    ignoreip=_split_list(values.get("ignoreip", "")) if values.get("ignoreip") else [],
                    action=_split_list(values.get("action", "")) if values.get("action") else [],
                    file_origin=origins.get(name, ""),
                )
            )
        return jails, [str(path) for path, _ in files], base
    return [], [], ""


# ---------------------------------------------------------------------------
# daemon interaction
# ---------------------------------------------------------------------------
class Fail2banClient:
    """Thin, read-only wrapper around ``fail2ban-client``.

    ``fail2ban-client`` normally requires root (the socket lives in
    /var/run/fail2ban with restrictive permissions). When AUREON is not root,
    every call returns a ``denied`` result instead of failing silently.
    """

    def __init__(self, ctx=None) -> None:
        self.ctx = ctx
        self.binary = which("fail2ban-client")

    @property
    def installed(self) -> bool:
        return bool(self.binary)

    def call(self, *args: str, timeout: Optional[float] = None) -> Result:
        if not self.binary:
            return Result.unavailable("fail2ban-client", "fail2ban-client not installed")
        argv = [self.binary] + [str(a) for a in args]
        if self.ctx is not None:
            res = self.ctx.run(argv, timeout=timeout or self.ctx.config.command_timeout)
        else:  # pragma: no cover - direct use without context
            from ..util import run

            res = run(argv, timeout=timeout or 8.0)
        if res.ok:
            return Result.ok_result(res.stdout.strip(), "fail2ban-client")
        message = (res.stderr or res.stdout or "").strip()
        lowered = message.lower()
        if "permission denied" in lowered or "must be root" in lowered or "access denied" in lowered:
            return Result(None, "fail2ban-client", "denied", message[:160] or "root privileges required")
        if res.timed_out:
            return Result(None, "fail2ban-client", "timeout", "fail2ban-client timed out")
        return Result(None, "fail2ban-client", "error", message[:160] or f"exit {res.returncode}")

    def version(self) -> Result:
        return self.call("version")

    def status(self) -> Result:
        return self.call("status")

    def server_status(self) -> Result:
        return self.call("-d")

    def jails(self) -> Result:
        return self.call("status")

    def banned_in_jail(self, jail: str) -> Result:
        if not re.fullmatch(r"[A-Za-z0-9_.+-]{1,64}", jail or ""):
            return Result(None, "fail2ban-client", "error", "invalid jail name")
        return self.call("status", jail)

    def banned_ips(self, jail: str) -> Result:
        return self.call("get", jail, "banned")

    def unbanned_ips(self, jail: str) -> Result:
        return self.call("get", jail, "unbanned")

    def jail_config(self, jail: str) -> Result:
        return self.call("get", jail, "bantime")

    # -- write operations (disabled unless explicitly enabled) -----------
    def set_ban(self, jail: str, ip: str) -> Result:
        return Result(None, "fail2ban-client", "error", "ban operations are disabled in this release")

    def set_unban(self, jail: str, ip: str) -> Result:
        return Result(None, "fail2ban-client", "error", "unban operations are disabled in this release")


# ---------------------------------------------------------------------------
# status assembly
# ---------------------------------------------------------------------------
def detect_status(client: Fail2banClient, ctx=None) -> Fail2banStatus:
    status = Fail2banStatus()
    status.installed = bool(which("fail2ban-server")) or bool(client.binary)
    status.client_path = client.binary or ""

    for path in VERSION_FILES:
        text = read_text(path, 256)
        if text:
            status.version = text.strip().splitlines()[0][:80]
            break
    if not status.version and client.installed:
        res = client.version()
        if res.available and res.value:
            status.version = str(res.value).splitlines()[0][:80]

    jails, files, base = load_jails()
    status.config_dir = base
    status.config_files = files
    status.jails = jails

    _service_state(status, ctx)
    _log_state(status, ctx)

    if client.installed:
        res = client.status()
        if res.available:
            text = str(res.value or "")
            for line in text.splitlines():
                if "Currently failed" in line:
                    status.backend = "systemd-backend" if "systemd" in text else "pyinotify/auto"
            if "Currently failed" in text:
                status.backend = status.backend or "auto"
        elif res.availability == "denied":
            status.root_required = True
            status.client_error = res.error or "root privileges required"
            status.warnings.append("fail2ban-client requires root to query live state")
        else:
            status.client_error = res.error or "unknown error"
            status.warnings.append(f"fail2ban-client failed: {res.error}")

        runtime_jails = client.jails()
        if runtime_jails.available:
            for name in _runtime_jail_names(str(runtime_jails.value or "")):
                jail = status.jail(name)
                if jail is None:
                    jail = JailInfo(name=name, enabled=None)
                    status.jails.append(jail)
                jail.runtime = True

        for jail in status.jails:
            if not jail.runtime:
                continue
            detail = client.banned_in_jail(jail.name)
            if not detail.available:
                continue
            text = str(detail.value or "")
            match = re.search(r"Currently banned:\s*(\d+)", text)
            if match:
                jail.currently_banned = int(match.group(1))
            match = re.search(r"Total banned:\s*(\d+)", text)
            if match:
                jail.total_banned = int(match.group(1))
            match = re.search(r"Currently failed:\s*(\d+)", text)
            if match:
                jail.currently_failed = int(match.group(1))

            ip_result = client.banned_ips(jail.name)
            if ip_result.available:
                entries = parse_banned_list(str(ip_result.value or ""))
                status.banned_ips[jail.name] = entries
            elif ip_result.availability != "unavailable":
                status.warnings.append(f"banned IP list unavailable for jail {jail.name}: {ip_result.error}")

    status.banned_total = sum(len(v) for v in status.banned_ips.values())
    status.ssh_jail = _find_ssh_jail(status.jails)
    _validate(status)
    return status


_IP_TOKEN_RE = re.compile(r"[0-9a-fA-F:.]{3,45}")


def parse_banned_list(output: str) -> List[Dict[str, str]]:
    """Parse the output of ``fail2ban-client get <jail> banned``.

    Fail2ban has returned this in several shapes:

    * one address per line (``1.2.3.4\n5.6.7.8``)
    * a Python list literal on a single line (``['1.2.3.4', '5.6.7.8']``)
    * address plus a relative timestamp (``1.2.3.4   since 3 minutes ago``)

    All three are handled; the address itself is validated, so no text that is
    not an IP can be mistaken for a banned address.
    """
    import ipaddress

    entries: List[Dict[str, str]] = []
    seen = set()
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        for token in _IP_TOKEN_RE.findall(line):
            token = token.strip("\'\",")
            try:
                ipaddress.ip_address(token)
            except ValueError:
                continue
            if token in seen:
                continue
            seen.add(token)
            remainder = line.split(token, 1)[-1].strip(" '\",")
            entries.append({"ip": token, "when": remainder[:60]})
    return entries


def _runtime_jail_names(output: str) -> List[str]:
    """Extract the loaded jail names from ``fail2ban-client status``.

    The output is a tree, so the line is prefixed (``|`- Jail list:  a, b``);
    the match must therefore search rather than anchor at the start.
    """
    names: List[str] = []
    for line in output.splitlines():
        match = re.search(r"Jail list:\s*(.*)", line)
        if match:
            names = [item.strip() for item in match.group(1).split(",") if item.strip()]
    return names


def _find_ssh_jail(jails: List[JailInfo]) -> Optional[JailInfo]:
    for candidate in ("sshd", "ssh"):
        for jail in jails:
            if jail.name == candidate:
                return jail
    for jail in jails:
        if "ssh" in jail.name.lower():
            return jail
    return None


def _run(ctx, argv, timeout: float = 6.0):
    """Run a command through the collection context when available."""
    if ctx is not None:
        return ctx.run(argv, timeout=timeout)
    from ..util import run

    return run(argv, timeout=timeout)


def _service_state(status: Fail2banStatus, ctx) -> None:
    systemctl = which("systemctl")
    if not systemctl:
        status.service_state = "unknown"
        return
    res = _run(ctx, [systemctl, "is-active", "fail2ban"])
    state = (res.stdout or "").strip().splitlines()
    status.service_state = state[0] if state else "unknown"
    status.service_known = status.service_state not in ("", "unknown", "not-found")
    enabled = _run(ctx, [systemctl, "is-enabled", "fail2ban"])
    text = (enabled.stdout or "").strip()
    if text in ("enabled", "enabled-runtime", "static", "indirect"):
        status.service_enabled = True
    elif text == "disabled":
        status.service_enabled = False
    else:
        status.service_enabled = None


def _log_state(status: Fail2banStatus, ctx) -> None:
    for candidate in LOG_CANDIDATES:
        path = Path(candidate)
        if path.exists():
            status.log_file = candidate
            status.log_readable = os.access(path, os.R_OK)
            if not status.log_readable:
                status.warnings.append(f"{candidate} exists but is not readable by this user")
            break
    journalctl = which("journalctl")
    if journalctl:
        status.journal_available = True
        if not status.log_readable:
            status.log_file = status.log_file or "journal:fail2ban.service"


def _validate(status: Fail2banStatus) -> None:
    """Turn observed facts into explicit problems/warnings."""
    if not status.installed:
        status.problems.append("Fail2ban is not installed on this system")
        return
    if status.service_state == "failed":
        status.problems.append("fail2ban.service is in a failed state")
    elif status.service_state not in ("active",):
        status.warnings.append(f"fail2ban.service is '{status.service_state}'")
    if status.service_enabled is False:
        status.warnings.append("fail2ban.service is not enabled at boot")
    if status.ssh_jail is None:
        status.problems.append("no SSH jail is defined (sshd protection absent)")
    else:
        jail = status.ssh_jail
        if jail.enabled is False:
            status.problems.append(f"SSH jail '{jail.name}' is disabled in the configuration")
        elif jail.runtime:
            if jail.currently_banned == 0 and (jail.total_banned or 0) == 0 and (jail.currently_failed or 0) == 0:
                status.warnings.append(
                    f"jail '{jail.name}' is running but has produced no ban/fail events: "
                    "verify the log path and backend"
                )
        else:
            status.problems.append(f"SSH jail '{jail.name}' is configured but not loaded by the daemon")
    if status.root_required:
        status.warnings.append(
            "live ban list requires root: run `sudo aureon` for full data"
            + (f" ({status.client_error})" if status.client_error else "")
        )
    if not status.log_readable and not status.journal_available:
        status.problems.append("no readable Fail2ban log source was found")
