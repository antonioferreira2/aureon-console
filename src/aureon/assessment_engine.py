"""Read-only collection and evaluation for the hardening assessment.

Commands are fixed query vectors; no shell, privilege escalation, package
manager mutation, service control, or audited-host writes are used here.
"""

from __future__ import annotations

import glob
import json
import os
import re
import shlex
import stat
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .hardening import CHECKS, CheckResult, Outcome, _result
from .util import Availability, which


def _read(path: str, limit: int = 256_000) -> Tuple[Optional[str], str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(limit), ""
    except PermissionError:
        return None, f"permission denied reading {path}"
    except OSError as exc:
        return None, f"{path} unavailable: {exc.strerror or exc}"


def _command(ctx, argv: List[str], timeout: Optional[float] = None):
    return ctx.run(argv, timeout=timeout or ctx.config.command_timeout)


def _simple(check_id: str, outcome: Outcome, evidence=(), reason="") -> CheckResult:
    return _result(check_id, outcome, evidence=evidence, reason=reason)


def _sshd_settings(ctx) -> Tuple[Dict[str, str], str]:
    binary = which("sshd")
    if not binary:
        return {}, "OpenSSH server executable not found; effective SSH settings are unverified"
    result = _command(ctx, [binary, "-T"])
    if result.timed_out:
        return {}, "sshd -T timed out"
    if result.truncated:
        return {}, "sshd -T output exceeded its collection limit; effective configuration is incomplete"
    if not result.ok:
        error = (result.stderr or "").strip()
        if "permission denied" in error.lower() or result.returncode in (13, 126):
            return {}, "permission denied reading effective sshd configuration"
        return {}, "sshd -T failed; effective configuration is unavailable or invalid"
    settings = {}
    for line in result.stdout.splitlines():
        key, _, value = line.strip().partition(" ")
        if key:
            settings[key.lower()] = value.strip().lower()
    return settings, ""


def _sshd_settings_from_output(output: str) -> Dict[str, str]:
    settings = {}
    for line in output.splitlines():
        key, _, value = line.strip().partition(" ")
        if key:
            settings[key.lower()] = value.strip().lower()
    return settings


def _discover_ssh_match_blocks(config_file: str = "/etc/ssh/sshd_config"):
    """Read a bounded sshd Include tree and return Match directives and gaps."""
    pending = [Path(config_file)]
    visited, matches, gaps = set(), [], []
    while pending:
        path = pending.pop(0)
        identity = str(path)
        if identity in visited:
            continue
        if len(visited) >= 100:
            gaps.append("sshd Include traversal reached the 100-file safety limit")
            break
        visited.add(identity)
        content, error = _read(identity, 256_000)
        if content is None:
            gaps.append(error)
            continue
        if len(content) >= 256_000:
            gaps.append(f"{identity} reached the 256 KiB read limit")
        match_context = []
        in_match = False
        for line_number, line in enumerate(content.splitlines(), 1):
            try:
                fields = shlex.split(line, comments=True, posix=True)
            except ValueError:
                gaps.append(f"could not parse {identity}:{line_number}")
                continue
            if not fields:
                continue
            directive = fields[0].lower()
            if directive == "match":
                match_context = fields[1:]
                in_match = True
                matches.append((identity, line_number, fields[1:]))
            elif directive == "include":
                for pattern in fields[1:]:
                    # OpenSSH resolves relative Include patterns beneath
                    # /etc/ssh; glob() is used only to read matching files.
                    absolute_pattern = pattern if os.path.isabs(pattern) else str(Path(config_file).parent / pattern)
                    matched_paths = sorted(glob.glob(absolute_pattern))
                    if not matched_paths:
                        gaps.append(f"Include pattern at {identity}:{line_number} matched no files")
                    if len(matched_paths) > 100:
                        gaps.append(f"Include pattern at {identity}:{line_number} exceeded the 100-file expansion limit")
                    for match_path in matched_paths[:100]:
                        candidate = Path(match_path)
                        if candidate.is_file() and str(candidate) not in visited:
                            pending.append(candidate)
                    if match_context and matched_paths:
                        gaps.append(f"Conditional Include at {identity}:{line_number} is not fully modeled (Match {' '.join(match_context)})")
    return matches, gaps, visited


def _representative_ssh_context(criteria: List[str]) -> Optional[str]:
    """Build a safe literal -C context; skip wildcards/groups we cannot prove."""
    values = {"user": "root", "host": "localhost", "addr": "127.0.0.1", "laddr": "127.0.0.1", "lport": "22", "rdomain": ""}
    aliases = {"user": "user", "host": "host", "address": "addr", "localaddress": "laddr", "localport": "lport", "rdomain": "rdomain"}
    recognized = {"user", "group", "host", "address", "localaddress", "localport", "rdomain", "all", "invalid-user"}
    index = 0
    while index < len(criteria):
        key = criteria[index].lower()
        index += 1
        if key in {"all", "invalid-user"}:
            if key == "invalid-user":
                return None
            continue
        if key not in recognized or index >= len(criteria):
            return None
        selectors = []
        while index < len(criteria) and criteria[index].lower() not in recognized:
            selectors.extend(criteria[index].split(","))
            index += 1
        # Match Group requires a real local account/group context; wildcard,
        # negated and multi-pattern selectors need operator-specific coverage.
        if key == "group" or len(selectors) != 1:
            return None
        selector = selectors[0]
        if not selector or any(char in selector for char in "!*?[]"):
            return None
        if key == "address":
            if "/" in selector:
                import ipaddress
                try:
                    selector = str(ipaddress.ip_network(selector, strict=False).network_address)
                except ValueError:
                    return None
            values[aliases[key]] = selector
        elif key in aliases:
            values[aliases[key]] = selector
    return ",".join(f"{key}={value}" for key, value in values.items() if value)


def _contains_incomplete_match_context(path: str, line_number: int, files) -> bool:
    """Return true when Match has conditional options the tree scan cannot model."""
    content, error = _read(path, 256_000)
    if content is None or len(content) >= 256_000:
        return True
    lines = content.splitlines()
    for line in lines[line_number:]:
        try:
            fields = shlex.split(line, comments=True, posix=True)
        except ValueError:
            return True
        if not fields:
            continue
        directive = fields[0].lower()
        if directive == "match":
            break
        if directive not in {"include"}:
            # sshd -T -C evaluates the selected context, but doesn't prove
            # every selector overlap or connection identity. Preserve this as
            # incomplete evidence rather than presenting a clean audit.
            return True
        if directive == "include":
            return True
    return False


def _ssh_match_check(ctx, default_settings: Dict[str, str], collection_error: str = "", config_file: str = "/etc/ssh/sshd_config") -> CheckResult:
    binary = which("sshd")
    if not binary or collection_error:
        return _simple("SSH-MATCH-CONTEXTS", Outcome.UNKNOWN, reason=collection_error or "sshd is unavailable; Match-specific policy was not evaluated")
    matches, gaps, files = _discover_ssh_match_blocks(config_file)
    evidence = [f"Read {len(files)} sshd configuration file(s)"]
    if not matches and not gaps:
        return _simple("SSH-MATCH-CONTEXTS", Outcome.PASS, evidence + ["No Match directives found in the default sshd configuration and discovered Include files"], "No Match-specific policy was found in the completely readable default configuration tree.")

    if not matches:
        return _simple("SSH-MATCH-CONTEXTS", Outcome.UNKNOWN, evidence + gaps[:10], "The sshd configuration tree could not be completely inspected; hidden Match directives may exist.")

    weak, sampled, unrepresented = [], 0, []
    blocks = [(path, line_number, criteria) for path, line_number, criteria in matches]
    for path, line_number, criteria in blocks[:20]:
        if _contains_incomplete_match_context(path, line_number, files):
            gaps.append(f"Directives within Match at {path}:{line_number} are not fully modeled")
        context = _representative_ssh_context(criteria)
        if context is None:
            unrepresented.append(f"{path}:{line_number} Match {' '.join(criteria)}")
            continue
        result = _command(ctx, [binary, "-T", "-C", context])
        if result.timed_out or not result.ok or result.truncated:
            gaps.append(f"sshd -T -C failed for Match at {path}:{line_number}")
            continue
        sampled += 1
        settings = _sshd_settings_from_output(result.stdout)
        evidence.append(f"Sampled {path}:{line_number} with -C {context}")
        required_settings = ("permitrootlogin", "passwordauthentication", "maxauthtries", "clientaliveinterval", "clientalivecountmax")
        if any(key not in settings for key in required_settings):
            gaps.append(f"sshd -T -C output omitted one or more assessed settings for Match at {path}:{line_number}")
        root = settings.get("permitrootlogin")
        password = settings.get("passwordauthentication")
        tries = settings.get("maxauthtries")
        interval = settings.get("clientaliveinterval")
        # Judge sampled policy only from sshd's effective output. Raw Match
        # directives can be overridden or shadowed by OpenSSH precedence and
        # must not independently create a confirmed finding.
        if root not in (None, "no"):
            weak.append(f"{path}:{line_number} representative context permits root login ({root})")
        if password == "yes":
            weak.append(f"{path}:{line_number} representative context enables password authentication")
        if tries and tries.isdigit() and int(tries) > 6:
            weak.append(f"{path}:{line_number} representative context has MaxAuthTries {tries}")
        if interval == "0":
            weak.append(f"{path}:{line_number} representative context has no SSH client-alive timeout")
        for key in ("permitrootlogin", "passwordauthentication", "maxauthtries", "clientaliveinterval", "clientalivecountmax"):
            if key in default_settings and key in settings and settings[key] != default_settings[key]:
                evidence.append(f"{path}:{line_number} changes {key} from default context {default_settings[key]} to {settings[key]}")

    if len(matches) > 20:
        gaps.append("Match directive count exceeded the 20-context query limit")
    evidence.extend(f"Not representable as one safe -C sample: {item}" for item in unrepresented[:10])
    evidence.extend(gaps[:10])
    if weak:
        return _simple("SSH-MATCH-CONTEXTS", Outcome.FAIL, evidence + weak[:20], "A sampled Match context demonstrably weakens one or more assessed SSH controls.")

    if sampled != len(blocks) or gaps or unrepresented:
        return _simple("SSH-MATCH-CONTEXTS", Outcome.UNKNOWN, evidence,
                       f"Found {len(blocks)} Match block(s), queried {sampled} representative context(s); at least one context or configuration include could not be fully checked.")
    return _simple("SSH-MATCH-CONTEXTS", Outcome.UNKNOWN, evidence,
                   f"Found {len(blocks)} Match block(s), queried {sampled} representative context(s); remaining wildcard, group, overlapping and real-connection combinations are not proven.")


def _ssh_checks(ctx) -> List[CheckResult]:
    settings, error = _sshd_settings(ctx)
    checks = []
    if error:
        checks.append(_simple("SSH-ROOT-LOGIN", Outcome.UNKNOWN, reason=error))
        for check_id in ("SSH-PASSWORD-AUTH", "SSH-MAX-AUTH-TRIES", "SSH-IDLE-TIMEOUT"):
            checks.append(_simple(check_id, Outcome.UNKNOWN, reason=error))
        checks.append(_ssh_match_check(ctx, {}, error))
        return checks
    root_login = settings.get("permitrootlogin")
    if root_login:
        root_outcome = Outcome.PASS if root_login == "no" else Outcome.FAIL if root_login in {"yes", "prohibit-password", "without-password"} else Outcome.UNKNOWN
        checks.append(_simple("SSH-ROOT-LOGIN", root_outcome,
                              [f"sshd -T reported permitrootlogin {root_login}"],
                              "Root SSH login is disabled." if root_outcome == Outcome.PASS else "Direct root SSH login remains possible or restricted to key authentication." if root_outcome == Outcome.FAIL else "Unrecognized effective PermitRootLogin value."))
    else:
        checks.append(_simple("SSH-ROOT-LOGIN", Outcome.UNKNOWN, reason="sshd -T did not provide permitrootlogin"))

    password = settings.get("passwordauthentication")
    if password in {"yes", "no"}:
        checks.append(_simple("SSH-PASSWORD-AUTH", Outcome.FAIL if password == "yes" else Outcome.PASS,
                              [f"sshd -T reported passwordauthentication {password}"],
                              "Password authentication is enabled; assess the account and MFA policy before changing it." if password == "yes" else "Password authentication is disabled."))
    else:
        checks.append(_simple("SSH-PASSWORD-AUTH", Outcome.UNKNOWN, reason="sshd -T did not provide passwordauthentication"))

    attempts = settings.get("maxauthtries")
    try:
        attempts_n = int(attempts or "")
    except ValueError:
        attempts_n = 0
    if attempts_n:
        checks.append(_simple("SSH-MAX-AUTH-TRIES", Outcome.FAIL if attempts_n > 6 else Outcome.PASS,
                              [f"sshd -T reported maxauthtries {attempts_n}"],
                              "The configured authentication attempt limit exceeds the assessment threshold of 6." if attempts_n > 6 else "The configured authentication attempt limit is at most 6."))
    else:
        checks.append(_simple("SSH-MAX-AUTH-TRIES", Outcome.UNKNOWN, reason="sshd -T did not provide a valid maxauthtries value"))

    interval = settings.get("clientaliveinterval")
    count = settings.get("clientalivecountmax")
    try:
        interval_n, count_n = int(interval or ""), int(count or "")
    except ValueError:
        interval_n = count_n = -1
    if interval_n >= 0 and count_n >= 0:
        # OpenSSH's default count of 3 and interval of 0 means no idle timeout.
        has_timeout = interval_n > 0 and count_n > 0
        checks.append(_simple("SSH-IDLE-TIMEOUT", Outcome.PASS if has_timeout else Outcome.FAIL,
                              [f"sshd -T reported clientaliveinterval {interval_n}", f"sshd -T reported clientalivecountmax {count_n}"],
                              "An SSH idle-session timeout is configured." if has_timeout else "No effective SSH idle-session timeout is configured."))
    else:
        checks.append(_simple("SSH-IDLE-TIMEOUT", Outcome.UNKNOWN, reason="sshd -T did not provide complete client-alive settings"))
    checks.append(_ssh_match_check(ctx, settings))
    return checks


def _account_checks() -> List[CheckResult]:
    text, error = _read("/etc/passwd")
    if text is None:
        uid_check = _simple("ACCOUNT-UID0", Outcome.UNKNOWN, reason=error)
    else:
        uid0 = []
        malformed = 0
        root_seen = False
        for line in text.splitlines():
            fields = line.split(":")
            if len(fields) < 3:
                malformed += 1
                continue
            if fields[0] == "root" and fields[2] == "0":
                root_seen = True
            if fields[2] == "0" and fields[0] != "root":
                uid0.append(fields[0])
        if uid0:
            uid_check = _simple("ACCOUNT-UID0", Outcome.FAIL,
                                ["Additional UID 0 account names: " + ", ".join(uid0[:20])],
                                "Accounts other than root have UID 0; verify their documented purpose and access path.")
        elif malformed or len(text) >= 256_000 or not root_seen:
            uid_check = _simple("ACCOUNT-UID0", Outcome.UNKNOWN, reason="/etc/passwd was malformed, reached the read limit, or did not confirm root UID 0; local UID 0 inventory may be incomplete")
        else:
            uid_check = _simple("ACCOUNT-UID0", Outcome.PASS, ["/etc/passwd contains root with UID 0 and no additional local UID 0 account"], "No additional local UID 0 account was observed; NSS and external identity providers are not queried.")

    observed, unsafe, denied = [], [], []
    sudoers_path = "/etc/sudoers"
    try:
        mode = stat.S_IMODE(os.stat(sudoers_path, follow_symlinks=False).st_mode)
        observed.append(f"{sudoers_path} mode {mode:04o}")
        if mode & 0o022:
            unsafe.append(f"{sudoers_path} mode {mode:04o}")
    except FileNotFoundError:
        pass
    except PermissionError:
        denied.append(sudoers_path)
    except OSError:
        pass
    include_dir = Path("/etc/sudoers.d")
    incomplete = False
    try:
        if include_dir.is_dir():
            for index, path in enumerate(include_dir.iterdir()):
                if index >= 100:
                    incomplete = True
                    break
                try:
                    mode = stat.S_IMODE(os.stat(path, follow_symlinks=False).st_mode)
                except PermissionError:
                    denied.append(str(path))
                    continue
                except OSError:
                    continue
                observed.append(f"{path} mode {mode:04o}")
                if mode & 0o022:
                    unsafe.append(f"{path} mode {mode:04o}")
    except PermissionError:
        denied.append(str(include_dir))
    except OSError:
        pass
    if unsafe:
        sudo_check = _simple("SUDOERS-PERMISSIONS", Outcome.FAIL, observed, "Sudo policy path is group- or world-writable; review ownership and permissions.")
    elif denied or incomplete or not observed:
        sudo_check = _simple("SUDOERS-PERMISSIONS", Outcome.UNKNOWN, observed, "Sudo policy permissions could not be fully inspected." + (" Entry cap exceeded." if incomplete else "") + (" Permission denied: " + ", ".join(denied) if denied else ""))
    else:
        sudo_check = _simple("SUDOERS-PERMISSIONS", Outcome.PASS, observed, "Observed sudo policy paths are not group- or world-writable.")
    login_defs, login_error = _read("/etc/login.defs")
    aging = None
    if login_defs is not None:
        for line in login_defs.splitlines():
            match = re.match(r"^\s*PASS_MAX_DAYS\s+(\d+)\b", line)
            if match:
                aging = int(match.group(1))
    if aging is None:
        aging_check = _simple("ACCOUNT-PASSWORD-AGING", Outcome.UNKNOWN, reason=login_error or "No explicit PASS_MAX_DAYS value was found")
    else:
        aging_check = _simple("ACCOUNT-PASSWORD-AGING", Outcome.UNKNOWN,
                              [f"/etc/login.defs PASS_MAX_DAYS {aging}"],
                              "Observed only the login.defs default; effective account aging and identity-provider policy are not queried.")
    return [uid_check, sudo_check, aging_check]


def _filesystem_checks() -> List[CheckResult]:
    # Inspect metadata only; never open secret/key contents.
    paths = ("/etc/shadow", "/etc/gshadow", "/etc/ssh/ssh_host_ed25519_key", "/etc/ssh/ssh_host_rsa_key")
    seen, bad, denied = [], [], []
    checked_shadow, checked_host_key = False, False
    for path in paths:
        try:
            info = os.stat(path, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except PermissionError:
            denied.append(path)
            continue
        except OSError:
            continue
        mode = stat.S_IMODE(info.st_mode)
        seen.append(f"{path} uid={info.st_uid} mode {mode:04o}")
        # Shadow databases permit the conventional root:shadow 0640 mode;
        # host private keys must be root-owned and private to root.
        if path.endswith(("shadow", "gshadow")):
            checked_shadow = True
            if info.st_uid != 0 or mode & 0o027:
                bad.append(path)
        if "ssh_host_" in path and path.endswith("_key"):
            checked_host_key = True
            if info.st_uid != 0 or mode & 0o077:
                bad.append(path)
    if bad:
        permission = _simple("FILESYSTEM-SECRET-PERMISSIONS", Outcome.FAIL, seen,
                             "Sensitive account database or SSH host-key permissions appear too broad.")
    elif denied or not checked_shadow or not checked_host_key:
        permission = _simple("FILESYSTEM-SECRET-PERMISSIONS", Outcome.UNKNOWN, seen,
                             "Sensitive file metadata was not fully available; no secret contents were read.")
    else:
        permission = _simple("FILESYSTEM-SECRET-PERMISSIONS", Outcome.PASS, seen,
                             "Observed sensitive account and host-key files have restrictive modes.")

    mounts, mount_error = _read("/proc/self/mounts")
    if mounts is None:
        mount_check = _simple("FILESYSTEM-TMP-MOUNT", Outcome.UNKNOWN, reason=mount_error)
    else:
        entry = None
        for line in mounts.splitlines():
            fields = line.split()
            if len(fields) >= 4 and fields[1] == "/tmp":
                entry = fields[3].split(",")
                break
        if entry is None:
            mount_check = _simple("FILESYSTEM-TMP-MOUNT", Outcome.UNKNOWN,
                                  ["/proc/self/mounts contains no distinct /tmp mount"],
                                  "A separate /tmp mount was not observed; this alone does not establish unsafe permissions.")
        else:
            missing = [flag for flag in ("nodev", "nosuid") if flag not in entry]
            mount_check = _simple("FILESYSTEM-TMP-MOUNT", Outcome.UNKNOWN,
                                  ["/tmp mount options: " + ",".join(entry)],
                                  "Observed /tmp mount lacks " + ", ".join(missing) + "; assess compatibility and effective mount context." if missing else "Observed /tmp mount includes nodev and nosuid; effective namespace and coverage still require review.")
    return [permission, mount_check]


def _logging_checks(ctx) -> List[CheckResult]:
    text, error = _read("/etc/systemd/journald.conf")
    if text is None:
        journald = _simple("LOG-PERSISTENT-JOURNAL", Outcome.UNKNOWN, reason=error)
    else:
        # Main file and drop-ins are read-only. An explicit setting is needed;
        # absence is not treated as proof that journald is volatile.
        values = []
        candidates = [Path("/etc/systemd/journald.conf")]
        try:
            candidates += sorted(Path("/etc/systemd/journald.conf.d").glob("*.conf"))
        except OSError:
            pass
        for path in candidates:
            content, _ = _read(str(path))
            if content is None:
                continue
            in_journal_section = False
            for line in content.splitlines():
                section = re.match(r"\s*\[([^]]+)\]\s*(?:#.*)?$", line)
                if section:
                    in_journal_section = section.group(1).strip().lower() == "journal"
                    continue
                if in_journal_section:
                    match = re.match(r"\s*Storage\s*=\s*(\w+)", line, re.I)
                    if match:
                        values.append((match.group(1).lower(), str(path)))
        if values:
            value, source = values[-1]
            journald = _simple("LOG-PERSISTENT-JOURNAL", Outcome.UNKNOWN, [f"{source}: Storage={value}"],
                               "An explicit journald Storage value was observed; effective drop-in precedence, runtime state, and retention are not fully validated.")
        else:
            journald = _simple("LOG-PERSISTENT-JOURNAL", Outcome.UNKNOWN,
                               ["No explicit Storage= value found in readable journald configuration"],
                               "Effective journald defaults and runtime storage were not queried; persistence is unknown.")

    auditctl = which("auditctl")
    if not auditctl:
        audit = _simple("LOG-AUDIT-SUBSYSTEM", Outcome.UNKNOWN, reason="auditctl is unavailable; kernel audit state is unverified")
    else:
        result = _command(ctx, [auditctl, "-s"])
        if result.timed_out or not result.ok:
            audit = _simple("LOG-AUDIT-SUBSYSTEM", Outcome.UNKNOWN, reason="auditctl -s failed or was denied; kernel audit state is unverified")
        else:
            enabled = re.search(r"(?m)^enabled\s+(\d+)", result.stdout)
            if not enabled:
                audit = _simple("LOG-AUDIT-SUBSYSTEM", Outcome.UNKNOWN, ["auditctl -s returned no enabled field"], "Audit subsystem state could not be parsed.")
            else:
                active = enabled.group(1) != "0"
                audit = _simple("LOG-AUDIT-SUBSYSTEM", Outcome.UNKNOWN,
                                ["auditctl -s reported enabled " + enabled.group(1)],
                                "Kernel audit status was observed; configured rule coverage and persistence are not assessed." if active else "Kernel audit reports disabled, but host policy applicability and compensating controls require review.")
    return [journald, audit]


def _network_checks(ctx) -> List[CheckResult]:
    binary = which("ss")
    if not binary:
        return [_simple("NETWORK-WILDCARD-LISTENERS", Outcome.UNKNOWN, reason="ss is unavailable; local listening sockets are unverified")]
    result = _command(ctx, [binary, "-H", "-lntu"])
    if result.timed_out or not result.ok:
        return [_simple("NETWORK-WILDCARD-LISTENERS", Outcome.UNKNOWN, reason="ss socket query failed or was denied")]
    lines = result.stdout.splitlines()[:1000]
    wildcards = [line.strip()[:500] for line in lines if any(token in line for token in ("0.0.0.0:", "[::]:", "*:"))]
    if wildcards:
        return [_simple("NETWORK-WILDCARD-LISTENERS", Outcome.UNKNOWN, wildcards[:30], "Wildcard-bound local listeners require review against service intent and firewall evidence; this does not prove external reachability.")]
    return [_simple("NETWORK-WILDCARD-LISTENERS", Outcome.UNKNOWN, [f"ss reported {len(lines)} listening TCP/UDP sockets; none used a recognized wildcard address"], "No recognized wildcard listener was observed, but socket parsing and address-family coverage are not sufficient to prove exposure safety.")]


def _kernel_checks() -> List[CheckResult]:
    paths = {
        "/proc/sys/kernel/randomize_va_space": {"2"},
        "/proc/sys/kernel/dmesg_restrict": {"1"},
        "/proc/sys/kernel/kptr_restrict": {"1", "2"},
    }
    evidence, missing, weak = [], [], []
    for path, expected in paths.items():
        value, error = _read(path, 32)
        if value is None:
            missing.append(f"{path}: {error}")
            continue
        observed = value.strip()
        evidence.append(f"{path}={observed}")
        if observed not in expected:
            weak.append(f"{path}={observed}")
    if weak:
        outcome, reason = Outcome.UNKNOWN, "One or more selected kernel security parameters differ from a heuristic baseline; namespace and distribution policy require review."
    elif missing:
        outcome, reason = Outcome.UNKNOWN, "Not all selected kernel security parameters could be read."
    else:
        outcome, reason = Outcome.UNKNOWN, "Selected kernel parameters match the heuristic baseline, but namespace visibility and broader kernel policy are not established."
    return [_simple("KERNEL-SECURITY-SYSCTLS", outcome, evidence + missing, reason)]


def _logging_retention_check() -> CheckResult:
    candidates = [Path("/etc/logrotate.conf")]
    try:
        candidates.extend(sorted(Path("/etc/logrotate.d").glob("*"))[:100])
    except OSError:
        pass
    values = []
    for path in candidates:
        if not path.is_file():
            continue
        content, _ = _read(str(path), 64_000)
        if content is None:
            continue
        for line in content.splitlines():
            match = re.match(r"^\s*rotate\s+(\d+)\s*(?:#.*)?$", line)
            if match:
                values.append((int(match.group(1)), str(path)))
    if not values:
        return _simple("LOG-ROTATION", Outcome.UNKNOWN, reason="No readable explicit rotate count found; effective per-log retention is not established")
    evidence = [f"{source}: rotate {count}" for count, source in values[:30]]
    return _simple("LOG-ROTATION", Outcome.UNKNOWN, evidence,
                   "Explicit rotation directives were observed, but stanza precedence, per-log coverage, and successful rotation are not evaluated.")


def _time_sync_check(ctx) -> CheckResult:
    binary = which("timedatectl")
    if not binary:
        return _simple("TIME-SYNCHRONIZATION", Outcome.UNKNOWN, reason="timedatectl unavailable; synchronization state is unverified")
    result = _command(ctx, [binary, "show", "-p", "NTPSynchronized", "--value"])
    if result.timed_out or not result.ok:
        return _simple("TIME-SYNCHRONIZATION", Outcome.UNKNOWN, reason="timedatectl could not provide synchronization status")
    value = result.stdout.strip().lower()
    if value not in {"yes", "no"}:
        return _simple("TIME-SYNCHRONIZATION", Outcome.UNKNOWN, ["timedatectl returned an unrecognized value"], "Synchronization state could not be interpreted.")
    return _simple("TIME-SYNCHRONIZATION", Outcome.PASS if value == "yes" else Outcome.FAIL,
                   [f"timedatectl NTPSynchronized={value}"],
                   "The system reports synchronized time." if value == "yes" else "The system reports unsynchronized time; assess time sources and service state.")


def _host_protection_checks() -> List[CheckResult]:
    results = []
    selinux, error = _read("/sys/fs/selinux/enforce", 32)
    if selinux is not None:
        state = selinux.strip()
        outcome = Outcome.PASS if state == "1" else Outcome.FAIL if state == "0" else Outcome.UNKNOWN
        results.append(_simple("HOST-SELINUX", outcome, [f"/sys/fs/selinux/enforce: {state}"],
                               "SELinux enforcement is enabled." if outcome == Outcome.PASS else "SELinux is present but not enforcing." if outcome == Outcome.FAIL else "SELinux state is not recognized."))
    else:
        # On systems without SELinux, report applicability rather than failure.
        if Path("/sys/fs/selinux").exists() or which("getenforce"):
            result = _simple("HOST-SELINUX", Outcome.UNKNOWN, reason=error or "SELinux state could not be read")
        else:
            result = _simple("HOST-SELINUX", Outcome.NOT_APPLICABLE, ["SELinux interface not detected"], "SELinux does not appear to be available on this host.")
        results.append(result)

    apparmor, error = _read("/sys/module/apparmor/parameters/enabled", 32)
    if apparmor is not None:
        enabled = apparmor.strip().upper()
        outcome = Outcome.PASS if enabled.startswith("Y") else Outcome.FAIL if enabled.startswith("N") else Outcome.UNKNOWN
        results.append(_simple("HOST-APPARMOR", outcome, [f"AppArmor enabled parameter: {enabled}"],
                               "AppArmor is enabled in the kernel." if outcome == Outcome.PASS else "AppArmor is not enabled." if outcome == Outcome.FAIL else "AppArmor state is unrecognized."))
    elif Path("/sys/module/apparmor").exists():
        results.append(_simple("HOST-APPARMOR", Outcome.UNKNOWN, reason=error or "AppArmor state could not be read"))
    else:
        results.append(_simple("HOST-APPARMOR", Outcome.NOT_APPLICABLE, ["AppArmor kernel module not detected"], "AppArmor does not appear to be available on this host."))
    return results


def _fail2ban_check(ctx) -> CheckResult:
    binary = which("fail2ban-client")
    if not binary:
        return _simple("F2B-SSH-JAIL", Outcome.UNKNOWN, reason="fail2ban-client is not installed; protection cannot be verified")
    result = _command(ctx, [binary, "status"])
    if result.timed_out or not result.ok:
        return _simple("F2B-SSH-JAIL", Outcome.UNKNOWN, reason="fail2ban-client status failed or was denied; active jail state is unverified")
    match = re.search(r"(?im)^\s*Jail list:\s*(.*?)\s*$", result.stdout)
    if not match:
        return _simple("F2B-SSH-JAIL", Outcome.UNKNOWN, ["fail2ban-client status returned no parseable jail list"], "Active Fail2ban jails could not be established.")
    jails = [name.strip() for name in match.group(1).split(",") if name.strip()]
    ssh_jail = any(name.lower() in {"sshd", "ssh", "sshd-ddos"} for name in jails)
    return _simple("F2B-SSH-JAIL", Outcome.UNKNOWN,
                   ["Active jail list: " + (", ".join(jails) if jails else "(empty)")],
                   "An SSH-related jail is active; configuration efficacy and exposed service correlation remain unverified." if ssh_jail else "No SSH-related jail was observed; without verified SSH exposure and compensating controls, applicability cannot be determined." )


def _container_check(ctx) -> CheckResult:
    """Inspect bounded Docker/Podman containers (running and stopped), read-only."""
    runtimes = [(which("docker"), "Docker"), (which("podman"), "Podman")]
    runtimes = [(binary, label) for binary, label in runtimes if binary]
    if not runtimes:
        return _simple("CONTAINERS-PRIVILEGED", Outcome.UNKNOWN, reason="No accessible Docker/Podman runtime was found; container state is unverified")

    evidence, high_risk = [], []
    total = 0
    for binary, label in runtimes:
        ids_result = _command(ctx, [binary, "ps", "--all", "--quiet"])
        if ids_result.timed_out or not ids_result.ok or ids_result.truncated:
            if high_risk:
                return _simple("CONTAINERS-PRIVILEGED", Outcome.FAIL, evidence[:120], "Concrete high-risk settings were found in an inspected runtime; another runtime's inventory is incomplete.")
            return _simple("CONTAINERS-PRIVILEGED", Outcome.UNKNOWN, evidence, f"{label} inventory failed, timed out, or was truncated; container coverage is incomplete")
        container_ids = list(dict.fromkeys(line.strip() for line in ids_result.stdout.splitlines() if line.strip()))
        if any(not re.fullmatch(r"[A-Fa-f0-9]{12,64}", item) for item in container_ids):
            return _simple("CONTAINERS-PRIVILEGED", Outcome.UNKNOWN, evidence, f"{label} returned an unexpected container identifier; inspection was not attempted")
        total += len(container_ids)
        if total > 100:
            return _simple("CONTAINERS-PRIVILEGED", Outcome.UNKNOWN, evidence + [f"Combined runtime inventory exceeds the 100-container safety cap"], "The assessment stopped before inspection because the combined Docker/Podman inventory exceeded its bounded limit.")
        if not container_ids:
            evidence.append(f"{label}: no containers returned by --all inventory")
            continue

        inspected = _command(ctx, [binary, "inspect", *container_ids])
        if inspected.timed_out or not inspected.ok or inspected.truncated:
            if high_risk:
                return _simple("CONTAINERS-PRIVILEGED", Outcome.FAIL, evidence[:120], "Concrete high-risk settings were observed in one runtime; another runtime's inspect evidence is incomplete.")
            return _simple("CONTAINERS-PRIVILEGED", Outcome.UNKNOWN, evidence, f"{label} inspection failed or exceeded the output cap; container posture is incomplete")
        try:
            records = json.loads(inspected.stdout)
        except (TypeError, ValueError):
            if high_risk:
                return _simple("CONTAINERS-PRIVILEGED", Outcome.FAIL, evidence[:120], "Concrete high-risk settings were observed in one runtime; another runtime returned malformed inspect data.")
            return _simple("CONTAINERS-PRIVILEGED", Outcome.UNKNOWN, evidence, f"{label} returned malformed inspect JSON")
        if not isinstance(records, list) or len(records) != len(container_ids) or not all(isinstance(item, dict) for item in records):
            if high_risk:
                return _simple("CONTAINERS-PRIVILEGED", Outcome.FAIL, evidence[:120], "Concrete high-risk settings were found in an inspected runtime; another runtime's inspection was incomplete.")
            return _simple("CONTAINERS-PRIVILEGED", Outcome.UNKNOWN, evidence + [f"Expected {len(container_ids)} inspect records"], "Runtime inspect output did not account for every inventoried container.")

        review = []
        requested_ids = {value.lower() for value in container_ids}
        returned_ids = [str(record.get("Id", "")).lower() for record in records]
        matched_ids = []
        unmatched = set(requested_ids)
        for requested in requested_ids:
            candidates = [actual for actual in returned_ids if actual == requested or actual.startswith(requested) or requested.startswith(actual)]
            if len(candidates) != 1:
                unmatched.add(requested)
                continue
            actual = candidates[0]
            if actual in matched_ids:
                unmatched.add(requested)
                continue
            matched_ids.append(actual)
            unmatched.discard(requested)
        if unmatched or len(set(returned_ids)) != len(container_ids):
            if high_risk:
                return _simple("CONTAINERS-PRIVILEGED", Outcome.FAIL, evidence[:120], "Concrete high-risk settings were found, but another runtime returned incomplete container identity evidence.")
            return _simple("CONTAINERS-PRIVILEGED", Outcome.UNKNOWN, evidence, "Inspect records did not uniquely match all requested container IDs")
        required_fields = {"Id", "HostConfig", "Mounts", "NetworkSettings", "Config"}
        incomplete_records = [
            str(record.get("Id", "unknown"))[:12]
            for record in records
            if not required_fields.issubset(record)
            or not isinstance(record.get("HostConfig"), dict)
            or not isinstance(record.get("Mounts"), list)
            or not isinstance(record.get("NetworkSettings"), dict)
            or not isinstance(record.get("Config"), dict)
        ]
        if incomplete_records:
            evidence.append("Inspect omitted required configuration fields for container(s): " + ", ".join(incomplete_records[:20]))
        for record in records:
            identifier = str(record.get("Id", "unknown"))[:12]
            host = record.get("HostConfig") if isinstance(record.get("HostConfig"), dict) else {}
            mounts = record.get("Mounts") if isinstance(record.get("Mounts"), list) else []
            network = record.get("NetworkSettings") if isinstance(record.get("NetworkSettings"), dict) else {}
            config = record.get("Config") if isinstance(record.get("Config"), dict) else {}
            risks = []
            if host.get("Privileged") is True:
                risks.append("privileged")
            caps = host.get("CapAdd") if isinstance(host.get("CapAdd"), list) else []
            risky_caps = sorted({str(cap).upper() for cap in caps} & {"SYS_ADMIN", "SYS_MODULE", "SYS_RAWIO", "DAC_READ_SEARCH", "NET_ADMIN"})
            if risky_caps:
                risks.append("added capabilities=" + ",".join(risky_caps))
            namespaces = {
                "pid": host.get("PidMode"), "network": host.get("NetworkMode"),
                "ipc": host.get("IpcMode"), "uts": host.get("UTSMode"),
            }
            shared = [key for key, value in namespaces.items() if value == "host"]
            if shared:
                risks.append("host namespaces=" + ",".join(shared))
            if config.get("ReadonlyRootfs") is not True and host.get("ReadonlyRootfs") is not True:
                review.append(f"{identifier} root filesystem is not reported read-only")
            for mount in mounts:
                if not isinstance(mount, dict):
                    continue
                source = str(mount.get("Source", ""))
                destination = str(mount.get("Destination", ""))
                writable = mount.get("RW") is True
                if any(socket in source or socket in destination for socket in ("docker.sock", "podman.sock", "/containerd.sock")):
                    risks.append("container runtime socket mounted")
                elif str(mount.get("Type", "")).lower() == "bind" and writable:
                    review.append(f"{identifier} writable host bind mounted at {destination[:80] or '(unknown destination)'}")
            bindings = network.get("Ports") if isinstance(network.get("Ports"), dict) else {}
            published = []
            for container_port, mappings in bindings.items():
                if not isinstance(mappings, list):
                    continue
                for mapping in mappings:
                    if not isinstance(mapping, dict):
                        continue
                    host_ip = str(mapping.get("HostIp", ""))
                    host_port = str(mapping.get("HostPort", ""))
                    published.append(f"{host_ip or '*'}:{host_port}->{container_port}")
                    if host_ip in {"0.0.0.0", "::", ""}:
                        review.append(f"{identifier} publishes {container_port} on wildcard host address")
            if risks:
                high_risk.extend(f"{identifier} {risk}" for risk in risks)
            container_review = [item for item in review if item.startswith(identifier)]
            evidence.append(f"container {identifier}: " + ("; ".join(risks + container_review) if risks or container_review else "no inspected high-risk flags"))
            if published:
                evidence.append(f"{identifier} published mappings: " + ", ".join(published[:20]))
            # Keep all user-controlled labels and host paths out of report evidence.
            if record.get("Id") is None:
                evidence.append("Runtime inspect object omitted the container ID")

    if high_risk:
        return _simple("CONTAINERS-PRIVILEGED", Outcome.FAIL, evidence[:120], "Concrete high-risk container configuration was observed: " + "; ".join(high_risk[:20]))
    if any("Inspect omitted required configuration fields" in item for item in evidence):
        return _simple("CONTAINERS-PRIVILEGED", Outcome.UNKNOWN, evidence[:120], "At least one runtime omitted required configuration fields; missing state was not treated as a safe default.")
    if total == 0:
        return _simple("CONTAINERS-PRIVILEGED", Outcome.PASS, evidence, "All discovered Docker/Podman inventories reported no containers, including stopped containers.")
    return _simple("CONTAINERS-PRIVILEGED", Outcome.UNKNOWN, evidence[:120],
                   "Inspected container configurations showed no confirmed privileged/socket/capability/host-namespace finding; writable host mounts, published ports, image/runtime policy and workload intent still need review.")



def _apt_security_updates(ctx, list_dir: str = "/var/lib/apt/lists") -> CheckResult:
    """Inspect existing APT indexes only; never refresh indexes or install."""
    apt, apt_cache = which("apt"), which("apt-cache")
    if not apt or not apt_cache:
        return _simple("OS-SECURITY-UPDATES", Outcome.UNKNOWN, reason="APT and apt-cache are required for the local Debian/Ubuntu security update check")
    try:
        security_indexes = [path for path in Path(list_dir).iterdir()
                            if path.is_file() and "_dists_" in path.name and "security" in path.name.lower()
                            and (path.name.endswith("_InRelease") or path.name.endswith("_Release"))]
        now = time.time()
        recent = [path for path in security_indexes if 0 <= now - path.stat().st_mtime <= 14 * 86400]
    except OSError:
        return _simple("OS-SECURITY-UPDATES", Outcome.UNKNOWN, reason="APT list directory or index metadata is unreadable; local security-index freshness is unknown")
    evidence = [f"Recent local security indexes: {len(recent)} of {len(security_indexes)} (14-day freshness window)"]
    if not recent:
        return _simple("OS-SECURITY-UPDATES", Outcome.UNKNOWN, evidence, "No recent local APT security Release index was found. No metadata refresh was attempted.")


    listed = _command(ctx, [apt, "list", "--upgradable"])
    if listed.timed_out or not listed.ok or listed.truncated:
        return _simple("OS-SECURITY-UPDATES", Outcome.UNKNOWN, evidence, "apt list --upgradable failed, timed out, or exceeded the output cap; no packages were changed.")
    packages = []
    for line in listed.stdout.splitlines():
        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9+._:-]*)/[^\s]+\s+([^\s]+)", line.strip())
        if match and match.group(1).lower() not in {"listing"}:
            package = match.group(1).split(":", 1)[0]
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+.-]*", package):
                packages.append((package, match.group(2)))
    packages = list(dict.fromkeys(packages))
    if listed.stdout.strip() and not packages:
        content_lines = [line for line in listed.stdout.splitlines() if line.strip()]
        if any("upgradable" in line.lower() or "/" in line for line in content_lines):
            return _simple("OS-SECURITY-UPDATES", Outcome.UNKNOWN, evidence + ["APT output contained package-like lines that could not be parsed"], "The local APT upgrade list was not reliably parsed; no clean status is inferred.")
    if len(packages) > 100:
        return _simple("OS-SECURITY-UPDATES", Outcome.UNKNOWN, evidence + [f"APT reports more than 100 upgradeable package entries"], "Package-origin inspection stopped at its 100-package safety limit.")
    if not packages:
        output_lines = [line.strip() for line in listed.stdout.splitlines() if line.strip()]
        if not output_lines or any(line.lower() != "listing..." for line in output_lines):
            return _simple("OS-SECURITY-UPDATES", Outcome.UNKNOWN, evidence + ["APT output did not consist solely of its expected empty-list marker"], "The local APT upgrade query did not prove that its package list was complete.")
        return _simple("OS-SECURITY-UPDATES", Outcome.PASS, evidence + ["apt list --upgradable returned only its empty-list marker"], "No upgrades are known to the current recent local APT metadata; this cannot establish that upstream metadata is current.")

    security_upgrades, unclassified, query_errors = [], [], []
    for package, version in packages:
        policy = _command(ctx, [apt_cache, "policy", package])
        if policy.timed_out or not policy.ok or policy.truncated:
            query_errors.append(package)
            continue
        candidate_sources = []
        in_candidate = False
        for line in policy.stdout.splitlines():
            if line.startswith("Candidate:"):
                in_candidate = line.partition(":")[2].strip() == version
                continue
            stripped = line.strip()
            # apt-cache policy version rows begin with a version token and a
            # priority; repository rows begin with a numeric priority and URI.
            source_row = re.match(r"^(\d+)\s+(\S+)\s+(.+)$", stripped)
            if in_candidate and source_row and source_row.group(2).startswith(("http:", "https:", "file:")):
                candidate_sources.append(stripped.lower())
                continue
            version_row = re.match(r"^(?:\*\*\*\s+)?([^\s]+)\s+-?\d+(?:\s|$)", stripped)
            if version_row:
                in_candidate = version_row.group(1) == version
        sources = [line for line in candidate_sources if "security" in line]
        if sources:
            security_upgrades.append((package, version, sources[0][:180]))
        else:
            unclassified.append(package)
    if security_upgrades:
        evidence.extend(f"Security candidate: {package} {version} ({source})" for package, version, source in security_upgrades[:20])
        return _simple("OS-SECURITY-UPDATES", Outcome.FAIL, evidence, "The current local APT candidate for one or more packages is available from a security-labelled repository; review and schedule normal maintenance.")
    if query_errors or unclassified:
        evidence.append(f"Upgradeable packages: {len(packages)}; origins unclassified: {len(unclassified)}; policy query errors: {len(query_errors)}")
        return _simple("OS-SECURITY-UPDATES", Outcome.UNKNOWN, evidence, "Upgradeable packages exist, but their candidate origins could not all be classified as security or non-security sources using local APT policy data.")
    return _simple("OS-SECURITY-UPDATES", Outcome.PASS, evidence + [f"Checked candidate origins for {len(packages)} upgradeable package(s); none came from a security-labelled source"], "No candidate from a security-labelled source was identified in local policy data; vendor-specific advisory channels may not use security-labelled suites.")


def _recent_metadata(cache_dir: str, pattern: str, *, days: int = 14) -> Tuple[List[Path], List[Path]]:
    """Return local package indexes split into recent and stale/missing metadata."""
    root = Path(cache_dir)
    try:
        paths = sorted(path for path in root.glob(pattern) if path.is_file())
    except OSError:
        return [], []
    if not paths:
        return [], []
    now = time.time()
    recent, stale = [], []
    for path in paths:
        try:
            (recent if 0 <= now - path.stat().st_mtime <= days * 86400 else stale).append(path)
        except OSError:
            stale.append(path)
    return recent, stale


def _dnf_security_updates(ctx, cache_dir: str = "/var/cache/dnf") -> CheckResult:
    """Query cached DNF advisories without refreshing metadata or changing packages."""
    binary = which("dnf")
    if not binary:
        return _simple("OS-SECURITY-UPDATES", Outcome.UNKNOWN, reason="DNF is unavailable on this distribution")
    recent, stale = _recent_metadata(cache_dir, "*/repodata/repomd.xml")
    evidence = [f"Local DNF repository metadata: {len(recent)} recent, {len(stale)} stale (14-day heuristic)"]
    if not recent or stale:
        return _simple("OS-SECURITY-UPDATES", Outcome.UNKNOWN, evidence, "DNF cache is missing or at least one cached repository index is stale; --cacheonly prevents refresh, so security status is not established.")
    result = _command(ctx, [binary, "--cacheonly", "--quiet", "repoquery", "--upgrades", "--security", "--queryformat", "%{name}-%{version}-%{release}.%{arch}"])
    if result.timed_out or not result.ok or result.truncated:
        return _simple("OS-SECURITY-UPDATES", Outcome.UNKNOWN, evidence, "Cache-only DNF security repoquery failed, timed out, or was truncated; no package action was attempted.")
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    package_pattern = re.compile(r"^[A-Za-z0-9+_.-]+-[A-Za-z0-9+_.:~%-]+\.[A-Za-z0-9_]+$")
    if any(not package_pattern.fullmatch(line) for line in lines):
        return _simple("OS-SECURITY-UPDATES", Outcome.UNKNOWN, evidence + ["DNF returned output that did not match the requested package-only format"], "The cached advisory query output could not be parsed conservatively.")
    if lines:
        return _simple("OS-SECURITY-UPDATES", Outcome.FAIL, evidence + ["Cached security-update candidates: " + ", ".join(lines[:20])], "DNF identified one or more available security-update candidates in local repository metadata; review through normal maintenance.")
    return _simple("OS-SECURITY-UPDATES", Outcome.PASS, evidence + ["Cache-only DNF security repoquery returned no package candidates"], "No security-update candidate was reported by current local DNF metadata; upstream freshness is not guaranteed.")


def _zypper_security_updates(ctx, cache_dir: str = "/var/cache/zypp/solv") -> CheckResult:
    """Use zypper's documented patch-check status with refresh explicitly disabled."""
    binary = which("zypper")
    if not binary:
        return _simple("OS-SECURITY-UPDATES", Outcome.UNKNOWN, reason="zypper is unavailable on this distribution")
    recent, stale = _recent_metadata(cache_dir, "*.solv")
    evidence = [f"Local zypper solv metadata: {len(recent)} recent, {len(stale)} stale (14-day heuristic)"]
    if not recent or stale:
        return _simple("OS-SECURITY-UPDATES", Outcome.UNKNOWN, evidence, "zypper cache is missing or at least one local solv index is stale; --no-refresh prevents metadata refresh.")
    result = _command(ctx, [binary, "--no-refresh", "patch-check"])
    if result.timed_out or result.truncated:
        return _simple("OS-SECURITY-UPDATES", Outcome.UNKNOWN, evidence, "zypper patch-check timed out or was truncated; no packages were changed.")
    output = (result.stdout or result.stderr).strip()
    evidence.append("zypper patch-check exit status: " + str(result.returncode))
    if output:
        evidence.append(output[:500])
    if result.returncode == 101:
        return _simple("OS-SECURITY-UPDATES", Outcome.FAIL, evidence, "zypper reports security patches are needed according to local metadata.")
    if result.returncode in (0, 100):
        return _simple("OS-SECURITY-UPDATES", Outcome.PASS, evidence, "zypper reports no pending security patches in local metadata; status 100 means non-security patches may still be available and upstream freshness is not guaranteed.")
    return _simple("OS-SECURITY-UPDATES", Outcome.UNKNOWN, evidence, "zypper returned an undocumented or error status; security update state is unverified.")


def _apk_security_updates(ctx, cache_dir: str = "/var/cache/apk") -> CheckResult:
    """Report Alpine's local upgrade simulation without mislabelling it security-only."""
    binary = which("apk")
    if not binary:
        return _simple("OS-SECURITY-UPDATES", Outcome.UNKNOWN, reason="apk is unavailable on this distribution")
    recent, stale = _recent_metadata(cache_dir, "APKINDEX*.tar.gz")
    evidence = [f"Local apk indexes: {len(recent)} recent, {len(stale)} stale (14-day heuristic)"]
    if not recent or stale:
        return _simple("OS-SECURITY-UPDATES", Outcome.UNKNOWN, evidence, "Alpine package indexes are missing or stale; no network refresh was attempted.")
    result = _command(ctx, [binary, "--no-network", "--simulate", "upgrade"])
    if result.timed_out or not result.ok or result.truncated:
        return _simple("OS-SECURITY-UPDATES", Outcome.UNKNOWN, evidence, "Offline apk upgrade simulation failed, timed out, or was truncated; no package changes were requested.")
    lines = [line.strip()[:240] for line in result.stdout.splitlines() if line.strip()]
    evidence.extend(lines[:20])
    return _simple("OS-SECURITY-UPDATES", Outcome.UNKNOWN, evidence, "apk can simulate general upgrades from local indexes but does not identify security-specific advisories; security update status remains unknown.")


def _security_update_check(ctx, os_release_path: str = "/etc/os-release") -> CheckResult:
    """Select only a local-cache query suitable for the detected distribution."""
    release, error = _read(os_release_path, 16_000)
    if release is None:
        return _simple("OS-SECURITY-UPDATES", Outcome.UNKNOWN, reason=error or "Distribution identity is unavailable")
    values = {}
    for line in release.splitlines():
        match = re.match(r"^([A-Z_]+)=(.*)$", line)
        if match:
            raw_value = match.group(2).strip()
            try:
                parsed_value = shlex.split(raw_value, comments=False, posix=True)
            except ValueError:
                return _simple("OS-SECURITY-UPDATES", Outcome.UNKNOWN, reason="Distribution identity contains malformed quoting")
            if len(parsed_value) != 1:
                return _simple("OS-SECURITY-UPDATES", Outcome.UNKNOWN, reason="Distribution identity could not be parsed unambiguously")
            values[match.group(1)] = parsed_value[0].lower()
    distro = values.get("ID", "")
    if distro in {"debian", "ubuntu", "linuxmint", "pop", "raspbian"}:
        return _apt_security_updates(ctx)
    if distro in {"fedora", "rhel", "centos", "rocky", "almalinux", "ol", "amzn"}:
        return _dnf_security_updates(ctx)
    if distro in {"opensuse", "opensuse-leap", "opensuse-tumbleweed", "sles", "sled"}:
        return _zypper_security_updates(ctx)
    if distro == "alpine":
        return _apk_security_updates(ctx)
    return _simple("OS-SECURITY-UPDATES", Outcome.UNKNOWN, [f"Detected distribution ID: {distro or 'unknown'}"], "No verified cache-only security-update query is configured for this distribution.")


def _os_checks(ctx) -> List[CheckResult]:
    reboot_markers = ("/var/run/reboot-required", "/run/reboot-required")
    present = [path for path in reboot_markers if Path(path).is_file()]
    if present:
        reboot = _simple("OS-REBOOT-REQUIRED", Outcome.FAIL, ["reboot marker present: " + ", ".join(present)], "A distribution reboot-required marker was found; inspect its reason and plan maintenance.")
    else:
        reboot = _simple("OS-REBOOT-REQUIRED", Outcome.UNKNOWN, ["No supported reboot marker was found"], "Marker absence does not prove that a reboot is unnecessary.")
    return [_security_update_check(ctx), reboot]


def _backup_check(ctx=None) -> CheckResult:
    """Collect low-cost local backup hints; never claim backup recovery success."""
    candidates = ("/etc/backup", "/etc/borg", "/etc/restic", "/var/lib/borg", "/var/lib/restic", "/var/backups", "/srv/backups", "/backup")
    found, stat_errors = [], []
    for raw_path in candidates:
        path = Path(raw_path)
        try:
            metadata = path.stat()
        except FileNotFoundError:
            continue
        except PermissionError:
            stat_errors.append(raw_path + " (permission denied)")
            continue
        except OSError:
            continue
        kind = "directory" if path.is_dir() else "file"
        found.append(f"{raw_path} ({kind}, mtime={int(metadata.st_mtime)})")
    tools = [name for name in ("restic", "borg", "duplicity", "rdiff-backup", "rsync", "timeshift", "snapper") if which(name)]
    evidence = (["Detected backup-related paths: " + "; ".join(found)] if found else [])
    evidence += (["Detected backup tools: " + ", ".join(tools)] if tools else [])
    evidence += (["Backup path metadata unavailable: " + ", ".join(stat_errors)] if stat_errors else [])

    if ctx is not None and which("systemctl"):
        result = _command(ctx, [which("systemctl"), "list-timers", "--all", "--no-pager", "--no-legend"])
        if result.ok and not result.timed_out and not result.truncated:
            timers = [line.strip()[:240] for line in result.stdout.splitlines() if re.search(r"(?i)\b(backup|restic|borg|duplicity|rsync|snapshot)\b", line)]
            if timers:
                evidence.append("Backup-related systemd timer rows: " + " | ".join(timers[:20]))
            else:
                evidence.append("No backup-named systemd timer was identified in the readable timer inventory")
        else:
            evidence.append("Systemd timer inventory unavailable; no backup schedule was inferred")

    return _simple("BACKUP-RECOVERY-EVIDENCE", Outcome.UNKNOWN, evidence,
                   "Local paths, timestamps, tools, and timer names are clues only; AUREON does not access backup contents or repositories and cannot establish completeness, isolation, integrity, successful jobs, or recoverability. Verify with an authorized restore drill.")


def collect_checks(ctx) -> List[CheckResult]:
    """Collect each check independently; one failed source does not stop others."""
    results = []
    try:
        results.extend(_ssh_checks(ctx))
    except Exception as exc:  # defensive boundary; preserve evidence state
        for check_id in ("SSH-ROOT-LOGIN", "SSH-PASSWORD-AUTH", "SSH-MAX-AUTH-TRIES", "SSH-IDLE-TIMEOUT", "SSH-MATCH-CONTEXTS"):
            results.append(_simple(check_id, Outcome.ERROR, reason=f"SSH check failed: {type(exc).__name__}"))
    try:
        results.extend(_account_checks())
    except Exception as exc:
        for check_id in ("ACCOUNT-UID0", "SUDOERS-PERMISSIONS", "ACCOUNT-PASSWORD-AGING"):
            results.append(_simple(check_id, Outcome.ERROR, reason=f"Account check failed: {type(exc).__name__}"))
    try:
        results.extend(_filesystem_checks())
    except Exception as exc:
        for check_id in ("FILESYSTEM-SECRET-PERMISSIONS", "FILESYSTEM-TMP-MOUNT"):
            results.append(_simple(check_id, Outcome.ERROR, reason=f"Filesystem check failed: {type(exc).__name__}"))
    try:
        results.extend(_logging_checks(ctx))
    except Exception as exc:
        for check_id in ("LOG-PERSISTENT-JOURNAL", "LOG-AUDIT-SUBSYSTEM"):
            results.append(_simple(check_id, Outcome.ERROR, reason=f"Logging check failed: {type(exc).__name__}"))
    try:
        results.extend(_os_checks(ctx))
    except Exception as exc:
        for check_id in ("OS-SECURITY-UPDATES", "OS-REBOOT-REQUIRED"):
            results.append(_simple(check_id, Outcome.ERROR, reason=f"Operating system check failed: {type(exc).__name__}"))
    for check_id, producer in (
        ("NETWORK-WILDCARD-LISTENERS", lambda: _network_checks(ctx)),
        ("KERNEL-SECURITY-SYSCTLS", _kernel_checks),
        ("TIME-SYNCHRONIZATION", lambda: [_time_sync_check(ctx)]),
        ("LOG-ROTATION", lambda: [_logging_retention_check()]),
    ):
        try:
            results.extend(producer())
        except Exception as exc:
            results.append(_simple(check_id, Outcome.ERROR, reason=f"Check failed: {type(exc).__name__}"))
    try:
        results.extend(_host_protection_checks())
    except Exception as exc:
        for check_id in ("HOST-SELINUX", "HOST-APPARMOR"):
            results.append(_simple(check_id, Outcome.ERROR, reason=f"Host protection check failed: {type(exc).__name__}"))
    for check_id, producer in (("F2B-SSH-JAIL", lambda: _fail2ban_check(ctx)),
                               ("CONTAINERS-PRIVILEGED", lambda: _container_check(ctx)),
                               ("BACKUP-RECOVERY-EVIDENCE", lambda: _backup_check(ctx))):
        try:
            results.append(producer())
        except Exception as exc:
            results.append(_simple(check_id, Outcome.ERROR, reason=f"Check failed: {type(exc).__name__}"))

    # Keep the inventory/provenance checks and conservative firewall result
    # implemented in the original engine.
    from .collectors.firewall import FirewallCollector
    from .hardening import assess_firewall
    try:
        firewall = FirewallCollector(ctx).collect()
        results.extend(assess_firewall(firewall.value if firewall.available else None, firewall.availability))
    except Exception as exc:
        results.extend(assess_firewall(None, Availability.ERROR))

    # Defensive invariant: exactly one result per stable definition ID. A
    # collector error must never yield duplicate rows or silently omit a check.
    by_id = {}
    duplicates = set()
    for item in results:
        if item.check.id in by_id:
            duplicates.add(item.check.id)
        by_id[item.check.id] = item
    for check_id in duplicates:
        by_id[check_id] = _simple(check_id, Outcome.ERROR, reason="Assessment collector produced this stable check ID more than once")
    for definition in CHECKS:
        if definition.id not in by_id:
            by_id[definition.id] = _simple(definition.id, Outcome.ERROR, reason="Check was not produced by the assessment collector")
    return [by_id[definition.id] for definition in CHECKS]


__all__ = ["collect_checks"]
