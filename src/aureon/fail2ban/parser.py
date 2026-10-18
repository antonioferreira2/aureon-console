"""Log parsers that normalise security events.

Three sources are supported and every produced event records which one it came
from:

  * ``fail2ban.log``   - the authoritative source for ban/unban history
  * ``journal``        - ``journalctl`` output for fail2ban and sshd units
  * ``auth``           - sshd authentication failures (not bans)

A failed SSH authentication is a *different fact* from a ban. AUREON never
converts one into the other.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Iterable, List, Optional

from ..models import SecurityEvent

MONTHS = {
    name: index
    for index, name in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1
    )
}

# 2026-03-05 14:22:31,123 fail2ban.actions [1234]: NOTICE [sshd] Ban 203.0.113.10
FAIL2BAN_SYSLOG_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})[ T](?P<time>\d{2}:\d{2}:\d{2})[,.](?P<ms>\d{3})\s+"
    r"(?P<proc>[\w.\-]+)\s*(?:\[\d+\])?:\s*(?P<level>[A-Z]+)\s+\[(?P<jail>[^\]]+)\]\s+(?P<action>Ban|Unban)\s+(?P<ip>\S+)"
)

# "Found <IP>" (fail2ban.filter) and "Fail <IP>" (jail bookkeeping) lines.
# A "Found" line means the filter matched; it is NOT a ban.
FAIL2BAN_FAIL_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})[ T](?P<time>\d{2}:\d{2}:\d{2})[,.]\d{3}\s+[\w.\-]+\s*(?:\[\d+\])?:\s*[A-Z]+\s+\[(?P<jail>[^\]]+)\]\s+(?:Fail|Found)\s+(?P<ip>\S+)"
)

# Journal-safe variant: the timestamp is taken from journald, so only the
# "NOTICE [jail] Ban <ip>" tail has to match.
FAIL2BAN_ACTION_RE = re.compile(
    r"\[(?P<jail>[^\]]+)\]\s+(?P<action>Ban|Unban)\s+(?P<ip>\S+)"
)
FAIL2BAN_FOUND_RE = re.compile(r"\[(?P<jail>[^\]]+)\]\s+(?:Fail|Found)\s+(?P<ip>\S+)")

# Mar  5 14:22:31 host sshd[1234]: Failed password for invalid user admin from 203.0.113.10 port 51234 ssh2
AUTH_FAILED_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+(?P<proc>[\w.\-/\[\]0-9]+?):\s+"
    r"(?P<msg>Failed password for (?:invalid user )?(?P<user>\S+)|Invalid user (?P<iuser>\S+) from|"
    r"authentication failure;.*?ruser=(?P<ruser>\S*)|Unable to negotiate with .*?\[(?P<negip>[\da-fA-F:.]+)\].*?fingerprint)"
)

# Files written with RFC3339 timestamps (systemd/rsyslog >= 8.x default):
# 2026-10-18T15:30:13.387131+01:00 afia01 sshd[993]: Failed password for root from 203.0.113.7 port 5123 ssh2
AUTH_ISO_RE = re.compile(
    r"^(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^\s:]+):\s+(?P<msg>.*)$"
)

AUTH_FAILURE_SIMPLE_RE = re.compile(
    r"(?:Failed password|Invalid user|authentication failure|PAM.*authentication failure)"
    r".*?from\s+(?P<ip>[\da-fA-F.:]+)"
    r"(?:.*?ruser=(?P<ruser>\S*))?"
)

# journalctl -o short-iso: 2026-03-05T14:22:31+0000 host fail2ban.actions[123]: NOTICE [sshd] Ban 1.2.3.4
JOURNAL_RE = re.compile(
    r"^(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{4})?)\s+(?P<host>\S+)\s+(?P<proc>[^\s\[]+)(?:\[\d+\])?:\s+(?P<body>.*)$"
)


def _event_time(date: str, time_str: str, tzinfo, year_hint: Optional[int] = None) -> datetime:
    naive = datetime.strptime(f"{date} {time_str}", "%Y-%m-%d %H:%M:%S")
    return naive.replace(tzinfo=tzinfo)


def parse_fail2ban_log(
    lines: Iterable[str],
    tzinfo,
    source: str = "fail2ban.log",
    year_hint: Optional[int] = None,
) -> List[SecurityEvent]:
    """Parse fail2ban.log content into ban/unban/fail events."""
    events: List[SecurityEvent] = []
    for line in lines:
        match = FAIL2BAN_SYSLOG_RE.match(line)
        if match:
            moment = _event_time(match.group("date"), match.group("time"), tzinfo)
            ip = match.group("ip")
            kind = "ban" if match.group("action").lower() == "ban" else "unban"
            events.append(
                SecurityEvent(
                    occurred_at=moment,
                    source=source,
                    source_id=f"{match.group('date')}T{match.group('time')}.{match.group('ms')}:{match.group('jail')}:{kind}:{ip}",
                    kind=kind,
                    jail=match.group("jail"),
                    ip=_clean_ip(ip),
                    meta={"level": match.group("level"), "raw": line.strip()[:400]},
                )
            )
            continue
        fail = FAIL2BAN_FAIL_RE.match(line)
        if fail:
            moment = _event_time(fail.group("date"), fail.group("time"), tzinfo)
            events.append(
                SecurityEvent(
                    occurred_at=moment,
                    source=source,
                    source_id=f"{fail.group('date')}T{fail.group('time')}:{fail.group('jail')}:found:{fail.group('ip')}",
                    kind="found",
                    jail=fail.group("jail"),
                    ip=_clean_ip(fail.group("ip")),
                    meta={"raw": line.strip()[:400]},
                )
            )
    return events


def parse_fail2ban_journal(
    lines: Iterable[str], tzinfo, source: str = "journal"
) -> List[SecurityEvent]:
    """Parse ``journalctl -o short-iso`` output from the fail2ban units.

    journald timestamps are authoritative, so the host's local-time string that
    fail2ban itself prints is deliberately ignored here.
    """
    events: List[SecurityEvent] = []
    for raw in lines:
        raw = raw.rstrip("\n")
        match = JOURNAL_RE.match(raw)
        if not match:
            continue
        body = match.group("body")
        moment = _iso_to_datetime(match.group("iso"), tzinfo)

        event_match = FAIL2BAN_ACTION_RE.search(body)
        if event_match and "fail2ban" in match.group("proc"):
            jail = event_match.group("jail")
            action = event_match.group("action").lower()
            ip = _clean_ip(event_match.group("ip"))
            events.append(
                SecurityEvent(
                    occurred_at=moment,
                    source=source,
                    source_id=f"{match.group('iso')}:{jail}:{action}:{ip}",
                    kind="ban" if action == "ban" else "unban",
                    jail=jail,
                    ip=ip,
                    meta={"unit": match.group("proc"), "raw": raw.strip()[:400]},
                )
            )
            continue

        fail_match = FAIL2BAN_FOUND_RE.search(body)
        if fail_match and "fail2ban" in match.group("proc"):
            ip = _clean_ip(fail_match.group("ip"))
            jail = fail_match.group("jail")
            events.append(
                SecurityEvent(
                    occurred_at=moment,
                    source=source,
                    source_id=f"{match.group('iso')}:{jail}:found:{ip}",
                    kind="found",
                    jail=jail,
                    ip=ip,
                    meta={"unit": match.group("proc")},
                )
            )
    return events


def parse_auth_log(
    lines: Iterable[str], tzinfo, source: str = "auth", year_hint: Optional[int] = None
) -> List[SecurityEvent]:
    """Parse SSH authentication failures (NOT bans).

    Two timestamp conventions are supported: classic ``Mmm dd HH:MM:SS`` syslog
    lines and the RFC3339 form used by modern rsyslog/systemd. Lines that match
    neither are skipped, never guessed.
    """
    events: List[SecurityEvent] = []
    year = year_hint or datetime.now(tzinfo).year
    for raw in lines:
        raw = raw.rstrip("\n")
        iso_match = AUTH_ISO_RE.match(raw)
        if iso_match:
            event = _auth_event_from_body(
                raw,
                iso_match.group("msg"),
                iso_match.group("proc"),
                _iso_to_datetime(iso_match.group("iso"), tzinfo),
                source,
            )
            if event:
                events.append(event)
            continue

        match = AUTH_FAILED_RE.match(raw)
        if match:
            month = MONTHS.get(match.group("month"))
            if not month:
                continue
            try:
                naive = datetime.strptime(
                    f"{year}-{month:02d}-{int(match.group('day')):02d} {match.group('time')}",
                    "%Y-%m-%d %H:%M:%S",
                )
            except ValueError:
                continue
            event = _auth_event_from_body(
                raw, raw, match.group("proc"), naive.replace(tzinfo=tzinfo), source
            )
            if event:
                events.append(event)
    return events


def _auth_event_from_body(
    raw: str, body: str, proc: str, moment: datetime, source: str
) -> Optional[SecurityEvent]:
    """Build an ``auth_failure`` event from a log message, or None."""
    failure = AUTH_FAILURE_SIMPLE_RE.search(body) or AUTH_FAILURE_SIMPLE_RE.search(raw)
    if not failure:
        return None
    ip = _clean_ip(failure.group("ip"))
    if not ip:
        return None
    username = failure.group("ruser") or ""
    user_match = re.search(r"(?:Failed password for (?:invalid user )?|Invalid user )(?P<u>\S+)", body)
    if user_match:
        username = user_match.group("u")
    return SecurityEvent(
        occurred_at=moment,
        source=source,
        source_id=f"{source}:{moment.isoformat()}:{ip}",
        kind="auth_failure",
        jail="",
        ip=ip,
        username=username,
        meta={"unit": proc, "raw": raw.strip()[:400]},
    )


def _clean_ip(value: str) -> str:
    value = value.strip().rstrip(".,;")
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    return value


def _iso_to_datetime(value: str, tzinfo) -> datetime:
    value = value.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"):
        try:
            parsed = datetime.strptime(value, fmt)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=tzinfo)
            return parsed.astimezone(tzinfo)
        except ValueError:
            continue
    return datetime.now(tzinfo)  # pragma: no cover - journalctl always emits ISO


def parse_journal_sshd(lines: Iterable[str], tzinfo, source: str = "journal-sshd") -> List[SecurityEvent]:
    """Extract sshd authentication failures from ``journalctl -o short-iso`` lines.

    Successful authentications are ignored: AUREON reports failures only.
    """
    events: List[SecurityEvent] = []
    for line in lines:
        match = JOURNAL_RE.match(line.rstrip("\n"))
        if not match:
            continue
        if "Accepted " in match.group("body"):
            continue
        event = _auth_event_from_body(
            match.group(0),
            match.group("body"),
            match.group("proc"),
            _iso_to_datetime(match.group("iso"), tzinfo),
            source,
        )
        if event:
            events.append(event)
    return events
