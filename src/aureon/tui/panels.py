"""Panels: one render function per module, each returning a Textual widget."""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional

from rich.text import Text
from textual.widgets import Static

from ..collectors.docker import DockerInfo
from ..collectors.logs import LogsInfo, PRIORITIES
from ..collectors.network import NetworkInfo
from ..collectors.sensors import SensorInfo
from ..collectors.services import ServicesInfo
from ..collectors.storage import StorageInfo
from ..collectors.system import SystemInfo, system_indicators
from ..collectors.tools import ToolStatus
from ..fail2ban.detect import Fail2banStatus
from ..models import Health, PeriodStats
from ..periods import BUILTIN_PERIODS
from ..util import Availability, Result, bar, human_bytes, human_duration, pct
from .widgets import HEALTH_STYLE, empty_state, make_table, source_text


def panel(result: Result, render, **kwargs):
    """Standard panel wrapper: content + provenance + error state.

    Returns a rich *renderable* (never a widget) so panels can be composed and
    unit-tested without an active Textual application.
    """
    if not result.available:
        message = {
            Availability.UNAVAILABLE: "This module is unavailable on this system.",
            Availability.DENIED: "Permission denied: run AUREON with sufficient privileges to see this data.",
            Availability.TIMEOUT: "The underlying command timed out. Data may be incomplete.",
            Availability.ERROR: "The underlying command failed.",
        }.get(result.availability, "Data unavailable.")
        return empty_state(message, result.error or "")

    body = render(result.value, **kwargs)
    parts = [body, source_text(result.availability, result.source, result.error)]
    for warning in result.warnings:
        parts.append(Text(f"! {warning}", style="#e5c07b"))
    return _table_block(*parts)


def widget(renderable):
    """Wrap a rich renderable in a Textual Static (requires an active app)."""
    static = Static()
    static.update(renderable)
    return static


def _table_block(*renderables):
    """Compose several rich renderables into one Group."""
    from rich.console import Group

    from textual.widget import Widget

    return Group(
        *[item for item in renderables if item is not None and not isinstance(item, Widget)]
    )


# ---------------------------------------------------------------------------
# dashboard
# ---------------------------------------------------------------------------
def render_system(info: SystemInfo):
    group = _table_block(
        Text("Host", style="bold #e6edf3"),
        make_table(
            ["Metric", "Value"],
            [
                ["Hostname", info.hostname],
                ["OS", f"{info.os_name} {info.os_version}".strip()],
                ["Kernel", f"{info.kernel} ({info.arch})"],
                ["Uptime", human_duration(info.uptime_seconds)],
                ["Boot time", info.boot_time.strftime("%Y-%m-%d %H:%M:%S %Z") if info.boot_time else "unknown"],
            ],
        ),
        Text("Resources", style="bold #e6edf3"),
        make_table(
            ["Metric", "Value", "Usage"],
            [
                [
                    "CPU",
                    f"{info.cpu_percent:.1f}%" if info.cpu_percent is not None else "n/a",
                    bar(info.cpu_percent or 0),
                ],
                [
                    "Load (1/5/15)",
                    f"{info.load1 if info.load1 is not None else '?'} / "
                    f"{info.load5 if info.load5 is not None else '?'} / "
                    f"{info.load15 if info.load15 is not None else '?'}",
                    f"of {info.cpu_count} cpu",
                ],
                [
                    "Memory",
                    f"{human_bytes(info.mem_used)} / {human_bytes(info.mem_total)}"
                    + (f" ({info.mem_percent:.0f}%)" if info.mem_percent is not None else ""),
                    bar(info.mem_percent or 0),
                ],
                [
                    "Swap",
                    f"{human_bytes(info.swap_used)} / {human_bytes(info.swap_total)}",
                    bar(pct(info.swap_used or 0, info.swap_total or 0)),
                ],
            ],
        ),
        Text(f"CPU model: {info.cpu_model or 'unknown'}", style="#6e7681"),
    )
    return group


def render_processes(info: SystemInfo, redact: bool = True):
    rows = []
    for proc in sorted(info.processes, key=lambda p: p.cpu_percent or 0, reverse=True)[:20]:
        rows.append(
            [
                str(proc.pid),
                "<redacted>" if redact else proc.user,
                proc.command[:28],
                f"{proc.cpu_percent:.1f}%" if proc.cpu_percent is not None else "n/a",
                f"{proc.mem_percent:.1f}%" if proc.mem_percent is not None else "n/a",
                human_bytes(proc.mem_rss),
                proc.state,
            ]
        )
    return _table_block(
        Text("Top processes by CPU", style="bold #e6edf3"),
        make_table(["PID", "User", "Command", "CPU", "MEM%", "RSS", "State"], rows),
        Text("AUREON never terminates processes.", style="#6e7681"),
    )


def render_storage(info: StorageInfo):
    rows = [
        [
            m.mountpoint,
            m.device,
            m.fstype,
            human_bytes(m.size),
            human_bytes(m.used),
            human_bytes(m.available),
            f"{m.use_percent:.0f}%" if m.use_percent is not None else "n/a",
            _health_cell(m.health),
        ]
        for m in info.mounts
    ]
    disk_rows = [
        [d.device, human_bytes(d.size_bytes), d.model or "n/a", "rotational" if d.rota else "solid-state", d.transport]
        for d in info.disks
    ]
    blocks = [
        Text("Filesystems", style="bold #e6edf3"),
        make_table(["Mount", "Device", "Type", "Size", "Used", "Available", "Use%", "State"], rows),
        Text("Block devices", style="bold #e6edf3"),
        make_table(["Device", "Size", "Model", "Type", "Transport"], disk_rows),
    ]
    if info.lvms:
        blocks += [
            Text("LVM logical volumes", style="bold #e6edf3"),
            make_table(["LV", "VG", "Size", "Devices"], [[v["lv"], v["vg"], v["size"], v["devices"]] for v in info.lvms]),
        ]
    return _table_block(*blocks)


def _health_cell(health: Health) -> Text:
    return Text(f"{health.symbol} {health.label}", style=HEALTH_STYLE[health])


def render_network(info: NetworkInfo):
    rows = [
        [
            i.name,
            i.state,
            ", ".join(i.addresses) or "-",
            human_bytes(i.rx_bytes),
            human_bytes(i.tx_bytes),
            f"{human_bytes(i.rx_rate)}/s" if i.rx_rate is not None else "n/a",
            f"{human_bytes(i.tx_rate)}/s" if i.tx_rate is not None else "n/a",
            f"{i.rx_errors}/{i.tx_errors}",
            f"{i.rx_dropped}/{i.tx_dropped}",
        ]
        for i in info.interfaces
    ]
    listeners = [
        [s.protocol, s.local_address, str(s.local_port), s.state]
        for s in sorted(info.listening, key=lambda s: (s.protocol, s.local_port))
    ]
    return _table_block(
        Text("Interfaces", style="bold #e6edf3"),
        make_table(["IF", "State", "Addresses", "RX", "TX", "RX/s", "TX/s", "Err", "Drops"], rows),
        Text(
            f"Listening sockets: {len(info.listening)}   Established TCP: {info.established}   "
            f"Default route via: {info.default_route or 'n/a'}",
            style="#6e7681",
        ),
        Text(
            "A listening port does not prove Internet exposure: firewall and routing context apply.",
            style="#e5c07b",
        ),
        Text("Listening sockets", style="bold #e6edf3"),
        make_table(["Proto", "Address", "Port", "State"], listeners),
    )


def render_services(info: ServicesInfo):
    rows = [
        [
            s.unit,
            s.active_state,
            s.sub_state,
            s.enabled,
            s.since or "-",
            str(s.restarts) if s.restarts is not None else "-",
            (s.description or "")[:40],
        ]
        for s in info.services
    ]
    failed = [f"{s.unit} ({s.active_state}/{s.sub_state})" for s in info.failed]
    header = Text(
        f"backend: {info.backend}   total: {info.total}   running: {info.running}   failed: {len(info.failed)}",
        style="bold #e6edf3",
    )
    parts = [header]
    if failed:
        parts.append(Text("Failed units: " + ", ".join(failed[:10]), style="#e06c75"))
    parts.append(make_table(["Unit", "Active", "Sub", "Enabled", "Since", "Restarts", "Description"], rows))
    parts.append(Text("Read-only: AUREON never restarts services.", style="#6e7681"))
    return _table_block(*parts)


def render_logs(info: LogsInfo):
    rows = [[line.render() for line in info.lines[-200:]]]
    parts = [
        Text(f"backend: {info.backend}   lines: {len(info.lines)}   errors: {info.errors}", style="bold #e6edf3"),
        make_table(["Log"], rows),
    ]
    if info.truncated:
        parts.append(Text("Output truncated: increase max_log_lines or narrow the filter.", style="#e5c07b"))
    return _table_block(*parts)


def render_docker(info: DockerInfo):
    if not info.permissions_ok:
        return empty_state("Docker daemon reachable but access denied.", "Add your user to the docker group or run as root.")
    rows = [
        [c.short_id, c.name, c.image, c.state, c.status, str(c.restarts) if c.restarts is not None else "-"]
        for c in info.containers
    ]
    parts = [
        Text(f"backend: {info.backend}   version: {info.version or 'unknown'}", style="bold #e6edf3"),
        make_table(["ID", "Name", "Image", "State", "Status", "Restarts"], rows),
    ]
    if info.restart_loops:
        parts.append(
            Text(
                "Containers restarting repeatedly: " + ", ".join(c.name for c in info.restart_loops),
                style="#e5c07b",
            )
        )
    if info.images:
        parts.append(Text("Local images", style="bold #e6edf3"))
        parts.append(
            make_table(["Image", "ID", "Size"], [[i["image"], i["id"], i["size"]] for i in info.images[:30]])
        )
    return _table_block(*parts)


def render_sensors(info: SensorInfo):
    temps = [r for r in info.readings if r.kind == "temperature"]
    others = [r for r in info.readings if r.kind != "temperature"]
    parts = [Text(f"backend: {info.backend}", style="bold #e6edf3")]
    if temps:
        parts.append(Text("Temperatures", style="bold #e6edf3"))
        parts.append(
            make_table(
                ["Sensor", "Value"],
                [[t.label, t.value] for t in temps]
                + [["max observed", f"{max((t.numeric or 0) for t in temps):.1f} C"]],
            )
        )
    if others:
        parts.append(Text("Other sensors", style="bold #e6edf3"))
        parts.append(make_table(["Sensor", "Value"], [[o.label, o.value] for o in others]))
    if info.gpus:
        parts.append(Text("GPUs", style="bold #e6edf3"))
        parts.append(make_table(["Name", "Utilisation", "Memory", "Temp"], [[g["name"], g["util"], g["mem"], g["temp"]] for g in info.gpus]))
    if not info.readings and not info.gpus:
        parts.append(empty_state("No sensor values are exposed by this hardware or kernel."))
    for warning in info.warnings:
        parts.append(Text(f"! {warning}", style="#e5c07b"))
    return _table_block(*parts)


def render_tools(statuses: List[ToolStatus]):
    rows = [
        [
            s.spec.name,
            "installed" if s.installed else "not installed",
            s.version or "-",
            s.spec.purpose,
            s.spec.license,
            s.spec.package_hint,
            s.spec.integration,
        ]
        for s in statuses
    ]
    return _table_block(
        Text("Optional tools (detected, never installed by AUREON)", style="bold #e6edf3"),
        make_table(["Tool", "Status", "Version", "Purpose", "License", "Package", "Use in AUREON"], rows),
    )


# ---------------------------------------------------------------------------
# security
# ---------------------------------------------------------------------------
def render_fail2ban_status(status: Fail2banStatus):
    if not status.installed:
        return empty_state(
            "Fail2ban is not installed on this system.",
            "AUREON will show a clear state once Fail2ban is present; no installation is performed automatically.",
        )
    summary = [
        ["Installed", f"yes   version: {status.version or 'unknown'}"],
        ["Service", f"{status.service_state}   enabled at boot: {_bool(status.service_enabled)}"],
        ["Client access", "root required" if status.root_required else "current user"],
        ["Config dir", status.config_dir or "n/a"],
        ["Log source", f"{status.log_file or 'none'}   readable: {_bool(status.log_readable)}"],
        ["Currently banned (live)", str(status.banned_total)],
        ["SSH jail", _ssh_jail_line(status)],
    ]
    parts = [
        Text("Fail2ban status", style="bold #e6edf3"),
        make_table(["Field", "Value"], summary),
    ]
    if status.jails:
        parts.append(Text("Jails", style="bold #e6edf3"))
        parts.append(
            make_table(
                ["Jail", "Enabled", "Running", "Port", "maxretry", "findtime", "bantime", "Banned now", "Total bans", "Origin"],
                [
                    [
                        j.name,
                        _bool(j.enabled),
                        "yes" if j.runtime else "no",
                        j.port or "default",
                        str(j.maxretry if j.maxretry is not None else "default"),
                        str(j.findtime if j.findtime is not None else "default"),
                        str(j.bantime if j.bantime is not None else "default"),
                        str(j.currently_banned) if j.runtime else "unverified",
                        str(j.total_banned) if j.total_banned is not None else "unverified",
                        j.file_origin or "-",
                    ]
                    for j in status.jails
                ],
            )
        )
    for problem in status.problems:
        parts.append(Text(f"PROBLEM: {problem}", style="#e06c75"))
    for warning in status.warnings:
        parts.append(Text(f"! {warning}", style="#e5c07b"))
    return _table_block(*parts)


def _bool(value: Optional[bool]) -> str:
    if value is None:
        return "unverified"
    return "yes" if value else "no"


def _ssh_jail_line(status: Fail2banStatus) -> str:
    jail = status.ssh_jail
    if jail is None:
        return "none configured"
    return f"{jail.name}: {jail.status}; port={jail.port or 'default'}; bantime={jail.bantime or 'default'}"


def render_security_periods(periods: Dict[str, PeriodStats], coverage_text: str):
    rows = []
    for name in BUILTIN_PERIODS:
        stats = periods.get(name)
        if stats is None:
            continue
        rows.append(
            [
                name,
                f"{stats.start:%Y-%m-%d %H:%M}",
                f"{stats.end:%Y-%m-%d %H:%M}",
                stats.unique_banned_ips,
                stats.ban_events,
                stats.unban_events,
                stats.unbanned_ips,
                stats.currently_banned if stats.currently_banned is not None else "unverified",
                stats.failed_auth_attempts if stats.data_available else "no data",
                stats.recurrent_ips,
            ]
        )
    parts = [
        Text("Security statistics (stored history)", style="bold #e6edf3"),
        make_table(
            ["Period", "Start", "End", "Unique IPs", "Ban events", "Unban events",
             "IPs unbanned", "Banned now", "Failed SSH", "Recurrent IPs"],
            rows,
        ),
        Text(coverage_text, style="#6e7681"),
    ]
    today = periods.get("today")
    if today:
        parts.append(Text("Today: window, event counts and distinct addresses", style="bold #e6edf3"))
        parts.append(
            make_table(
                ["Metric", "Value"],
                [
                    ["Window", f"{today.start.isoformat()} -> {today.end.isoformat()}"],
                    ["Timezone", today.timezone],
                    ["Distinct banned IPs", today.unique_banned_ips],
                    ["Ban events", today.ban_events],
                    ["Last event", today.last_event_at.isoformat() if today.last_event_at else "no events"],
                    ["Data available", "yes" if today.data_available else "no"],
                ],
            )
        )
        if today.top_ips:
            parts.append(Text("Most active addresses today", style="bold #e6edf3"))
            parts.append(
                make_table(
                    ["IP", "Events", "Bans", "Recurrent"],
                    [[t["ip"], t["events"], t["bans"], "yes" if t["recurrent"] else "no"] for t in today.top_ips[:15]],
                )
            )
        for warning in today.warnings:
            parts.append(Text(f"! {warning}", style="#e5c07b"))
    return _table_block(*parts)


def render_banned_ips(rows: List[Dict], live: Dict[str, List[Dict[str, str]]], read_only: bool = True):
    parts = [
        Text("Currently banned (live, from fail2ban-client)", style="bold #e6edf3"),
    ]
    if live:
        live_rows = [
            [ip, jail, entry.get("when", "-")]
            for jail, entries in live.items()
            for entry in entries
            for ip in [entry.get("ip", "")]
        ]
        parts.append(make_table(["IP", "Jail", "Since (relative)"], live_rows))
    else:
        parts.append(
            empty_state(
                "Live ban list unavailable.",
                "It requires root: run `sudo aureon`. AUREON never fabricates this list.",
            )
        )

    parts.append(Text("Banned addresses recorded in history (period to date)", style="bold #e6edf3"))
    if rows:
        parts.append(
            make_table(
                ["IP", "Jail", "Last ban event", "Events"],
                [[r["ip"], r["jail"], r["last"].strftime("%Y-%m-%d %H:%M"), r["events"]] for r in rows],
            )
        )
    else:
        parts.append(empty_state("No historical ban events stored for the current period."))
    if read_only:
        parts.append(Text("Read-only build: unban actions are not available from the console.", style="#6e7681"))
    return _table_block(*parts)
