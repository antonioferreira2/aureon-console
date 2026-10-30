"""Panels: Rich renderers with translated static labels and verbatim host evidence."""
from __future__ import annotations

from typing import Dict, List, Optional
from rich.text import Text
from textual.widgets import Static

from ..collectors.docker import DockerInfo
from ..collectors.firewall import FirewallInfo
from ..hardening import Assessment
from ..collectors.logs import LogsInfo
from ..collectors.network import NetworkInfo
from ..collectors.sensors import SensorInfo
from ..collectors.services import ServicesInfo
from ..collectors.storage import StorageInfo
from ..collectors.system import SystemInfo
from ..collectors.tools import ToolStatus
from ..fail2ban.detect import Fail2banStatus
from ..models import Health, PeriodStats
from ..periods import BUILTIN_PERIODS
from ..util import Availability, Result, bar, human_bytes, human_duration, pct
from ..i18n import tr
from .widgets import HEALTH_STYLE, empty_state, make_table, source_text


def _t(key: str, language: str = "en") -> str:
    value = tr(key, language)
    return value if value != key else key.rsplit(".", 1)[-1].replace("_", " ").capitalize()


def panel(result: Result, render, language: str = "en", **kwargs):
    if not result.available:
        message = {
            Availability.UNAVAILABLE: _t("ui.module_unavailable", language),
            Availability.DENIED: _t("ui.permission_denied_detail", language),
            Availability.TIMEOUT: _t("ui.command_timeout", language),
            Availability.ERROR: _t("ui.command_failed", language),
        }.get(result.availability, _t("ui.data_unavailable", language))
        return empty_state(message, result.error or "")
    import inspect

    parameters = inspect.signature(render).parameters
    if "language" in parameters or any(item.kind == inspect.Parameter.VAR_KEYWORD for item in parameters.values()):
        body = render(result.value, language=language, **kwargs)
    else:
        body = render(result.value, **kwargs)
    parts = [body, source_text(result.availability, result.source, result.error)]
    parts.extend(Text("! " + warning, style="#e5c07b") for warning in result.warnings)
    return _table_block(*parts)


def widget(renderable):
    static = Static()
    static.update(renderable)
    return static


def _table_block(*renderables):
    from rich.console import Group
    from textual.widget import Widget
    return Group(*[item for item in renderables if item is not None and not isinstance(item, Widget)])


def render_system(info: SystemInfo, language: str = "en"):
    return _table_block(
        Text(_t("ui.host", language), style="bold #e6edf3"),
        make_table([_t("ui.metric", language), _t("ui.value", language)], [
            [_t("ui.hostname", language), info.hostname],
            [_t("ui.os", language), f"{info.os_name} {info.os_version}".strip()],
            [_t("ui.kernel", language), f"{info.kernel} ({info.arch})"],
            [_t("ui.uptime", language), human_duration(info.uptime_seconds)],
            [_t("ui.boot_time", language), info.boot_time.strftime("%Y-%m-%d %H:%M:%S %Z") if info.boot_time else _t("ui.unknown", language)],
        ]),
        Text(_t("ui.resources", language), style="bold #e6edf3"),
        make_table([_t("ui.metric", language), _t("ui.value", language), _t("ui.usage", language)], [
            [_t("ui.cpu", language), f"{info.cpu_percent:.1f}%" if info.cpu_percent is not None else "n/a", bar(info.cpu_percent or 0)],
            [_t("ui.load", language), f"{info.load1 if info.load1 is not None else '?'} / {info.load5 if info.load5 is not None else '?'} / {info.load15 if info.load15 is not None else '?'}", f"of {info.cpu_count} cpu"],
            [_t("ui.memory", language), f"{human_bytes(info.mem_used)} / {human_bytes(info.mem_total)}" + (f" ({info.mem_percent:.0f}%)" if info.mem_percent is not None else ""), bar(info.mem_percent or 0)],
            [_t("ui.swap", language), f"{human_bytes(info.swap_used)} / {human_bytes(info.swap_total)}", bar(pct(info.swap_used or 0, info.swap_total or 0))],
        ]),
        Text(f"CPU model: {info.cpu_model or _t('ui.unknown', language)}", style="#6e7681"),
    )


def render_processes(info: SystemInfo, redact: bool = True, language: str = "en"):
    rows = [[str(p.pid), "<redacted>" if redact else p.user, p.command[:28], f"{p.cpu_percent:.1f}%" if p.cpu_percent is not None else "n/a", f"{p.mem_percent:.1f}%" if p.mem_percent is not None else "n/a", human_bytes(p.mem_rss), p.state] for p in sorted(info.processes, key=lambda p: p.cpu_percent or 0, reverse=True)[:20]]
    return _table_block(Text(_t("ui.processes_cpu", language), style="bold #e6edf3"), make_table(["PID", _t("ui.user", language), _t("ui.command", language), _t("ui.cpu", language), "MEM%", "RSS", _t("ui.state", language)], rows), Text(_t("ui.never_terminate", language), style="#6e7681"))


def render_storage(info: StorageInfo, language: str = "en"):
    rows = [[m.mountpoint, m.device, m.fstype, human_bytes(m.size), human_bytes(m.used), human_bytes(m.available), f"{m.use_percent:.0f}%" if m.use_percent is not None else "n/a", _health_cell(m.health)] for m in info.mounts]
    disks = [[d.device, human_bytes(d.size_bytes), d.model or "n/a", _t("ui.rotational", language) if d.rota else _t("ui.solid_state", language), d.transport] for d in info.disks]
    parts = [Text(_t("ui.filesystems", language), style="bold #e6edf3"), make_table([_t("ui.mount", language), _t("ui.device", language), _t("ui.type", language), _t("ui.size", language), _t("ui.used", language), _t("ui.available", language), "Use%", _t("ui.state", language)], rows), Text(_t("ui.block_devices", language), style="bold #e6edf3"), make_table([_t("ui.device", language), _t("ui.size", language), _t("ui.model", language), _t("ui.type", language), _t("ui.transport", language)], disks)]
    if info.lvms:
        parts.extend([Text("LVM " + _t("ui.logical_volumes", language), style="bold #e6edf3"), make_table(["LV", "VG", _t("ui.size", language), _t("ui.devices", language)], [[v["lv"], v["vg"], v["size"], v["devices"]] for v in info.lvms])])
    return _table_block(*parts)


def _health_cell(health: Health) -> Text:
    return Text(f"{health.symbol} {health.label}", style=HEALTH_STYLE[health])


def render_network(info: NetworkInfo, language: str = "en"):
    rows = [[i.name, i.state, ", ".join(i.addresses) or "-", human_bytes(i.rx_bytes), human_bytes(i.tx_bytes), f"{human_bytes(i.rx_rate)}/s" if i.rx_rate is not None else "n/a", f"{human_bytes(i.tx_rate)}/s" if i.tx_rate is not None else "n/a", f"{i.rx_errors}/{i.tx_errors}", f"{i.rx_dropped}/{i.tx_dropped}"] for i in info.interfaces]
    listeners = [[s.protocol, s.local_address, str(s.local_port), s.state] for s in sorted(info.listening, key=lambda s: (s.protocol, s.local_port))]
    return _table_block(Text(_t("ui.interfaces_title", language), style="bold #e6edf3"), make_table(["IF", _t("ui.state", language), _t("ui.addresses", language), "RX", "TX", "RX/s", "TX/s", "Err", "Drops"], rows), Text(f"{_t('ui.listening', language)}: {len(info.listening)}   Established TCP: {info.established}   Default route via: {info.default_route or 'n/a'}", style="#6e7681"), Text(_t("ui.socket_warning", language), style="#e5c07b"), Text(_t("ui.listening", language), style="bold #e6edf3"), make_table(["Proto", _t("ui.address", language), _t("ui.port", language), _t("ui.state", language)], listeners))


def render_services(info: ServicesInfo, language: str = "en"):
    rows = [[s.unit, s.active_state, s.sub_state, s.enabled, s.since or "-", str(s.restarts) if s.restarts is not None else "-", (s.description or "")[:40]] for s in info.services]
    failed = [f"{s.unit} ({s.active_state}/{s.sub_state})" for s in info.failed]
    parts = [Text(f"{_t('ui.backend', language)}: {info.backend}   {_t('ui.total', language)}: {info.total}   {_t('ui.running', language)}: {info.running}   {_t('ui.failed', language)}: {len(info.failed)}", style="bold #e6edf3")]
    if failed:
        parts.append(Text(_t("ui.failed_units", language) + ": " + ", ".join(failed[:10]), style="#e06c75"))
    parts += [make_table([_t("ui.unit", language), _t("ui.active", language), _t("ui.sub", language), _t("ui.enabled", language), _t("ui.since", language), _t("ui.restarts", language), _t("ui.description", language)], rows), Text(_t("ui.readonly_service", language), style="#6e7681")]
    return _table_block(*parts)


def render_logs(info: LogsInfo, language: str = "en"):
    parts = [Text(f"{_t('ui.backend', language)}: {info.backend}   {_t('ui.lines', language)}: {len(info.lines)}   {_t('ui.errors', language)}: {info.errors}", style="bold #e6edf3"), make_table([_t("ui.log", language)], [[line.render() for line in info.lines[-200:]]])]
    if info.truncated:
        parts.append(Text(_t("ui.log_truncated", language), style="#e5c07b"))
    return _table_block(*parts)


def render_docker(info: DockerInfo, language: str = "en"):
    if not info.permissions_ok:
        return empty_state(_t("ui.docker_denied", language), _t("ui.docker_denied_detail", language))
    rows = [[c.short_id, c.name, c.image, c.state, c.status, str(c.restarts) if c.restarts is not None else "-"] for c in info.containers]
    parts = [Text(f"{_t('ui.backend', language)}: {info.backend}   {_t('ui.version', language)}: {info.version or _t('ui.unknown', language)}", style="bold #e6edf3"), make_table(["ID", _t("ui.name", language), _t("ui.image", language), _t("ui.state", language), _t("ui.status", language), _t("ui.restarts", language)], rows)]
    if info.restart_loops:
        parts.append(Text(_t("ui.restart_loops", language) + ": " + ", ".join(c.name for c in info.restart_loops), style="#e5c07b"))
    if info.images:
        parts.extend([Text(_t("ui.local_images", language), style="bold #e6edf3"), make_table([_t("ui.image", language), "ID", _t("ui.size", language)], [[i["image"], i["id"], i["size"]] for i in info.images[:30]])])
    return _table_block(*parts)


def render_sensors(info: SensorInfo, language: str = "en"):
    temps = [r for r in info.readings if r.kind == "temperature"]
    others = [r for r in info.readings if r.kind != "temperature"]
    parts = [Text(f"{_t('ui.backend', language)}: {info.backend}", style="bold #e6edf3")]
    if temps:
        parts += [Text(_t("ui.temperatures", language), style="bold #e6edf3"), make_table([_t("ui.sensor", language), _t("ui.value", language)], [[t.label, t.value] for t in temps] + [[_t("ui.max_observed", language), f"{max((t.numeric or 0) for t in temps):.1f} C"]])]
    if others:
        parts += [Text(_t("ui.other_sensors", language), style="bold #e6edf3"), make_table([_t("ui.sensor", language), _t("ui.value", language)], [[o.label, o.value] for o in others])]
    if info.gpus:
        parts += [Text(_t("ui.gpus", language), style="bold #e6edf3"), make_table([_t("ui.name", language), _t("ui.utilisation", language), _t("ui.memory", language), _t("ui.temperature", language)], [[g["name"], g["util"], g["mem"], g["temp"]] for g in info.gpus])]
    if not info.readings and not info.gpus:
        parts.append(empty_state(_t("ui.no_sensor_data", language)))
    parts.extend(Text("! " + warning, style="#e5c07b") for warning in info.warnings)
    return _table_block(*parts)


def render_tools(statuses: List[ToolStatus], language: str = "en"):
    rows = [[s.spec.name, _t("ui.installed", language) if s.installed else _t("ui.not_installed", language), s.version or "-", s.spec.purpose, s.spec.license, s.spec.package_hint, s.spec.integration] for s in statuses]
    return _table_block(Text(_t("ui.optional_tools", language), style="bold #e6edf3"), make_table([_t("ui.tool", language), _t("ui.status", language), _t("ui.version", language), _t("ui.purpose", language), _t("ui.license", language), _t("ui.package", language), _t("ui.use_in_aureon", language)], rows))


def render_fail2ban_status(status: Fail2banStatus, language: str = "en"):
    if not status.installed:
        return empty_state(_t("ui.f2b_not_installed", language), _t("ui.f2b_no_install", language))
    summary = [[_t("ui.installed", language), f"{_t('ui.yes', language)}   {_t('ui.version', language)}: {status.version or _t('ui.unknown', language)}"], [_t("ui.service", language), f"{status.service_state}   {_t('ui.enabled_at_boot', language)}: {_bool(status.service_enabled, language)}"], [_t("ui.client_access", language), _t("ui.root_required", language) if status.root_required else _t("ui.current_user", language)], [_t("ui.config_dir", language), status.config_dir or "n/a"], [_t("ui.log_source", language), f"{status.log_file or _t('ui.none', language)}   {_t('ui.readable', language)}: {_bool(status.log_readable, language)}"], [_t("ui.currently_banned", language), str(status.banned_total)], [_t("ui.ssh_jail", language), _ssh_jail_line(status, language)]]
    parts = [Text(_t("ui.f2b_status", language), style="bold #e6edf3"), make_table([_t("ui.field", language), _t("ui.value", language)], summary)]
    if status.jails:
        parts += [Text(_t("ui.jails", language), style="bold #e6edf3"), make_table([_t("ui.jail", language), _t("ui.enabled", language), _t("ui.running", language), _t("ui.port", language), "maxretry", "findtime", "bantime", _t("ui.banned_now", language), _t("ui.total_bans", language), _t("ui.origin", language)], [[j.name, _bool(j.enabled, language), _t("ui.yes", language) if j.runtime else _t("ui.no", language), j.port or _t("ui.default", language), str(j.maxretry if j.maxretry is not None else _t("ui.default", language)), str(j.findtime if j.findtime is not None else _t("ui.default", language)), str(j.bantime if j.bantime is not None else _t("ui.default", language)), str(j.currently_banned) if j.runtime else _t("ui.unverified", language), str(j.total_banned) if j.total_banned is not None else _t("ui.unverified", language), j.file_origin or "-"] for j in status.jails])]
    parts.extend(Text(_t("ui.problem", language) + ": " + problem, style="#e06c75") for problem in status.problems)
    parts.extend(Text("! " + warning, style="#e5c07b") for warning in status.warnings)
    return _table_block(*parts)


def _bool(value: Optional[bool], language: str = "en") -> str:
    if value is None:
        return _t("ui.unverified", language)
    return _t("ui.yes" if value else "ui.no", language)


def _ssh_jail_line(status: Fail2banStatus, language: str = "en") -> str:
    jail = status.ssh_jail
    if jail is None:
        return _t("ui.none_configured", language)
    return f"{jail.name}: {jail.status}; {_t('ui.port', language)}={jail.port or _t('ui.default', language)}; bantime={jail.bantime or _t('ui.default', language)}"


def render_security_periods(periods: Dict[str, PeriodStats], coverage_text: str, language: str = "en"):
    rows = []
    for name in BUILTIN_PERIODS:
        stats = periods.get(name)
        if stats is not None:
            rows.append([_t("period." + name, language), f"{stats.start:%Y-%m-%d %H:%M}", f"{stats.end:%Y-%m-%d %H:%M}", stats.unique_banned_ips, stats.ban_events, stats.unban_events, stats.unbanned_ips, stats.currently_banned if stats.currently_banned is not None else _t("ui.unverified", language), stats.failed_auth_attempts if stats.data_available else _t("ui.no_data", language), stats.recurrent_ips])
    parts = [Text(_t("ui.security_stats", language), style="bold #e6edf3"), make_table([_t("ui.period", language), _t("ui.start", language), _t("ui.end", language), _t("ui.unique_ips", language), _t("ui.ban_events", language), _t("ui.unban_events", language), _t("ui.ips_unbanned", language), _t("ui.banned_now", language), _t("ui.failed_ssh", language), _t("ui.recurrent_ips", language)], rows), Text(coverage_text, style="#6e7681")]
    today = periods.get("today")
    if today:
        parts += [Text(_t("ui.today", language), style="bold #e6edf3"), make_table([_t("ui.metric", language), _t("ui.value", language)], [[_t("ui.window", language), f"{today.start.isoformat()} -> {today.end.isoformat()}"], [_t("ui.timezone", language), today.timezone], [_t("ui.distinct_banned_ips", language), today.unique_banned_ips], [_t("ui.ban_events", language), today.ban_events], [_t("ui.last_event", language), today.last_event_at.isoformat() if today.last_event_at else _t("ui.no_events", language)], [_t("ui.data_available", language), _t("ui.yes" if today.data_available else "ui.no", language)]])]
        if today.top_ips:
            parts += [Text(_t("ui.most_active_addresses", language), style="bold #e6edf3"), make_table(["IP", _t("ui.events", language), _t("ui.bans", language), _t("ui.recurrent", language)], [[t["ip"], t["events"], t["bans"], _t("ui.yes" if t["recurrent"] else "ui.no", language)] for t in today.top_ips[:15]])]
        parts.extend(Text("! " + warning, style="#e5c07b") for warning in today.warnings)
    return _table_block(*parts)


def render_banned_ips(rows: List[Dict], live: Dict[str, List[Dict[str, str]]], read_only: bool = True, language: str = "en"):
    parts = [Text(_t("ui.currently_banned_live", language), style="bold #e6edf3")]
    if live:
        live_rows = [[entry.get("ip", ""), jail, entry.get("when", "-")] for jail, entries in live.items() for entry in entries]
        parts.append(make_table(["IP", _t("ui.jail", language), _t("ui.since_relative", language)], live_rows))
    else:
        parts.append(empty_state(_t("ui.live_ban_unavailable", language), _t("ui.root_for_live_bans", language)))
    parts.append(Text(_t("ui.historical_bans_period", language), style="bold #e6edf3"))
    if rows:
        parts.append(make_table(["IP", _t("ui.jail", language), _t("ui.last_ban_event", language), _t("ui.events", language)], [[r["ip"], r["jail"], r["last"].strftime("%Y-%m-%d %H:%M"), r["events"]] for r in rows]))
    else:
        parts.append(empty_state(_t("ui.no_historical_bans", language)))
    if read_only:
        parts.append(Text(_t("ui.readonly_unban", language), style="#6e7681"))
    return _table_block(*parts)


def render_firewall(info: FirewallInfo, language: str = "en"):
    parts = [Text(_t("ui.firewall_local", language), style="bold #e6edf3"), Text(_t("ui.detected_tools", language) + ": " + (", ".join(info.detected) or _t("ui.none", language)))]
    if info.evidence:
        rows = [[item.technology, item.query, item.availability, _t("ui.yes" if item.truncated else "ui.no", language)] for item in info.evidence]
        parts.append(make_table([_t("ui.technology", language), _t("ui.query", language), _t("ui.state", language), _t("ui.truncated", language)], rows))
        for item in info.evidence:
            parts.append(Text(f"[{item.technology}: {item.query}]", style="bold"))
            if item.output:
                parts.append(Text(item.output.rstrip("\n")))
            if item.error:
                parts.append(Text(_t("ui.error", language) + ": " + item.error, style="#e5c07b"))
    parts.extend(Text("! " + warning, style="#e5c07b") for warning in info.warnings)
    return _table_block(*parts)


def render_assessment_history(records, language: str = "en"):
    parts = [Text(tr("nav.assessment-history", language), style="bold #e6edf3")]
    if not records:
        parts.append(Text(_t("ui.no_assessments_detail", language)))
    else:
        rows = [[record.get("id", ""), record.get("assessed_at", ""), record.get("score") if record.get("score") is not None else _t("assessment.unavailable", language), record.get("definition_version", "")] for record in reversed(records)]
        parts.append(make_table(["ID", _t("ui.assessed_at", language), _t("assessment.score", language), _t("ui.definition", language)], rows))
        parts.append(Text(_t("ui.compare_snapshots", language)))
    return _table_block(*parts)


def render_assessment(assessment: Assessment, language: str = "en"):
    parts = [Text(_t("assessment.title", language), style="bold #e6edf3"), Text(f"{_t('ui.assessed_at', language)}: {assessment.assessed_at} | tool {assessment.tool_version} | checks v{assessment.definition_version}"), Text(f"{_t('assessment.score', language)}: {assessment.score if assessment.score is not None else _t('assessment.unavailable', language)} / 100"), Text(_t("assessment.scoring_method", language), style="#6e7681")]
    rows = [[r.check.id, r.check.domain, _t("outcome." + r.outcome.value, language), r.check.severity, r.check.title] for r in assessment.checks]
    parts.append(make_table(["ID", _t("ui.domain", language), _t("ui.outcome", language), _t("ui.severity", language), _t("ui.check", language)], rows))
    for result in assessment.checks:
        parts.append(Text(f"{result.check.id}: {result.reason or result.check.description}"))
        parts.extend(Text("  " + _t("assessment.evidence", language) + ": " + item, style="#6e7681") for item in result.evidence)
        if result.outcome.value == "FAIL":
            parts += [Text("  " + _t("assessment.recommendation", language) + ": " + result.check.remediation, style="#e5c07b"), Text("  " + _t("assessment.verification", language) + ": " + result.check.verification)]
        if result.check.limitations:
            parts.append(Text("  " + _t("assessment.limitation", language) + ": " + result.check.limitations, style="#6e7681"))
    return _table_block(*parts)
