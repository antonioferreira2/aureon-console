"""Read-only inspection of locally visible Linux firewall configuration.

Only fixed query command vectors are allowed. Output is preserved as evidence;
this collector does not infer external reachability or interpret complex rules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple

from ..util import Availability, MAX_OUTPUT_BYTES, Result, which
from .base import Collector


@dataclass
class FirewallEvidence:
    technology: str
    query: str
    availability: str
    output: str = ""
    error: str = ""
    truncated: bool = False


@dataclass
class FirewallInfo:
    detected: List[str] = field(default_factory=list)
    evidence: List[FirewallEvidence] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


# Keep every command static and visibly read-only. Never add rules, alter
# policies, write configuration, or change a firewall service's state here.
_QUERIES: Tuple[Tuple[str, str, Tuple[Tuple[str, Tuple[str, ...]], ...]], ...] = (
    ("ufw", "ufw", (("version", ("version",)), ("status", ("status", "verbose")),
                       ("numbered rules", ("status", "numbered")), ("application profiles", ("app", "list")))),
    ("nftables", "nft", (("ruleset", ("list", "ruleset")),)),
    ("iptables", "iptables", (("IPv4 rules", ("-S",)),)),
    ("iptables", "ip6tables", (("IPv6 rules", ("-S",)),)),
    ("iptables", "iptables-save", (("IPv4 full ruleset", ()),)),
    ("iptables", "ip6tables-save", (("IPv6 full ruleset", ()),)),
    ("firewalld", "firewall-cmd", (("runtime state", ("--state",)),
                                      ("default zone", ("--get-default-zone",)),
                                      ("active zones", ("--get-active-zones",)),
                                      ("runtime zones", ("--list-all-zones",)),
                                      ("permanent zones", ("--permanent", "--list-all-zones")))),
)


class FirewallCollector(Collector):
    key = "firewall"
    title = "Firewall audit"
    source = "UFW, nftables, iptables, firewalld (read-only local queries)"

    def available(self) -> bool:
        return any(which(binary) for _, binary, _ in _QUERIES)

    def collect(self) -> Result:
        info = FirewallInfo()
        binaries = {}
        remaining = MAX_OUTPUT_BYTES
        for technology, binary, queries in _QUERIES:
            if binary not in binaries:
                binaries[binary] = which(binary)
            path = binaries[binary]
            if not path:
                continue
            if technology not in info.detected:
                info.detected.append(technology)
            for label, arguments in queries:
                if remaining <= 0:
                    info.warnings.append("Aggregate firewall output reached the 4 MiB collection limit; later query output was not retained.")
                    result = Result.ok_result(info, self.source)
                    result.warnings = info.warnings
                    return result
                result = self.ctx.run([path, *arguments], timeout=self.timeout())
                error_text = (result.stderr or "").lower()
                if result.timed_out:
                    state = Availability.TIMEOUT
                elif result.returncode in (126, 13) or "permission denied" in error_text or "operation not permitted" in error_text:
                    state = Availability.DENIED
                elif result.returncode == 127:
                    state = Availability.UNAVAILABLE
                elif result.returncode != 0:
                    state = Availability.ERROR
                elif result.stdout.strip():
                    state = Availability.OK
                else:
                    state = Availability.EMPTY

                # Bound aggregate stored evidence in addition to run()'s
                # per-process cap. Leave metadata for every attempted query.
                output = result.stdout[:remaining]
                truncated = result.truncated or len(output) < len(result.stdout)
                if truncated and len(result.stdout) > remaining:
                    info.warnings.append("Aggregate firewall output reached the 4 MiB collection limit; later query output was not retained.")
                remaining -= len(output)
                info.evidence.append(FirewallEvidence(
                    technology=technology,
                    query=label,
                    availability=state,
                    output=output,
                    error=(result.stderr or "").strip()[:500],
                    truncated=truncated,
                ))

        if not info.detected:
            return Result.unavailable(self.source, "no supported firewall query tool found in PATH")
        active_firewalld = any(item.technology == "firewalld" and item.query == "runtime state" and item.availability == Availability.OK and item.output.strip() == "running" for item in info.evidence)
        successful_ruleset = any(item.technology in {"ufw", "nftables", "iptables"} and item.query in {"status", "ruleset", "IPv4 rules", "IPv6 rules"} and item.availability == Availability.OK for item in info.evidence)
        if len(info.detected) > 1:
            info.warnings.append(
                "Multiple firewall tools are installed. Their relationship and which frontend manages effective rules cannot be established from local discovery alone."
            )
        if active_firewalld and successful_ruleset:
            info.warnings.append(
                "firewalld and another firewall rules frontend both returned data; determine which rules are managed by the active service before interpreting them as independent controls."
            )
        info.warnings.append(
            "Tool presence and local rules do not prove external Internet reachability; NAT, routing, cloud security groups and upstream firewalls may change exposure."
        )
        if any(item.availability in (Availability.DENIED, Availability.TIMEOUT, Availability.ERROR) for item in info.evidence):
            info.warnings.append(
                "Some queries were denied, timed out, or failed. Their ruleset is unverified; inspect per-query state and permissions."
            )
        result = Result.ok_result(info, self.source)
        result.warnings = info.warnings
        return result


__all__ = ["FirewallCollector", "FirewallEvidence", "FirewallInfo"]
