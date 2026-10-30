"""Small, evidence-based hardening assessment for locally verifiable controls.

Unknown or failed collection is never scored as a pass. The score is a weighted
summary of evaluated checks, not a certification or guarantee of security.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import re
from pathlib import Path
from typing import Dict, List, Optional

from .collectors.firewall import FirewallInfo
from .util import Availability

CHECK_DEFINITION_VERSION = "6"


class Outcome(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"


@dataclass(frozen=True)
class CheckDefinition:
    id: str
    domain: str
    title: str
    description: str
    data_sources: tuple
    expected_state: str
    severity: str
    weight: int
    remediation: str
    verification: str
    limitations: str


@dataclass
class CheckResult:
    check: CheckDefinition
    outcome: Outcome
    evidence: List[str] = field(default_factory=list)
    reason: str = ""

    def as_dict(self) -> dict:
        data = asdict(self)
        data["outcome"] = self.outcome.value
        return data


@dataclass
class Assessment:
    assessed_at: str
    tool_version: str
    definition_version: str
    score: Optional[int]
    domain_scores: Dict[str, Optional[int]]
    checks: List[CheckResult]
    scoring_method: str = "Weighted earned points / evaluated points; NOT_APPLICABLE and informational checks excluded. If any applicable non-informational check is UNKNOWN or ERROR, score is withheld. Critical failures cap the score at 25. This is not a certification."

    def as_dict(self) -> dict:
        return {
            "assessed_at": self.assessed_at,
            "tool_version": self.tool_version,
            "definition_version": self.definition_version,
            "score": self.score,
            "domain_scores": self.domain_scores,
            "scoring_method": self.scoring_method,
            "checks": [check.as_dict() for check in self.checks],
        }


CHECKS = (
    CheckDefinition(
        id="SSH-ROOT-LOGIN",
        domain="SSH",
        title="SSH root login policy",
        description="Check effective sshd policy for PermitRootLogin.",
        data_sources=("sshd -T",),
        expected_state="permitrootlogin is not yes",
        severity="high",
        weight=5,
        remediation="Review PermitRootLogin in the effective sshd configuration; plan a safe alternative access path before changing it.",
        verification="Re-run `sshd -T` and confirm permitrootlogin is not yes.",
        limitations="Default sshd -T context only; SSH-MATCH-CONTEXTS discovers readable Include files and queries safe representative contexts, but cannot prove every user, group, wildcard, address, host, port, include ordering, or overlapping Match combination.",
    ),
    CheckDefinition(
        id="FIREWALL-TOOL-AVAILABLE",
        domain="Firewall",
        title="Firewall query capability",
        description="Check whether a supported local firewall inspection tool was detected.",
        data_sources=("PATH discovery",),
        expected_state="at least one supported query tool is available",
        severity="informational",
        weight=1,
        remediation="Determine which network controls protect this host; an absent local tool does not prove that no upstream firewall exists.",
        verification="Inspect host and provider-level network policy separately.",
        limitations="Installed tools do not prove a firewall is active or effective.",
    ),
    CheckDefinition(
        id="FIREWALL-INBOUND-POLICY",
        domain="Firewall",
        title="Firewall inbound posture",
        description="Conservatively evaluate active UFW defaults, paired IPv4/IPv6 iptables INPUT policies, and a narrow nftables input subset; flag an unconditional nft accept or a universal-source allow for common administrative ports only when a complete single-chain inet ruleset is visible. Do not infer external reachability or interpret arbitrary allow rules as safe.",
        data_sources=("ufw status verbose", "nft list ruleset", "iptables -S", "iptables-save", "firewalld runtime zones"),

        expected_state="explicit restrictive inbound policy is evidenced",
        severity="high",
        weight=5,
        remediation="Review the active ruleset and external network controls with the system owner before proposing a targeted change.",
        verification="Compare runtime firewall policy, listening services, IPv4/IPv6 coverage, and upstream controls.",
        limitations="Parses a single-table/single-input-chain nftables subset, including a narrowly matched universal-source ACCEPT for common administrative ports only as its first rule, or complete IPv4/IPv6 iptables filter rulesets with no rules; detects an unconditional iptables INPUT ACCEPT in the first INPUT rule position. Other explicit rules, additional chains/tables, chain flow, ordering, forwarding, namespaces, routing, other firewall managers, upstream controls and external reachability remain UNKNOWN or require separate review.",
    ),
    CheckDefinition("SSH-PASSWORD-AUTH", "SSH", "SSH password authentication", "Inspect effective password authentication policy.", ("sshd -T",), "password authentication disabled or separately justified", "high", 4, "Review account recovery, keys and MFA before changing authentication policy.", "Re-run sshd -T and verify passwordauthentication.", "Does not evaluate Match blocks or account-level controls."),
    CheckDefinition("SSH-MAX-AUTH-TRIES", "SSH", "SSH authentication attempt limit", "Inspect effective MaxAuthTries.", ("sshd -T",), "at most 6 attempts", "medium", 2, "Review MaxAuthTries against operational access needs.", "Re-run sshd -T and verify maxauthtries.", "Threshold is a conservative heuristic, not a universal policy."),
    CheckDefinition("SSH-IDLE-TIMEOUT", "SSH", "SSH idle session timeout", "Inspect effective ClientAlive settings.", ("sshd -T",), "positive client alive interval and count", "medium", 2, "Review ClientAliveInterval and ClientAliveCountMax for operational impact.", "Re-run sshd -T and verify both effective settings.", "Does not measure client-side or network idle timeouts."),
    CheckDefinition("SSH-MATCH-CONTEXTS", "SSH", "SSH Match-specific policies", "Read the sshd configuration Include tree and query representative literal Match contexts using sshd -T -C; report gaps for wildcards and groups.", ("/etc/ssh/sshd_config", "read-only Include traversal", "sshd -T -C"), "no sampled Match context weakens assessed controls and all relevant contexts are reviewed", "high", 4, "Review each Match block and validate effective settings for the actual users, groups, source addresses, local addresses, hostnames and ports that can connect.", "Run sshd -T -C with representative real connection contexts and compare the security-sensitive effective settings.", "The Include walk and context samples are bounded and do not model conditional Include placement, every wildcard/group/negated selector, precedence overlap, or all real connections; complex and incomplete cases remain UNKNOWN."),
    CheckDefinition("ACCOUNT-UID0", "Accounts", "UID 0 accounts", "Find accounts other than root with UID zero.", ("/etc/passwd",), "only root has UID 0", "critical", 5, "Verify each additional UID 0 account and remove/disable only through a separately reviewed change.", "Re-read /etc/passwd and confirm UID 0 account inventory.", "Name alone does not establish maliciousness."),
    CheckDefinition("SUDOERS-PERMISSIONS", "Accounts", "Sudo policy permissions", "Check sudoers path group/world write permissions.", ("/etc/sudoers", "/etc/sudoers.d metadata"), "not group/world writable", "high", 4, "Review ownership and access of sudo policy paths.", "Recheck modes and validate policy through an administrator-controlled procedure.", "Does not parse sudo policy semantics."),
    CheckDefinition("FILESYSTEM-SECRET-PERMISSIONS", "Filesystem", "Sensitive file permissions", "Inspect metadata for account databases and SSH host keys without reading contents.", ("stat metadata",), "restrictive access modes", "high", 4, "Review ownership and permissions of sensitive files.", "Recheck metadata after separately approved changes.", "Only selected conventional paths are checked; secret contents are never opened."),
    CheckDefinition("FILESYSTEM-TMP-MOUNT", "Filesystem", "Temporary filesystem mount options", "Inspect options for a distinct /tmp mount.", ("/proc/self/mounts",), "nodev and nosuid if separately mounted", "low", 1, "Assess mount options in the context of application requirements.", "Re-read effective mount options.", "A missing separate mount is UNKNOWN, not a failure."),
    CheckDefinition("LOG-PERSISTENT-JOURNAL", "Logging", "Persistent system journal", "Inspect explicit journald Storage configuration.", ("journald config files",), "persistent logging configured", "medium", 2, "Review journal retention and storage policy.", "Verify effective journald settings and log persistence.", "Defaults and runtime state are not inferred from absent directives."),
    CheckDefinition("LOG-AUDIT-SUBSYSTEM", "Logging", "Kernel audit subsystem", "Inspect audit subsystem status when auditctl is available.", ("auditctl -s",), "audit enabled", "medium", 2, "Assess audit policy and system requirements.", "Re-query audit status and review configured rules.", "Does not evaluate audit rules completeness."),
    CheckDefinition("HOST-SELINUX", "Host protection", "SELinux enforcement", "Inspect SELinux enforcement state when available.", ("/sys/fs/selinux/enforce",), "enforcing when applicable", "high", 3, "Review SELinux policy and application compatibility.", "Recheck enforcement state and policy status.", "Not applicable on systems without SELinux."),
    CheckDefinition("HOST-APPARMOR", "Host protection", "AppArmor kernel support", "Inspect the kernel AppArmor enabled parameter.", ("/sys/module/apparmor/parameters/enabled",), "enabled when applicable", "medium", 2, "Review AppArmor profiles and required application coverage.", "Recheck kernel state and loaded profiles.", "Kernel enablement does not prove profile coverage."),
    CheckDefinition("F2B-SSH-JAIL", "Fail2ban", "SSH Fail2ban jail", "Inspect active Fail2ban jail inventory.", ("fail2ban-client status",), "an SSH-related jail active where appropriate", "medium", 2, "Review authentication exposure and whether host-level brute-force mitigation is appropriate.", "Query Fail2ban status and inspect the effective SSH jail.", "A local jail is not required in every deployment and does not replace upstream controls."),
    CheckDefinition("CONTAINERS-PRIVILEGED", "Containers", "Container privilege and exposure posture", "Inspect up to 100 Docker/Podman containers, including stopped containers, for privileged mode, added high-risk capabilities, host namespaces, runtime sockets, writable bind mounts, rootfs mode and published ports.", ("docker/podman ps --all --quiet", "docker/podman inspect JSON"), "no confirmed high-risk privileges; other workload-dependent settings manually reviewed", "high", 4, "Review each workload's privilege, host integration, mount, capability and port requirements before proposing a least-privilege change.", "Reinspect the same runtime configuration and validate exposure from an authorized network vantage point.", "Inspection is limited to accessible containers (max 100 combined across detected runtimes). A clean result remains UNKNOWN because image vulnerabilities, secrets, processes, kernel isolation, orchestrator settings, writable mounts/ports intent and external reachability are not fully evaluated."),
    CheckDefinition("BACKUP-RECOVERY-EVIDENCE", "Backups", "Backup and recovery evidence", "Inventory selected local backup indicators without claiming recovery readiness.", ("known paths and executable discovery",), "verified recent backup and tested recovery", "medium", 2, "Verify backup freshness, isolation, retention and a restore drill.", "Perform an authorized restore test using documented recovery procedures.", "Local file/tool presence cannot prove backup integrity or recoverability."),
    CheckDefinition("OS-SECURITY-UPDATES", "Operating system", "Security update status", "Inspect recent local package metadata with read-only/cache-only APT, DNF or zypper security-update queries; never refresh metadata or change packages.", ("apt list --upgradable", "apt-cache policy package", "dnf repoquery --cacheonly --security", "zypper --no-refresh patch-check", "local package-index metadata"), "no pending security candidate is reported by fresh, complete local metadata", "high", 4, "Review package origins and security advisories, then schedule updates through the normal maintenance process.", "After separately approved maintenance and an administrator-run metadata refresh, rerun the assessment.", "Only local package-manager state is queried. Index freshness is a 14-day heuristic; vendor-specific advisory channels and upstream state may not be represented. Alpine apk identifies general upgrades but not security advisories, so remains UNKNOWN; unsupported distributions, stale/missing indexes and ambiguous output are UNKNOWN."),
    CheckDefinition("OS-REBOOT-REQUIRED", "Operating system", "Reboot-required indicator", "Inspect supported distribution reboot-required markers.", ("/var/run/reboot-required",), "no reboot-required marker", "medium", 2, "Review the reason and plan a maintenance reboot through normal operations.", "Recheck the distribution marker after an approved reboot.", "Marker presence is distro-specific; absence is not proof that no reboot is needed."),
    CheckDefinition("ACCOUNT-PASSWORD-AGING", "Accounts", "Default password aging policy", "Inspect PASS_MAX_DAYS in login.defs without reading password hashes.", ("/etc/login.defs",), "positive maximum age no greater than 365 days", "medium", 2, "Review password expiry policy with identity and service-account owners.", "Re-read PASS_MAX_DAYS and audit account-specific policy separately.", "This global default does not prove policy for existing accounts or external identity providers."),
    CheckDefinition("NETWORK-WILDCARD-LISTENERS", "Network", "Wildcard listening sockets", "Review local listening socket addresses using ss.", ("ss -H -lntu",), "no unreviewed wildcard-bound listeners", "medium", 2, "Review each wildcard-bound service together with host and upstream firewall policy.", "Re-query local sockets and validate exposure from an authorized external vantage point.", "Local socket state does not prove Internet reachability."),
    CheckDefinition("KERNEL-SECURITY-SYSCTLS", "Host protection", "Kernel security parameters", "Inspect a small set of read-only kernel security sysctls.", ("/proc/sys/kernel/randomize_va_space", "/proc/sys/kernel/dmesg_restrict", "/proc/sys/kernel/kptr_restrict"), "ASLR enabled, dmesg restricted, kernel pointers restricted", "high", 3, "Review kernel security parameter guidance and workload compatibility before changing values.", "Re-read the effective /proc/sys values after a separately approved change.", "Only selected parameters are checked; namespaces and distribution policy may affect applicability."),
    CheckDefinition("TIME-SYNCHRONIZATION", "Logging", "System time synchronization", "Query timedatectl synchronization state when available.", ("timedatectl show -p NTPSynchronized --value",), "synchronized", "medium", 2, "Review the time service and its upstream sources; do not change it from AUREON.", "Re-query synchronization status and compare timestamps with a trusted source.", "A synchronized flag does not establish source integrity or accuracy."),
    CheckDefinition("LOG-ROTATION", "Logging", "Log rotation configuration evidence", "Inspect existing logrotate configuration for a declared positive retention count.", ("/etc/logrotate.conf", "/etc/logrotate.d metadata/config"), "a positive rotation count is configured", "low", 1, "Review retention and storage requirements for security logs.", "Inspect effective logrotate configuration through an administrator-controlled review.", "Does not establish that rotation ran successfully or that journals have equivalent retention."),
)


def _result(check_id: str, outcome: Outcome, evidence=(), reason="") -> CheckResult:
    definition = next(check for check in CHECKS if check.id == check_id)
    return CheckResult(definition, outcome, list(evidence), reason)


def assess_ssh_root_login(value: Optional[str], *, collection_error: str = "") -> CheckResult:
    if collection_error:
        return _result("SSH-ROOT-LOGIN", Outcome.ERROR, reason=collection_error)
    if value is None or not value.strip():
        return _result("SSH-ROOT-LOGIN", Outcome.UNKNOWN, reason="sshd effective configuration was unavailable")
    setting = value.strip().lower().split()[0]
    if setting == "yes":
        return _result(
            "SSH-ROOT-LOGIN",
            Outcome.FAIL,
            evidence=[f"sshd -T reported permitrootlogin {setting}"],
            reason="Direct SSH root login is enabled in the queried effective configuration.",
        )
    if setting in {"no", "prohibit-password", "without-password"}:
        outcome = Outcome.FAIL if setting in {"prohibit-password", "without-password"} else Outcome.PASS
        return _result(
            "SSH-ROOT-LOGIN",
            outcome,
            evidence=[f"sshd -T reported permitrootlogin {setting}"],
            reason="Root SSH login is limited to non-password authentication, but direct root login remains enabled." if outcome == Outcome.FAIL else "Root SSH login is disabled.",
        )

    return _result("SSH-ROOT-LOGIN", Outcome.UNKNOWN, evidence=[f"sshd -T reported permitrootlogin {setting}"], reason="Unrecognized value; manual review required.")


def _assess_simple_firewall_policy(info: FirewallInfo):
    """Interpret only explicit, narrowly understood inbound defaults."""
    entries = {(item.technology, item.query): item for item in info.evidence}
    successful = [item for item in info.evidence if item.availability in (Availability.OK, Availability.EMPTY)]
    evidence = [f"{item.technology} {item.query}: {item.output.strip()[:300]}" for item in successful if item.output.strip()]
    if len(info.detected) != 1:
        return Outcome.UNKNOWN, evidence, "Multiple firewall frontends or no active frontend were detected; effective rule ownership and precedence are ambiguous."

    technology = info.detected[0]
    if technology == "ufw":
        status = entries.get(("ufw", "status"))
        if not status or status.availability != Availability.OK:
            return Outcome.UNKNOWN, evidence, "UFW status could not be read; active state and defaults remain unknown."
        text = status.output
        if re.search(r"(?im)^\s*Status:\s*inactive\s*$", text):
            return Outcome.FAIL, evidence, "UFW explicitly reports inactive; this does not establish whether another upstream firewall protects the host."
        numbered = entries.get(("ufw", "numbered rules"))
        if not numbered or numbered.availability != Availability.OK or numbered.truncated:
            return Outcome.UNKNOWN, evidence, "UFW numbered rules could not be read completely; effective allow exceptions are unknown."
        default = re.search(r"(?im)^\s*Default:\s*([^,]+)\s*,\s*([^,]+)", text)
        try:
            ipv6_config = Path("/etc/default/ufw").read_text(encoding="utf-8", errors="replace")[:64_000]
            ipv6_error = ""
        except OSError as exc:
            ipv6_config, ipv6_error = "", str(exc)
        ipv6_match = re.search(r"(?im)^\s*IPV6\s*=\s*['\"]?(yes|no)['\"]?\s*(?:#.*)?$", ipv6_config)
        if not re.search(r"(?im)^\s*Status:\s*active\s*$", text) or not default or not ipv6_match:
            extra = ["/etc/default/ufw IPv6 setting unavailable"] if ipv6_error or not ipv6_match else []
            return Outcome.UNKNOWN, evidence + extra, "UFW output/config did not establish active status, both default directions, and explicit IPv6 handling."
        incoming, outgoing = (value.strip().lower() for value in default.groups())
        ipv6_enabled = ipv6_match.group(1).lower() == "yes"
        if incoming.startswith(("deny", "reject")) and ipv6_enabled:
            rule_rows = [line for line in numbered.output.splitlines() if re.match(r"^\s*\[\s*\d+\]", line)]
            if rule_rows:
                return Outcome.UNKNOWN, evidence + [f"/etc/default/ufw IPV6={ipv6_match.group(1)}", f"UFW reports {len(rule_rows)} explicit rule row(s)"], "UFW has a restrictive inbound default, but explicit rules may allow broad traffic and their semantics are not fully evaluated."
            return Outcome.PASS, evidence + [f"/etc/default/ufw IPV6={ipv6_match.group(1)}"], f"UFW is active with default incoming={incoming}, outgoing={outgoing}, IPv6 enabled and no explicit rules displayed; external reachability is not established."
        if incoming.startswith(("allow",)) or not ipv6_enabled:
            return Outcome.FAIL, evidence + [f"/etc/default/ufw IPV6={ipv6_match.group(1)}"], f"UFW reports default incoming={incoming} or IPv6 filtering disabled."
        return Outcome.UNKNOWN, evidence, f"UFW incoming default {incoming!r} was not recognized conservatively."

    if technology == "iptables":
        parsed = []
        for query, save_query, family in (("IPv4 rules", "IPv4 full ruleset", "IPv4"), ("IPv6 rules", "IPv6 full ruleset", "IPv6")):
            item = entries.get(("iptables", query))
            if not item or item.availability != Availability.OK or item.truncated:
                return Outcome.UNKNOWN, evidence, f"{family} iptables INPUT policy is unavailable or truncated."
            policy = re.search(r"(?m)^-P INPUT (ACCEPT|DROP|REJECT)\s*$", item.output)
            if not policy:
                return Outcome.UNKNOWN, evidence, f"{family} iptables output has no parseable INPUT default policy."
            if policy.group(1) == "ACCEPT":
                return Outcome.FAIL, evidence, f"{family} iptables has an ACCEPT default INPUT policy."
            save = entries.get(("iptables", save_query))
            if not save or save.availability != Availability.OK or save.truncated:
                return Outcome.UNKNOWN, evidence, f"{family} iptables full ruleset is unavailable; the -S output alone cannot prove absence of explicit rules."
            save_policy = re.search(r"(?m)^:INPUT (ACCEPT|DROP|REJECT)\s", save.output)
            if not save_policy or save_policy.group(1) != policy.group(1):
                return Outcome.UNKNOWN, evidence, f"{family} iptables policy evidence is inconsistent or incomplete."
            chain_policies = re.findall(r"(?m)^:([^\s]+)\s+(ACCEPT|DROP|REJECT)\s+\[\d+:\d+\]\s*$", save.output)
            if len(chain_policies) != 3 or {name for name, _ in chain_policies} != {"INPUT", "FORWARD", "OUTPUT"}:
                return Outcome.UNKNOWN, evidence, f"{family} iptables full filter table did not include exactly the standard INPUT/FORWARD/OUTPUT chains."
            all_chains = re.findall(r"(?m)^:([^\s]+)\s+[^\s]+\s+\[\d+:\d+\]\s*$", save.output)
            if len(all_chains) != 3 or set(all_chains) != {"INPUT", "FORWARD", "OUTPUT"}:
                return Outcome.UNKNOWN, evidence, f"{family} iptables contains user-defined or otherwise unsupported chains; jump semantics are not evaluated."
            tables = [line for line in save.output.splitlines() if line.startswith("*")]
            allowed_lines = re.compile(r"(?:#.*|\*filter|:[A-Z]+ (?:ACCEPT|DROP|REJECT) \[\d+:\d+\]|-A [A-Za-z0-9_.:+-]+(?: .*)?|COMMIT|)")
            if tables != ["*filter"] or not re.search(r"(?m)^COMMIT\s*$", save.output) or any(not allowed_lines.fullmatch(line) for line in save.output.splitlines()):
                return Outcome.UNKNOWN, evidence, f"{family} iptables includes unsupported or incomplete lines/tables; their exposure effects are not interpreted."
            if {name: policy for name, policy in chain_policies}.get("INPUT") != policy.group(1):
                return Outcome.UNKNOWN, evidence, f"{family} iptables-save and iptables -S report inconsistent INPUT policies."
            rules = [line for line in save.output.splitlines() if line.startswith("-A ")]
            # An unconditional ACCEPT on INPUT is a demonstrable broad allow.
            # More specific expressions stay UNKNOWN for manual semantic review.
            input_rules = [rule for rule in rules if len(rule.split()) > 1 and rule.split()[1] == "INPUT"]
            for rule_index, rule in enumerate(input_rules):
                tokens = rule.split()
                if len(tokens) < 4:
                    continue
                target = next((tokens[index + 1] for index, token in enumerate(tokens[:-1]) if token in {"-j", "--jump"}), None)
                if target != "ACCEPT":
                    continue
                match_tokens = tokens[2:]
                effective = []
                index = 0
                while index < len(match_tokens):
                    token = match_tokens[index]
                    if token in {"-m", "--match"} and index + 1 < len(match_tokens):
                        extension = match_tokens[index + 1]
                        if extension == "comment":
                            index += 2
                            continue
                    if token == "--comment" and index + 1 < len(match_tokens):
                        index += 2
                        continue
                    if token in {"-j", "--jump"}:
                        index += 2
                        continue
                    if token == "ACCEPT":
                        index += 1
                        continue
                    effective.append(token)
                    index += 1
                if not effective and rule_index == 0:
                    return Outcome.FAIL, evidence, f"{family} iptables starts INPUT with an unconditional ACCEPT rule."
                if not effective:
                    return Outcome.UNKNOWN, evidence, f"{family} iptables has an unconditional ACCEPT rule after earlier INPUT rules; ordered verdict semantics are not fully evaluated."
            parsed.append((family, policy.group(1), rules))
        if any(policy == "ACCEPT" for _, policy, _ in parsed):
            return Outcome.FAIL, evidence, "At least one IP family has an ACCEPT default INPUT policy."
        if any(rules for _, _, rules in parsed):
            return Outcome.UNKNOWN, evidence, "Both IP-family INPUT defaults are restrictive, but explicit rules require ordered chain/jump/conntrack/interface semantic analysis."
        return Outcome.PASS, evidence, "Complete IPv4 and IPv6 iptables-save output has restrictive INPUT defaults and no rules in any table; this does not establish external reachability or namespace/upstream policy."

    if technology == "nftables":
        item = entries.get(("nftables", "ruleset"))
        if not item or item.availability != Availability.OK or item.truncated:
            return Outcome.UNKNOWN, evidence, "nftables ruleset is unavailable or truncated."
        # Recognize only a complete, single inet input base chain. In that
        # constrained shape a universal-source ACCEPT for a common remote
        # administration port is directly evidenced; arbitrary expressions,
        # additional base chains and cross-table ordering remain unknown.
        single_input = re.fullmatch(
            r"\s*table\s+inet\s+[A-Za-z0-9_.-]+\s*\{\s*"
            r"chain\s+[A-Za-z0-9_.-]+\s*\{\s*"
            r"type\s+filter\s+hook\s+input\s+priority\s+[^;{}]+;\s*"
            r"policy\s+(?:drop|accept)\s*;(?P<rules>.*?)\}\s*\}\s*",
            item.output,
        )
        if single_input:
            nft_rules = [rule.strip() for rule in re.split(r";\s*", single_input.group("rules")) if rule.strip()]
            for rule_index, rule in enumerate(nft_rules):
                normalized = re.sub(r"^counter(?:\s+packets\s+\d+\s+bytes\s+\d+)?\s+", "", rule)
                broad_admin = re.fullmatch(
                    r"(?:(?:ip\s+saddr\s+0\.0\.0\.0/0|ip6\s+saddr\s+::/0)\s+)?"
                    r"(?:tcp|udp)\s+dport\s+(?:22|3389|5900|2375|2376|3306|5432|6379|9200|27017)\s+accept",
                    normalized,
                )
                universal_source = re.match(r"^(?:ip saddr 0\.0\.0\.0/0|ip6 saddr ::/0)\s", normalized)
                if broad_admin and universal_source and rule_index == 0:
                    return Outcome.FAIL, evidence + ["First nftables input rule: " + normalized[:180]], "The complete single inet input-chain ruleset starts by allowing a common administrative or data-service port from a universal IP source; confirm intended service exposure and external controls."

        # nft syntax is intentionally not interpreted rule-by-rule. Only a
        # complete single-table/single-chain policy-only shape is classified;
        # all real rulesets with extra chains, statements, sets or verdicts stay
        # UNKNOWN until a full semantic evaluator is available.
        unconditional_accept = re.fullmatch(
            r"\s*table\s+inet\s+[A-Za-z0-9_.-]+\s*\{\s*"
            r"chain\s+[A-Za-z0-9_.-]+\s*\{\s*"
            r"type\s+filter\s+hook\s+input\s+priority\s+[^;{}]+;\s*"
            r"policy\s+drop\s*;\s*"
            r"(?:counter(?:\s+packets\s+\d+\s+bytes\s+\d+)?\s+)?accept\s*;?\s*"
            r"\}\s*\}\s*",
            item.output,
        )
        if unconditional_accept:
            return Outcome.FAIL, evidence, "The complete single-table nftables ruleset has one input base chain whose first and only verdict accepts unconditionally."
        unconditional_drop = re.fullmatch(
            r"\s*table\s+inet\s+[A-Za-z0-9_.-]+\s*\{\s*"
            r"chain\s+[A-Za-z0-9_.-]+\s*\{\s*"
            r"type\s+filter\s+hook\s+input\s+priority\s+[^;{}]+;\s*"
            r"policy\s+accept\s*;\s*"
            r"(?:counter(?:\s+packets\s+\d+\s+bytes\s+\d+)?\s+)?drop\s*;?\s*"
            r"\}\s*\}\s*",
            item.output,
        )
        if unconditional_drop:
            return Outcome.PASS, evidence, "The complete single-table nftables ruleset has one input base chain whose only verdict unconditionally drops traffic."
        policy_only = re.fullmatch(
            r"\s*table\s+inet\s+[A-Za-z0-9_.-]+\s*\{\s*"
            r"chain\s+[A-Za-z0-9_.-]+\s*\{\s*"
            r"type\s+filter\s+hook\s+input\s+priority\s+[^;{}]+;\s*"
            r"policy\s+(accept|drop)\s*;\s*\}\s*\}\s*",
            item.output,
        )
        if not policy_only:
            return Outcome.UNKNOWN, evidence, "The nftables ruleset is outside the complete single-chain policy subset; expressions, sets, chain flow, ordering, and verdict semantics need review."
        if policy_only.group(1) == "accept":
            return Outcome.FAIL, evidence, "The complete nftables ruleset contains one inet input base chain with an accept policy and no explicit rules."
        return Outcome.PASS, evidence, "The complete nftables ruleset contains one inet input base chain with a drop policy and no other declarations or rules; external reachability is not established."

    return Outcome.UNKNOWN, evidence, f"No conservative default-policy parser is implemented for {technology}."


def assess_firewall(info: Optional[FirewallInfo], availability: str = Availability.OK) -> List[CheckResult]:
    if info is None or availability in (Availability.UNAVAILABLE, Availability.DENIED, Availability.TIMEOUT, Availability.ERROR):
        evidence = [availability] if availability else []
        return [
            _result("FIREWALL-TOOL-AVAILABLE", Outcome.UNKNOWN, evidence, "Firewall inspection could not establish local tool availability."),
            _result("FIREWALL-INBOUND-POLICY", Outcome.UNKNOWN, evidence, "No effective policy can be assessed without readable ruleset evidence."),
        ]
    detected = ", ".join(info.detected)
    tool_result = _result(
        "FIREWALL-TOOL-AVAILABLE",
        Outcome.PASS if info.detected else Outcome.UNKNOWN,
        evidence=[f"Detected query tools: {detected}"] if detected else [],
        reason="Tool presence is not evidence that firewall policy is active or effective.",
    )
    outcome, evidence, reason = _assess_simple_firewall_policy(info)
    policy_result = _result("FIREWALL-INBOUND-POLICY", outcome, evidence=evidence, reason=reason)
    return [tool_result, policy_result]


def calculate_score(results: List[CheckResult]) -> tuple[Optional[int], Dict[str, Optional[int]]]:
    def score(items: List[CheckResult]) -> Optional[int]:
        # Informational checks establish inventory only and cannot inflate a
        # security posture score. Unknown/error checks remain visible but are
        # never silently converted to passes.
        applicable = [item for item in items if item.check.severity != "informational" and item.outcome != Outcome.NOT_APPLICABLE]
        if not applicable or any(item.outcome in (Outcome.UNKNOWN, Outcome.ERROR) for item in applicable):
            return None
        evaluated = [item for item in applicable if item.outcome in (Outcome.PASS, Outcome.FAIL)]
        if not evaluated:
            return None
        total = sum(item.check.weight for item in evaluated)
        earned = sum(item.check.weight for item in evaluated if item.outcome == Outcome.PASS)
        value = round(earned * 100 / total) if total else None
        if value is not None and any(item.check.severity == "critical" and item.outcome == Outcome.FAIL for item in evaluated):
            value = min(value, 25)
        return value

    domains = {domain: score([item for item in results if item.check.domain == domain]) for domain in sorted({r.check.domain for r in results})}
    return score(results), domains


def create_assessment(results: List[CheckResult], tool_version: str) -> Assessment:
    score, domains = calculate_score(results)
    return Assessment(
        assessed_at=datetime.now(timezone.utc).isoformat(),
        tool_version=tool_version,
        definition_version=CHECK_DEFINITION_VERSION,
        score=score,
        domain_scores=domains,
        checks=results,
    )


def run_assessment(ctx, tool_version: str) -> Assessment:
    """Collect the defined local checks without changing the audited host."""
    from .assessment_engine import collect_checks
    from . import __version__

    return create_assessment(collect_checks(ctx), tool_version or __version__)


def which_sshd() -> Optional[str]:
    from .util import which

    return which("sshd")


__all__ = [
    "Assessment", "CHECKS", "CHECK_DEFINITION_VERSION", "CheckDefinition", "CheckResult",
    "Outcome", "assess_firewall", "assess_ssh_root_login", "calculate_score",
    "create_assessment", "run_assessment",
]
