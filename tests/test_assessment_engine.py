"""Assessment checks fail closed and never execute remediation operations."""

from aureon.assessment_engine import _apt_security_updates, _container_check, _discover_ssh_match_blocks, _filesystem_checks, _network_checks, _representative_ssh_context, _ssh_checks
from aureon.hardening import Outcome, calculate_score
from aureon.util import CommandResult


class Ctx:
    def __init__(self, results, config=None):
        self.results = list(results)
        self.config = config or type("Config", (), {"command_timeout": 1})()
        self.commands = []

    def run(self, argv, timeout=None):
        self.commands.append(list(argv))
        return self.results.pop(0)


def result(argv, stdout="", stderr="", code=0, timeout=False):
    return CommandResult(argv, code, stdout, stderr, 0.01, timed_out=timeout)


def test_sshd_queries_are_read_only_and_root_settings_preserve_effective_value(monkeypatch):
    from aureon import assessment_engine

    monkeypatch.setattr(assessment_engine, "which", lambda name: "/usr/sbin/sshd")
    ctx = Ctx([result([], "permitrootlogin no\npasswordauthentication yes\nmaxauthtries 6\nclientaliveinterval 0\nclientalivecountmax 3\n")])
    checks = _ssh_checks(ctx)
    assert ctx.commands == [["/usr/sbin/sshd", "-T"]]
    assert {item.check.id for item in checks} == {"SSH-ROOT-LOGIN", "SSH-PASSWORD-AUTH", "SSH-MAX-AUTH-TRIES", "SSH-IDLE-TIMEOUT", "SSH-MATCH-CONTEXTS"}
    assert next(item for item in checks if item.check.id == "SSH-ROOT-LOGIN").outcome == Outcome.PASS
    assert next(item for item in checks if item.check.id == "SSH-PASSWORD-AUTH").outcome == Outcome.FAIL


def test_filesystem_assessment_uses_stat_only_and_never_opens_sensitive_content(monkeypatch):
    import os
    from types import SimpleNamespace
    from aureon import assessment_engine

    observed = []
    modes = {"/etc/shadow": 0o640, "/etc/gshadow": 0o640,
             "/etc/ssh/ssh_host_ed25519_key": 0o600, "/etc/ssh/ssh_host_rsa_key": 0o600}
    def fake_stat(path, follow_symlinks=False):
        observed.append((str(path), follow_symlinks))
        if str(path) in modes:
            return SimpleNamespace(st_mode=modes[str(path)], st_uid=0)
        raise FileNotFoundError(str(path))
    monkeypatch.setattr(assessment_engine.os, "stat", fake_stat)
    monkeypatch.setattr(assessment_engine, "_read", lambda path, limit=256000: ("rootfs / / ext4 rw,relatime 0 0\n", ""))
    checks = _filesystem_checks()
    assert checks[0].outcome == Outcome.PASS
    assert all(not follow for _, follow in observed)
    assert set(path for path, _ in observed) == set(modes)


def test_kernel_and_network_observations_remain_unknown(monkeypatch):
    from aureon import assessment_engine

    monkeypatch.setattr(assessment_engine, "which", lambda name: "/usr/bin/ss" if name == "ss" else None)
    ctx = Ctx([result([], "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n")])
    check = _network_checks(ctx)[0]
    assert check.outcome == Outcome.UNKNOWN
    assert ctx.commands == [["/usr/bin/ss", "-H", "-lntu"]]
    assert calculate_score([check])[0] is None


def test_container_limit_blocks_unbounded_or_unexpected_ids(monkeypatch):
    from aureon import assessment_engine

    monkeypatch.setattr(assessment_engine, "which", lambda name: "/usr/bin/docker" if name == "docker" else None)
    ctx = Ctx([result([], "not-a-container-id\n")])
    check = _container_check(ctx)
    assert check.outcome == Outcome.UNKNOWN
    assert len(ctx.commands) == 1
    assert ctx.commands[0] == ["/usr/bin/docker", "ps", "--all", "--quiet"]


def test_ssh_match_include_discovery_and_safe_context_samples(tmp_path, monkeypatch):
    from aureon import assessment_engine

    conf = tmp_path / "sshd_config"
    include_dir = tmp_path / "sshd_config.d"
    include_dir.mkdir()
    conf.write_text("Include sshd_config.d/*.conf\nPermitRootLogin no\n", encoding="utf-8")
    (include_dir / "20-policy.conf").write_text("Match User admin Address 192.0.2.0/24\n  PasswordAuthentication yes\n", encoding="utf-8")
    monkeypatch.setattr(assessment_engine, "_read", lambda path, limit=256000: (open(path, encoding="utf-8").read(limit), ""))
    matches, gaps, files = _discover_ssh_match_blocks(str(conf))
    assert not gaps
    assert len(files) == 2
    assert matches[0][2] == ["User", "admin", "Address", "192.0.2.0/24"]
    context = _representative_ssh_context(matches[0][2])
    assert context == "user=admin,host=localhost,addr=192.0.2.0,laddr=127.0.0.1,lport=22"
    assert _representative_ssh_context(["Group", "wheel"]) is None
    assert len(matches) == 1


def test_ssh_match_evaluates_context_and_reports_directive_coverage_unknown(tmp_path, monkeypatch):
    from aureon import assessment_engine

    conf = tmp_path / "sshd_config"
    conf.write_text("Match User admin\n  PasswordAuthentication yes\n", encoding="utf-8")
    monkeypatch.setattr(assessment_engine, "which", lambda name: "/usr/sbin/sshd")
    monkeypatch.setattr(assessment_engine, "_discover_ssh_match_blocks", lambda _path: ([(str(conf), 1, ["User", "admin"])], [], {str(conf)}))
    monkeypatch.setattr(assessment_engine, "_contains_incomplete_match_context", lambda *_args: True)
    ctx = Ctx([result([], "permitrootlogin no\npasswordauthentication yes\nmaxauthtries 6\nclientaliveinterval 30\nclientalivecountmax 3\n")])
    check = assessment_engine._ssh_match_check(ctx, {"permitrootlogin": "no", "passwordauthentication": "no"}, config_file=str(conf))
    assert check.outcome == Outcome.FAIL
    assert any("password authentication" in item for item in check.evidence)
    assert any("not fully modeled" in item for item in check.evidence)
    assert any("representative context enables password authentication" in item for item in check.evidence)
    assert ctx.commands == [["/usr/sbin/sshd", "-T", "-C", "user=admin,host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=22"]]


def test_container_inventory_inspects_all_states_for_each_runtime(monkeypatch):
    import json
    from aureon import assessment_engine

    monkeypatch.setattr(assessment_engine, "which", lambda name: {"docker": "/usr/bin/docker", "podman": "/usr/bin/podman"}.get(name))
    record = {"Id": "a" * 64, "HostConfig": {"Privileged": False, "CapAdd": [], "PidMode": "", "NetworkMode": "bridge", "IpcMode": "private", "UTSMode": "private", "ReadonlyRootfs": True}, "Mounts": [], "NetworkSettings": {"Ports": {}}, "Config": {"ReadonlyRootfs": True}}
    ctx = Ctx([result([], ""), result([], "b" * 64 + "\n"), result([], json.dumps([{**record, "Id": "b" * 64}]))])
    check = _container_check(ctx)
    assert check.outcome == Outcome.UNKNOWN
    assert [command[:3] for command in ctx.commands] == [["/usr/bin/docker", "ps", "--all"], ["/usr/bin/podman", "ps", "--all"], ["/usr/bin/podman", "inspect", "b" * 64]]


def test_container_structured_inspection_detects_privileges_and_exposure(monkeypatch):
    import json
    from aureon import assessment_engine

    monkeypatch.setattr(assessment_engine, "which", lambda name: "/usr/bin/docker" if name == "docker" else None)
    record = {
        "Id": "a" * 64, "Name": "/service", "HostConfig": {
            "Privileged": False, "CapAdd": ["SYS_ADMIN"], "PidMode": "host", "NetworkMode": "bridge",
            "IpcMode": "private", "UTSMode": "private", "ReadonlyRootfs": False,
        },
        "Mounts": [{"Type": "bind", "Source": "/host/data", "Destination": "/data", "RW": True}],
        "NetworkSettings": {"Ports": {"443/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8443"}]}},
        "Config": {},
    }
    ctx = Ctx([result([], "a" * 64 + "\n"), result([], json.dumps([record]))])
    check = _container_check(ctx)
    assert check.outcome == Outcome.FAIL
    assert "SYS_ADMIN" in check.reason
    assert any("published mappings" in item for item in check.evidence)
    assert ctx.commands[1] == ["/usr/bin/docker", "inspect", "a" * 64]


def test_apt_update_check_uses_only_local_cache_and_fails_closed(tmp_path, monkeypatch):
    from aureon import assessment_engine

    index = tmp_path / "mirror_dists_stable-security_InRelease"
    index.write_text("local metadata", encoding="utf-8")
    import os, time as time_module
    os.utime(index, (time_module.time(), time_module.time()))
    monkeypatch.setattr(assessment_engine, "which", lambda name: {"apt": "/usr/bin/apt", "apt-cache": "/usr/bin/apt-cache"}.get(name))
    ctx = Ctx([result([], "Listing...\n")])
    check = _apt_security_updates(ctx, str(tmp_path))
    assert check.outcome == Outcome.PASS
    assert ctx.commands == [["/usr/bin/apt", "list", "--upgradable"]]
    assert all("update" not in " ".join(command) for command in ctx.commands)


def test_local_update_checks_for_dnf_zypper_and_apk_are_cache_only(tmp_path, monkeypatch):
    import os
    import os
    import time as time_module
    from aureon import assessment_engine

    dnf_index = tmp_path / "repo" / "repodata" / "repomd.xml"
    dnf_index.parent.mkdir(parents=True)
    dnf_index.write_text("metadata", encoding="utf-8")
    os.utime(dnf_index, (time_module.time(), time_module.time()))
    monkeypatch.setattr(assessment_engine, "which", lambda name: "/usr/bin/dnf" if name == "dnf" else None)
    dnf = Ctx([result([], "openssl-3.0.1-2.fc40.x86_64\n")])
    checked = assessment_engine._dnf_security_updates(dnf, str(tmp_path))
    assert checked.outcome == Outcome.FAIL
    assert dnf.commands == [["/usr/bin/dnf", "--cacheonly", "--quiet", "repoquery", "--upgrades", "--security", "--queryformat", "%{name}-%{version}-%{release}.%{arch}"]]
    assert "refresh" not in " ".join(dnf.commands[0])

    solv = tmp_path / "zypp" / "repo.solv"
    solv.parent.mkdir()
    solv.write_text("cached", encoding="utf-8")
    os.utime(solv, (time_module.time(), time_module.time()))
    monkeypatch.setattr(assessment_engine, "which", lambda name: "/usr/bin/zypper" if name == "zypper" else None)
    zypper = Ctx([result([], "No security patches needed.\n", code=0)])
    checked = assessment_engine._zypper_security_updates(zypper, str(solv.parent))
    assert checked.outcome == Outcome.PASS
    assert zypper.commands == [["/usr/bin/zypper", "--no-refresh", "patch-check"]]
    zypper = Ctx([result([], "Security patches needed", code=101)])
    assert assessment_engine._zypper_security_updates(zypper, str(solv.parent)).outcome == Outcome.FAIL

    apk_index = tmp_path / "apk" / "APKINDEX.abc.tar.gz"
    apk_index.parent.mkdir()
    apk_index.write_text("cached", encoding="utf-8")
    os.utime(apk_index, (time_module.time(), time_module.time()))
    monkeypatch.setattr(assessment_engine, "which", lambda name: "/sbin/apk" if name == "apk" else None)
    apk = Ctx([result([], "(1/1) Upgrading openssl\n")])
    checked = assessment_engine._apk_security_updates(apk, str(apk_index.parent))
    assert checked.outcome == Outcome.UNKNOWN
    assert apk.commands == [["/sbin/apk", "--no-network", "--simulate", "upgrade"]]
    assert "does not identify security-specific" in checked.reason


def test_distribution_update_dispatch_uses_safe_os_release_parser(tmp_path, monkeypatch):
    from aureon import assessment_engine

    release = tmp_path / "os-release"
    release.write_text('ID="fedora"\nNAME="Fedora Linux"\n', encoding="utf-8")
    monkeypatch.setattr(assessment_engine, "which", lambda name: "/usr/bin/dnf" if name == "dnf" else None)
    monkeypatch.setattr(assessment_engine, "_dnf_security_updates", lambda ctx: assessment_engine._simple("OS-SECURITY-UPDATES", Outcome.UNKNOWN, reason="selected dnf"))
    check = assessment_engine._security_update_check(Ctx([]), str(release))
    assert check.reason == "selected dnf"
    release.write_text('ID="fedora\n', encoding="utf-8")
    assert assessment_engine._security_update_check(Ctx([]), str(release)).outcome == Outcome.UNKNOWN


def test_firewall_assesses_explicit_restrictive_defaults_and_unknown_complex_rules():
    from aureon.collectors.firewall import FirewallEvidence, FirewallInfo
    from aureon.hardening import assess_firewall
    from aureon.util import Availability

    nft = FirewallInfo(detected=["nftables"], evidence=[FirewallEvidence(
        "nftables", "ruleset", Availability.OK,
        "table inet filter {\n chain input { type filter hook input priority filter; policy drop; }\n}\n",
    )])
    assert assess_firewall(nft)[1].outcome == Outcome.PASS
    # A port allow without source restriction is not independently enough
    # to claim Internet-wide exposure; source/NAT context is not established.
    nft.evidence[0].output = "table inet filter {\n chain input { type filter hook input priority filter; policy drop; tcp dport 22 accept; }\n}\n"
    assert assess_firewall(nft)[1].outcome == Outcome.UNKNOWN
    nft.evidence[0].output = "table inet filter {\n chain input { type filter hook input priority filter; policy drop; accept; }\n}\n"
    assert assess_firewall(nft)[1].outcome == Outcome.FAIL
    nft.evidence[0].output = "table inet filter {\n chain input { type filter hook input priority filter; policy accept; drop; }\n}\n"
    assert assess_firewall(nft)[1].outcome == Outcome.PASS
    nft.evidence[0].output = "table inet filter {\n chain input { type filter hook input priority filter; policy drop; tcp dport 22 accept; }\n chain forward { type filter hook forward priority filter; policy drop; }\n}\n"
    assert assess_firewall(nft)[1].outcome == Outcome.UNKNOWN
    nft.evidence[0].output = "table inet filter {\n chain input { type filter hook input priority filter; policy accept; }\n}\n"
    assert assess_firewall(nft)[1].outcome == Outcome.FAIL
    nft.evidence[0].output = "table inet filter {\n chain input { type filter hook input priority filter; policy drop; ip saddr 0.0.0.0/0 tcp dport 22 accept; }\n}\n"
    assert assess_firewall(nft)[1].outcome == Outcome.FAIL
    nft.evidence[0].output = "table inet filter {\n chain input { type filter hook input priority filter; policy drop; ct state established,related accept; tcp dport 22 accept; }\n}\n"
    assert assess_firewall(nft)[1].outcome == Outcome.UNKNOWN
    nft.evidence[0].output = "table inet filter {\n chain input { type filter hook input priority filter; policy drop; ip saddr 192.0.2.0/24 tcp dport 22 accept; }\n}\n"
    assert assess_firewall(nft)[1].outcome == Outcome.UNKNOWN

    iptables = FirewallInfo(detected=["iptables"], evidence=[
        FirewallEvidence("iptables", "IPv4 rules", Availability.OK, "-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT DROP\n"),
        FirewallEvidence("iptables", "IPv6 rules", Availability.OK, "-P INPUT REJECT\n-P FORWARD DROP\n-P OUTPUT DROP\n"),
        FirewallEvidence("iptables", "IPv4 full ruleset", Availability.OK, "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT DROP [0:0]\nCOMMIT\n"),
        FirewallEvidence("iptables", "IPv6 full ruleset", Availability.OK, "*filter\n:INPUT REJECT [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT DROP [0:0]\nCOMMIT\n"),
    ])
    assert assess_firewall(iptables)[1].outcome == Outcome.PASS
    iptables.evidence[1].output = "-P INPUT ACCEPT\n-P FORWARD DROP\n-P OUTPUT DROP\n"
    assert assess_firewall(iptables)[1].outcome == Outcome.FAIL
    iptables.evidence[1].output = "-P INPUT REJECT\n-P FORWARD DROP\n-P OUTPUT DROP\n"
    iptables.evidence[2].output += "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
    assert assess_firewall(iptables)[1].outcome == Outcome.UNKNOWN
    iptables.evidence[2].output = iptables.evidence[2].output.replace("-A INPUT -p tcp --dport 22 -j ACCEPT\n", "")
    iptables.evidence[2].output += "-A INPUT -j ACCEPT\n"
    assert assess_firewall(iptables)[1].outcome == Outcome.FAIL
    iptables.evidence[2].output = iptables.evidence[2].output.replace("-A INPUT -j ACCEPT\n", "-A INPUT -p tcp --dport 22 -j ACCEPT\n-A INPUT -j ACCEPT\n")
    assert assess_firewall(iptables)[1].outcome == Outcome.UNKNOWN
    iptables.evidence[2].output += ":CUSTOM - [0:0]\n"
    assert assess_firewall(iptables)[1].outcome == Outcome.UNKNOWN


def test_backup_timer_collection_is_bounded_and_remains_unknown(monkeypatch):
    from aureon import assessment_engine

    monkeypatch.setattr(assessment_engine, "which", lambda name: {"systemctl": "/usr/bin/systemctl", "restic": "/usr/bin/restic"}.get(name))
    ctx = Ctx([result([], "NEXT LEFT LAST UNIT\nMon 12:00:00 2h left backup.timer backup.service\n")])
    check = assessment_engine._backup_check(ctx)
    assert check.outcome == Outcome.UNKNOWN
    assert any("backup.timer" in item for item in check.evidence)
    assert ctx.commands == [["/usr/bin/systemctl", "list-timers", "--all", "--no-pager", "--no-legend"]]
    assert "recoverability" in check.reason


def test_apt_update_security_candidate_uses_local_policy(tmp_path, monkeypatch):
    from aureon import assessment_engine

    index = tmp_path / "mirror_dists_stable-security_InRelease"
    index.write_text("local metadata", encoding="utf-8")
    import os, time as time_module
    os.utime(index, (time_module.time(), time_module.time()))
    monkeypatch.setattr(assessment_engine, "which", lambda name: {"apt": "/usr/bin/apt", "apt-cache": "/usr/bin/apt-cache"}.get(name))
    ctx = Ctx([
        result([], "Listing...\nopenssl/stable-security 3.0.1 amd64 [upgradable from: 3.0.0]\n"),
        result([], "openssl:\n  Installed: 3.0.0\n  Candidate: 3.0.1\n  Version table:\n *** 3.0.1 500\n        500 https://mirror.example stable-security/main amd64 Packages\n"),
    ])
    check = _apt_security_updates(ctx, str(tmp_path))
    assert check.outcome == Outcome.FAIL
    assert "openssl" in " ".join(check.evidence)
    assert all("update" not in " ".join(command) for command in ctx.commands)
