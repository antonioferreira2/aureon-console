# Data accuracy: definitions and guarantees

Author: António Lourenço Ferreira

Monitoring tools fail in a specific way: they show a confident `0` where they
simply have no data. This document defines exactly what every number means.

## 1. Timezone

All periods are computed in the **server's configured local timezone**:

1. `timezone` from the AUREON config / `--tz` / `AUREON_TZ`, if set;
2. otherwise `/etc/timezone`;
3. otherwise the `/etc/localtime` symlink target;
4. otherwise the process-local offset.

Boundaries are computed on wall-clock values and then localised, so "today"
means the same interval an administrator sees in `date`. The timezone in use is
printed in the status bar and in `aureon stats` output.

## 2. Period definitions

All windows are half-open: `[start, end)`.

| Period | Start | End |
|---|---|---|
| `24h` | now − 24 h | now |
| `today` | local 00:00:00 today | local 00:00:00 tomorrow |
| `week` | Monday 00:00 of the current ISO week | the following Monday 00:00 |
| `month` | 1st at 00:00 | 1st of the next month at 00:00 |
| `year` | 1 January 00:00 | 1 January next year 00:00 |
| `custom` | user supplied | user supplied |

### Week

ISO 8601: Monday is the first day, week 1 contains the first Thursday of the
year. Consequences: 2027-01-01 (a Friday) belongs to the week that starts on
2026-12-28 - tested in `test_iso_week_crossing_year_boundary`.

### Year transitions

Month and year windows are computed by calendar arithmetic, so December rolls
into the next year without special cases. Cross-year ISO weeks are handled by
the same `isocalendar()` arithmetic.

## 3. Clock changes

- Windows are computed from the *current* wall clock at query time.
- A backward clock jump can make an event appear twice in ordering terms; the
  store is keyed on the event's own timestamp, so duplicates are still removed
  by `dedup_key`.
- An event whose timestamp is ambiguous (DST fall-back hour) is stored exactly as
  reported by the log/journal, with the offset that was recorded. AUREON does
  not rewrite timestamps.
- Forward jumps simply create a gap; the coverage report shows it.

## 4. Duplicate events

Every event carries a deterministic key:

```
source:source_id                     when the source provides an identity
source|kind|jail|ip|timestamp        otherwise
```

`security_events.dedup_key` is UNIQUE, and inserts use `INSERT OR IGNORE`.
Consequences:

- Re-ingesting the same log range never inflates counters.
- Two *genuine* bans of the same IP at the same second by the same source are
  treated as one event. This is a deliberate, documented trade-off: counters
  prefer under-counting to phantom duplication.

## 5. Incomplete historical data

Fail2ban keeps no durable ban history. AUREON therefore reports coverage:

- `coverage_start` / `coverage_end`: the oldest and newest stored event;
- if the requested window starts before `coverage_start`, a warning says so;
- if the store is empty, the period is reported as **data unavailable**, with an
  explicit note that it is *not* zero;
- `aureon ingest --import-history` reports how much history existed in
  `fail2ban.log` and which span it covers.

## 6. Continuous collection requires running the console

In 0.1.0 there is no daemon, timer or systemd unit. Events are collected while
`aureon` is running (and by `aureon ingest`). If the console is not run for a
week, that week has **no** coverage, and the UI says so.

If continuous collection is required, the options are documented in
`docs/LOGS-AND-RETENTION.md` §5 - and installing any persistent service requires
your explicit approval; AUREON does not install one.

## 7. Failed authentication vs ban

They are different facts and are stored with different `kind` values:

| kind | Meaning | Source |
|---|---|---|
| `ban` | Fail2ban blocked an address | fail2ban.log / journal |
| `unban` | Fail2ban released an address | fail2ban.log / journal |
| `found` | the filter matched an address (no ban yet) | fail2ban.log / journal |
| `auth_failure` | sshd rejected an authentication | auth log / sshd journal |

A failed authentication is **never** displayed as a ban, and a ban is **never**
counted as a failed authentication.

## 8. Classification rules

- AUREON does not label anything a "confirmed attack". It reports *observed
  events* with their source.
- Recurrence means "more than one event from the same address in the window",
  nothing more.
- No port in the listening list is presented as Internet-exposed; firewall and
  routing context are unknown to AUREON.

## 9. Guarantee summary

| Claim | Guaranteed? |
|---|---|
| Period boundaries follow the rules above | Yes (unit-tested) |
| Re-ingesting does not duplicate events | Yes (unit-tested) |
| Zero is never used to mean "no data" | Yes (unit-tested) |
| Historical coverage is complete | **No** - reported explicitly |
| Failures are distinguishable from bans | Yes (separate event kinds) |
| Live ban list is accurate | Only when run as root, and only at query time |
