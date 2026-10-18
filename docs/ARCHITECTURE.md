# Architecture

Author: António Lourenço Ferreira · Version 0.1.0

## 1. Design goals

1. **Read-only by construction.** Nothing in the default code path writes to the
   monitored system. The only writer of *AUREON's own* state is the SQLite store.
2. **Honest data.** Every figure carries provenance; missing data is never
   rendered as zero.
3. **Graceful degradation.** An absent optional tool must degrade one module,
   never the application.
4. **Testability.** Each integration is a small class with a `collect()` method
   returning a `Result` envelope, so it can be unit-tested without a server.

## 2. Layers

```
                 ┌───────────────────────────────────────────────┐
   SSH session   │  aureon.tui.app        (Textual application)   │
                 │  aureon.tui.panels     (render functions)      │
                 │  aureon.tui.widgets    (tables, source notes)   │
                 └───────────────┬───────────────────────────────┘
                                 │
                 ┌───────────────▼───────────────────────────────┐
   Services     │  aureon.security   SecurityService (Fail2ban +   │
                 │                   periods + wizard)              │
                 │  aureon.ingest     Ingestor (files, journal)     │
                 │  aureon.export     CSV / JSON export             │
                 └───────────────┬───────────────────────────────┘
                                 │
      ┌──────────────────────────┼──────────────────────────────┐
      │                          │                              │
┌─────▼──────┐          ┌────────▼────────┐            ┌────────▼───────┐
│ collectors │          │ fail2ban/       │            │ db/            │
│ system     │          │  detect.py      │            │  schema.py     │
│ storage    │          │  parser.py      │            │  repo.py       │
│ network    │          │  stats.py       │            └────────┬───────┘
│ services   │          │  wizard.py      │                     │
│ logs       │          └─────────────────┘            SQLite (WAL)
│ docker     │
│ sensors    │          ┌─────────────────┐
│ tools      │          │ aureon.periods  │  timezone-aware intervals
└─────┬──────┘          │ aureon.config   │  preferences
      │                 │ aureon.util     │  safe exec, Result envelope
      └─────────────────▼─────────────────┘
                 /proc, /sys, systemctl, journalctl, external tools
```

Strict dependency direction: `tui -> services -> collectors/fail2ban/db/util`.
Collectors never import the TUI. The database layer never imports a collector.

## 3. The `Result` envelope

```python
Result(value, source, availability, error, warnings)
```

`availability` is one of `ok | empty | unavailable | denied | timeout | error`.
The TUI renders `unavailable`, `denied`, `timeout` and `error` as distinct
states, because "the tool is missing" and "the command failed" lead to different
decisions. `Result.from_command()` maps process exit codes to these states
(127 → unavailable, 126 → denied, timeout → timeout).

## 4. Safe command execution

`aureon.util.run()` is the single choke point for external commands:

- argument vector only, `shell=False`;
- hard timeout (default 8 s, configurable);
- output cap (4 MiB) with a `truncated` flag;
- exit-code classification.

No module builds a shell string. Test `test_commands_never_use_a_shell` and
`test_dangerous_characters_are_passed_literally` enforce this.

## 5. Period model

`aureon.periods.period_range()` converts a period name into a concrete
`[start, end)` interval in the server's local timezone:

| Period | Start | End |
|---|---|---|
| `24h` | now − 24 h | now |
| `today` | local midnight | next local midnight |
| `week` | Monday 00:00 (ISO 8601) | Monday + 7 days |
| `month` | 1st, 00:00 | 1st of the next month |
| `year` | 1 January 00:00 | 1 January next year |
| `custom` | user supplied | user supplied |

Boundaries are computed on wall-clock values and then localised, so a server
with a non-UTC timezone reports the same "today" the administrator sees in
`date`. See `docs/DATA-ACCURACY.md`.

## 6. Persistence

SQLite in WAL mode, schema version tracked with `PRAGMA user_version`, migrations
applied transactionally at open time. Three tables:

- `security_events` - normalised events with a UNIQUE `dedup_key` and indexes
  on `(occurred_ts)`, `(ip)`, `(jail)`, `(kind, occurred_ts)`.
- `ingest_sources` - per-file cursors (inode, size, offset, state).
- `collection_runs` - one row per ingestion, with counts and outcome.

See `docs/LOGS-AND-RETENTION.md`.

## 7. Fail2ban module

```
detect.py    status = detect_status(Fail2banClient(), ctx)
             ├─ load_jails()      parse jail.conf + jail.local + jail.d/*
             ├─ systemctl is-active/is-enabled
             ├─ fail2ban-client status / get <jail> banned   (root)
             └─ _validate()       turns observations into problems/warnings
parser.py    fail2ban.log, journalctl (short-iso), auth logs -> SecurityEvent
ingest.py    cursor-based, rotation-aware, idempotent file ingestion
stats.py     period statistics with data-coverage reporting
wizard.py    plan -> diff -> validate -> backup -> apply (all opt-in)
```

The module deliberately keeps *live state* and *stored history* apart; see
`docs/FAIL2BAN.md`.

## 8. Extension points

To add a new source:

1. Implement a `Collector` in `src/aureon/collectors/` returning a `Result`.
2. Register it in `COLLECTORS`.
3. Add a render function in `tui/panels.py` and a navigation entry in `tui/app.py`.
4. Add tests in `tests/` covering: normal data, missing tool, failing command,
   timeout.

To add a new event kind: extend the parsers in `fail2ban/parser.py` and handle
it in the statistics queries. `kind` is a plain string, so no schema migration
is needed for a new kind.

## 9. Threading model

Textual runs the UI in an asyncio loop. Collection happens in a worker
(`run_worker(..., exclusive=True)`) and blocking command execution is pushed to
a thread executor, so a slow `journalctl` cannot freeze the interface. A single
in-flight collection is allowed at a time; the auto-refresh timer skips a tick
rather than queueing a second one.
