# Video reference analysis - AUREON Console

Author: António Lourenço Ferreira
Status: **VIDEO NOT ACCESSIBLE - architecture is provisional**

## 1. What was attempted

The only reference material supplied was a single video:

```
https://www.facebook.com/reel/2253032832177895/
```

Attempts made from the development environment:

| Attempt | Result |
|---|---|
| `WebFetch` on the reel URL | HTTP 400 - Facebook rejects automated access |
| `WebFetch` with alternate URL forms (`?mibextid=...`, without query string) | HTTP 400 |
| Local `curl` fallback | Not attempted after the fetch layer returned 400; no browser session or authentication is available in this environment |

**Conclusion: the video content was not observed.** Nothing in this document
claims to describe what appears in it.

## 2. Evidence available

- The URL itself (an identifier, not content).
- No screenshots, transcripts or descriptions were provided.
- No secondary material (README, man page, project page) accompanied the link.

## 3. Consequences for the implementation

Because the video could not be analysed, the module list of AUREON Console was
derived from the written specification alone (sections 5.1 to 5.9 of the master
prompt) plus a survey of the tools that are mainstream for each area on Linux.
Every tool AUREON knows about is listed in `src/aureon/collectors/tools.py`
with its purpose, license and integration status, so adding a tool discovered
in the video later is a one-entry change.

## 4. Tools evaluated for the unified TUI

Nothing here is "observed in the video"; each was evaluated as a candidate to
detect and/or integrate.

| Tool | License | What AUREON does with it |
|---|---|---|
| btop | GPL-3.0 | Detection only |
| htop | GPL-2.0 | Detection only |
| glances | GPL-3.0 | Detection only |
| fastfetch | MIT | Detection only |
| lm-sensors (`sensors`) | GPL-2.0 | Native integration |
| smartmontools (`smartctl`) | GPL-2.0 | Native integration (opt-in device query) |
| sysstat (`sar`) | GPL-2.0 | Detection only |
| iftop | GPL-2.0 | Detection only |
| nload | GPL-2.0 | Detection only |
| nvtop | GPL-3.0 | Detection only |
| nvidia-smi | NVIDIA proprietary terms | Native integration |
| docker / podman | Apache-2.0 | Native integration |
| fail2ban-client | GPL-2.0 | Native integration (read-only) |
| lvm (`lvs`) | GPL-2.0 | Native integration (read-only) |
| ncdu, tree, jq, curl | GPL-2.0 / MIT | Detection only / unused |

AUREON invokes GPL tools as separate processes and never links their code, so
MIT licensing of AUREON is unaffected. See `docs/DEPENDENCIES.md`.

## 5. Intended features (from the specification, not from the video)

These are the features the master prompt asks for, and are all implemented or
planned as described in `docs/ARCHITECTURE.md`:

1. General dashboard, processes, storage, network, systemd services, system logs.
2. Containers, sensors/GPU, optional tools inventory.
3. Fail2ban: detection, jail inventory, banned IPs, historical statistics by
   period, persistent event store, assisted configuration.
4. Read-only guarantees, no telemetry, no network listeners.

## 6. Still unverified

- The exact set of tools shown in the video.
- Any UI workflow or feature demonstrated in the video that is not described in
  the written specification.
- Whether the video shows a specific licensing model or distribution target.

## 7. What is requested from the project author

To close this gap, one of the following is enough:

1. A re-upload of the video on a host that allows anonymous access.
2. A short written list of the tools/panels shown.
3. Screenshots (or a transcript) of each view.

Once available, this document will be updated with the observed inventory and
the comparison table, and the affected code paths will be re-checked against it.
