# Kharibulbul SIEM — The Complete Guide

*Xarıbülbül SIEM · a national mini-SIEM built from scratch · version 1.0.0*

This guide explains **everything** in the repository: the idea, every component, how data flows,
how to configure, run, test, extend and operate the system, and how it maps to the four-week
assignment. Shorter, focused documents live in `docs/`; this one is the single place a new team
member (or the professor) can read from start to end.

---

## Table of contents

1. [What Kharibulbul is](#1-what-kharibulbul-is)
2. [Quick start in ten minutes](#2-quick-start-in-ten-minutes)
3. [Repository map](#3-repository-map)
4. [Core concepts](#4-core-concepts)
5. [The Bülbül agent](#5-the-bülbül-agent)
6. [The server: ingest and pipeline](#6-the-server-ingest-and-pipeline)
7. [Parsers in detail](#7-parsers-in-detail)
8. [Normalisation and enrichment](#8-normalisation-and-enrichment)
9. [Storage and the query language](#9-storage-and-the-query-language)
10. [The detection engine](#10-the-detection-engine)
11. [Rule catalogue](#11-rule-catalogue)
12. [Alerts and notifications](#12-alerts-and-notifications)
13. [HTTP API reference](#13-http-api-reference)
14. [The web dashboard](#14-the-web-dashboard)
15. [Command-line reference](#15-command-line-reference)
16. [Synthetic scenarios and safe validation](#16-synthetic-scenarios-and-safe-validation)
17. [Configuration reference](#17-configuration-reference)
18. [Deployment, hardening and operations](#18-deployment-hardening-and-operations)
19. [Testing](#19-testing)
20. [The four-week plan and deliverables](#20-the-four-week-plan-and-deliverables)
21. [Kharibulbul versus Wazuh](#21-kharibulbul-versus-wazuh)
22. [Limitations and future work](#22-limitations-and-future-work)
23. [FAQ for the defence](#23-faq-for-the-defence)
24. [Glossary (EN / AZ)](#24-glossary-en--az)

---

## 1. What Kharibulbul is

Kharibulbul is a **Security Information and Event Management** system for a small, isolated lab:
it collects logs from Windows and Linux hosts, turns them into one consistent schema, enriches
them with location, asset and threat-intelligence context, stores them searchably, evaluates
detection rules in real time, raises de-duplicated alerts with response playbooks, and shows
everything on a dashboard.

The assignment (B.5 *Local Mini-SIEM*) suggested Wazuh + OpenSearch + Beats + Sysmon. Our professor
pointed out that installing those proves nothing, so **every component here is our own code**:

| Layer | Ours | Lines (approx.) |
|-------|------|-----------------|
| Agent, transport, server, pipeline, 10 parsers, store, query language, rule engine, alerting, API, CLI, simulator (52 scenarios) | Python 3.10+, only PyYAML + FastAPI/uvicorn as libraries | 7,000 |
| Dashboard | HTML/CSS/vanilla JS with self-written SVG charts (no CDN, works offline) | 640 |
| Detection content | 95 YAML rules in 20 files, MITRE ATT&CK-mapped (18 written by the team in Week 3) | 2,000 |
| Tests | 123 pytest tests (parsers, query, rules, end-to-end scenarios, API, playbooks, agent shipper, dashboard features) | 1,300 |
| Playbooks, docs, reports, scripts, Sysmon config | Markdown / PowerShell / bash / XML | 2,500 |

Only Sysmon itself (a Microsoft tool that produces the Windows telemetry) and the optional MaxMind
GeoLite2 database are external.

### National identity

The **Khari Bulbul** (*Ophrys caucasica*, Azerbaijani *Xarıbülbül*) is the orchid of Shusha and
Karabakh and a national symbol. Its lip resembles a nightingale (*bülbül*) sitting in the flower.
The SIEM "sits in the network and listens" like the nightingale; the agent is the **Bülbül agent**.
The logo (`kharibulbul/web/static/logo.png`, favicon `favicon.png`) shows the green nightingale sitting in the
violet-magenta orchid, outlined in gold; the dashboard keeps the flag colours as its accent palette
(`#0092BC`, `#E4002B`, `#00AF66`).

---

## 2. Quick start in ten minutes

### Windows laptop (development / demo)

```powershell
cd "C:\...\Milli Siem"
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\run-dev.ps1            # creates .venv, installs deps, validates rules, starts the server
```
Second PowerShell window:
```powershell
.\scripts\run-dev.ps1 -Simulate  # 52 scenarios, 671 synthetic events -> alerts for 94 of 95 rules
.\scripts\run-dev.ps1 -Tests     # pytest
.\scripts\run-dev.ps1 -WindowsAgent   # Bülbül agent on this laptop (System/Application/PowerShell/Defender… channels, no admin rights)
.\scripts\run-dev.ps1 -WslSetup       # once: Ubuntu in WSL 2 gets python3-yaml + systemd; then  wsl --terminate Ubuntu
.\scripts\run-dev.ps1 -WslAgent       # Linux agent inside WSL 2 shipping the systemd journal to the same server
.\scripts\run-dev.ps1 -WslActivity    # benign admin actions + synthetic sshd lines in WSL -> Linux alerts
```
Open <http://127.0.0.1:8080/>. With the two agents running, *Agents* shows `win-laptop` (Windows) and
`ubuntu-wsl` (Linux) online (§ 5, *Two agents on one laptop*).

### Linux

```bash
bash scripts/run-dev.sh            # server
bash scripts/run-dev.sh simulate   # scenarios
bash scripts/run-dev.sh tests
```

### Manual

```bash
python -m pip install -r requirements.txt
python -m pip install -e .
kharibulbul rules validate rules
kharibulbul server -c config/server.yml
```

### Your first ten minutes in the UI

1. **Overview** – fleet, events over time, alerts by severity, top hosts/actions/IPs/countries.
2. **Events** – type `event.action:logon-failed` → Search; click a row to see every field and the raw XML/line.
3. **Alerts** – open an alert; read *sample events*; click the playbook link; *Acknowledge* with your name.
4. **Rules** – toggle a rule off/on; click a title to read its YAML; **＋ New rule** to write your own.
5. **Agents** – **＋ Add agent** generates the configuration and the install steps for a new host; once the
   agent runs there (`kharibulbul agent -c config/agent-<name>.yml`) the host appears `online` with its IP addresses.
6. **Playbooks** – read a procedure, or **＋ New playbook** to add the team's own.

---

## 3. Repository map

```
Milli Siem/
├── kharibulbul/                 Python package
│   ├── cli.py                   `kharibulbul` command (server, agent, rules, simulate, replay, parse, query, alerts, geoip, stats)
│   ├── common/                  schema.py (KES fields), ecs.py (ECS allowed values, conform / validate / nested view), config.py (YAML+env), timeutil.py, util.py
│   ├── agent/                   main.py, shipper.py (protocol, acks, backoff), spool.py, inputs/{file,winlog,journald,command}.py
│   ├── server/                  main.py (wiring, background loops), ingest.py (TCP/TLS agents, syslog), api.py (FastAPI),
│   │                            enroll.py (Add-agent wizard: config + install guide), content.py (custom rules / playbooks)
│   ├── pipeline/                pipeline.py, normalize.py, enrich.py, geoip.py (custom ranges, MaxMind, CountryDB), countries.py (ISO 3166), assets.py, intel.py, parsers/*
│   ├── store/                   sqlite_store.py (events/alerts/agents/rule_stats), query.py (KQL-ish → SQL), opensearch_store.py
│   ├── detect/                  rules.py (loader/validator), matchers.py, condition.py, engine.py
│   ├── alerts/                  manager.py (dedupe, lifecycle), notify.py (console/file/webhook/SMTP)
│   ├── simulate/                scenarios.py (27 scenarios) + coverage_pack.py (25 more): log records only
│   └── web/static/              index.html, app.js, style.css, logo.png, favicon.png
├── config/                      server.yml, agent.yml (Linux), agent-windows.yml, assets.yml
├── rules/                       windows/ sysmon/ network/ linux/ web/ intel/ correlation/ kharibulbul/ team/ (Week 3 rules)
├── playbooks/                   PB-001 … PB-010 response procedures + README
├── custom/                      rules/ and playbooks/ written from the dashboard (+ README)
├── intel/                       ips.txt, domains.txt, hashes.txt (local threat intel)
├── geoip/                       custom_ranges.csv (lab zones), dbip-country-lite.csv.gz (country table, DB-IP, CC BY 4.0), README
├── sysmon/                      kharibulbul-sysmon.xml
├── scripts/                     install-server.sh, install-agent.sh/.ps1, enable-sysmon.ps1, enable-audit-policy.ps1,
│                                register-agent-task.ps1, gen-certs.sh, *.service, run-dev.ps1/.sh, rsyslog-forward.conf
├── samples/                     auth.log, ufw.log, nginx-access.log (+README)
├── dashboards/                  README (built-in UI + OpenSearch mirror), opensearch/index-template.json
├── docs/                        ARCHITECTURE, SCHEMA, QUERY-LANGUAGE, RULES, OPERATIONS, LAB-SETUP, WEEK1-4, TEAM-ROLES, PRESENTATION,
│                                TUNING-LOG, INCIDENTS, reports/ (WEEK1-REPORT, WEEK2-REPORT, WEEK3-VALIDATION, WEEK3-TABLETOP, WEEK4-REPORT, FINAL-REPORT)
├── tests/                       pytest suite
├── GUIDE.md (this file) · README.md · cloud.md (project log) · CLAUDE.md · LICENSE · pyproject.toml · requirements.txt
└── data/                        runtime (git-ignored): kharibulbul.db, alerts.jsonl, agent.id, spool/, agent-state/
```

---

## 4. Core concepts

| Term | Meaning in Kharibulbul |
|------|------------------------|
| **Envelope** | What a shipper sends: `{"raw": "<line or XML>", "dataset": "windows.security", "@timestamp": "...", "host.name": "ws01", "log.file.path": "...", "fields": {...}}`. Only `raw` is required. |
| **Dataset** | Logical source name, `module.subset`: `windows.security`, `windows.sysmon`, `windows.powershell`, `windows.system`, `windows.firewall_log`, `linux.auth`, `linux.firewall`, `linux.cron`, `linux.journald`, `nginx.access`, `syslog`, `kharibulbul.internal`. |
| **Document / KES** | The parsed, normalised, enriched event: a flat dict with dotted ECS-style keys (`docs/SCHEMA.md`). |
| **Parser** | Function `parse(raw, meta) -> doc or None`; registered by name; picked by dataset hint and content sniffing. |
| **Enrichment** | Adds context: direction, GeoIP/zone, asset role/criticality, threat-intel match, severity. |
| **Rule** | YAML detection logic: selections + condition, optional threshold or sequence, suppression, MITRE, playbook. |
| **Entity / group key** | The "who/what" an alert is about, built from `group_by` (e.g. `host.name=ws01, source.ip=10.10.99.10`). One open alert per rule + entity. |
| **Alert** | Stored object with severity, status workflow, count, sample events, playbook link. |
| **Playbook** | Markdown procedure for a family of alerts: triage queries, containment, recovery, tuning. |
| **Scenario** | A safe generator of synthetic log records that should trigger specific rules. |

---

## 5. The Bülbül agent

`kharibulbul agent -c config/agent.yml` (Linux) or `-c config\agent-windows.yml` (Windows, elevated).
Demo profiles for one laptop: `config/agent-windows-host.yml` (Windows, no admin rights) and
`config/agent-linux-wsl.yml` (Ubuntu inside WSL 2) — see *Two agents on one laptop* below.

### Inputs

| Type | What it does | Key options |
|------|--------------|-------------|
| `file` | Tails files/globs, detects rotation & truncation, remembers offsets in `data/agent-state/file-N.json`, handles partial lines | `paths`, `dataset`, `start: end\|beginning`, `interval`, `encoding`, `fields` |
| `winlog` | Polls Windows channels with `wevtutil qe … /q:*[System[EventRecordID > N]] /f:renderedxml`; bookmarks per channel; ships each `<Event>` as XML | `channels`, `interval`, `batch`, `start: now\|beginning`, `exclude_event_ids: {Security: [5158, …]}` |
| `journald` | Streams `journalctl -o json -f --cursor-file …` | `units` |
| `command` | Runs a command periodically and ships each output line (custom collectors) | `command`, `interval`, `skip_lines`, `timeout` |

Every envelope also carries `host.name`, `host.ip`, `host.os.type`, `agent.id/name/version/type`.

### Shipper and protocol

* Connects to `server.host:port` (TCP; TLS if `server.tls.enabled`, with CA verification and optional
  client certificate for mutual TLS), sends `{"type":"hello","agent":{...},"secret":"..."}` and expects
  `{"type":"welcome"}`.
* Batches up to `batch.size` envelopes or `batch.flush_interval` seconds, sends
  `{"type":"batch","id":n,"events":[...]}`, waits for `{"type":"ack","id":n,"n":stored}`.
* A batch is split so that no protocol line exceeds `batch.max_bytes` (512 KiB, half the server's
  `ingest.max_line_bytes`); a single event above the limit is sent with its `raw` cut short. If the
  server still answers `line too long`, the agent halves its limit and retries.
* No ack / connection error → the undelivered part of the batch is written to the **disk spool**
  (`data/spool/batch-*.jsonl`, capped by `spool.max_mb`, oldest dropped first) and replayed in order
  after reconnect; a partly replayed spool file keeps only its undelivered rest (no duplicates).
* Reconnect uses exponential back-off with jitter (`reconnect_min` … `reconnect_max`); a rejected
  send backs off the same way.
* Idle connections send `heartbeat` every `heartbeat_interval` seconds; the server updates *last seen*.
* Back-pressure: if the in-memory queue (50k) is full the input writes straight to the spool – inputs never block.

### Identity and state

`data/agent.id` is created once (uuid) so the server recognises the agent across restarts; an id
issued by the dashboard (`agent.id` in the generated config, see below) takes precedence.
Bookmarks/offsets live in `data/agent-state/`. Delete them to re-read from the beginning
(`start: beginning`) or from now. In its hello the agent reports its addresses, most useful first:
the one facing the SIEM server, the default route's, then the remaining interfaces (loopback left
out, link-local last) — these are the **IP addresses** column of the Agents page and `host.ip`.

### Adding an agent from the dashboard

**Agents → ＋ Add agent** asks for a name, a profile (`windows`, `windows-admin`, `linux-files`,
`linux-journald`), the address under which the new host reaches the server, the ingest port and an
optional zone label. `POST /api/agents/enroll` then

1. issues an agent id and stores the agent as **pending** (it is listed at once, status `pending`),
2. returns the ready-to-save `agent-<name>.yml` (download / copy) — inputs for the chosen profile,
   the server address, `agent.id`, labels; the shared secret is never written into the file,
3. returns the install guide for that system: copy the folder, install PyYAML, save the file, test
   the port (`Test-NetConnection` / `nc -vz`), set `KB_SHARED_SECRET` and copy `certs/ca.crt` when the
   server requires them, prepare audit policy + Sysmon (`windows-admin`), start the agent, register it
   as a scheduled task / systemd unit, verify.

Nothing is pushed to the host. When the agent starts with that file it connects under the issued id:
the same row turns `online` and shows its addresses. `DELETE /api/agents/{id}` (the ✕ button) forgets
an agent; its events stay, and a running agent simply registers again.

### Two agents on one laptop (Windows + WSL 2)

For the classroom demo the server, a Windows agent and a Linux agent all run on one machine:

* **Windows** – `config/agent-windows-host.yml` (`.\scripts\run-dev.ps1 -WindowsAgent`) reads the channels a
  standard user may read: System, Application, PowerShell/Operational, Windows Defender/Operational,
  TerminalServices-LocalSessionManager, Windows Firewall With Advanced Security, BITS-Client. Every PowerShell
  window you open produces 40961/40962/53504 (and 4104 script-block) events that appear in *Events* within
  seconds. `Security` and Sysmon need an elevated agent (`config/agent-windows.yml`).
* **Linux** – Ubuntu inside WSL 2 (`wsl --install -d Ubuntu`, no admin rights needed once WSL itself exists).
  `scripts/wsl-agent.sh setup` (`-WslSetup`) installs `python3-yaml`, enables systemd in `/etc/wsl.conf`
  (journald needs it) and sets `hostname=ubuntu-wsl` there, because WSL otherwise reports the Windows
  hostname and the two agents would collapse into one host; restart the distro once with `wsl --terminate Ubuntu`.
  The profile uses the journal only: Ubuntu's image also runs rsyslog, and tailing `/var/log/auth.log` as
  well would ship every line twice.
  `scripts/wsl-agent.sh run` (`-WslAgent`) finds the Windows host from inside WSL — `127.0.0.1` when WSL uses
  mirrored networking, otherwise the NAT default gateway — exports it as `KB_SERVER_HOST` and starts
  `config/agent-linux-wsl.yml`, whose `journald` input streams the whole journal (`sudo`, `useradd`, `su`,
  cron, `logger` lines). The server's JSON parser recognises journald records and applies the same
  sshd/sudo/user-management sub-parsers as for `/var/log/auth.log`.
* **Activity** – `scripts/wsl-agent.sh activity` (`-WslActivity`) performs benign admin actions inside WSL
  (`useradd`/`usermod`/`userdel` of a throw-away account, `sudo -n true`) and writes synthetic sshd/sudo lines
  with `logger` — the same content as the `ssh-brute-force` scenario, but travelling the real path
  journal → agent → TCP → server → parser → rules (KB-LNX-001/002, KB-COR-002, KB-LNX-017).

Both agents keep their id, bookmarks and spool under `data/agent-windows-host/` and `data/agent-linux-wsl/`.

### Running as a service

Windows: `scripts/register-agent-task.ps1` creates the scheduled task *Kharibulbul Agent* (SYSTEM,
at startup, auto-restart). Linux: `scripts/kharibulbul-agent.service`. Appliances without Python:
forward syslog with `scripts/rsyslog-forward.conf`.

---

## 6. The server: ingest and pipeline

`kharibulbul server -c config/server.yml` runs one asyncio process:

| Listener | Default | Purpose |
|----------|---------|---------|
| TCP agents | `0.0.0.0:5044` | Bülbül protocol (optionally TLS/mTLS, shared secret) |
| Syslog UDP | `0.0.0.0:5514` | rsyslog/journald forwarders, network devices |
| Syslog TCP | disabled | same, reliable |
| HTTP | `0.0.0.0:8080` | API, UI, `POST /api/ingest` |

`KharibulbulServer.handle_batch()` (runs in a thread-pool so the event loop stays responsive):

1. attach agent/host fields from the hello to each envelope,
2. `Pipeline.process()` each envelope → document (or drop),
3. queue documents to the store writer thread,
4. `DetectionEngine.evaluate()` each document → alerts via `AlertManager`,
5. optional OpenSearch mirror,
6. update the agent's event counter.

Background loops: **retention** (off by default — `store.retention_days: 0` keeps every event; set N to
purge events older than N days hourly) and **agent monitor**
(every minute; a silent agent produces an internal `agent-silent` event → rule KB-KB-001).

### Pipeline stages

```
envelope ──► select_parsers(raw, dataset) ──► first parser that returns a doc
        ──► normalize(doc)  (schema hygiene, derived fields, ECS conformance)
        ──► enrich(doc)     (direction, GeoIP, assets, intel, severity)
        ──► ecs.validate()  (problems → tag ecs-nonconformant)
        ──► document
```
Parser choice: `<Event` → windows; `{` → json; dataset `windows.*` → windows/json; `nginx.access`/`*.access`
→ web; `linux.*`/`syslog` → syslog; `windows.firewall_log` → winfirewall; then the general order
syslog → web → json → windows → **generic** (never fails). A parser exception is caught, the next
parser is tried, and the document gets `kharibulbul.pipeline.errors` + tag `parser-error`.

---

## 7. Parsers in detail

| Parser | Handles | Produces (highlights) |
|--------|---------|------------------------|
| `windows` | rendered XML of any channel; `System` → `winlog.*`; `EventData`/`UserData` → `winlog.event_data.*`; then per-channel mapping | **Security**: 4624/4625 (`logon-success/failed`, logon type words, failure reason text, source ip/port), 4634/4647, 4648, 4672, 4688 (hex pids → int, command line, parent), 4689, 4697, 4698–4702 (task name + `<Command>` extracted to `process.command_line`), 4720–4781 (IAM), 4728/4732/4756 (+removals), 4740, 4768/4769/4771/4776 (Kerberos/NTLM), 1102, 4719, 5140/5145, 5152/5156/5157/5158. **System**: 7045, 7036, 7040, 104, 1074, 6005/6006/6008, 41. **PowerShell**: 4104 (`powershell.file.script_block_text`), 4103, 400/403/600. **Defender**: 1006/1015/1116/1117…, 5001/5004/5010/5012. **TaskScheduler** 106/129/200. **RDP** LocalSessionManager 21–25. |
| `sysmon` (mapper used by `windows`) | Sysmon 1–29 | 1 process-created (hashes, PE info, parent, integrity), 3 network-connection (`network.direction` from *Initiated*), 5, 6/7 image/driver load (signature), 8 remote thread, 10 process access (`sysmon.granted_access`, `process.target.*`), 11/23/26/29 file events, 12/13/14 registry (`registry.path/hive/value/data`), 15 ADS, 17/18 pipes, 19–21 WMI, 22 DNS (`dns.question.name`, answers), 25 tampering, 4/16 state/config |
| `syslog` | RFC3164, RFC5424, ISO-timestamp variants, `<PRI>` facility/severity | program sub-parsers: **sshd** (failed/accepted/invalid user/max attempts/PAM/session/disconnect), **sudo** (command, failures, PAM, session), **su**, **useradd/userdel/usermod/groupadd/passwd**, **kernel/ufw** (`[UFW BLOCK] … SRC= DST= SPT= DPT= PROTO=` → `firewall-block/allow`), **cron**, **systemd**, **systemd-logind**, **fail2ban** (`fail2ban-ban/unban/found`, jail in `rule.name`) |
| `web` | nginx/Apache combined log (+X-Forwarded-For) | `http.request.method`, `url.original/path/query`, `http.response.status_code/body.bytes`, `user_agent.original`, tag `scanner-user-agent` |
| `json` | journald JSON (`MESSAGE`, `_HOSTNAME` … → program sub-parsers), pre-parsed `winlog.*` dicts, ECS pass-through (nested → flat) | whatever the JSON carries |
| `winfirewall` | `pfirewall.log` W3C lines | `firewall-block/allow`, ports, `network.direction` (RECEIVE/SEND) |
| `auditd` | `/var/log/audit/audit.log` records (`type=… msg=audit(ts:serial): …`) | `auditd.type/serial/key`, hex-decoded `cmd`/`proctitle`/args, standard actions (`auth-failed`, `logon-success`, `sudo-command`, `process-executed`, `user-created`, `service-stopped`, `auditd-config-change`), `source.ip`, `user.*`, `process.*` |
| `apache_error` | nginx and Apache *error* logs | `log.level`, `source.ip/port`, `http.request.method`, `url.path`, `file.path`, `error.code` (AHxxxxx), `error.message`, tag `sensitive-path` |
| `windows_dhcp` | Windows DHCP server audit log CSV | `event.code` (DHCP id), `dhcp-lease-assigned/renewed/released`, `dhcp-ip-conflict`, `dhcp-lease-denied`…, `client.ip/mac/domain`, `dhcp.transaction_id` (header text skipped) |
| `generic` | anything else | timestamp, log level, IPs (`related.ip`), `key=value` pairs (`extracted.*`) |

Debug any line without a server: `kharibulbul parse file.log --dataset linux.auth --fields event.action,user.name,source.ip`.

---

## 8. Normalisation and enrichment

**`normalize.py`** guarantees: lower-case `process.name`/`host.name`, `process.name` derived from the
executable path, `process.args` (Windows-aware splitting), `user.domain` split from `DOMAIN\user`
or `user@domain`, tag `machine-account` for `name$`, valid IPs only in `source.ip`/`destination.ip`
(bad values move to `*.address`), `network.type`, `related.ip`, `related.user`,
`dns.question.registered_domain` / `top_level_domain`, tag `suspicious-tld`
(`.xyz .top .zip .click .tk .ml .ga .cf .gq .onion .ru .su .pw .cc .ws`), numeric ports/pids,
and finally `finalize()` (mandatory fields, severity score, empty values dropped). After that the
**time context** is added: `kharibulbul.time.hour` and `.weekday` in lab local time
(`pipeline.timezone_offset_hours`, Baku = 4) and `kharibulbul.time.business_hours`
(Monday–Friday inside `pipeline.business_hours`, default `[8, 19]`) — used by the out-of-hours rules.

**ECS-style normalisation** (`common/ecs.py`) is what makes the ECS naming more than a habit:

* `conform()` (called by `normalize`) stamps `ecs.version` (8.11.0), lower-cases `event.kind /
  category / type / outcome` and maps sloppy source values onto the ECS allowed values
  (`Auth` → `authentication`, `create` → `creation`, `failed` → `failure` …), and fills
  `related.hosts` / `related.hash` next to `related.ip` / `related.user`.
* `validate()` runs after enrichment and checks: UTC ISO `@timestamp`, the four categorisation fields
  against the ECS allowed values, IP / integer / list field types, `geo.country_iso_code` (ISO 3166
  alpha-2) and `geo.location` (`{lat, lon}`), and that every key belongs to an ECS field set or a
  documented extension (`kharibulbul.*`, `winlog.*`, `sysmon.*`, `powershell.*`, `auditd.*`, `dhcp.*` …).
  A document with problems is kept, tagged `ecs-nonconformant` and carries `kharibulbul.ecs.problems`
  (search `tags:ecs-nonconformant`; counter `pipeline.ecs_nonconformant` in `/api/stats`).
* `to_nested()` turns the flat document into a real nested ECS object with `event.category` /
  `event.type` as arrays: `GET /api/events?format=ecs`, the *ECS document* block in the event drawer,
  *export ECS JSON*, `kharibulbul parse --ecs`, and the OpenSearch mirror.

Every event of the 52 scenarios is validated in the test-suite: zero ECS problems.
`kharibulbul parse <file> --check` validates any log file offline.

**`enrich.py`** adds:

* `network.direction` (kept if a parser already knew it) and `kharibulbul.network.zone_direction`
  from `pipeline.lab_networks`: `internal` / `inbound` / `outbound` / `external`.
* **GeoIP** (`geoip.py`), sources in this order, result cached per IP:
  1. our `geoip/custom_ranges.csv` (most specific CIDR wins): lab zone names such as `Lab-Attacker`,
     documentation ranges, hand-picked public ranges with city / coordinates / organisation;
  2. private, loopback and link-local addresses → `Lab-Network` (inside `pipeline.lab_networks`) or
     `Lab-Private`, country code `XL` (ISO 3166 user-assigned; `XX` = documentation ranges);
  3. MaxMind GeoLite2-City if `geoip/GeoLite2-City.mmdb` exists (optional, city level);
  4. **the country table** `geoip/dbip-country-lite.csv.gz` — DB-IP "IP to Country Lite"
     (CC BY 4.0): ~357k IPv4 + ~360k IPv6 ranges covering the whole address space, read by our own
     `CountryDB` (ranges in `array`s, bisection; ~1.5 s to load, ~20 MB, exact for both families).
     Every public address gets `geo.country_iso_code`, `geo.country_name`, `geo.continent_code/name`.
     Refresh monthly with `kharibulbul geoip update`; check with `kharibulbul geoip lookup <ip>` or
     `GET /api/geoip/lookup?ip=`; loaded sources are in `/api/stats` → `geoip`.

  Writes `source.geo.name/country_iso_code/country_name/continent_code/continent_name/city_name/location`,
  `source.as.organization.name` and the same for `destination`. *IP Geolocation by DB-IP
  (https://db-ip.com).*
* **Assets** (`assets.py`, `config/assets.yml`): `host.role`, `kharibulbul.asset.owner`,
  `kharibulbul.asset.criticality`, `labels.*`, zone names for private IPs.
* **Threat intel** (`intel.py`, `intel/*.txt`, hot-reloaded): `threat.indicator.matched/type/value/description`,
  tag `threat-intel-match`, severity raised to at least *high*.
* **Severity**: parser severity + criticality boost (medium +5, high +15, critical +25), capped at 100.

---

## 9. Storage and the query language

`store/sqlite_store.py` – one SQLite file (`data/kharibulbul.db`, WAL mode):

| Table | Content |
|-------|---------|
| `events` | `id`, `event_id`, `ts` (epoch), hot columns `dataset, category, action, code, outcome, host, user, src_ip, dst_ip, dst_port, process, agent_id, severity`, `doc` (full JSON) – indexes on ts and host/dataset/action/src_ip/user/severity + ts |
| `events_fts` | FTS5 over message, command line, raw, file path, url, dns name, users, hosts, process names |
| `alerts` | alert columns + full JSON |
| `agents` | id, name, host, ips, os, version, labels, first/last seen, events, status, remote |
| `rule_stats` | hits, alerts, last hit per rule |

A single writer thread batches inserts (`batch_size`, `flush_interval`); readers use thread-local
connections; `put()` never blocks ingest. There is **no date limit** by default
(`store.retention_days: 0`): events stay until deleted, and any period can be searched — a quick range
(15 m … 1 y), `all` (since the oldest stored event) or exact `from` / `to` dates. With
`retention_days: N` old events (and closed alerts) are purged hourly.
Duplicate `event.id`s are ignored (safe replays).

**Query language** (`store/query.py`, full reference in `docs/QUERY-LANGUAGE.md`):
`field:value`, quotes, wildcards `* ?`, comparisons `field:>n`, `field:*` / `_exists_:field`, list
fields element-wise (`tags:x`), free text = FTS (prefix with `word*`), `AND` (implicit), `OR`,
`NOT`/`!`, parentheses, and one field with several values `process.name:(certutil.exe OR mshta.exe)`
(`AND` inside the group also works). Hot fields hit real columns; others use `json_extract`. Time is a
separate parameter (`from`/`to`, `now-15m` style).

**OpenSearch mirror** (`store/opensearch_store.py`): optional write-only bulk indexing of unflattened
documents into `kharibulbul-events-YYYY.MM.dd` with an ECS-friendly index template, for OpenSearch
Dashboards demos (`dashboards/README.md`).

---

## 10. The detection engine

Rules (`docs/RULES.md`) are loaded from `rules/**/*.yml`, validated (`validate_rule`) and compiled
(`build_rule`): selections stay as data, the `condition` becomes a closure, thresholds/sequences are
normalised (durations → seconds).

### Evaluation of one document

```
for rule in enabled rules:
    if rule.sequence: advance/start the track for the `by` key
    else:
        if logsource pre-filter fails: skip           (dataset / module / category)
        if not rule.matches(doc): skip                (selections + condition)
        threshold? update group state, fire when count/distinct >= N
        else fire immediately
```

* **Matching** (`matchers.py`): case-insensitive by default, wildcards, modifiers
  `contains startswith endswith re all cs cidr gt gte lt lte exists not`; list values = OR (`all` = AND);
  document lists match element-wise; `null` = absent.
* **Conditions** (`condition.py`): `and or not ( ) 1 of sel_* all of sel_* 1 of them all of them`.
* **Thresholds**: per `group_by` key a deque of `(event_time, distinct_value, event)`; entries older
  than `window` are dropped relative to the *current event's time* (so replayed history works);
  `count` events or `distinct` unique values trigger; the group resets after firing and stays
  suppressed for `suppress` (further matches bump the open alert's count).
* **Sequences**: per `by` key a track `{stage, count, since, events}`; stages must complete in order
  within `within`; the track is consumed when the last stage completes.
* **Suppression**: `suppress` per rule (default `detect.default_suppress` = 10 m) – plus the alert
  manager's dedupe on open alerts.
* **Garbage collection** every 5000 events removes stale groups/tracks.
* Errors in one rule (bad regex) are counted in `detect.errors` and never stop other rules.
* Rules can be enabled/disabled live and reloaded from disk through the API/UI.

### Severity of an alert

`severity_score = rule severity score (+ asset criticality boost, forced ≥ high on intel match)`;
`severity` name is derived: ≥95 critical, ≥75 high, ≥50 medium, ≥30 low, else informational.

---

## 11. Rule catalogue

`kharibulbul rules list` prints all 95. By family:

| Family (file) | Ids | What they catch |
|---------------|-----|-----------------|
| Windows auth (`rules/windows/auth.yml`) | KB-WIN-001…006 | brute force (4625 ×10/5 m per host+source), password spraying (8 distinct users), lockouts, logons from outside the lab (RDP/interactive/network), explicit-credential logons, Kerberos/NTLM failure bursts |
| Windows IAM (`iam.yml`) | KB-WIN-010…013 | user created, privileged group membership, user deleted/disabled, password reset by others |
| Windows defense evasion (`defense-evasion.yml`) | KB-WIN-020…024 | log cleared, audit policy changed, Defender disabled, Defender detection, Sysmon tampering |
| Windows persistence (`persistence.yml`) | KB-WIN-030…033 | service from suspicious path, service inventory, suspicious scheduled task, task inventory |
| LOLBins (`rules/sysmon/lolbin.yml`) | KB-SYS-010…018 | certutil download/decode, mshta, rundll32, regsvr32, bitsadmin, wmic process create, script hosts from user dirs, recon bursts and chained recon |
| PowerShell (`powershell.yml`) | KB-SYS-020, KB-PS-001…003 | encoded commands, download cradles (command line or 4104), hidden+bypass, offensive-tooling keywords |
| Process behaviour (`process.yml`) | KB-SYS-030, 040, 041, 050, 060, 061 | Office spawning shells, LSASS access, remote thread injection, execution from temp/public, process tampering, shadow-copy/backup deletion |
| Registry (`registry.yml`) | KB-SYS-070, 071 | autorun persistence keys, security settings disabled via registry |
| Network scans (`rules/network/scan.yml`) | KB-NET-001…004, 020, 021 | port scans seen by Sysmon / UFW / Windows Firewall (distinct ports per source), host sweeps, outbound to uncommon ports from user-writable binaries, classic C2 ports |
| DNS (`dns.yml`) | KB-NET-010…013 | suspicious TLDs, DNS from user-writable processes, query bursts (tunnelling/DGA), paste/tunnel/anonymiser services |
| Linux auth (`rules/linux/auth.yml`) | KB-LNX-001…005 | SSH brute force, user enumeration, logins from outside the lab, root SSH, failures-then-success sequence |
| Linux privilege (`privilege.yml`) | KB-LNX-010…016 | sudo failures, privileged group additions, new users, `curl \| bash`, failed su, sudo shells (hunting), suspicious cron |
| Web (`rules/web/scan.yml`) | KB-WEB-001…005 | 404/403 bursts, login brute force, scanner user agents, sensitive paths, injection payloads |
| Threat intel (`rules/intel/intel.yml`) | KB-TI-001…003 | IP / domain / hash indicator matches |
| Correlation (`rules/correlation/sequences.yml`) | KB-COR-001…005 | brute force → success (Windows, SSH), account created → privileged, scan → logon, download utility → outbound beacon |
| SIEM health (`rules/kharibulbul/internal.yml`) | KB-KB-001, 002 | agent silent, parser-error bursts |
| Team rules, Week 3 (`rules/team/windows.yml`) | KB-WIN-007, 008, KB-COR-006, 007, KB-SYS-072 | out-of-hours logon on critical assets, one account on many hosts, RDP → service install, download → execute, Defender exclusion added |
| Team rules, Week 3 (`rules/team/network.yml`) | KB-NET-005, 014, 030, 031, 032, 033 | outbound block bursts, DNS beacon per domain, fail2ban bans (any / internal source), DHCP conflict or denial, DHCP lease out of hours |
| Team rules, Week 3 (`rules/team/linux.yml`) | KB-LNX-017, 020, 021, 022 | sudo by non-admin, sensitive credential files, auditd auth-failure bursts, audit subsystem disabled |
| Team rules, Week 3 (`rules/team/web.yml`) | KB-WEB-006, 007, 008 | 5xx spikes, error-log probes for sensitive files, upstream failures |

Every rule carries MITRE technique/tactic, a playbook, and (where relevant) false-positive notes.

---

## 12. Alerts and notifications

**Lifecycle**: `new → acknowledged → investigating → [escalated] → closed | false_positive` (PATCH
`/api/alerts/{id}` with `status`, `assignee`, `notes`; history is appended).

**Escalation** (`POST /api/alerts/{id}/escalate`, the *⬆ Escalate* button in the alert drawer,
`kharibulbul alerts escalate <id>`): hands an alert to the next tier. Body (all optional):
`to`, `reason`, `by`, `raise_severity` (default true), `assignee`, `notes`.

* status becomes `escalated` — still an *open* alert, so new matching events keep updating it;
* `escalation.level` goes 1 → 2 → 3; without `to` the alert goes to *Tier 2 analyst*, then
  *SOC lead / incident responder*, then *Incident manager (CSIRT)*;
* the severity is raised one step (high → critical) unless `raise_severity` is false;
* `escalation {level, to, reason, by, ts, severity_before, severity_after}` and a history entry are stored;
* **every enabled sink is notified** (console `ESCALATED L1 -> …`, a line in `alerts.jsonl`, webhook,
  e-mail) regardless of `min_severity` — a human decided it matters.

A closed / false-positive alert must be reopened (status `new`) before it can be escalated.

**De-duplication**: when a rule fires for an entity and an *open* alert for the same rule + `group_key`
exists with `last_seen` inside the suppress window, the alert's `count` and `last_seen` are updated and
new sample events appended (max 10) – an *update* notification is sent instead of a new alert.

**Alert document** (see `docs/SCHEMA.md` § Alert documents): id, rule id/name/description, severity +
score, status, entity, group values, first/last seen, count, host/user/source ip/country, MITRE list,
tags, playbook, sample events, trigger event id, notes, assignee, history.

**Notifiers** (`alerts.notify` in `config/server.yml`, run in a background thread):

| Sink | Config | Notes |
|------|--------|-------|
| console | `console.enabled` | log line `[HIGH] NEW <rule> | <entity> | count=…` |
| file | `file.path` | append-only JSONL (`data/alerts.jsonl`) – evidence for the report |
| webhook | `url`, `headers`, `min_severity` | generic JSON POST (`{"source":"kharibulbul","alert":{…},"text":"…"}`) – Slack/Teams/Discord-compatible via their incoming-webhook URLs |
| smtp | host/port/user/pass/from/to/starttls, `min_severity` | one e-mail per new alert |

---

## 13. HTTP API reference

Base URL `http://server:8080`. If `api.token` is set send `Authorization: Bearer <token>` (or
`X-API-Key`). Interactive docs: `/api/docs` (not linked from the dashboard menu; open the address directly).

| Method & path | Parameters | Returns |
|---------------|-----------|---------|
| `GET /api/health` | – | status, version, uptime, `ui` (dashboard build) (no auth) |
| `GET /api/stats` | – | server (incl. `retention_days`), pipeline counters, ingest counters, store stats, detection snapshot, notifications, `geoip` sources |
| `GET /api/schema` | – | field dictionary (`ecs: true/false` per field) + ECS version and allowed values |
| `GET /api/events` | `q`, `from`, `to`, `limit` (≤5000), `offset`, `sort`, `format=ecs` | `{total, hits[]}` (flat documents, or nested ECS objects with `format=ecs`) |
| `GET /api/events/histogram` | `q`, `from` (default now-1h), `to`, `interval` | buckets (interval chosen automatically from seconds up to a year) |
| `GET /api/events/terms` | `field`, `q`, `from` (default now-24h), `to`, `size` | top values |
| `GET /api/events/{id}` | `format=ecs` | one document |
| `POST /api/ingest` | body: envelope, list, or `{"events":[…]}` | `{received, stored}` |
| `GET /api/alerts` | `status` (csv), `severity` (csv), `rule`, `q`, `from`, `to`, `limit`, `offset` | `{hits[]}` |
| `GET /api/alerts/summary` | `from` | totals by severity/status/rule, open count |
| `GET /api/alerts/histogram` | `from`, `to`, `interval` | buckets |
| `GET /api/alerts/{id}` | – | alert |
| `PATCH /api/alerts/{id}` | body `{status, assignee, notes}` (`status: escalated` also takes `to`, `reason`, `raise_severity`) | updated alert |
| `POST /api/alerts/{id}/escalate` | body `{to, reason, by, raise_severity, assignee, notes}` (all optional) | escalated alert (400 if closed, 404 if unknown) |
| `GET /api/agents` | – | agents with computed `online/silent/disconnected/pending`, `ip[]`, `ip_primary`, `remote` |
| `GET /api/agents/enroll/info` | – | what the Add-agent wizard pre-fills: server addresses, ingest port, TLS, `secret_required`, profiles |
| `POST /api/agents/enroll` | body `{name, profile, server_host, port, zone}` | pending agent + `config` (YAML), `filename`, `steps[]` (install guide); 409 if the name exists |
| `DELETE /api/agents/{id}` | – | forget an agent (events stay) |
| `GET /api/rules` | – | all rules + stats, `custom` flag and count |
| `GET /api/rules/template` | – | commented rule skeleton with the next free `KB-CUS-NNN` id |
| `POST /api/rules` | body `{rule: "<yaml>"}` | create a custom rule (validated, written to `custom/rules/<id>.yml`, engine reloaded); 409 if the id exists |
| `GET /api/rules/{id}` | – | rule + YAML source |
| `PUT /api/rules/{id}` · `DELETE /api/rules/{id}` | body `{rule}` | edit / delete a **custom** rule (403 for shipped rules) |
| `POST /api/rules/{id}/enable` · `/disable` | – | toggle |
| `POST /api/rules/reload` | – | reload shipped + custom rules from disk |
| `POST /api/rules/test` | body `{rule: "<yaml>", events: [lines or envelopes]}` | validity, per-event matches, alerts (nothing stored) |
| `GET /api/playbooks` | – | `playbooks[]` (names), `items[] {name, custom}`, `template` |
| `GET /api/playbooks/{name}` | – | markdown (header `X-Kharibulbul-Custom`) |
| `POST /api/playbooks` | body `{name, content}` | create a custom playbook in `custom/playbooks/` (409 if the name exists) |
| `PUT /api/playbooks/{name}` · `DELETE /api/playbooks/{name}` | body `{content}` | edit / delete a **custom** playbook (403 for shipped ones) |
| `GET /api/geoip/lookup` | `ip` | what GeoIP enrichment returns for the address |
| `GET /api/dashboard/overview` | `from` (default now-24h), `to`, `q` | everything the Overview page shows in one call |

Time values: relative (`now`, `now-15m`, `now-24h`, `now-365d`), an ISO-8601 date or date-time
(`2026-09-28`, `2026-09-28T18:00:00Z`), or `all` (= since the oldest stored event). There is no
upper bound on the range; `to` must be later than `from`.

---

## 14. The web dashboard

Single-page app in `kharibulbul/web/static/` (no build, no CDN):

* **Overview** – KPI cards, events/alerts over time (own SVG area/bar charts), alerts-by-severity donut,
  top hosts / actions / source IPs / datasets / users / **source and destination countries (GeoIP)** /
  processes (click → Events filter), recent alerts, alerts by rule, **authentication success vs failure**
  (multi-line chart), **open alerts by ATT&CK tactic**, **events by asset criticality**; auto-refresh 30 s.
* **Time range** (Overview, Events, Alerts) – quick ranges 15 m · 1 h · 6 h · 24 h · 7 d · 30 d · 90 d ·
  1 y · **all**, or an exact **from / to** date-time (local time, *apply dates*); no 30-day limit.
* **Events** – query box with syntax help, histogram, results with severity chips, side panel of clickable
  facets, event drawer (fields table, chips to pivot on host/action/user/source/destination with their
  GeoIP country, ECS version chip, **ECS document (nested JSON)**, raw event), pagination, JSON export and
  **ECS JSON export**.
* **Alerts** – filters (incl. `escalated`), summary charts, table with MITRE tags, drawer with triage
  buttons, assignee, notes, **Escalate** (to whom, reason, raise severity), escalation banner, sample
  events, playbook link, status history, raw JSON.
* **Agents** – fleet status with every agent's **IP addresses** (the one facing the server in bold) and
  the address the server sees, **＋ Add agent** wizard (configuration file + install guide), remove,
  and a short "how an agent is added" guide on the page.
* **Rules** – toggles, stats, filter box, YAML; **＋ New rule** editor (template, *Validate & test*
  against pasted log lines, save), *Edit* / *Delete* for custom rules, *Clone as custom rule* for shipped ones.
* **Playbooks** – rendered markdown; **＋ New playbook** editor with live preview, *Edit* / *Delete* for
  custom playbooks, *use as template* for shipped ones.
* The *API token* link in the sidebar stores the token in the browser (`localStorage`).
* **Never stale**: static files are sent with `Cache-Control: no-cache`, the page links its assets as
  `app.js?v=<build>` (version + newest file time, also in `/api/health` → `ui`), and a tab that runs an
  older build than the server shows an "updated on the server — Reload now" bar. Without this a browser
  keeps an old script for hours and new buttons simply do not appear.

### Custom rules and playbooks

What analysts write in the dashboard is stored under `custom/` (`custom_dir` in `config/server.yml`),
next to — never inside — the shipped content: `custom/rules/<id>.yml` (one rule per file) and
`custom/playbooks/<name>.md`. A rule is accepted only if it validates (required fields, condition,
known modifiers, compilable regexes, valid CIDRs, existing playbook, an id no other rule uses, one
document) and is live immediately: the engine reloads, no restart. Shipped rules (`rules/`) and
playbooks (`playbooks/`) are read-only in the UI; their ids and names cannot be taken. Suggested ids:
`KB-CUS-001` …. A custom rule can link a custom playbook with `playbook: custom/playbooks/<name>.md`.
The files are plain text — edit them by hand and press *reload from disk*, or commit them.

---

## 15. Command-line reference

| Command | Purpose |
|---------|---------|
| `kharibulbul server -c config/server.yml` | run the server |
| `kharibulbul agent -c config/agent.yml` | run the agent |
| `kharibulbul rules validate [dir]` | strict validation, duplicate ids, exit 1 on problems |
| `kharibulbul rules list [dir]` | table of rules (id, severity, kind, title, MITRE) |
| `kharibulbul rules test <rule.yml> <events file> [--dataset X] [-v]` | offline: parse the file, count matches, show alerts |
| `kharibulbul rules coverage [dir] [-c config] [--out file.md] [--seed n]` | run every scenario offline through pipeline + engine; markdown matrix scenario → rules fired, rules never fired, baseline noise check (Week 3 validation deliverable) |
| `kharibulbul simulate --list` / `simulate <names…> \| all [--host --source-ip --user --spacing --seed --out file]` | generate synthetic events and POST them (or write JSONL) |
| `kharibulbul replay <file> [--dataset X] [--host H] [--speed n/s] [--out]` | send raw lines / JSONL envelopes |
| `kharibulbul parse <file> [--dataset X] [--fields a,b] [--limit n] [--compact] [--ecs] [--check]` | run the pipeline locally, print documents (`--ecs`: nested ECS objects; `--check`: validate against ECS, exit 1 on problems) |
| `kharibulbul query "<q>" [--since now-24h --until … --limit 50 --sort desc --json]` | search via the API (`--since all`, `--since 2026-09-01 --until 2026-09-15`) |
| `kharibulbul alerts [--status --severity --since --limit --json]` · `alerts ack\|investigate\|close\|fp <id> [--assignee --notes]` | list / triage |
| `kharibulbul alerts escalate <id> [--to "SOC lead" --reason "…" --assignee me --keep-severity]` | escalate an alert to the next tier |
| `kharibulbul geoip update [--url U] [--out file]` · `geoip lookup <ip…>` · `geoip status` | download the current DB-IP country table · show the enrichment for addresses · loaded sources |
| `kharibulbul stats` | `/api/stats` |
| `kharibulbul version` | – |

Global options for API commands: `--server http://host:8080`, `--token` (or env `KB_SERVER`, `KB_TOKEN`).
`python -m kharibulbul …` and the short alias `kb` work too.

---

## 16. Synthetic scenarios and safe validation

`kharibulbul/simulate/scenarios.py` builds **log records only** – Windows XML events (Security,
System, Sysmon, PowerShell), syslog lines, nginx lines – with realistic field values, and stamps them
so the last event is a few seconds before "now" (dashboards with `to=now` see them). No process is
started, no host is touched.

| Scenario | Records | Rules expected |
|----------|---------|----------------|
| `baseline` | benign logons, processes, DNS, ssh, cron, web | **none** (false-positive check) |
| `windows-brute-force` | 15×4625 then 4624 from one IP | KB-WIN-001, KB-COR-001 |
| `ssh-brute-force` | sshd failures for 9 users (6 invalid) then accepted | KB-LNX-001, KB-LNX-002, KB-COR-002 |
| `port-scan` | Sysmon 3 inbound to 40 ports + 30 UFW blocks | KB-NET-001, KB-NET-002 |
| `lolbin` | certutil, mshta, rundll32, regsvr32, bitsadmin, wmic, wscript, chained recon | KB-SYS-010…016, 018 |
| `encoded-powershell` | `-EncodedCommand` + 4104 download cradle | KB-SYS-020, KB-PS-001, KB-PS-002 |
| `new-admin-user` | 4720, 4732 Administrators, 4672 | KB-WIN-010, KB-WIN-011, KB-COR-003 |
| `log-cleared` | 1102 | KB-WIN-020 |
| `suspicious-service` | 7045 + 4697 from Temp | KB-WIN-030, KB-WIN-031 |
| `scheduled-task` | 4698 hidden PowerShell action | KB-WIN-032, KB-WIN-033 |
| `suspicious-dns` | Sysmon 22 to `.xyz`/`.top`/listed names | KB-NET-010, KB-TI-002 (+KB-NET-011/013) |
| `intel-hit` | Sysmon 3 + 22 to listed IP/domain | KB-TI-001, KB-TI-002, KB-NET-021 (+KB-NET-020, KB-COR-005) |
| `linux-privilege` | sudo PAM failures, useradd, usermod sudo, su, curl\|bash | KB-LNX-010…013, KB-COR-003 |
| `web-scan` | Nikto-style probing + login brute force | KB-WEB-001…004 |
| `office-spawn` | WINWORD → cmd → powershell | KB-SYS-030 |
| `credential-access` | Sysmon 10 lsass access | KB-SYS-040 |

`tests/test_pipeline_e2e.py` asserts exactly this table; `simulate all` on a live server produced
**246 events → 48 alerts, 0 rule errors** on 2026-09-27 with these 16 scenarios.

Week 3 added 11 team scenarios (`after-hours-logon`, `multi-host-logon`, `rdp-then-service`,
`download-then-execute`, `dns-beacon`, `defender-exclusion`, `web-errors`, `fail2ban`, `auditd`,
`firewall-outbound-burst`, `dhcp`) and a **coverage pack** of 25 more (`simulate/coverage_pack.py`:
password spraying, lockouts, logons from outside the lab, Kerberos failures, account lifecycle, audit
tampering, Defender detection, injection/tampering, ransomware precursors, registry persistence, recon
bursts, offensive PowerShell keywords, intel hash, SSH from outside / slow brute force, su + cron,
auditd tampering, host sweep, Windows Firewall scan, DNS tunnelling, web injection, scan → logon,
download → beacon, agent silent) — **52 scenarios** in total. `kharibulbul rules coverage` runs all of
them offline and writes the matrix: **94 / 95 rules fire, baseline fires 0** (only KB-KB-002, the
parser-error burst, is not simulated because well-formed input never raises a parser error).

Hand-written samples (`samples/`) exercise the same rules through `replay`/`rules test`.

---

## 17. Configuration reference

### `config/server.yml`

| Key | Default | Meaning |
|-----|---------|---------|
| `data_dir` | `data` | runtime directory |
| `log_level` | `INFO` | logging |
| `ingest.tcp.{enabled,host,port}` | true, 0.0.0.0, 5044 | agent listener |
| `ingest.tcp.tls.{enabled,cert,key,ca}` | off | TLS; `ca` set = require client certs |
| `ingest.syslog_udp / syslog_tcp` | udp on 5514, tcp off | syslog listeners |
| `ingest.http.enabled` | true | `POST /api/ingest` |
| `ingest.shared_secret` | `${KB_SHARED_SECRET:-}` | agents must present it |
| `ingest.max_line_bytes` | 1 MiB | protocol line limit |
| `api.{host,port,token,cors}` | 0.0.0.0, 8080, `${KB_API_TOKEN:-}`, false | API/UI |
| `store.sqlite.{path,batch_size,flush_interval}` | data/kharibulbul.db, 200, 1.0 | writer |
| `store.retention_days` | 0 | 0 = keep every event (no date limit); N = purge events older than N days, hourly |
| `store.opensearch.{enabled,url,index_prefix,username,password,verify_tls}` | off | mirror (nested ECS documents) |
| `pipeline.lab_networks` | lab CIDRs | direction / "outside lab" rules |
| `pipeline.geoip.{custom_ranges,mmdb,country_db}` | geoip/custom_ranges.csv, geoip/GeoLite2-City.mmdb, geoip/dbip-country-lite.csv.gz | GeoIP sources: own CIDR table, optional MaxMind city database, DB-IP country table |
| `custom_dir` | custom | rules and playbooks written from the dashboard (`<custom_dir>/rules`, `<custom_dir>/playbooks`) |
| `pipeline.assets` | config/assets.yml | inventory |
| `pipeline.intel_dir` | intel | threat-intel lists |
| `pipeline.drop_datasets` | [] | ignore datasets |
| `pipeline.timezone_offset_hours` | 0 (lab config: 4) | lab local time for `kharibulbul.time.*` |
| `pipeline.business_hours` | [8, 19] | Monday–Friday local hours counted as business hours |
| `detect.{enabled,rules_dir,default_suppress}` | true, rules, 10m | engine |
| `alerts.notify.{console,file,webhook,smtp}` | console+file on | sinks |
| `agents.heartbeat_timeout` | 5m | silent-agent threshold |

`${VAR}` / `${VAR:-default}` are expanded from the environment anywhere in the YAML.

### `config/agent*.yml`

`agent.{name,id,id_file,labels}` (`id` is set by the Add-agent wizard), `server.{host,port,tls{enabled,ca,verify,cert,key},shared_secret,reconnect_min,reconnect_max}`,
`spool.{dir,max_mb}`, `batch.{size,flush_interval,max_bytes}`, `heartbeat_interval`, `log_level`, `inputs[]` (see § 5).
Profiles: `agent.yml` (Linux server), `agent-windows.yml` (Windows, elevated), `agent-windows-host.yml` (this
laptop, no admin), `agent-linux-wsl.yml` (Ubuntu in WSL 2, `server.host` from `KB_SERVER_HOST`),
`agent-local-test.yml` / `agent-tls-test.yml` (test profiles).

### `config/assets.yml`

`zones[] {name, cidrs[]}` and `assets[] {hostnames[], ips[], role, owner, criticality, os, labels{}}`.

---

## 18. Deployment, hardening and operations

* **Server (Ubuntu)**: `sudo bash scripts/install-server.sh` → `/opt/kharibulbul`, venv, systemd unit
  (`kharibulbul-server.service`, runs as user `kharibulbul`, `ProtectSystem`, `CAP_NET_BIND_SERVICE`), UFW rules for the lab ranges.
* **Windows hosts**: `scripts/enable-audit-policy.ps1` (advanced audit policy, 4688 command line, PowerShell
  script-block/module logging, Windows Firewall drop log, larger log sizes), `scripts/enable-sysmon.ps1`
  (downloads Sysmon or uses an offline zip, installs `sysmon/kharibulbul-sysmon.xml`),
  `scripts/install-agent.ps1 -ServerIp … -SharedSecret …` (Python check/install, files, config, scheduled task as SYSTEM).
* **Linux hosts**: `sudo bash scripts/install-agent.sh <server-ip>`; enables UFW logging; switches to
  journald input when no auth.log exists.
* **TLS/mTLS**: `bash scripts/gen-certs.sh <server-ip> ws01 srv-web01` → `certs/`; enable in server and agent configs.
* **Secrets**: `KB_API_TOKEN`, `KB_SHARED_SECRET` via environment / systemd `EnvironmentFile`.
* **Sysmon config highlights**: all process creation (minus noisy system chatter), network connections
  for scripting/LOLBin/user-dir binaries and admin ports plus all inbound, DNS for everything but
  Microsoft/lab domains, image loads of credential/automation DLLs and unsigned modules, LSASS access,
  file creates of executables/scripts in user-writable and startup locations, autorun/services/LSA/RDP/Defender
  registry keys, ADS on downloads, offensive-tooling pipes, all WMI, process tampering.
* **Operations**: daily routine, backup (`.backup`), retention/VACUUM, health signals, troubleshooting
  matrix, change management – `docs/OPERATIONS.md`. Response procedures – `playbooks/`.

---

## 19. Testing

`python -m pytest -q` (123 tests, ~20 s):

| File | Covers |
|------|--------|
| `tests/test_parsers.py` | timestamps, Windows 4625/4688, Sysmon 1/3/22 (+intel & GeoIP enrichment), System 7045, syslog RFC3164/5424, sshd, UFW, sudo/useradd/usermod, su (switch user: success, failure, PAM and session lines), nginx, journald, ECS JSON, Windows Firewall, generic, empty lines |
| `tests/test_query.py` | query compiler (terms, wildcards, comparisons, lists, FTS, boolean logic, errors), store round-trip, aggregations, dedupe, alerts/agents/rule-stats tables |
| `tests/test_rules.py` | strict load of the repository rules (unique ids, MITRE, playbooks exist), validator errors, every matcher modifier, condition parser, match/threshold/distinct/sequence/prefilter/disable semantics with suppression |
| `tests/test_pipeline_e2e.py` | every scenario fires its expected rules; baseline is quiet; all scenarios parse without errors |
| `tests/test_api.py` | health/auth, ingest → search → histogram/terms → alerts → triage → summary → overview, rules endpoints incl. `/rules/test`, playbooks path safety, agents, schema |
| `tests/test_parsers_week2.py` | auditd (all record types, hex decoding), nginx/Apache error logs, Windows DHCP (header skipping), fail2ban, time-context fields and `configure()` |
| `tests/test_playbooks.py` | every ```` ```kql ```` query in the playbooks compiles, every cited rule id exists, every rule links to an existing playbook |
| `tests/test_agent_shipper.py` | batches split below the protocol line limit, oversized event truncated, 1.1 MB batch delivered to a line-limited server, `line too long` lowers the limit, spool keeps only the undelivered rest |
| `tests/test_features.py` | date search without a limit (`all`, exact dates, two-year-old events, chart interval), alert escalation (levels, severity, notifications, still de-duplicated), agent enrolment (generated YAML, pending → online, IP addresses, delete), custom rules (create / validate / edit / delete, shipped rules read-only, rule is live), selection checks, custom playbooks, country table (IPv4 + IPv6, gzip), GeoIP source order, ECS (`conform`, `validate`, nested view, every scenario conformant, `format=ecs`) |

Add a scenario → add its expected rule ids to `EXPECTED`; add a parser → add a `test_parsers.py` case.
`scripts/run-dev.ps1 -Tests` / `scripts/run-dev.sh tests` wrap this.

---

## 20. The four-week plan and deliverables

| Week | Focus | Detailed plan |
|------|-------|---------------|
| 1 | Stand up the stack, deploy agents, enable Sysmon; understand every module | `docs/WEEK1.md` |
| 2 | Parsing, ECS-style normalisation, GeoIP; write one parser yourselves | `docs/WEEK2.md` |
| 3 | Rules for the incident patterns (failed logins, unusual process launches, scan-like patterns, LOLBins), safe validation, notifications, tuning | `docs/WEEK3.md` |
| 4 | Dashboards, playbooks, operations guide, hardening, report and defence | `docs/WEEK4.md` |

Assignment deliverables → repository: **dashboards** (`kharibulbul/web`, `dashboards/`), **alert rules**
(`rules/`), **lab scripts** (`scripts/`, `sysmon/`), **procedure guide** (`playbooks/`, `docs/OPERATIONS.md`,
this guide). Team split: `docs/TEAM-ROLES.md`. Slides/report: `docs/PRESENTATION.md`. Running log: `cloud.md`.

---

## 21. Kharibulbul versus Wazuh

| Aspect | Wazuh (reference) | Kharibulbul |
|--------|-------------------|-------------|
| Agent | C agent, many modules (FIM, SCA, rootcheck, command, logcollector) | Python agent: file, winlog, journald, command; simpler, readable, disk spool + acks |
| Transport | encrypted agent protocol to wazuh-remoted, key enrolment | newline-JSON over TCP with optional TLS/mTLS + shared secret |
| Decoding | XML decoders (regex, prematch, order) | Python parser registry with per-source mappers, sniffing, generic fallback |
| Schema | Wazuh fields + `data.win.eventdata.*` | ECS-style flat fields (`docs/SCHEMA.md`) |
| Rules | XML rules with levels, groups, `if_sid`, frequency/timeframe | YAML Sigma-like selections, thresholds with `distinct`, sequences, suppression, MITRE |
| Storage / search | OpenSearch indices, Wazuh indexer | SQLite + FTS5 + own query language; optional OpenSearch mirror |
| Alerts | alerts.json + integrations | alert lifecycle with dedupe/status/assignee; console/file/webhook/SMTP |
| UI | Wazuh dashboard (OpenSearch Dashboards plugin) | own single-page app with SVG charts |
| Extra modules | FIM, vulnerability detection, SCA, active response, agent groups | not implemented (see limitations) |
| Size | hundreds of thousands of lines | ~6k lines Python – every line explainable by the team |

What we deliberately kept from the reference design: agent/manager split, decode → normalise → rule → alert
pipeline, event-time based frequency rules, ECS naming for interoperability.

---

## 22. Limitations and future work

* Single node, no HA or clustering; SQLite fits a lab (tens of events/s), not a campus.
* No file-integrity monitoring, vulnerability detection, configuration assessment or active response.
* Windows collection polls `wevtutil` (2 s latency) instead of subscribing to the Event Log API.
* GeoIP is country-level for public addresses (DB-IP Lite table); city-level detail needs the optional
  MaxMind file or a row in `geoip/custom_ranges.csv`. The table must be refreshed by hand
  (`kharibulbul geoip update`, needs internet once a month).
* Rules are signature/threshold based; no statistical baselining or ML.
* UI has no user accounts (single API token) and no multi-tenant separation.
* Ideas: `auditd`/DHCP/DNS-server parsers, agent-side filtering, rule packs per host role,
  scheduled reports, case management, OpenSearch as primary backend for larger deployments.

---

## 23. FAQ for the defence

**Why not just Wazuh?** – The professor asked for our own SIEM; Wazuh was studied as a reference
(§ 21). We can explain and modify every layer.

**How do you know detections work without attacking the lab?** – Synthetic log records that look
exactly like the real events (§ 16) pass through the *same* code path as live logs; 123 tests assert
the outcomes; baseline traffic proves the rules stay quiet.

**What happens if the server goes down?** – Agents spool to disk and replay in order after reconnect;
acks guarantee nothing is lost; duplicates are ignored by `event.id`.

**How do you avoid alert storms?** – `logsource` pre-filters, thresholds per entity, `suppress`,
dedupe on open alerts, notifier `min_severity`.

**Why event time instead of arrival time?** – Replays and delayed agents must not break windows; the
engine slides windows on `@timestamp` and garbage-collects stale state.

**Why SQLite?** – Zero external services, transactional, fast enough (thousands of events/s), FTS5 for
free text, one file to back up; the schema is ECS-compatible so OpenSearch can be added (§ 9).

**Why is Sysmon EID 3 not enough for port scans?** – Sysmon only logs connections a process accepts;
closed ports are seen by firewall drop logs (KB-NET-002/003), which we also collect.

**How is the SIEM itself protected?** – API token, shared secret / mTLS for agents, isolated network,
no execution of log content, parsers isolated by try/except, retention, systemd sandboxing.

---

## 24. Glossary (EN / AZ)

| Term | Azərbaycanca | Meaning |
|------|--------------|---------|
| SIEM | təhlükəsizlik hadisələrinin idarə edilməsi sistemi | central collection, correlation and alerting on security logs |
| Agent (Bülbül) | agent / bülbül | program on each host that ships logs |
| Event / document | hadisə | one parsed log record |
| Dataset | məlumat dəsti | logical log source |
| Enrichment | zənginləşdirmə | adding context (GeoIP, asset, intel) |
| Rule | qayda | detection logic |
| Threshold | hədd | count-based rule |
| Sequence | ardıcıllıq | ordered multi-stage rule |
| Alert | xəbərdarlıq | a rule result that needs an analyst |
| Playbook | cavab kitabçası | response procedure |
| False positive | yalan pozitiv | benign activity that triggered a rule |
| Threat intelligence | təhdid kəşfiyyatı | known-bad indicators |
| Lab / isolated network | laboratoriya / təcrid olunmuş şəbəkə | the test environment |

*Salam və uğurlar — the Kharibulbul team.*
