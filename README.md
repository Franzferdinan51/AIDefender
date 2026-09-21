# AIDefender

User-mode **antivirus / defense suite** for **macOS, Linux, and Windows**. Package
version **0.11.0** (this tree). It is **AI-powered** when you opt in; the default
on-demand scan stays offline.

It scans files, quarantines hits, watches folders in real time, flags hostile
processes and sockets, detects internet-side logins, port scans, and host-level
floods, updates malware intel from a JSON feed, and can run as a login service
or an Electron app. People and **agents** use the same CLI (`--json` on every
command; `tools` lists actions).

The default install is **Python 3.9+ stdlib only**. `psutil` and `watchdog` are
optional. OS firewall drops are **opt-in** so a default install cannot lock you
out of your own machine.

- Source: https://github.com/Franzferdinan51/AIDefender
- Binaries: https://github.com/Franzferdinan51/AIDefender/releases — the latest
  **tagged** GitHub Release is **v0.9.0**; it lags this `main` tree (0.11.0).
  Install from source for current behavior. Pushing a new `v*` tag rebuilds CLI
  + Electron installers.

## Honest scope

AIDefender is a **user-mode** / **user-space** antivirus and defense layer:
files, processes, sockets, login logs, quarantine, and optional local AI
triage. It is **not** a kernel antivirus, EDR, or network scrubbing service.

**It does**

- **Antivirus scan** — SHA-256 and string signatures, explainable heuristics
  (0–100), nested zip/tar with size/depth/bomb caps, PE/ELF injection and
  packer stamps. A signature hit is **malicious**; a nested archive containing
  the same class of hit is **malicious**; a benign text file is **clean**.
- **Quarantine** — isolate malicious files and restore them by id.
- **Real-time protect** — on-access files (Linux fanotify when privileged;
  else FSEvents / ReadDirectoryChanges / polling), process and network diffs,
  persistence dirs. With `auto_quarantine`, a dropped signature file is
  isolated and a threat event is logged.
- **Allowlist** — IPs, CIDRs, ports, processes, paths, hashes in
  `allowlist.json`. An allowlisted path/hash is not treated as a threat.
- **AI-powered opt-in triage** — `scan --ai` (and `analyze`) send **scan
  artifacts** (hash, verdict, reasons, bounded sample) to a local-first
  OpenAI-compatible backend (Ollama `:11434`, LM Studio `:1234`), then optional
  cloud. Escalate-only: the model cannot silently turn signature / clamd /
  heuristic-malicious (or DDOS) into `clean`. `unavailable` is never implicit
  `clean`. Default `scan` without `--ai` opens **no** model HTTP.
- **Local-first AI assist** on attacking-AI artifacts and DDOS/intrusion
  alerts. Detectors still fire with no model.
- **counter-AI / rogue-AI** — prompt-injection / jailbreak / LLM-exfil **text**
  and LLM-API **cmdlines/sockets** (deterministic tokens; no live attacking
  model required).
- Host IDS: inbound sessions on admin ports, brute-force, port-scan, and
  **DDOS** (many public sources or SYN_RECV on one listener).
- Local blocklist (`blocked-ips.json`). Optional OS firewall drop **only** if
  you set `intrusion_firewall_block` or pass `intrusion --firewall`.
- Bounded receive-only packet **summary** if `tcpdump`/`tshark` is installed.
- AI backend discovery: probe LM Studio / Ollama for loaded models, select one,
  test the roundtrip (`ai status|use|test`).
- Engine status JSON: definition counts, on-access mode, clamd, login service,
  and local AI URL/model **reachability**.
- Electron UI as a `--json` front-end for the same CLI, including a Settings tab.

**It does not**

- Ship a signed Windows **minifilter**, Apple Endpoint Security system
  extension, or anything that inspects every packet in the kernel
- Stop a **volumetric** DDoS that already saturates the uplink (no SYN cookies,
  no NIC drop, no CDN/BGP scrubbing). Host detection + local blocklist is the bar
- Guarantee every jailbreak, autonomous agent, or novel LLM API is caught
- Replace Gatekeeper / XProtect, Windows Defender, or SELinux
- Upload full files to VirusTotal or other clouds
- Inject packets, exploit hosts, or kill pid 1 / itself
- Sign or notarize macOS/Windows installers (binaries are **unsigned**;
  first-open may need right-click → Open)

Use it **with** the OS defender, not instead of it, in high-risk environments.

## Install

### Prebuilt binaries

From [Releases](https://github.com/Franzferdinan51/AIDefender/releases).
Tagged assets follow electron-builder / PyInstaller names (the v0.9.0 tag
shipped `AIDefender-0.9.0-arm64.dmg`, `AIDefender.Setup.0.9.0.exe`,
`AIDefender-0.9.0.AppImage`, and CLI `aidefender-macos-arm64` /
`aidefender-windows-x64.exe` / `aidefender-linux-x64`). A future `v*` tag
uses the same pattern with that version number.

| Platform | Desktop UI | CLI |
| --- | --- | --- |
| macOS (Apple Silicon) | `AIDefender-*-arm64.dmg` (+ zip) | `aidefender-macos-arm64` |
| Windows | `AIDefender.Setup.*.exe` / `AIDefender-*-win.zip` | `aidefender-windows-x64.exe` |
| Linux | `AIDefender-*.AppImage` (+ tar.gz) | `aidefender-linux-x64` |

Those installers are **unsigned**. For 0.11.0 behavior (AI-powered `scan --ai`,
Settings/`config`, `engines.local_ai`), use source below until a matching tag
exists.

### From source (macOS / Linux)

```bash
./install.sh
source .venv/bin/activate
python -m aidefender status
```

### From source (Windows PowerShell)

```powershell
.\install.ps1
.\.venv\Scripts\Activate.ps1
python -m aidefender status
```

### pip

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .\.venv\Scripts\Activate.ps1
pip install .
pip install ".[full]"       # optional psutil + watchdog
python -m aidefender status
```

## Quick start

```bash
python -m aidefender status
python -m aidefender scan ~/Downloads
python -m aidefender scan ~/Downloads --ai          # AI-powered opt-in triage
python -m aidefender scan ./bad.txt --quarantine
python -m aidefender protect --once --auto-quarantine
python -m aidefender --json engines
python -m aidefender --json intrusion --no-geo
python -m aidefender update
python -m aidefender --json tools
python -m aidefender allow add --cidr 10.0.0.0/8 --note "home LAN"
python -m aidefender service install
```

Safe signature check (do **not** write the live EICAR string to disk on macOS):

```bash
echo 'cli test token: mimikatz' > /tmp/aidefender-sig-test.txt
python -m aidefender scan /tmp/aidefender-sig-test.txt   # MALICIOUS, exit 1
```

EICAR hash/string exist **in memory** in the built-in database only.

## What it does

- **Scan (antivirus)** — SHA-256, string signatures, explainable heuristics
  (0–100), nested zip/tar with zip-bomb caps, PE/ELF injection and packer
  stamps, **counter-AI** prompt-injection / jailbreak / LLM-exfil (normalized
  paraphrases). Default `scan` is offline (no network). `scan --ai` is the
  **AI-powered opt-in** path: escalate-only merge after the deterministic scan.
- **Analyze** — local-first OpenAI-compatible triage of **artifacts** (hash,
  verdict, reasons, bounded sample), not a full-file upload. Same lock: no
  silent downgrade of deterministic malicious/DDOS. `unavailable` stays
  `unavailable`.
- **Quarantine** — `scan --quarantine` or protect/monitor/daemon with
  `--auto-quarantine` / `auto_quarantine`. `quarantine list|restore|delete`.
- **Protect / monitor / daemon** — **real-time protect**: on-access files
  (Linux fanotify when privileged; else FSEvents / ReadDirectoryChanges /
  polling), process and network diffs, persistence dirs, intrusion/DDOS ticks,
  optional auto-update of definitions.
- **Intrusion / DDOS** — inbound SSH/RDP/VNC/SMB (etc.) from **public** IPs,
  brute-force, port-scan, many-source or SYN_RECV **DDOS**. Geo/rDNS optional.
  LAN/loopback ignored. Evaluate a saved snapshot with `--connections-json`.
- **Processes / network / memory** — flag suspicious cmdlines, risky remotes,
  running image hashes; LLM API hosts unless allowlisted.
- **Allow / block** — `allowlist.json` and `blocked-ips.json` under the config
  dir. Firewall mutation is opt-in (`intrusion --firewall`).
- **Diag / capture / inspect** — ss/netstat, listeners, ARP, routes, tool
  inventory; bounded receive-only capture; IP geo + live sockets.
- **Engines / status / events / service / ui** — definition counts, on-access,
  clamd, `local_ai` reachability; JSONL event log; login unit; Electron window.
- **Live definitions** — `update` merges GitHub `signatures.json`. A failed
  fetch keeps the last good database.

## Commands

```bash
python -m aidefender scan ./dir
python -m aidefender scan ./dir --ai
python -m aidefender scan ./dir --quarantine
python -m aidefender analyze ./file --local-url http://127.0.0.1:1234/v1
python -m aidefender ai status
python -m aidefender ai use lmstudio --model <id-from-status>
python -m aidefender ai test
python -m aidefender config get
python -m aidefender config set heuristic_malicious 80
python -m aidefender protect --once --auto-quarantine
python -m aidefender monitor ~/Downloads --seconds 30
python -m aidefender --json intrusion --no-geo
python -m aidefender intrusion --firewall
python -m aidefender --json intrusion --no-geo --no-block --connections-json ./flood.json
python -m aidefender allow add --ip 203.0.113.10 --note "office VPN"
python -m aidefender allow add --process curl --note "my research agent"
python -m aidefender allow list
python -m aidefender block add --ip 198.51.100.9
python -m aidefender diag
python -m aidefender --json diag
python -m aidefender inspect ip 198.51.100.9 --no-geo
python -m aidefender capture --seconds 3 --count 40 --filter "port 22"
python -m aidefender --json tools
python -m aidefender act stop-process --pid 1234 --name malware
python -m aidefender processes
python -m aidefender network
python -m aidefender memory
python -m aidefender events -n 20
python -m aidefender engines
python -m aidefender --json engines
python -m aidefender update
python -m aidefender quarantine list
python -m aidefender daemon --once
python -m aidefender service install
python -m aidefender ui
python -m aidefender --json status
```

`--json` goes **before** the subcommand. Exit **1** means threats (or a
malicious/DDOS intrusion finding). Default `scan` does not open a network
connection; `scan --ai`, `update`, `analyze`, `ai`, and intrusion geo do.

`--json engines` includes `definitions.counts`, `on_access`, `clamd`, and
`local_ai` (`base_url`, `model`, `reachable`, `models`, `error`, `latency_ms`).

## For agents

`python -m aidefender --json tools` is the catalog. Prefer `--json` everywhere.
Do not inject packets. Do not SIGTERM pid 1 or the defender process. Allowlist
the operator’s own local LLM/agent if it would otherwise match API-host rules.
`scan --ai` is opt-in; do not assume a model is reachable. A missing backend is
`unavailable`, not clean.

## Configuration

Config directory (override with `--config-dir`):

- macOS: `~/Library/Application Support/AIDefender/`
- Linux: `~/.config/aidefender/`
- Windows: `%APPDATA%\AIDefender\`

Also written there: `allowlist.json`, `blocked-ips.json`, `intel-state.json`,
quarantine dir, event log, `config.json`.

| Key | Default | Meaning |
| --- | --- | --- |
| `auto_quarantine` | `false` | Quarantine malicious hits in protect/monitor/daemon |
| `watch_paths` | Downloads, Desktop | Folders for protect/daemon |
| `local_ai_base_url` | `http://127.0.0.1:11434/v1` | Ollama-compatible endpoint |
| `local_ai_model` | `llama3.2` | Local model id |
| `cloud_ai_base_url` | empty | Cloud OpenAI-compatible fallback |
| `ai_timeout_seconds` | `8` | AI HTTP timeout |
| `ai_sample_bytes` | `4096` | Max sample bytes sent to the model |
| `signatures_url` | GitHub `signatures.json` | Live intel feed |
| `auto_update_definitions` | `true` | Refresh feed in long-running protect/daemon |
| `clamd_enable` | `false` | Local ClamAV daemon only |
| `heuristic_malicious` | `75` | Score ≥ this is malicious (0–100) |
| `intrusion_auto_block` | `true` | Persist caught public IPs locally |
| `intrusion_firewall_block` | `false` | OS firewall drop (opt-in) |
| `intrusion_allow_ips` | `[]` | Extra IPs merged into the allowlist |
| `intrusion_ddos_sources` | `12` | Distinct public sources → `ddos` |
| `intrusion_ddos_syn` | `20` | SYN_RECV count → `ddos` |

`config get` lists all 26 settable keys. Cloud key:
`AIDEFENDER_CLOUD_AI_API_KEY` or `OPENAI_API_KEY`. LM Studio:
`http://127.0.0.1:1234/v1`. `*api_key` cannot be set via `config set`.

Change settings from the CLI or the desktop Settings tab (values are validated
and clamped on load):

```bash
python -m aidefender config get                     # all settable keys
python -m aidefender config set watch_paths ~/Downloads,~/Desktop
python -m aidefender config set auto_quarantine true
```

### Security-AI backends (LM Studio / Ollama)

1. Load a model. LM Studio: start the server (Developer tab, or
   `lms server start`) at `http://127.0.0.1:1234/v1`. Ollama: `11434`.
2. `python -m aidefender ai status` — lists reachable backends and models.
3. `python -m aidefender ai use lmstudio --model <id>` — persist the choice
   (`ai use ollama` is the same shape).
4. `python -m aidefender ai test` — one chat roundtrip to prove it answers.
5. `python -m aidefender scan ./file --ai` or `analyze ./file` — triage uses
   that backend.

Only scan artifacts (hash, verdict, reasons, bounded sample) are ever sent —
never full files. Signature/clamd/heuristic-malicious cannot be downgraded to
clean.

## Desktop UI

```bash
cd ui && npm install && npm start
# or
python -m aidefender ui
```

The window is a `--json` front-end. Tabs: Dashboard (`status`/`engines`), Scan,
Protect, Quarantine list, Definitions (`update`), Intrusion, Engines, **analyze**,
**allowlist** (`allow list` / `add` / `remove`), **diag**, **processes**,
**network**, **events**, **settings** (Security-AI backend detect/use/test plus
`config get` / `config set`). Result text is shown as the CLI returned it
(including rogue-AI / DDOS reasons). Packet `capture`, OS `--firewall`,
`scan --ai`, and `act stop-process` stay CLI-only.

## Tests and CI

```bash
python -m unittest discover -s tests -v
```

GitHub Actions `ci` does `pip install .` then that suite on Ubuntu, macOS, and
Windows (Python 3.9 / 3.11 / 3.12). Tagged `v*` builds CLI + Electron installers.

## Layout

```text
aidefender/      scan, protect, intrusion/DDOS, rogue-AI, allow/block, diag, AI, CLI
ui/              Electron desktop (renderer is a classic <script src>)
tests/           stdlib unittest (including renderer_harness.js)
signatures.json  community intel feed
packaging/       PyInstaller spec
.github/         ci.yml + release.yml
install.sh / install.ps1
CHANGELOG.md     release notes
```

## License

MIT — see `LICENSE`.
