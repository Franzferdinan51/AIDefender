# AIDefender

User-mode defender for **macOS, Linux, and Windows**. Package version **0.10.0**.

It scans files, watches folders, flags hostile processes and sockets, detects
internet-side logins, port scans, and host-level floods, updates malware intel
from a JSON feed, and can run as a login service or an Electron app. People and
**agents** use the same CLI (`--json` on every command; `tools` lists actions).

The default install is **Python 3.9+ stdlib only**. `psutil` and `watchdog` are
optional. OS firewall drops are **opt-in** so a default install cannot lock you
out of your own machine.

- Source: https://github.com/Franzferdinan51/AIDefender
- Binaries: https://github.com/Franzferdinan51/AIDefender/releases (latest **tagged**
  release may lag `main`; the tree version is 0.10.0)

## Honest scope

AIDefender is a **user-mode** / **user-space** defense layer: files, processes,
sockets, login logs, and optional local AI triage. It is **not** a kernel
antivirus, EDR, or network scrubbing service.

**It does**

- Hash/string/heuristic scans (including nested zip/tar with size/depth caps)
- Prompt-injection / jailbreak / LLM-exfil **text** and LLM-API **cmdlines/sockets**
  (deterministic tokens, no live attacking model required)
- Host IDS: inbound sessions on admin ports, brute-force, port-scan, and **ddos**
  (many public sources or SYN_RECV on one listener)
- Local blocklist + allowlist (IPs, CIDRs, ports, processes, paths, hashes)
- Optional OS firewall drop **only** if you set `intrusion_firewall_block` or pass
  `--firewall`
- Local-first AI assist on scan findings, attacking-AI artifacts, and
  DDOS/intrusion alerts (Ollama/LM Studio, then optional cloud). Detectors still
  fire with no model. The model cannot silently turn malicious/DDOS into `clean`.
  `unavailable` is never implicit `clean`.
- Bounded receive-only packet **summary** if `tcpdump`/`tshark` is installed
- Electron UI as a `--json` front-end for the same CLI

**It does not**

- Ship a signed Windows minifilter, Apple Endpoint Security system extension,
  or anything that inspects every packet in the kernel
- Stop a **volumetric DDoS** that already saturates the uplink (no SYN cookies,
  no NIC drop, no CDN/BGP scrubbing). Host detection + local blocklist is the bar
- Guarantee every jailbreak, autonomous agent, or novel LLM API is caught
- Replace Gatekeeper / XProtect, Windows Defender, or SELinux
- Upload full files to VirusTotal or other clouds
- Inject packets, exploit hosts, or kill pid 1 / itself
- Sign or notarize macOS/Windows installers (binaries are **unsigned**; first-open may need right-click → Open)

Use it **with** the OS defender, not instead of it, in high-risk environments.

## Install

### Prebuilt binaries

From [Releases](https://github.com/Franzferdinan51/AIDefender/releases):

| Platform | Desktop UI | CLI |
| --- | --- | --- |
| macOS (Apple Silicon) | `AIDefender-*-arm64.dmg` | `aidefender-macos-arm64` |
| Windows | `AIDefender.Setup-*.exe` / `AIDefender-Setup-*.exe` | `aidefender-windows-x64.exe` |
| Linux | `AIDefender-*.AppImage` | `aidefender-linux-x64` |

Also published: zip/tar.gz of the UI. Names follow electron-builder (`AIDefender.Setup.0.9.0.exe` on some tags).

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
python -m aidefender protect --once
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

- **Scan** — SHA-256, string signatures, explainable heuristics (0–100), nested
  zip/tar with zip-bomb caps, PE/ELF injection and packer stamps, **counter-AI**
  prompt-injection / jailbreak / LLM-exfil (normalized paraphrases). `scan` is
  offline (no network).
- **Analyze** — local-first OpenAI-compatible triage of **artifacts** (hash,
  verdict, reasons, bounded sample), not a full-file upload. Same lock: no
  silent downgrade of deterministic malicious/DDOS.
- **Protect / monitor / daemon** — on-access files (Linux fanotify when
  privileged; else FSEvents / ReadDirectoryChanges / polling), process and
  network diffs, persistence dirs, intrusion/DDOS ticks, optional auto-update
  of definitions.
- **Intrusion / DDOS** — inbound SSH/RDP/VNC/SMB (etc.) from **public** IPs,
  brute-force, port-scan, many-source or SYN_RECV **ddos**. Geo/rDNS optional.
  LAN/loopback ignored. Evaluate a saved snapshot with `--connections-json`.
- **Processes / network / memory** — flag suspicious cmdlines, risky remotes,
  running image hashes; LLM API hosts unless allowlisted.
- **Allow / block** — `allowlist.json` and `blocked-ips.json` under the config
  dir. Firewall mutation is opt-in.
- **Diag / capture / inspect** — ss/netstat, listeners, ARP, routes, tool
  inventory; bounded receive-only capture; IP geo + live sockets.
- **Quarantine, events, engines, service, ui** — isolate files, JSONL log,
  engine status, login unit, Electron window.
- **Live definitions** — `update` merges GitHub `signatures.json`. A failed
  fetch keeps the last good database.

## Commands

```bash
python -m aidefender scan ./dir --quarantine
python -m aidefender analyze ./file --local-url http://127.0.0.1:1234/v1
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
python -m aidefender update
python -m aidefender daemon --once
python -m aidefender service install
python -m aidefender ui
python -m aidefender --json status
```

`--json` goes **before** the subcommand. Exit **1** means threats (or a
malicious/DDOS intrusion finding). `scan` does not open a network connection;
`update`, `analyze`, and intrusion geo do.

## For agents

`python -m aidefender --json tools` is the catalog. Prefer `--json` everywhere.
Do not inject packets. Do not SIGTERM pid 1 or the defender process. Allowlist
the operator’s own local LLM/agent if it would otherwise match API-host rules.

## Configuration

Config directory (override with `--config-dir`):

- macOS: `~/Library/Application Support/AIDefender/`
- Linux: `~/.config/aidefender/`
- Windows: `%APPDATA%\AIDefender\`

Also written there: `allowlist.json`, `blocked-ips.json`, `intel-state.json`,
quarantine dir, event log.

| Key | Default | Meaning |
| --- | --- | --- |
| `auto_quarantine` | `false` | Quarantine malicious hits in protect/monitor/daemon |
| `watch_paths` | Downloads, Desktop | Folders for protect/daemon |
| `local_ai_base_url` | `http://127.0.0.1:11434/v1` | Ollama-compatible endpoint |
| `cloud_ai_base_url` | empty | Cloud OpenAI-compatible fallback |
| `signatures_url` | GitHub `signatures.json` | Live intel feed |
| `auto_update_definitions` | `true` | Refresh feed in long-running protect/daemon |
| `clamd_enable` | `false` | Local ClamAV daemon only |
| `intrusion_auto_block` | `true` | Persist caught public IPs locally |
| `intrusion_firewall_block` | `false` | OS firewall drop (opt-in) |
| `intrusion_allow_ips` | `[]` | Extra IPs merged into the allowlist |
| `intrusion_ddos_sources` | `12` | Distinct public sources → `ddos` |
| `intrusion_ddos_syn` | `20` | SYN_RECV count → `ddos` |

Cloud key: `AIDEFENDER_CLOUD_AI_API_KEY` or `OPENAI_API_KEY`. LM Studio:
`http://127.0.0.1:1234/v1`.

## Desktop UI

```bash
cd ui && npm install && npm start
# or
python -m aidefender ui
```

The window is a `--json` front-end. Tabs: Dashboard (`status`/`engines`), Scan,
Protect, Quarantine list, Definitions (`update`), Intrusion, Engines, **analyze**,
**allowlist** (`allow list` / `add` / `remove`), **diag**, **processes**,
**network**, **events**. Result text is shown as the CLI returned it (including
rogue-AI / DDOS reasons). Packet `capture`, OS `--firewall`, and
`act stop-process` stay CLI-only.

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
```

## License

MIT — see `LICENSE`.
