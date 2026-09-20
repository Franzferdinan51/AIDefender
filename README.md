# AIDefender

Cross-platform **user-mode** defender for **macOS, Linux, and Windows** (v0.9.0).

It scans files, watches folders, flags hostile processes and network sessions,
detects internet-side logins and port scans, updates malware intel live, and
can run as a login service or an Electron desktop app. People and **agents**
share the same CLI: `--json` on every command, plus `tools` for a catalog of
defensive actions.

No kernel drivers. The default install is **stdlib-only**; `psutil` and
`watchdog` are optional extras. OS firewall drops are **opt-in** so a default
install cannot lock you out of your own machine.

Repository: https://github.com/Franzferdinan51/AIDefender  
Releases: https://github.com/Franzferdinan51/AIDefender/releases

## Install

### Prebuilt binaries (recommended)

Download from [Releases](https://github.com/Franzferdinan51/AIDefender/releases):

| Platform | Desktop UI | CLI |
| --- | --- | --- |
| macOS (Apple Silicon) | `AIDefender-*-arm64.dmg` | `aidefender-macos-arm64` |
| Windows | `AIDefender-Setup-*.exe` | `aidefender-windows-x64.exe` |
| Linux | `AIDefender-*.AppImage` | `aidefender-linux-x64` |

macOS builds are unsigned — first launch may need **right-click → Open**.

### From source (macOS / Linux)

```bash
./install.sh
source .venv/bin/activate
aidefender status
aidefender scan ~/Downloads
```

### From source (Windows PowerShell)

```powershell
.\install.ps1
.\.venv\Scripts\Activate.ps1
aidefender status
aidefender scan $HOME\Downloads
```

### pip (any OS)

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .\.venv\Scripts\Activate.ps1
pip install .
pip install ".[full]"            # optional: psutil + watchdog
python -m aidefender status
```

Requires **Python 3.9+**.

## Quick start

```bash
aidefender status
aidefender scan ~/Downloads
aidefender protect --once
aidefender intrusion --no-geo    # skip geo if you are offline
aidefender update                # pull live definitions
aidefender --json tools          # catalog for agents
aidefender diag                  # netstat/ARP/routes
aidefender allow add --cidr 10.0.0.0/8 --note "home LAN"
aidefender service install       # start at login
```

Safe signature check (do **not** write the live EICAR string to disk on macOS;
endpoint protection often blocks the file):

```bash
echo 'cli test token: mimikatz' > /tmp/aidefender-sig-test.txt
aidefender scan /tmp/aidefender-sig-test.txt   # expect MALICIOUS, exit 1
```

The EICAR hash and string still live **in memory** in the built-in database
for scanners that need the industry test file.

## What it does

- **Scan** — SHA-256 hashes, string signatures, explainable heuristics (0–100),
  nested zip/tar with zip-bomb caps, PE/ELF injection and packer stamps,
  plus **rogue-AI** prompt-injection / jailbreak / LLM-exfil text (no live model required)
- **Unauthorized agent/LLM use** — process cmdlines and sockets aimed at common
  LLM APIs (`api.openai.com`, Anthropic, Groq, OpenRouter, …) or agent-runtime
  tokens; suppress with `allow add --process` / `--ip`
- **Quarantine** — isolate / list / restore / delete with metadata
- **Protect / monitor** — on-access file events (Linux fanotify when available;
  otherwise FSEvents / ReadDirectoryChanges / polling), settle + debounce,
  ransomware-like burst alerts, process and network diffs, user persistence dirs
- **Intrusion detection** — inbound SSH/RDP/VNC/SMB (and similar) from **public**
  IPs, failed-login brute force, port-scan bursts; reverse DNS + geo
  (city / region / country / ISP); local blocklist. LAN and loopback are ignored
- **Live definitions** — `update` merges the GitHub JSON feed (hashes, family
  strings, C2 hints, process tokens). protect/daemon refresh on an interval.
  A failed fetch keeps the last good database
- **Local-first AI triage** — `analyze` sends **artifacts only** (hash, verdict,
  score, reasons, bounded sample) to localhost OpenAI-compatible servers
  (Ollama / LM Studio) and falls back to a configured cloud API. A signature
  `malicious` finding cannot be downgraded to `clean`
- **Optional ClamAV** — local `clamd` only (no cloud upload), off by default
- **Desktop UI** — Electron app for scan, protect, quarantine, definitions,
  engines, and intrusion
- **Allowlist** — IPs, CIDRs, ports, process names, paths, and SHA-256 hashes
  the user trusts; skipped by scan, process, network, and intrusion checks
- **Diagnostics** — `diag` wraps ss/netstat, listeners, ARP, and routes;
  `capture` is a bounded receive-only packet summary via tcpdump/tshark
  (Wireshark) when installed
- **Local actions** — block/unblock IPs, quarantine files, SIGTERM a local
  process (never pid 1 or the defender itself)
- **Always-on** — `service install` writes a user LaunchAgent, systemd user
  unit, or Windows Startup script

## Commands

```bash
aidefender scan ./suspect-dir --quarantine
aidefender analyze ./suspect.bin
aidefender analyze ./suspect.bin --local-url http://127.0.0.1:1234/v1 --model local-model
aidefender protect ~/Downloads ~/Desktop --auto-quarantine
aidefender protect --once
aidefender monitor ~/Downloads --auto-quarantine
aidefender intrusion
aidefender --json intrusion --no-geo
aidefender intrusion --firewall          # opt-in OS firewall drop
aidefender allow add --ip 203.0.113.10 --note "office VPN"
aidefender allow add --cidr 10.0.0.0/8 --note "home LAN"
aidefender allow add --process chrome --note "browser"
aidefender allow add --path /Users/me/lab --note "malware lab folder"
aidefender allow list
aidefender block add --ip 198.51.100.9 --reason "caught scanning"
aidefender block remove --ip 198.51.100.9
aidefender diag                          # connections, listeners, ARP, routes, tools
aidefender --json diag tools
aidefender inspect ip 198.51.100.9 --no-geo
aidefender capture --seconds 3 --count 40 --filter "port 22"
aidefender --json tools                  # catalog for agents
aidefender act stop-process --pid 1234 --name malware
aidefender quarantine list
aidefender quarantine restore <id> --dest ./restored.bin
aidefender processes
aidefender network
aidefender memory
aidefender engines
aidefender events -n 20
aidefender update
aidefender --json update --source ./signatures.json
aidefender daemon --interval 3600 --auto-quarantine
aidefender daemon --once
aidefender service install
aidefender service status
aidefender ui
aidefender --json status
```

Add `--json` **before** the subcommand for machine-readable output
(`aidefender --json scan ./dir`). Exit code **1** means threats (or, for
`intrusion`, a malicious finding).

`scan` itself never opens a network connection. `update`, `analyze`, and
intrusion geo lookups do.

## For agents

`aidefender --json tools` prints a catalog of every defensive action (scan,
diag, capture, allow, block, inspect, stop-process, …) with argv templates.
Prefer `--json` on every command. Capture is **receive-only** and capped
(time + packet count); it will not inject packets. `act stop-process`
refuses pid 1 and the defender’s own process.

If `tcpdump` or `tshark` (Wireshark) is installed, `capture` produces a
flow summary. `diag` always wraps **ss/netstat/arp/route** when those
binaries exist.

## Intrusion detection

Caught public IPs are stored in `blocked-ips.json` under the config directory
and honored by the network guard. Trusted items go in `allowlist.json` (or
`aidefender allow add`).

| Default | Behavior |
| --- | --- |
| Local blocklist | **on** (`intrusion_auto_block`) |
| OS firewall drop | **off** — set `intrusion_firewall_block` or pass `--firewall` |
| Geo / rDNS | **on** — disable with `--no-geo` or `intrusion_geo: false` |
| Allowlist | `allowlist.json` plus `intrusion_allow_ips` in config |

`--no-block` is detect-only. Private, loopback, and link-local addresses are
never treated as intruders.

## Configuration

First run writes a config directory:

- macOS: `~/Library/Application Support/AIDefender/`
- Linux: `~/.config/aidefender/`
- Windows: `%APPDATA%\AIDefender\`

Override with `--config-dir`. Useful keys in `config.json`:

| Key | Default | Meaning |
| --- | --- | --- |
| `auto_quarantine` | `false` | Move malicious hits during protect/monitor/daemon |
| `watch_paths` | Downloads, Desktop | Folders for protect/daemon |
| `local_ai_base_url` | `http://127.0.0.1:11434/v1` | Ollama-compatible endpoint |
| `cloud_ai_base_url` | empty | Cloud OpenAI-compatible fallback |
| `signatures_url` | GitHub `signatures.json` | Live intel feed |
| `auto_update_definitions` | `true` | Refresh feed in protect/daemon (~15 min) |
| `clamd_enable` | `false` | Use a local ClamAV daemon |
| `intrusion_auto_block` | `true` | Persist caught public IPs locally |
| `intrusion_firewall_block` | `false` | Also drop them in the OS firewall |
| `intrusion_allow_ips` | `[]` | Extra IPs merged into the allowlist |

Cloud AI key: `AIDEFENDER_CLOUD_AI_API_KEY` or `OPENAI_API_KEY`.

LM Studio example: set `local_ai_base_url` to `http://127.0.0.1:1234/v1`.

## Desktop UI (from source)

```bash
cd ui
npm install
npm start
```

Or `python -m aidefender ui` after `npm install` in `ui/`. Release installers
bundle a CLI binary next to the app.

The window is a `--json` front-end for the same CLI. Existing tabs:
Dashboard (status/engines), Scan, Protect, Quarantine list, Definitions
(`update`), Intrusion, and Engines. Operator surfaces in the same window:
**allowlist** (`allow list` / `allow add` / `allow remove`), **diag**,
**processes**, **network**, **events**, and **analyze**. Scan/analyze result
text includes rogue-AI reasons when the CLI returns them. Packet `capture`,
OS `--firewall` block, and `act stop-process` stay CLI-only.

## Tests and CI

```bash
python -m unittest discover -s tests -v
```

GitHub Actions `ci` installs the package from committed files and runs that
suite on Ubuntu, macOS, and Windows (Python 3.9 / 3.11 / 3.12).

## Layout

```text
aidefender/      core package (scan, protect, intrusion, allow/block, diag, CLI)
ui/              Electron desktop app
tests/           stdlib unittest suite
signatures.json  community intel feed (merged by `update`)
packaging/       PyInstaller spec for release CLI binaries
.github/         CI + tagged-release workflows
install.sh       macOS/Linux installer
install.ps1      Windows installer
```

## Honest scope

AIDefender is the **user-mode** layer commercial AV runs outside the kernel:
login service, on-access file events, live definitions, PE/ELF heuristics,
process-image scanning, optional local clamd, network/login IDS, allowlisting,
and netstat/packet diagnostics. Capture never injects packets.

It does **not** ship a signed Windows minifilter, an Apple Endpoint Security
system extension, or a vendor cloud-reputation network. Use it **with**
Gatekeeper / XProtect, Windows Defender, or SELinux — not as a silent
replacement in high-risk environments.

## License

MIT — see `LICENSE`.
