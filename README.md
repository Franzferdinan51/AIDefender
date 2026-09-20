# AIDefender

Cross-platform **user-mode** defender for **macOS, Linux, and Windows** (v0.7.0).

It scans files, watches folders, flags hostile processes and network sessions,
detects internet-side logins and port scans, updates malware intel live, and
can run as a login service or an Electron desktop app.

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
  nested zip/tar with zip-bomb caps, PE/ELF injection and packer stamps
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

## Intrusion detection

Caught public IPs are stored in `blocked-ips.json` under the config directory
and honored by the network guard.

| Default | Behavior |
| --- | --- |
| Local blocklist | **on** (`intrusion_auto_block`) |
| OS firewall drop | **off** — set `intrusion_firewall_block` or pass `--firewall` |
| Geo / rDNS | **on** — disable with `--no-geo` or `intrusion_geo: false` |
| Allowlist | `intrusion_allow_ips` in config (your office SSH IP, etc.) |

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
| `intrusion_allow_ips` | `[]` | Never treat these IPs as intruders |

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

## Tests and CI

```bash
python -m unittest discover -s tests -v
```

GitHub Actions `ci` installs the package from committed files and runs that
suite on Ubuntu, macOS, and Windows (Python 3.9 / 3.11 / 3.12).

## Layout

```text
aidefender/      core package (scan, protect, intrusion, AI, CLI)
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
process-image scanning, optional local clamd, and network/login IDS.

It does **not** ship a signed Windows minifilter, an Apple Endpoint Security
system extension, or a vendor cloud-reputation network. Use it **with**
Gatekeeper / XProtect, Windows Defender, or SELinux — not as a silent
replacement in high-risk environments.

## License

MIT — see `LICENSE`.
