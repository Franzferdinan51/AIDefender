# AIDefender — AI-assisted full defense suite

Cross-platform defender for **macOS, Linux, and Windows**: file scanning,
explainable AI-style heuristics, quarantine, real-time folder protection,
process + network guards, signature updates, and a background daemon.

No kernel drivers. No heavy ML dependencies. Everything runs on the
standard library by default; `psutil` + `watchdog` unlock full power.

## Features

- **Scanner**: SHA-256 signatures + portable string rules + heuristic score (0–100)
- **Nested archives**: zip/tar (including gzip) walked in memory with depth,
  member-count, and decompressed-size caps so zip bombs cannot hang a scan
- **AI heuristics**: entropy, extension/content mismatch, double-extension,
  dropper/LOLBin/family tokens, curl|sh droppers — every point explained
- **Local-first AI triage**: `analyze` sends scan artifacts (hash, verdict,
  score/reasons/features, bounded text/hex sample) to a localhost
  OpenAI-compatible server (Ollama / LM Studio / llama.cpp) and falls back
  to a configured cloud API only when local is unset or unreachable. A
  signature `malicious` finding cannot be downgraded to `clean`.
- **Quarantine**: isolate / list / restore / delete with metadata
- **Real-time protect**: file on-access (settle + debounce + hash cache),
  process/network snapshot diffs, user persistence dirs, ransomware-like
  burst alerts, JSONL event log — `watchdog` when installed, polling fallback
- **Process guard**: `psutil` → `ps` → `tasklist` fallback chain; flags
  LOLBins, encoded PowerShell, temp-dir executables
- **Network guard**: risky ports/IPs, Tor, listen-on-malware-port;
  `psutil` → `ss` → `netstat` fallback
- **Malware intel / virus definitions**: SHA-256 hashes, family strings
  (ransomware, stealers, RATs, web shells), C2 IPs/ports, and process
  tokens. `aidefender update` merges a live JSON feed; protect/daemon
  refresh it on an interval so new definitions apply without restart.
  A failed fetch keeps the last good database.
- **Daemon**: periodic sweeps plus live definition refresh
- **Always-on service**: `service install` writes a login LaunchAgent / systemd user unit / Windows Startup script
- **On-access**: Linux **fanotify** (ClamAV-style notification mode) when privileged; otherwise FSEvents/ReadDirectoryChanges/polling
- **Multi-engine**: built-in signatures + heuristics + optional **local clamd** (no cloud upload)
- **Process images**: `memory` hashes running executables against the definition DB
- **CLI**: human + `--json` output, exit code 1 on threats
- **Electron UI**: desktop app for scan, protect, quarantine, live definitions
- **Intrusion detection**: inbound SSH/RDP/VNC/SMB sessions from public IPs,
  failed-login brute force, port-scan bursts; reverse DNS + geo (country/city/ISP);
  auto-blocklist the attacker and optionally drop them in the OS firewall
- **GitHub Releases**: CLI binaries (PyInstaller) and Electron installers (macOS/Windows/Linux)

## Desktop UI

```bash
cd ui
npm install
npm start
```

Or from the repo after `npm install` in `ui/`:

```bash
python -m aidefender ui
```

The UI talks to the shipped CLI (`python -m aidefender --json …`, or a bundled
PyInstaller binary inside release builds).

## GitHub binaries

Tagged releases (`v*`) build via `.github/workflows/release.yml`:

- `aidefender` CLI for Linux, Windows, and macOS
- Electron installers: `.dmg` / `.zip` (macOS), NSIS `.exe` / `.zip` (Windows),
  AppImage / `.tar.gz` (Linux)

https://github.com/Franzferdinan51/AIDefender/releases

## Quick start

### macOS / Linux

```bash
./install.sh
source .venv/bin/activate
aidefender status
aidefender scan ~/Downloads
```

### Windows (PowerShell)

```powershell
.\install.ps1
.\.venv\Scripts\Activate.ps1
aidefender status
aidefender scan $HOME\Downloads
```

### Manual (any OS)

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .\.venv\Scripts\Activate.ps1
pip install -e .
pip install -e ".[full]"         # optional: psutil + watchdog
python -m aidefender status
```

## Usage

```bash
aidefender scan ./suspect-dir --quarantine
aidefender analyze ./suspect.bin          # local Ollama/LM Studio first, then cloud
aidefender analyze ./suspect.bin --local-url http://127.0.0.1:1234/v1 --model local-model
aidefender protect ~/Downloads ~/Desktop --auto-quarantine
aidefender protect --once
aidefender monitor ~/Downloads ~/Desktop --auto-quarantine
aidefender events -n 20
aidefender quarantine list
aidefender quarantine restore <id> --dest ./restored.bin
aidefender processes
aidefender network
aidefender update                          # pull live definitions (GitHub feed by default)
aidefender --json update --source ./signatures.json
aidefender daemon --interval 3600 --auto-quarantine
aidefender daemon --once
aidefender daemon --seconds 30
aidefender engines
aidefender memory
aidefender service install
aidefender service status
aidefender intrusion
aidefender --json intrusion --no-geo
```

JSON for automation: add `--json` before the subcommand, e.g.
`aidefender --json scan ./dir` or `aidefender --json analyze ./file`.

Local AI defaults to `http://127.0.0.1:11434/v1` (Ollama). Point
`local_ai_base_url` at LM Studio (`http://127.0.0.1:1234/v1`) or any
OpenAI-compatible endpoint. Set `cloud_ai_base_url` plus
`AIDEFENDER_CLOUD_AI_API_KEY` / `OPENAI_API_KEY` for API fallback.
Deterministic `scan` never opens a network connection.

## Safety test (harmless)

AIDefender ships with the standard EICAR test signature (a harmless
industry test string, not malware):

```bash
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt
aidefender scan /tmp/eicar.txt   # expect: MALICIOUS + EICAR
```

## Layout

```text
aidefender/      core package (scanner, heuristics, quarantine, guards, cli)
tests/           stdlib unittest suite + CLI smoke tests
signatures.json  community feed merged by the updater
install.sh       macOS/Linux installer
install.ps1      Windows installer
```

## Honest scope

AIDefender now covers the **user-mode stack** commercial AV actually runs
outside the kernel: always-on login service, on-access file events
(fanotify on Linux; FSEvents / ReadDirectoryChanges elsewhere), live
definitions, PE/ELF injection and packer heuristics, process-image
scanning, and an optional local ClamAV daemon.

It still does **not** ship a signed Windows minifilter, an Apple Endpoint
Security system extension, or AVG's cloud reputation network. Those need
vendor certificates and notarization. Use it **with** Gatekeeper /
XProtect, Windows Defender, or SELinux — not as a silent replacement for
them in high-risk environments.

## License

MIT — see `LICENSE`.
