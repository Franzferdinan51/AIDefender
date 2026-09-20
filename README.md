# AIDefender — AI-assisted full defense suite

Cross-platform defender for **macOS, Linux, and Windows**: file scanning,
explainable AI-style heuristics, quarantine, real-time folder protection,
process + network guards, signature updates, and a background daemon.

No kernel drivers. No heavy ML dependencies. Everything runs on the
standard library by default; `psutil` + `watchdog` unlock full power.

## Features

- **Scanner**: SHA-256 signatures + portable string rules + heuristic score (0–100)
- **AI heuristics**: entropy, extension/content mismatch, double-extension,
  suspicious keywords, curl|sh droppers — every point explained
- **Quarantine**: isolate / list / restore / delete with metadata
- **Real-time monitor**: `watchdog` when installed, portable polling fallback
- **Process guard**: `psutil` → `ps` → `tasklist` fallback chain
- **Network guard**: risky ports/IPs and Tor-tunnel hints
- **Updater**: fetch merged `signatures.json` from URL or file
- **Daemon**: periodic sweeps for scheduled protection
- **CLI**: human + `--json` output, exit code 1 on threats

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
aidefender monitor ~/Downloads ~/Desktop
aidefender quarantine list
aidefender quarantine restore <id> --dest ./restored.bin
aidefender processes
aidefender network
aidefender update
aidefender daemon --interval 3600 --auto-quarantine
aidefender daemon --once
```

JSON for automation: add `--json` before the subcommand, e.g.
`aidefender --json scan ./dir`.

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

AIDefender is a high-quality user-space defense layer: great for downloads,
repos, shared folders, and scheduled sweeps. It is **not** a kernel
antivirus replacement and does not replace OS protections (Gatekeeper /
XProtect, Defender, SELinux), backups, patching, or a commercial EDR for
high-risk environments.

## License

MIT — see `LICENSE`.
