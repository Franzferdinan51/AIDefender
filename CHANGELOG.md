# Changelog

All notable changes to AIDefender. Versions below 1.0.0 may change the CLI
surface; JSON shapes are additive-only within a minor series.

## [0.11.0] - 2026-09-21

Added:

- `ai status|use|test`: discover LM Studio / Ollama / custom OpenAI-compatible
  backends, list loaded models (HTTP probe plus `lms` enrichment), persist the
  operator's choice, and run a chat roundtrip to prove the connection.
- `config get|set`: view (redacted) and change 26 validated settings with type
  coercion and clamping. `*api_key` is rejected — keys stay in env vars.
- Config hardening: wrong-typed `config.json` values are repaired on load,
  thresholds clamped to 0–100, timeouts and counters bounded.
- Desktop UI **Settings** tab: Security-AI backend detect/use/test plus a
  defense-settings editor over the same `--json` CLI.
- Agent catalog entries for `ai-*` and `config-*`.
- This changelog. Renderer harness now runs in CI.

Fixed:

- HTTP `User-Agent` now reports the real package version (was pinned to 0.4).

## [0.10.0] - 2026-09-20

Added DDOS flood detection (many-source / SYN_RECV), broader counter-AI with
normalized paraphrases, local-first assist over scan/attacking-AI/DDOS
artifacts, and a rewritten README with honest scope.

## [0.9.0] - 2026-09-20

Added agent/operator toolkit (`allow`, `block`, `diag`, `capture`, `inspect`,
`act`, `tools`), rogue-AI defenses (prompt injection, LLM exfil, agent APIs),
and matching desktop UI tabs. Default installs made production-safe
(opt-in firewall).

## [0.7.0] - 2026-09-20

Added intrusion detection with IP geo intel and auto-block, live malware
definitions feed, user-space real-time protection (`protect`), nested archive
scanning, local-first AI triage (`analyze`), and the Electron desktop UI with
GitHub Release binaries.

## [0.1.0] - 2026-09-20

Initial release: cross-platform scanner (signatures + explainable heuristics),
quarantine, polling/watchdog monitor, process and network guards, updater,
daemon, and CLI for macOS, Linux, and Windows.
