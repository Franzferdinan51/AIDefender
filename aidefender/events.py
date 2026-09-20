"""JSONL defense event log (user-space RTP)."""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .config import DefenderConfig, get_config


@dataclass
class DefenseEvent:
    kind: str  # file | process | network | burst | persistence | sweep
    severity: str  # info | suspicious | malicious
    message: str
    path: str = ""
    pid: int | None = None
    details: dict = field(default_factory=dict)
    ts: float = 0.0

    def __post_init__(self) -> None:
        if not self.ts:
            self.ts = time.time()

    def to_dict(self) -> dict:
        return asdict(self)


def append_event(event: DefenseEvent, cfg: DefenderConfig | None = None) -> None:
    cfg = cfg or get_config()
    path = Path(cfg.log_file)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
    except OSError:
        return


def load_events(cfg: DefenderConfig | None = None, limit: int = 100) -> list[DefenseEvent]:
    cfg = cfg or get_config()
    path = Path(cfg.log_file)
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    events: list[DefenseEvent] = []
    for line in lines[-max(1, int(limit)) :]:
        try:
            data = json.loads(line)
            events.append(
                DefenseEvent(
                    kind=str(data.get("kind", "")),
                    severity=str(data.get("severity", "info")),
                    message=str(data.get("message", "")),
                    path=str(data.get("path", "")),
                    pid=data.get("pid"),
                    details=data.get("details") or {},
                    ts=float(data.get("ts") or 0),
                )
            )
        except (ValueError, TypeError, KeyError):
            continue
    return events
