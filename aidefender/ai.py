"""Local-first OpenAI-compatible triage over scan artifacts.

Deterministic scan/heuristics/quarantine stay offline. This module is the
only HTTP path for analysis: a configured localhost endpoint (Ollama, LM
Studio, llama.cpp, etc.) is tried before any cloud API. If neither backend
is usable, the result is ``unavailable`` — never an implicit ``clean``.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

from .config import DefenderConfig, get_config
from .scanner import Finding

ALLOWED_VERDICTS = {"clean", "suspicious", "malicious"}

SYSTEM_PROMPT = (
    "You are a malware triage assistant. You receive scan artifacts "
    "(hashes, verdict, heuristic score/reasons/features, and a bounded "
    "text/hex sample) — not a full file. Reply with JSON only, no markdown: "
    '{"verdict":"clean|suspicious|malicious","confidence":0.0,"reasons":["..."]}. '
    "confidence is 0..1. Never downgrade a signature-based malicious finding "
    "or a deterministic DDOS/malicious detector hit to clean."
)

HttpPost = Callable[[str, dict, bytes, float], tuple[int, str]]


class AiUnavailable(Exception):
    """Transport or protocol failure for one backend."""


@dataclass
class AnalysisResult:
    verdict: str  # clean | suspicious | malicious | unavailable
    confidence: float = 0.0
    reasons: list[str] = field(default_factory=list)
    backend: str = "none"  # local | cloud | none
    model: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def completions_url(base_url: str) -> str:
    url = (base_url or "").strip().rstrip("/")
    if not url:
        return ""
    if url.endswith("/chat/completions"):
        return url
    return url + "/chat/completions"


def bounded_sample(path: str | os.PathLike, max_bytes: int) -> tuple[str, str]:
    p = Path(path)
    try:
        with open(p, "rb") as fh:
            data = fh.read(max(0, int(max_bytes)))
    except OSError:
        return "", ""
    text = data.decode("utf-8", errors="replace")
    hex_part = data[: min(len(data), 512)].hex()
    return text, hex_part


def artifacts_from_finding(finding: Finding, cfg: DefenderConfig | None = None) -> dict:
    cfg = cfg or get_config()
    sample_text, sample_hex = "", ""
    p = Path(finding.path)
    if p.is_file():
        sample_text, sample_hex = bounded_sample(p, cfg.ai_sample_bytes)
    return {
        "path": finding.path,
        "sha256": finding.sha256,
        "scan_verdict": finding.verdict,
        "score": finding.score,
        "reasons": list(finding.reasons[:30]),
        "features": dict(finding.features or {}),
        "signature_malicious": bool(finding.signature_hit),
        "sample_text": sample_text,
        "sample_hex": sample_hex,
        "kind": "scan",
    }


def parse_model_json(content: str) -> dict | None:
    if not content or not content.strip():
        return None
    text = content.strip()
    if text.startswith("```"):
        lines = [ln for ln in text.splitlines() if not ln.strip().startswith("```")]
        text = "\n".join(lines)
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end < 0 or end <= start:
        return None
    try:
        data = json.loads(text[start : end + 1])
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    return data


def analysis_from_payload(data: dict, backend: str, model: str) -> AnalysisResult | None:
    verdict = str(data.get("verdict", "")).strip().lower()
    if verdict not in ALLOWED_VERDICTS:
        return None
    try:
        confidence = float(data.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))
    raw_reasons = data.get("reasons", [])
    if isinstance(raw_reasons, str):
        reasons = [raw_reasons] if raw_reasons else []
    elif isinstance(raw_reasons, list):
        reasons = [str(r) for r in raw_reasons if str(r).strip()]
    else:
        reasons = []
    if not reasons:
        reasons = ["model returned no reasons"]
    return AnalysisResult(
        verdict=verdict,
        confidence=confidence,
        reasons=reasons,
        backend=backend,
        model=model,
    )


def lock_signature_verdict(result: AnalysisResult, signature_malicious: bool) -> AnalysisResult:
    if signature_malicious and result.verdict == "clean":
        result.verdict = "malicious"
        result.reasons = list(result.reasons) + [
            "signature finding cannot be downgraded to clean"
        ]
        result.confidence = max(result.confidence, 1.0)
    return result


def lock_deterministic_verdict(result: AnalysisResult, artifacts: dict) -> AnalysisResult:
    result = lock_signature_verdict(result, bool(artifacts.get("signature_malicious")))
    if result.verdict != "clean":
        return result
    det = str(artifacts.get("deterministic_verdict") or artifacts.get("scan_verdict") or "").lower()
    kind = str(artifacts.get("kind") or "").lower()
    category = str(artifacts.get("category") or "").lower()
    if det in ("malicious", "ddos") or kind == "ddos" or category == "ddos":
        result.verdict = "malicious"
        result.reasons = list(result.reasons) + [
            "deterministic malicious/DDOS finding cannot be downgraded to clean"
        ]
        result.confidence = max(result.confidence, 1.0)
    return result


def artifacts_from_attacking_ai(text: str, finding: Finding | None = None) -> dict:
    return {
        "kind": "attacking-ai",
        "sample_text": (text or "")[:2000],
        "scan_verdict": finding.verdict if finding else "suspicious",
        "deterministic_verdict": finding.verdict if finding else "suspicious",
        "reasons": list(finding.reasons[:30]) if finding else [],
        "signature_malicious": bool(finding.signature_hit) if finding else False,
        "score": finding.score if finding else 0,
    }


def artifacts_from_alert(alert) -> dict:
    payload = alert.to_dict() if hasattr(alert, "to_dict") else dict(alert)
    category = str(payload.get("category") or "")
    kind = "ddos" if category == "ddos" else "intrusion"
    det = "ddos" if category == "ddos" else str(payload.get("severity") or "suspicious")
    return {
        "kind": kind,
        "category": category,
        "deterministic_verdict": det,
        "scan_verdict": det,
        "ip": payload.get("ip", ""),
        "reasons": list(payload.get("evidence") or [])[:30],
        "signature_malicious": False,
        "local_port": payload.get("local_port"),
    }


def stdlib_post(url: str, headers: dict, body: bytes, timeout: float) -> tuple[int, str]:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            charset = resp.headers.get_content_charset() or "utf-8"
            return int(resp.status), resp.read().decode(charset, errors="replace")
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")[:300]
        raise AiUnavailable(f"HTTP {exc.code} from {url}: {err_body}") from exc
    except urllib.error.URLError as exc:
        raise AiUnavailable(f"unreachable {url}: {exc.reason}") from exc
    except (TimeoutError, OSError) as exc:
        raise AiUnavailable(f"unreachable {url}: {exc}") from exc


def _chat_complete(
    base_url: str,
    api_key: str,
    model: str,
    artifacts: dict,
    timeout: float,
    poster: HttpPost,
) -> str:
    url = completions_url(base_url)
    if not url:
        raise AiUnavailable("empty base url")
    payload = {
        "model": model or "aidefender",
        "temperature": 0,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(artifacts, ensure_ascii=False)},
        ],
    }
    try:
        from . import __version__ as _pkg_version
    except ImportError:  # pragma: no cover
        _pkg_version = "0.0"
    headers = {
        "Content-Type": "application/json",
        "User-Agent": f"AIDefender/{_pkg_version}",
        "Accept": "application/json",
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    status, text = poster(url, headers, json.dumps(payload).encode("utf-8"), timeout)
    if status < 200 or status >= 300:
        raise AiUnavailable(f"HTTP {status} from {url}")
    try:
        envelope = json.loads(text)
    except ValueError as exc:
        raise AiUnavailable("backend returned non-JSON") from exc
    try:
        return envelope["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise AiUnavailable("backend JSON missing choices[0].message.content") from exc


def _backends(cfg: DefenderConfig) -> list[tuple[str, str, str, str]]:
    """Ordered (name, base_url, api_key, model). Local first; cloud only after."""
    ordered: list[tuple[str, str, str, str]] = []
    if (cfg.local_ai_base_url or "").strip():
        ordered.append(
            (
                "local",
                cfg.local_ai_base_url.strip(),
                cfg.local_ai_api_key or "",
                cfg.local_ai_model or "",
            )
        )
    cloud_url = (cfg.cloud_ai_base_url or "").strip()
    cloud_key = cfg.cloud_ai_api_key or os.environ.get("AIDEFENDER_CLOUD_AI_API_KEY") or os.environ.get("OPENAI_API_KEY") or ""
    if cloud_url:
        ordered.append(("cloud", cloud_url, cloud_key, cfg.cloud_ai_model or ""))
    return ordered


def analyze_artifacts(
    artifacts: dict,
    cfg: DefenderConfig | None = None,
    poster: HttpPost | None = None,
) -> AnalysisResult:
    cfg = cfg or get_config()
    poster = poster or stdlib_post
    timeout = float(cfg.ai_timeout_seconds or 8.0)
    errors: list[str] = []
    signature_hit = bool(artifacts.get("signature_malicious"))

    for name, base_url, api_key, model in _backends(cfg):
        try:
            content = _chat_complete(base_url, api_key, model, artifacts, timeout, poster)
        except AiUnavailable as exc:
            errors.append(f"{name}: {exc}")
            continue
        parsed = parse_model_json(content)
        if not parsed:
            return AnalysisResult(
                verdict="unavailable",
                reasons=["model output was not valid JSON"],
                backend=name,
                model=model,
                error="parse failure",
            )
        result = analysis_from_payload(parsed, name, model)
        if result is None:
            return AnalysisResult(
                verdict="unavailable",
                reasons=["model JSON missing verdict/confidence/reasons"],
                backend=name,
                model=model,
                error="parse failure",
            )
        return lock_deterministic_verdict(result, artifacts)

    if not _backends(cfg):
        reason = "no local or cloud AI backend configured"
    else:
        reason = "no usable AI backend"
    return AnalysisResult(
        verdict="unavailable",
        reasons=[reason],
        backend="none",
        error="; ".join(errors) if errors else reason,
    )


def analyze_finding(
    finding: Finding,
    cfg: DefenderConfig | None = None,
    poster: HttpPost | None = None,
) -> AnalysisResult:
    cfg = cfg or get_config()
    return analyze_artifacts(artifacts_from_finding(finding, cfg), cfg=cfg, poster=poster)


_VERDICT_RANK = {"clean": 0, "skipped": 1, "error": 2, "unavailable": 2, "suspicious": 3, "malicious": 4}


def _is_allowlisted_finding(finding: Finding) -> bool:
    return any(str(r).lower().startswith("allowlisted") for r in finding.reasons)


def merge_ai_into_finding(finding: Finding, result: AnalysisResult) -> Finding:
    """Escalate-only merge. Never downgrade signature/clamd/heuristic-malicious to clean."""
    finding.analysis = result.to_dict()
    if _is_allowlisted_finding(finding):
        return finding
    if result.verdict == "unavailable":
        extra = result.reasons[0] if result.reasons else (result.error or "unavailable")
        finding.reasons.append(f"ai unavailable: {extra}")
        return finding
    if finding.verdict == "malicious" and result.verdict == "clean":
        finding.reasons.append("ai cannot downgrade signature/heuristic malicious to clean")
        return finding
    if finding.signature_hit and result.verdict == "clean":
        finding.reasons.append("ai cannot downgrade signature finding to clean")
        finding.verdict = "malicious"
        return finding
    if result.verdict in ("suspicious", "malicious"):
        if _VERDICT_RANK.get(result.verdict, 0) > _VERDICT_RANK.get(finding.verdict, 0):
            finding.reasons.append(
                f"ai-powered escalate {finding.verdict}->{result.verdict}: "
                + "; ".join(result.reasons[:3])
            )
            finding.verdict = result.verdict
            finding.score = max(finding.score, 40 if result.verdict == "suspicious" else 75)
        else:
            finding.reasons.extend(f"ai: {r}" for r in result.reasons[:3])
    return finding


def attach_ai_to_findings(
    findings: list[Finding],
    cfg: DefenderConfig | None = None,
    poster: HttpPost | None = None,
) -> list[Finding]:
    """Opt-in AI triage after deterministic scan. Skip nested/error/allowlisted."""
    cfg = cfg or get_config()
    from .allowlist import is_file_allowed

    for finding in findings:
        if finding.nested or finding.verdict in ("error", "skipped"):
            continue
        if _is_allowlisted_finding(finding) or is_file_allowed(cfg, finding.path, finding.sha256):
            continue
        try:
            result = analyze_finding(finding, cfg=cfg, poster=poster)
        except Exception as exc:  # noqa: BLE001
            result = AnalysisResult(
                verdict="unavailable",
                reasons=[f"analysis failed: {exc}"],
                backend="none",
                error=str(exc),
            )
        merge_ai_into_finding(finding, result)
    return findings
