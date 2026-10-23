"""Admin WAF sandbox: HTTP probe to nginx /__waf_sandbox/ + audit correlation."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import quote

from app.bastion.modsec_audit_aggregator import (
    CRS_RULE_LABELS,
    resolve_modsec_audit_log_path,
)
from app.bastion.nginx_waf_reality import portal_engine_mode, read_nginx_waf_reality
from app.bastion.waf_reactivation import _PROBE_OPENER, _smoke_host, read_arm_state
from app.bastion.waf_virtual_patches import _PACK_RULE_LABELS
from app.sso_settings import Settings

SANDBOX_PATH_PREFIX = "/__waf_sandbox"
SANDBOX_HEADER = "X-Bastion-Sandbox-Id"
SANDBOX_TIMEOUT_SEC = 8
AUDIT_WAIT_SEC = 2.0
AUDIT_POLL_INTERVAL_SEC = 0.1
MAX_BODY_BYTES = 32_768
MAX_URI_LEN = 512

VALID_METHODS = frozenset({"GET", "POST", "PUT", "HEAD"})
VALID_CONTENT_TYPES = {
    "application/x-www-form-urlencoded": "application/x-www-form-urlencoded",
    "application/json": "application/json",
    "text/plain": "text/plain; charset=utf-8",
}

_DISRUPTIVE = ("deny", "block", "drop", "redirect", "proxy")


def _rule_label(rule_id: str) -> str:
    rid = (rule_id or "").strip()
    if rid in _PACK_RULE_LABELS:
        return _PACK_RULE_LABELS[rid]
    return CRS_RULE_LABELS.get(rid, f"Règle {rid}")


def _is_disruptive_message(msg: dict[str, Any]) -> bool:
    details = msg.get("details") if isinstance(msg.get("details"), dict) else {}
    blob = " ".join(
        str(x)
        for x in (
            msg.get("message"),
            details.get("actions"),
            details.get("action"),
            details.get("data"),
            details.get("match"),
        )
        if x
    ).lower()
    if any(tok in blob for tok in _DISRUPTIVE):
        return True
    if "denied" in blob or "access denied" in blob:
        return True
    # Anomaly score / block rules often carry high severity without "deny" text.
    try:
        sev = int(details.get("severity") or 0)
    except (TypeError, ValueError):
        sev = 0
    rid = str(details.get("ruleId") or details.get("rule_id") or "")
    if sev >= 2 and rid.startswith(("94", "93", "92", "100096")):
        return True
    return False


def _extract_matched_rules(tx: dict[str, Any]) -> list[dict[str, Any]]:
    messages = tx.get("messages") or []
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    if not isinstance(messages, list):
        return out
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        details = msg.get("details") if isinstance(msg.get("details"), dict) else {}
        rid = str(details.get("ruleId") or details.get("rule_id") or "").strip()
        if not rid or rid in seen:
            continue
        seen.add(rid)
        try:
            severity = int(details.get("severity") or 0)
        except (TypeError, ValueError):
            severity = 0
        phase = details.get("phase")
        try:
            phase_i = int(phase) if phase is not None else None
        except (TypeError, ValueError):
            phase_i = None
        disruptive = _is_disruptive_message(msg)
        out.append(
            {
                "id": rid,
                "message": str(msg.get("message") or _rule_label(rid))[:240],
                "label": _rule_label(rid),
                "severity": severity,
                "phase": phase_i,
                "disruptive": disruptive,
                "tags": list(details.get("tags") or [])[:12]
                if isinstance(details.get("tags"), list)
                else [],
            }
        )
    return out


def _header_has_sandbox_id(headers: Any, sandbox_id: str) -> bool:
    if not isinstance(headers, dict):
        return False
    needle = sandbox_id.lower()
    for key, val in headers.items():
        if str(key).lower() != "x-bastion-sandbox-id":
            continue
        raw = val[0] if isinstance(val, list) and val else str(val)
        if needle in str(raw).lower():
            return True
    return False


def _tx_matches_sandbox(data: dict[str, Any], sandbox_id: str) -> bool:
    tx = data.get("transaction") if isinstance(data.get("transaction"), dict) else {}
    req = tx.get("request") if isinstance(tx.get("request"), dict) else {}
    headers = req.get("headers")
    if _header_has_sandbox_id(headers, sandbox_id):
        return True
    # Some serializers flatten request headers differently.
    blob = json.dumps(data, ensure_ascii=False)
    return sandbox_id in blob


def find_sandbox_audit_event(
    log_path: Path,
    sandbox_id: str,
    *,
    wait_sec: float = AUDIT_WAIT_SEC,
) -> dict[str, Any] | None:
    """Poll the shared audit log for a JSON line containing the sandbox id."""
    deadline = time.monotonic() + max(0.2, float(wait_sec))
    best: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        if log_path.is_file():
            try:
                # Read tail only (last ~256 KiB) for responsiveness under load.
                with log_path.open("rb") as fh:
                    fh.seek(0, 2)
                    size = fh.tell()
                    fh.seek(max(0, size - 262_144))
                    chunk = fh.read().decode("utf-8", errors="replace")
            except OSError:
                chunk = ""
            for line in reversed(chunk.splitlines()):
                line = line.strip()
                if not line.startswith("{") or sandbox_id not in line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(data, dict) and _tx_matches_sandbox(data, sandbox_id):
                    return data
                if isinstance(data, dict):
                    best = data
        time.sleep(AUDIT_POLL_INTERVAL_SEC)
    return best


def normalize_sandbox_uri(uri: str) -> str:
    raw = (uri or "").strip() or "/"
    if not raw.startswith("/"):
        raw = "/" + raw
    if raw.startswith(SANDBOX_PATH_PREFIX):
        raise ValueError("URI ne doit pas commencer par /__waf_sandbox")
    if len(raw) > MAX_URI_LEN:
        raise ValueError(f"URI trop longue (max {MAX_URI_LEN})")
    if "://" in raw or "\\" in raw or ".." in raw.split("/"):
        raise ValueError("URI invalide")
    return raw


def build_sandbox_readiness(
    settings: Settings,
    *,
    active: dict[str, Any] | None = None,
    audit_health: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Warn when audit/engine will not produce useful sandbox results."""
    active = active if active is not None else read_nginx_waf_reality(settings=settings)
    arm = read_arm_state(settings)
    portal_mode = portal_engine_mode(active) if active.get("verifiable") else None
    log_path = resolve_modsec_audit_log_path(settings)
    log_ok = log_path.is_file()
    warnings: list[str] = []
    if not log_ok:
        warnings.append(
            "Journal modsec_audit.log absent — la sonde ne pourra pas corréler les règles."
        )
    if portal_mode == "off" and not arm.get("armed"):
        warnings.append(
            "Moteur portal désarmé (Off). La sandbox force DetectionOnly sur "
            "/__waf_sandbox/, mais un moteur global Off / connecteur off peut "
            "réduire la couverture. Réactiver le WAF pour un test représentatif."
        )
    if audit_health is None:
        try:
            from app.bastion.waf_virtual_patches import build_audit_health

            audit_health = build_audit_health(settings)
        except Exception:  # noqa: BLE001 — readiness must stay best-effort
            audit_health = None
    if isinstance(audit_health, dict):
        level = str(audit_health.get("level") or "")
        if level in ("red", "orange"):
            label = str(audit_health.get("label") or "Audit dégradé")
            detail = str(audit_health.get("detail") or "").strip()
            warnings.append(
                f"Audit WAF dégradé ({label})"
                + (f" — {detail}" if detail else "")
                + ". Le dry-run peut être inconclusive."
            )
    return {
        "log_present": log_ok,
        "log_path": str(log_path),
        "portal_mode": portal_mode,
        "armed": bool(arm.get("armed")),
        "warnings": warnings,
        "usable": True,  # location forces DetectionOnly + modsecurity on
    }


def run_waf_sandbox(
    settings: Settings,
    *,
    method: str,
    uri: str,
    body: str = "",
    content_type: str = "application/x-www-form-urlencoded",
    extra_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Forge an internal probe and correlate ModSecurity audit messages."""
    method_u = (method or "GET").strip().upper()
    if method_u not in VALID_METHODS:
        raise ValueError(f"méthode non supportée: {method}")
    path = normalize_sandbox_uri(uri)
    ct_key = (content_type or "").strip().lower()
    if ct_key not in VALID_CONTENT_TYPES:
        raise ValueError(
            "content_type invalide (urlencoded | json | text/plain)"
        )
    body_raw = body or ""
    if method_u in ("GET", "HEAD"):
        body_raw = ""  # ignore leftover textarea when switching method in the UI
    body_b = body_raw.encode("utf-8")
    if len(body_b) > MAX_BODY_BYTES:
        raise ValueError(f"corps trop volumineux (max {MAX_BODY_BYTES} octets)")

    readiness = build_sandbox_readiness(settings)
    sandbox_id = str(uuid.uuid4())
    host = _smoke_host(settings)
    # Encode path segments safely but keep slashes.
    encoded = quote(path, safe="/?=&#")
    url = f"http://nginx:8080{SANDBOX_PATH_PREFIX}{encoded}"

    headers = {
        "Host": host,
        SANDBOX_HEADER: sandbox_id,
        "User-Agent": "BastionWafSandbox/1.0",
        "Accept": "*/*",
    }
    if body_b:
        headers["Content-Type"] = VALID_CONTENT_TYPES[ct_key]
        headers["Content-Length"] = str(len(body_b))
    for key, val in (extra_headers or {}).items():
        lk = key.lower()
        if lk in ("host", "content-length", SANDBOX_HEADER.lower()):
            continue
        if len(key) > 64 or len(val) > 512:
            continue
        headers[key] = val

    probe: dict[str, Any] = {
        "ok": False,
        "status": None,
        "error": None,
        "url": url,
    }
    req = urllib.request.Request(
        url, data=body_b or None, headers=headers, method=method_u
    )
    try:
        with _PROBE_OPENER.open(req, timeout=SANDBOX_TIMEOUT_SEC) as resp:
            probe["status"] = int(resp.status)
            probe["ok"] = int(resp.status) in (200, 204)
            resp.read(1024)
    except urllib.error.HTTPError as exc:
        probe["status"] = int(exc.code)
        probe["ok"] = int(exc.code) in (200, 204)
        probe["error"] = f"HTTP {exc.code}"
    except Exception as exc:  # noqa: BLE001 — never raise to admin UI
        probe["error"] = str(exc)[:200]

    log_path = resolve_modsec_audit_log_path(settings)
    event = find_sandbox_audit_event(log_path, sandbox_id, wait_sec=AUDIT_WAIT_SEC)
    matched: list[dict[str, Any]] = []
    blocked_intent = False
    audit_found = False
    if event:
        audit_found = True
        tx = event.get("transaction") if isinstance(event.get("transaction"), dict) else {}
        matched = _extract_matched_rules(tx)
        blocked_intent = any(r.get("disruptive") for r in matched)

    return {
        "sandbox_id": sandbox_id,
        "method": method_u,
        "uri": path,
        "content_type": ct_key,
        "probe": probe,
        "audit_found": audit_found,
        "blocked_intent": blocked_intent,
        "matched_rules": matched,
        "readiness": readiness,
        "verdict": (
            "blocked"
            if blocked_intent
            else ("clean" if audit_found or probe.get("ok") else "inconclusive")
        ),
    }
