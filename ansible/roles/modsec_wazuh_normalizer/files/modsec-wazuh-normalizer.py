#!/usr/bin/env python3
"""ModSecurity JSON audit → Wazuh NDJSON (one event per CRS rule match).

Host-side tailer for Bastion: reads modsec_audit.log (Docker volume), writes
modsec_wazuh.jsonl. Aligned with bastion-app aggregator semantics (families,
loopback Host filter). No secrets / cookies / body / Matched Data values.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import signal
import sys
import time
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

INTEGRATION = "bastion_modsecurity"
EVENT_DETECTION = ("BST-WAF-1001", "MODSECURITY_DETECTION", "detected")
EVENT_BLOCKED = ("BST-WAF-2001", "MODSECURITY_REQUEST_BLOCKED", "blocked")

REDACT = "[REDACTED]"
SENSITIVE_KEYS = re.compile(
    r"(?i)\b("
    r"password|passwd|pwd|token|access_token|refresh_token|"
    r"authorization|proxy-authorization|cookie|set-cookie|"
    r"session|sessionid|api[_-]?key|csrf|xsrf"
    r")\b"
)
MATCHED_DATA_RE = re.compile(r"(?i)Matched Data:\s*.+")
DISRUPTIVE_RE = re.compile(
    r"(?i)\b(denied|blocked|disrupt(?:ive)?|intercept(?:ed)?)\b"
)

_STOP = False


def _request_stop(signum: int, _frame: Any) -> None:
    global _STOP
    _STOP = True
    logging.info("signal %s — stopping", signum)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return float(raw)


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return int(raw)


def host_without_port(host: str) -> str:
    text = (host or "").strip().lower()
    if not text:
        return ""
    if text.count(":") == 1 and not text.startswith("["):
        return text.split(":", 1)[0]
    if text.startswith("[") and "]" in text:
        return text[1 : text.index("]")]
    return text


def is_loopback_host(host: str) -> bool:
    return host_without_port(host) in {"127.0.0.1", "::1", "localhost"}


def rule_family(rule_id: str) -> str:
    rid = str(rule_id).strip()
    if rid == "949110":
        return "anomaly_score_block"
    if not rid.isdigit():
        return "other"
    prefix = rid[:3]
    if prefix == "942":
        return "sqli"
    if prefix == "941":
        return "xss"
    if prefix in ("932", "933"):
        return "rce"
    if prefix == "930":
        return "lfi"
    if prefix == "913":
        return "scanner"
    if prefix == "920":
        return "protocol"
    return "other"


def redact_text(value: str, *, max_len: int) -> str:
    if not value:
        return ""
    text = MATCHED_DATA_RE.sub(f"Matched Data: {REDACT}", str(value))
    # key=value / key: value patterns for sensitive names
    text = re.sub(
        r"(?i)([\"']?(?:password|passwd|pwd|token|access_token|refresh_token|"
        r"authorization|cookie|session(?:id)?|api[_-]?key|csrf)[\"']?\s*[:=]\s*)"
        r"([^\s&;,\"']+)",
        rf"\1{REDACT}",
        text,
    )
    if SENSITIVE_KEYS.search(text) and "=" in text:
        # belt-and-suspenders for remaining sensitive tokens in query-like strings
        parts = []
        for chunk in re.split(r"([&;])", text):
            if SENSITIVE_KEYS.search(chunk) and ("=" in chunk or ":" in chunk):
                sep = "=" if "=" in chunk else ":"
                k, _, _ = chunk.partition(sep)
                parts.append(f"{k}{sep}{REDACT}")
            else:
                parts.append(chunk)
        text = "".join(parts)
    if len(text) > max_len:
        text = text[: max_len - 1] + "…"
    return text


def uri_path_only(uri: str) -> str:
    raw = (uri or "").strip() or "/"
    try:
        path = urlsplit(raw).path or "/"
    except ValueError:
        path = raw.split("?", 1)[0].split("#", 1)[0] or "/"
    return path[:2048]


def header_host(headers: Any) -> str:
    if not isinstance(headers, dict):
        return ""
    for key, val in headers.items():
        if str(key).lower() == "host":
            if isinstance(val, list) and val:
                return str(val[0]).strip()
            return str(val).strip()
    return ""


def extract_messages(tx: dict[str, Any], root: dict[str, Any]) -> list[dict[str, Any]]:
    for candidate in (tx.get("messages"), root.get("messages")):
        if isinstance(candidate, list):
            return [m for m in candidate if isinstance(m, dict)]
    return []


def message_rule_id(msg: dict[str, Any]) -> str:
    details = msg.get("details") if isinstance(msg.get("details"), dict) else {}
    rid = details.get("ruleId") or details.get("rule_id") or msg.get("ruleId")
    return str(rid).strip() if rid is not None else ""


def message_details(msg: dict[str, Any]) -> dict[str, Any]:
    details = msg.get("details")
    return details if isinstance(details, dict) else {}


def is_blocked(
    *,
    http_code: int | None,
    messages: list[dict[str, Any]],
    msg: dict[str, Any],
) -> bool:
    if http_code in (403, 406):
        return True
    details = message_details(msg)
    blobs = [
        str(msg.get("message") or ""),
        str(details.get("file") or ""),
        str(details.get("data") or ""),
        json.dumps(details, ensure_ascii=False) if details else "",
    ]
    for other in messages:
        blobs.append(str(other.get("message") or ""))
    joined = " ".join(blobs)
    return bool(DISRUPTIVE_RE.search(joined))


def parse_timestamp(raw: str | None) -> str:
    if not raw:
        return datetime.now(timezone.utc).isoformat()
    text = str(raw).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return datetime.now(timezone.utc).isoformat()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def normalize_events(
    payload: dict[str, Any],
    *,
    max_string: int,
    max_tags: int,
    exclude_loopback: bool,
) -> list[dict[str, Any]]:
    tx = payload.get("transaction")
    if not isinstance(tx, dict):
        tx = {}
    req = tx.get("request") if isinstance(tx.get("request"), dict) else {}
    resp = tx.get("response") if isinstance(tx.get("response"), dict) else {}
    producer = tx.get("producer") if isinstance(tx.get("producer"), dict) else {}

    host = header_host(req.get("headers"))
    if exclude_loopback and is_loopback_host(host):
        return []

    messages = extract_messages(tx, payload)
    if not messages:
        return []

    try:
        http_code = int(resp.get("http_code")) if resp.get("http_code") is not None else None
    except (TypeError, ValueError):
        http_code = None

    engine_mode = str(
        producer.get("secrules_engine")
        or producer.get("modsecurity")
        or os.environ.get("MODSEC_ENGINE_MODE")
        or ""
    ).strip()
    detection_only = "detectiononly" in engine_mode.lower()

    client_ip = str(tx.get("client_ip") or tx.get("remote_address") or "").strip()
    client_port = tx.get("client_port")
    try:
        client_port_i = int(client_port) if client_port is not None else None
    except (TypeError, ValueError):
        client_port_i = None

    txn_id = str(
        tx.get("unique_id") or tx.get("transaction_id") or tx.get("id") or ""
    ).strip()
    method = str(req.get("method") or "").strip().upper()
    uri = uri_path_only(str(req.get("uri") or "/"))
    event_time = parse_timestamp(tx.get("time_stamp") or tx.get("timestamp"))

    out: list[dict[str, Any]] = []
    for msg in messages:
        rid = message_rule_id(msg)
        if not rid:
            continue
        details = message_details(msg)
        blocked = is_blocked(http_code=http_code, messages=messages, msg=msg)
        code, name, outcome = EVENT_BLOCKED if blocked else EVENT_DETECTION

        tags_raw = details.get("tags") or msg.get("tags") or []
        tags: list[str] = []
        if isinstance(tags_raw, list):
            for t in tags_raw[:max_tags]:
                tags.append(redact_text(str(t), max_len=128))
        elif tags_raw:
            tags.append(redact_text(str(tags_raw), max_len=128))

        rule_message = redact_text(str(msg.get("message") or ""), max_len=max_string)
        fam = rule_family(rid)
        dedup_src = f"{txn_id}|{rid}|{client_ip}|{host}|{method}|{uri}|{outcome}"
        dedup_key = hashlib.sha256(dedup_src.encode("utf-8")).hexdigest()[:32]

        out.append(
            {
                "integration": INTEGRATION,
                "event_code": code,
                "event_name": name,
                "event_time": event_time,
                "outcome": outcome,
                "severity": _severity(details, blocked),
                "engine_mode": engine_mode or "unknown",
                "transaction_id": txn_id,
                "client_ip": client_ip,
                "client_port": client_port_i,
                "host": host.lower() if host else "",
                "method": method,
                "uri_path": uri,
                "http_code": http_code,
                "rule_id": rid,
                "rule_family": fam,
                "rule_message": rule_message,
                "rule_severity": _as_int(details.get("severity")),
                "rule_phase": _as_int(details.get("phase") or msg.get("phase")),
                "rule_file": redact_text(str(details.get("file") or ""), max_len=256),
                "rule_line": _as_int(details.get("line")),
                "rule_version": str(details.get("ver") or details.get("version") or ""),
                "tags": tags,
                "tags_text": ",".join(tags),
                "blocked": blocked,
                "detection_only": detection_only,
                "dedup_key": dedup_key,
            }
        )
    return out


def _as_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None and value != "" else None
    except (TypeError, ValueError):
        return None


def _severity(details: dict[str, Any], blocked: bool) -> str:
    sev = _as_int(details.get("severity"))
    if blocked:
        return "high"
    if sev is not None and sev >= 3:
        return "medium"
    return "low"


class Deduper:
    def __init__(self, *, max_items: int, ttl_seconds: int) -> None:
        self.max_items = max(1, max_items)
        self.ttl = max(1, ttl_seconds)
        self._items: OrderedDict[str, float] = OrderedDict()

    def seen(self, key: str, now: float) -> bool:
        self._purge(now)
        if key in self._items:
            self._items.move_to_end(key)
            self._items[key] = now
            return True
        self._items[key] = now
        while len(self._items) > self.max_items:
            self._items.popitem(last=False)
        return False

    def _purge(self, now: float) -> None:
        cutoff = now - self.ttl
        dead = [k for k, ts in self._items.items() if ts < cutoff]
        for k in dead:
            self._items.pop(k, None)


class State:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.inode: int | None = None
        self.offset: int = 0
        self.initialized: bool = False

    def load(self) -> None:
        if not self.path.is_file():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(data, dict):
            return
        self.inode = data.get("inode")
        self.offset = int(data.get("offset") or 0)
        self.initialized = bool(data.get("initialized"))

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        payload = {
            "inode": self.inode,
            "offset": self.offset,
            "initialized": self.initialized,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        tmp.replace(self.path)


def process_line(
    line: str,
    *,
    max_string: int,
    max_tags: int,
    exclude_loopback: bool,
    deduper: Deduper,
) -> list[dict[str, Any]]:
    line = line.strip()
    if not line or not line.startswith("{"):
        return []
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        logging.debug("skip non-json line")
        return []
    if not isinstance(payload, dict):
        return []
    events = normalize_events(
        payload,
        max_string=max_string,
        max_tags=max_tags,
        exclude_loopback=exclude_loopback,
    )
    now = time.time()
    kept = []
    for ev in events:
        if deduper.seen(str(ev["dedup_key"]), now):
            continue
        kept.append(ev)
    return kept


def run_once_file(
    source: Path,
    output: Path,
    state: State,
    *,
    start_at_end: bool,
    max_string: int,
    max_tags: int,
    exclude_loopback: bool,
    deduper: Deduper,
) -> int:
    """Read new bytes from source; return number of events written."""
    if not source.is_file():
        return 0
    st = source.stat()
    inode = int(getattr(st, "st_ino", 0) or 0)
    size = int(st.st_size)

    if state.inode is None or state.inode != inode or size < state.offset:
        # New file / rotation / truncate
        if start_at_end and not state.initialized:
            state.offset = size
            state.inode = inode
            state.initialized = True
            state.save()
            logging.info("first start: seek end offset=%s (no replay)", size)
            return 0
        state.offset = 0
        state.inode = inode

    written = 0
    with source.open("rb") as fh:
        fh.seek(state.offset)
        chunk = fh.read()
        new_offset = fh.tell()
    text = chunk.decode("utf-8", errors="replace")
    if not text:
        state.offset = new_offset
        state.inode = inode
        state.initialized = True
        state.save()
        return 0

    lines = text.splitlines()
    # Keep incomplete trailing line for next read by not advancing past last \n
    if not text.endswith("\n"):
        incomplete = lines.pop() if lines else ""
        new_offset -= len(incomplete.encode("utf-8", errors="replace"))

    if lines:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("a", encoding="utf-8") as out_fh:
            for line in lines:
                for ev in process_line(
                    line,
                    max_string=max_string,
                    max_tags=max_tags,
                    exclude_loopback=exclude_loopback,
                    deduper=deduper,
                ):
                    out_fh.write(json.dumps(ev, ensure_ascii=False, separators=(",", ":")) + "\n")
                    written += 1

    state.offset = new_offset
    state.inode = inode
    state.initialized = True
    state.save()
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true", help="Single pass then exit")
    parser.add_argument("--source", default=os.environ.get("MODSEC_WAZUH_SOURCE", ""))
    parser.add_argument("--output", default=os.environ.get("MODSEC_WAZUH_OUTPUT", ""))
    parser.add_argument("--state", default=os.environ.get("MODSEC_WAZUH_STATE", ""))
    args = parser.parse_args(argv)

    source = Path(args.source or "/tools/portal/data/nginx-logs/modsec_audit.log")
    output = Path(args.output or "/tools/portal/data/nginx-logs/modsec_wazuh.jsonl")
    state_path = Path(
        args.state or "/tools/portal/data/modsec-wazuh-normalizer-state.json"
    )

    level = getattr(
        logging, os.environ.get("MODSEC_WAZUH_LOG_LEVEL", "INFO").upper(), logging.INFO
    )
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s modsec-wazuh-normalizer: %(message)s",
    )

    start_at_end = _env_bool("MODSEC_WAZUH_START_AT_END", True)
    poll = _env_float("MODSEC_WAZUH_POLL_SECONDS", 0.5)
    max_string = _env_int("MODSEC_WAZUH_MAX_STRING", 1024)
    max_tags = _env_int("MODSEC_WAZUH_MAX_TAGS", 32)
    exclude_loopback = _env_bool("MODSEC_WAZUH_EXCLUDE_LOOPBACK", True)
    deduper = Deduper(
        max_items=_env_int("MODSEC_WAZUH_DEDUP_MAX", 10000),
        ttl_seconds=_env_int("MODSEC_WAZUH_DEDUP_SECONDS", 3600),
    )

    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)

    state = State(state_path)
    state.load()
    logging.info(
        "watching source=%s output=%s start_at_end=%s",
        source,
        output,
        start_at_end,
    )

    while not _STOP:
        try:
            n = run_once_file(
                source,
                output,
                state,
                start_at_end=start_at_end,
                max_string=max_string,
                max_tags=max_tags,
                exclude_loopback=exclude_loopback,
                deduper=deduper,
            )
            if n:
                logging.debug("wrote %s events", n)
        except Exception:
            logging.exception("normalize cycle failed")
        if args.once:
            break
        time.sleep(max(0.1, poll))
    return 0


if __name__ == "__main__":
    sys.exit(main())
