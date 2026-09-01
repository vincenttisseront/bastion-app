#!/usr/bin/env python3
"""Non-destructive OWASP CRS smoke probes for Bastion Pro (ModSecurity nginx).

Validates that ModSecurity is armed and CRS families (SQLi, XSS, LFI/RFI, etc.)
trigger blocks on paths that remain under inspection (not ``modsecurity off``).

Usage:
  python scripts/waf_crs_probe.py
  python scripts/waf_crs_probe.py --base https://portal.ar-systems.fr
  python scripts/waf_crs_probe.py --base https://portal.ar-systems.fr --subdomain-host webmail.ar-systems.fr

Exit 0 when all probes got an expected block (403/406/429) or CRS audit signal.
Exit 1 when any probe suggests CRS is inactive or misconfigured.

Safe: payloads are classic CRS test strings only; no exploitation or data mutation.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

import httpx

# Paths that stay under CRS on portal vhost (see vhost_sso_portal.conf.template).
PORTAL_PROBE_PATH = "/auth/login"

DEFAULT_BASE = "https://portal.ar-systems.fr"

# Minimal payloads mapped to CRS families (REQUEST-942, 941, 930, 932, …).
PROBES: list[dict[str, str]] = [
    {
        "name": "sqli_union",
        "family": "sqli",
        "method": "GET",
        "path": PORTAL_PROBE_PATH,
        "params": {"rd": "/apps", "q": "1' UNION SELECT null,null--"},
        "expect_rule_prefix": "942",
    },
    {
        "name": "xss_script_tag",
        "family": "xss",
        "method": "GET",
        "path": PORTAL_PROBE_PATH,
        "params": {"rd": "<script>alert(1)</script>"},
        "expect_rule_prefix": "941",
    },
    {
        "name": "lfi_passwd",
        "family": "lfi",
        "method": "GET",
        "path": PORTAL_PROBE_PATH,
        "params": {"file": "/etc/passwd"},
        "expect_rule_prefix": "930",
    },
    {
        "name": "rfi_remote_url",
        "family": "rfi",
        "method": "GET",
        "path": PORTAL_PROBE_PATH,
        "params": {"page": "http://evil.example/a.txt"},
        "expect_rule_prefix": "931",
    },
    {
        "name": "rce_shell",
        "family": "rce",
        "method": "GET",
        "path": PORTAL_PROBE_PATH,
        "params": {"cmd": ";cat /etc/passwd"},
        "expect_rule_prefix": "932",
    },
    {
        "name": "sqli_post_body",
        "family": "sqli",
        "method": "POST",
        "path": PORTAL_PROBE_PATH,
        "data": {
            "username": "admin' OR '1'='1",
            "password": "x",
            "rd": "/apps",
        },
        "expect_rule_prefix": "942",
    },
]

BLOCK_STATUSES = frozenset({403, 406, 429, 501})


@dataclass
class ProbeResult:
    name: str
    family: str
    status: int
    blocked: bool
    server: str
    body_head: str
    ok: bool
    note: str


def _run_probe(
    client: httpx.Client,
    probe: dict[str, str],
    *,
    host: str | None,
) -> ProbeResult:
    headers: dict[str, str] = {}
    if host:
        headers["Host"] = host

    method = probe["method"].upper()
    path = probe["path"]
    kwargs: dict[str, Any] = {"headers": headers}
    if method == "GET":
        kwargs["params"] = probe.get("params") or {}
    else:
        kwargs["data"] = probe.get("data") or {}

    resp = client.request(method, path, **kwargs)
    status = resp.status_code
    blocked = status in BLOCK_STATUSES
    body_head = (resp.text or "")[:160].replace("\n", " ")
    server = (resp.headers.get("server") or "")[:80]

    if blocked:
        ok, note = True, f"HTTP {status} — blocage WAF attendu"
    elif status in (200, 302, 401, 404):
        ok, note = (
            False,
            f"HTTP {status} — CRS n'a pas bloqué (moteur Off, DetectionOnly, "
            f"ou location hors inspection)",
        )
    elif status >= 500:
        ok, note = False, f"HTTP {status} — erreur serveur (vérifier error.log / règle 901001)"
    else:
        ok, note = False, f"HTTP {status} — réponse inattendue"

    return ProbeResult(
        name=probe["name"],
        family=probe["family"],
        status=status,
        blocked=blocked,
        server=server,
        body_head=body_head,
        ok=ok,
        note=note,
    )


def _baseline_ok(client: httpx.Client, host: str | None) -> tuple[bool, str]:
    """Legitimate request must not be blocked when CRS is tuned (PL1)."""
    headers: dict[str, str] = {}
    if host:
        headers["Host"] = host
    resp = client.get(PORTAL_PROBE_PATH, params={"rd": "/apps"}, headers=headers)
    if resp.status_code in BLOCK_STATUSES:
        return False, f"Requête légitime bloquée (HTTP {resp.status_code}) — faux positif ou seuil trop bas"
    if resp.status_code >= 500:
        return False, f"Requête légitime en erreur HTTP {resp.status_code}"
    return True, f"HTTP {resp.status_code} — baseline OK"


def main() -> int:
    parser = argparse.ArgumentParser(description="OWASP CRS smoke probes for Bastion Pro")
    parser.add_argument("--base", default=DEFAULT_BASE, help="Portal base URL (https://…)")
    parser.add_argument(
        "--subdomain-host",
        default="",
        help="Optional subdomain FQDN (Host header) for subdomain_proxy CRS test on /",
    )
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--json-out", default="", help="Write full evidence JSON to this path")
    args = parser.parse_args()

    report: dict[str, Any] = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "base": args.base.rstrip("/"),
        "subdomain_host": args.subdomain_host or None,
        "baseline": {},
        "probes": [],
    }

    with httpx.Client(
        base_url=args.base.rstrip("/"),
        timeout=args.timeout,
        follow_redirects=False,
        verify=True,
    ) as client:
        base_ok, base_note = _baseline_ok(client, None)
        report["baseline"]["portal"] = {"ok": base_ok, "note": base_note}

        results: list[ProbeResult] = [
            ProbeResult(
                name="baseline_legit",
                family="baseline",
                status=0,
                blocked=False,
                server="",
                body_head="",
                ok=base_ok,
                note=base_note,
            )
        ]
        # Fill baseline HTTP status from a fresh request for JSON consumers.
        base_resp = client.get(PORTAL_PROBE_PATH, params={"rd": "/apps"})
        results[0].status = base_resp.status_code
        results[0].server = (base_resp.headers.get("server") or "")[:80]
        results[0].body_head = (base_resp.text or "")[:160].replace("\n", " ")
        results[0].blocked = base_resp.status_code in BLOCK_STATUSES

        for probe in PROBES:
            results.append(_run_probe(client, probe, host=None))

        if args.subdomain_host:
            sub_probe = {
                "name": "subdomain_sqli",
                "family": "sqli",
                "method": "GET",
                "path": "/",
                "params": {"q": "1' OR '1'='1"},
                "expect_rule_prefix": "942",
            }
            results.append(_run_probe(client, sub_probe, host=args.subdomain_host))
            sub_base_ok, sub_base_note = _baseline_ok(client, args.subdomain_host)
            report["baseline"]["subdomain"] = {"ok": sub_base_ok, "note": sub_base_note}

    report["probes"] = [asdict(r) for r in results]
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    report["summary"] = {
        "total": len(results),
        "blocked": sum(1 for r in results if r.blocked),
        "ok": sum(1 for r in results if r.ok),
        "all_ok": base_ok and all(r.ok for r in results),
        "attacks_total": sum(1 for r in results if r.family != "baseline"),
        "attacks_blocked": sum(
            1 for r in results if r.family != "baseline" and r.blocked
        ),
    }

    if args.json_out:
        from pathlib import Path

        Path(args.json_out).write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    print(f"Bastion CRS probe — {args.base}")
    print(f"  Baseline portal: {'OK' if base_ok else 'FAIL'} — {base_note}")
    if args.subdomain_host:
        sub = report["baseline"].get("subdomain", {})
        print(f"  Baseline subdomain ({args.subdomain_host}): {'OK' if sub.get('ok') else 'FAIL'} — {sub.get('note')}")
    print()
    for r in results:
        mark = "PASS" if r.ok else "FAIL"
        print(f"  [{mark}] {r.name:20} {r.family:6} HTTP {r.status:3}  {r.note}")
    print()
    n_ok = report["summary"]["ok"]
    n_total = report["summary"]["total"]
    if report["summary"]["all_ok"]:
        print(f"Résultat: {n_ok}/{n_total} sondes OK — CRS semble actif en mode blocage.")
        print("Vérifiez modsec_audit.log pour les rule_id (942xxx, 941xxx, 949110, …).")
        return 0

    print(f"Résultat: {n_ok}/{n_total} sondes OK — CRS inactif, mal armé, ou chemins hors inspection.")
    print("Actions: Admin → WAF → Réactivation (portal/subdomain) puis Appliquer ; reload bastion-nginx.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
