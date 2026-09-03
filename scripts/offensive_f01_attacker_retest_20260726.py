"""Attacker-POV F-01 retest 2026-07-26 — wrong password only, no break-glass account.

Périmètre A (Vincent) : pas de compte break-glass, pas de bon mot de passe.
Run: python scripts/offensive_f01_attacker_retest_20260726.py
"""

from __future__ import annotations

import json
import os
import socket
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx

BASE = "https://portal.ar-systems.fr"
EXPECTED_IP = os.environ.get("BASTION_SECURITY_EXPECTED_IP", "172.24.0.110")
OUT = (
    Path(__file__).resolve().parents[1]
    / "rapport-audit-securite-bastion-offensif-addendum-2026-07-26-evidence.json"
)

# Jetable inventé — n'existe pas ; volontairement mauvais (posture attaquant).
DISPOSABLE_USER = "audit-attacker-probe-20260726"
DISPOSABLE_PASS = "AttackerGuess-Wrong-NotARealSecret-7kM"


def _resolve(url: str) -> str:
    return socket.gethostbyname(urlparse(url).hostname or "")


def _snap(resp: httpx.Response) -> dict:
    sc = resp.headers.get("set-cookie") or ""
    cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
    if not cookies and sc:
        cookies = [sc]
    return {
        "status": resp.status_code,
        "location": (resp.headers.get("location") or "")[:200],
        "set_cookie_has_bg": any("bg_session=" in c for c in cookies) or ("bg_session=" in sc),
        "set_cookie_names": [
            c.split("=", 1)[0].strip() for c in cookies if "=" in c
        ][:12],
        "retry_after": resp.headers.get("retry-after"),
        "body_head": (resp.text or "")[:280].replace("\n", " "),
        "content_type": (resp.headers.get("content-type") or "")[:80],
    }


def main() -> None:
    resolved = _resolve(BASE)
    evidence: dict = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "base": BASE,
        "resolved_ip": resolved,
        "expected_staging_ip": EXPECTED_IP,
        "scope": "A_attacker_no_breakglass_account",
        "authorized_by": (
            "Vincent chat 2026-07-26: périmètre A "
            "(attaquant sans compte break-glass) ; "
            "DNS re-vérifié = 172.24.0.108 (même cible que staging 2026-07-25)."
        ),
        "limitation": (
            "Sans mot de passe break-glass valide, ce retest ne prouve PAS "
            "isolément F-01 (bon MDP + IP non-LAN). Il prouve seulement : "
            "rejet sans session + spoof headers inefficace depuis le chemin externe."
        ),
        "points": {},
        "errors": [],
    }
    if resolved != EXPECTED_IP:
        evidence["errors"].append(f"DNS drifted to {resolved}; abort")
        OUT.write_text(json.dumps(evidence, indent=2, ensure_ascii=False), encoding="utf-8")
        raise SystemExit(f"DNS drifted to {resolved}; abort")

    client = httpx.Client(base_url=BASE, timeout=20.0, follow_redirects=False, verify=True)

    def save() -> None:
        evidence["finished_at"] = datetime.now(timezone.utc).isoformat()
        OUT.write_text(json.dumps(evidence, indent=2, ensure_ascii=False), encoding="utf-8")

    try:
        # Étape type 2 (attaquant) : mauvais MDP, chemin externe réel, sans spoof
        r = client.post(
            "/auth/login",
            data={
                "username": DISPOSABLE_USER,
                "password": DISPOSABLE_PASS,
                "rd": "/dashboard",
            },
        )
        evidence["points"]["html_wrong_password_no_spoof"] = _snap(r)

        r_api = client.post(
            "/api/admin/breakglass/login",
            json={"username": DISPOSABLE_USER, "password": DISPOSABLE_PASS},
            headers={"Accept": "application/json"},
        )
        evidence["points"]["api_wrong_password_no_spoof"] = _snap(r_api)

        # Étape type 3 : spoof LAN + X-Portal-Client-IP (écrasement attendu côté reverse)
        spoof = {
            "X-Real-IP": "10.0.0.5",
            "X-Forwarded-For": "10.0.0.5",
            "X-Portal-Client-IP": "10.0.0.5",
            "CF-Connecting-IP": "192.168.1.50",
        }
        r2 = client.post(
            "/auth/login",
            data={
                "username": DISPOSABLE_USER,
                "password": DISPOSABLE_PASS,
                "rd": "/dashboard",
            },
            headers=spoof,
        )
        evidence["points"]["html_wrong_password_spoof_portal_client_ip"] = {
            **_snap(r2),
            "client_sent_headers": spoof,
        }

        r2_api = client.post(
            "/api/admin/breakglass/login",
            json={"username": DISPOSABLE_USER, "password": DISPOSABLE_PASS},
            headers={"Accept": "application/json", **spoof},
        )
        evidence["points"]["api_wrong_password_spoof_portal_client_ip"] = {
            **_snap(r2_api),
            "client_sent_headers": spoof,
        }

        # Surfaces protégées : spoof ne doit pas ouvrir admin
        for path in ("/admin", "/admin/logs", "/dashboard", "/api/apps"):
            evidence["points"][f"get{path.replace('/', '_')}"] = _snap(
                client.get(path, headers={**spoof, "Accept": "text/html,application/json"})
            )

        # Message d'échec HTML (si présent)
        fail_msg = None
        for needle in (
            "Identifiants invalides",
            "invalides",
            "non autoris",
            "refus",
            "interdit",
            "IP",
        ):
            if needle.lower() in (r.text or "").lower():
                fail_msg = needle
                break
        evidence["points"]["html_failure_message_hint"] = fail_msg

    except Exception as exc:  # noqa: BLE001
        evidence["errors"].append(f"{type(exc).__name__}: {exc}")
    finally:
        client.close()
        save()
        print(json.dumps({"out": str(OUT), "resolved": resolved, "errors": evidence["errors"]}, indent=2))


if __name__ == "__main__":
    main()
