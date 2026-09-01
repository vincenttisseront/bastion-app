#!/usr/bin/env python3
"""Pre-reload WAF armament checks for Bastion Pro (ModSecurity / nginx).

Validates operational readiness before ``nginx -s reload``:

1. ``exports/modsecurity/waf-engine-arm.json`` → ``"armed": true``
2. ``exports/modsecurity-portal-switch.conf`` → ``modsecurity on;``
3. (optional) container ``engine-mode-generated.conf`` → ``SecRuleEngine On``

Usage:
  python scripts/waf_arm_check.py
  python scripts/waf_arm_check.py --exports-dir /tools/portal/data/exports
  python scripts/waf_arm_check.py --skip-docker
  python scripts/waf_arm_check.py --json-out /tmp/waf-arm.json

Exit 0 when all enabled checks pass; 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_EXPORTS_DIR = Path("/tools/portal/data/exports")
DEFAULT_CONTAINER = "bastion-nginx"
ENGINE_PATH_IN_CONTAINER = "/etc/nginx/modsecurity/generated/engine-mode-generated.conf"


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str
    skipped: bool = False


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        return f"<unreadable: {exc}>"


def check_arm_json(exports_dir: Path) -> CheckResult:
    path = exports_dir / "modsecurity" / "waf-engine-arm.json"
    if not path.is_file():
        return CheckResult(
            name="waf-engine-arm.json",
            ok=False,
            detail=f"missing: {path}",
        )
    text = _read_text(path)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return CheckResult(
            name="waf-engine-arm.json",
            ok=False,
            detail=f"invalid JSON: {exc}",
        )
    armed = bool(data.get("armed"))
    return CheckResult(
        name="waf-engine-arm.json",
        ok=armed,
        detail=f'"armed": {json.dumps(armed)} ({path})',
    )


def check_portal_switch(exports_dir: Path) -> CheckResult:
    path = exports_dir / "modsecurity-portal-switch.conf"
    if not path.is_file():
        return CheckResult(
            name="modsecurity-portal-switch.conf",
            ok=False,
            detail=f"missing: {path}",
        )
    text = _read_text(path)
    live = [
        ln.strip()
        for ln in text.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    ok = any(re.fullmatch(r"modsecurity\s+on\s*;", ln, flags=re.I) for ln in live)
    snippet = live[0] if live else "(empty)"
    return CheckResult(
        name="modsecurity-portal-switch.conf",
        ok=ok,
        detail=f"live line: {snippet!r}",
    )


def check_engine_in_container(container: str) -> CheckResult:
    cmd = [
        "docker",
        "exec",
        container,
        "cat",
        ENGINE_PATH_IN_CONTAINER,
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except FileNotFoundError:
        return CheckResult(
            name="engine-mode-generated.conf (container)",
            ok=False,
            detail="docker CLI not found",
        )
    except subprocess.TimeoutExpired:
        return CheckResult(
            name="engine-mode-generated.conf (container)",
            ok=False,
            detail=f"timeout reading {ENGINE_PATH_IN_CONTAINER} in {container}",
        )

    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()[:200]
        return CheckResult(
            name="engine-mode-generated.conf (container)",
            ok=False,
            detail=f"docker exec failed ({proc.returncode}): {err}",
        )

    text = proc.stdout or ""
    live = [
        ln.strip()
        for ln in text.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    ok = any(re.fullmatch(r"SecRuleEngine\s+On", ln, flags=re.I) for ln in live)
    snippet = live[-1] if live else "(empty)"
    return CheckResult(
        name="engine-mode-generated.conf (container)",
        ok=ok,
        detail=f"{container}:{ENGINE_PATH_IN_CONTAINER} → {snippet!r}",
    )


def check_crs_setup_generated(exports_dir: Path) -> CheckResult:
    """Ensure IHM threshold export uses safe Bastion id (not CRS 901xxx)."""
    path = exports_dir / "modsecurity" / "crs-setup-generated.conf"
    if not path.is_file():
        return CheckResult(
            name="crs-setup-generated.conf",
            ok=False,
            detail=f"missing: {path} (Admin → WAF → Appliquer)",
        )
    text = _read_text(path)
    if re.search(r"id:901\d{3},", text):
        return CheckResult(
            name="crs-setup-generated.conf",
            ok=False,
            detail="stale CRS rule id 901xxx — must be 1000900110",
        )
    if "id:1000900110" not in text:
        return CheckResult(
            name="crs-setup-generated.conf",
            ok=False,
            detail="missing id:1000900110",
        )
    if "inbound_anomaly_score_threshold=" not in text:
        return CheckResult(
            name="crs-setup-generated.conf",
            ok=False,
            detail="missing inbound_anomaly_score_threshold",
        )
    return CheckResult(
        name="crs-setup-generated.conf",
        ok=True,
        detail=f"export OK ({path.name})",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Bastion WAF pre-reload armament check")
    parser.add_argument(
        "--exports-dir",
        type=Path,
        default=DEFAULT_EXPORTS_DIR,
        help=f"Host exports directory (default: {DEFAULT_EXPORTS_DIR})",
    )
    parser.add_argument(
        "--container",
        default=DEFAULT_CONTAINER,
        help=f"nginx container name (default: {DEFAULT_CONTAINER})",
    )
    parser.add_argument(
        "--skip-docker",
        action="store_true",
        help="Skip live SecRuleEngine check inside the container",
    )
    parser.add_argument("--json-out", default="", help="Write JSON report to this path")
    args = parser.parse_args()

    exports_dir: Path = args.exports_dir
    results: list[CheckResult] = [
        check_arm_json(exports_dir),
        check_portal_switch(exports_dir),
        check_crs_setup_generated(exports_dir),
    ]
    if args.skip_docker:
        results.append(
            CheckResult(
                name="engine-mode-generated.conf (container)",
                ok=True,
                detail="skipped (--skip-docker)",
                skipped=True,
            )
        )
    else:
        results.append(check_engine_in_container(args.container))

    report = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "exports_dir": str(exports_dir),
        "container": args.container,
        "checks": [asdict(r) for r in results],
        "all_ok": all(r.ok for r in results),
    }

    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    print(f"WAF armament check — exports: {exports_dir}")
    for r in results:
        mark = "SKIP" if r.skipped else ("OK" if r.ok else "FAIL")
        print(f"  [{mark}] {r.name}: {r.detail}")

    if report["all_ok"]:
        print("\nPrêt pour nginx -t / reload (armement portal cohérent).")
        return 0

    print("\nArmement incomplet — ne pas recharger en mode Enforce avant correction.")
    print("Actions: Admin → WAF → Réactivation, puis Appliquer ; sync exports → conteneur.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
