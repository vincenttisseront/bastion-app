"""MTA-STS policy (RFC 8461) — store in portal_settings, publish via nginx edge.

Publishes ``https://mta-sts.<mail_domain>/.well-known/mta-sts.txt`` as a static
nginx ``return 200`` (no upstream). Does not enforce SMTP; that stays on the MTA.
"""

from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.audit import log_action
from app.bastion.nginx_known_hosts_export import normalize_hostname
from app.models import PortalSettings, utcnow
from app.portal_settings_service import ensure_portal_settings
from app.sso_settings import Settings

logger = logging.getLogger(__name__)

MTA_STS_MODES = frozenset({"testing", "enforce", "none"})
DEFAULT_MAX_AGE = 604800  # 7 days
MIN_MAX_AGE = 86400
MAX_MAX_AGE = 31557600  # ~1 year

_MX_SAFE = re.compile(
    r"^(\*\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$"
)
_DOMAIN_SAFE = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$"
)


def parse_mx_hosts(raw: str | None) -> list[str]:
    """Split MX patterns from textarea (newline / comma). Strips URL junk."""
    out: list[str] = []
    seen: set[str] = set()
    for part in re.split(r"[\n,;]+", raw or ""):
        token = part.strip().lower()
        if not token or token.startswith("#"):
            continue
        # Common paste mistakes: URLs / schemes
        for prefix in ("https://", "http://", "://", "//"):
            if token.startswith(prefix):
                token = token[len(prefix) :]
        token = token.split("/")[0].split("?")[0].strip(".")
        if not token or token in seen:
            continue
        seen.add(token)
        out.append(token)
    return out


def validate_mail_domain(domain: str) -> str:
    host = normalize_hostname(domain) or ""
    if not host or not _DOMAIN_SAFE.match(host):
        raise ValueError(
            "Domaine mail invalide — ex. example.com (sans schéma http/https)."
        )
    if host.startswith("mta-sts."):
        raise ValueError("Indiquez le domaine mail, pas le host mta-sts.*")
    return host


def validate_mx_hosts(hosts: list[str]) -> list[str]:
    if not hosts:
        raise ValueError("Au moins un hôte MX est requis (ex. mail.example.com).")
    cleaned: list[str] = []
    for h in hosts:
        if not _MX_SAFE.match(h):
            raise ValueError(
                f"Hôte MX invalide: {h!r} — utilisez un hostname "
                f"(mail.example.com) ou un joker (*.example.com), pas une URL."
            )
        cleaned.append(h)
    return cleaned


def validate_mode(mode: str) -> str:
    m = (mode or "").strip().lower()
    if m not in MTA_STS_MODES:
        raise ValueError("Mode MTA-STS invalide (testing, enforce ou none).")
    return m


def validate_max_age(raw: int | str | None) -> int:
    try:
        value = int(raw if raw is not None else DEFAULT_MAX_AGE)
    except (TypeError, ValueError) as exc:
        raise ValueError("max_age doit être un entier (secondes).") from exc
    if value < MIN_MAX_AGE or value > MAX_MAX_AGE:
        raise ValueError(
            f"max_age hors plage ({MIN_MAX_AGE}–{MAX_MAX_AGE} s) — "
            f"recommandé 604800 (7 j) puis 2592000 (30 j)."
        )
    return value


def mta_sts_fqdn(mail_domain: str) -> str:
    return f"mta-sts.{mail_domain}"


def build_policy_text(
    *,
    mode: str,
    mx_hosts: list[str],
    max_age: int,
) -> str:
    lines = [
        "version: STSv1",
        f"mode: {mode}",
    ]
    for mx in mx_hosts:
        lines.append(f"mx: {mx}")
    lines.append(f"max_age: {int(max_age)}")
    return "\n".join(lines) + "\n"


def policy_id_hint(policy_text: str) -> str:
    """Suggested id= value for DNS TXT ``_mta-sts.<domain>`` (change on each update)."""
    digest = hashlib.sha256(policy_text.encode("utf-8")).hexdigest()[:12]
    return digest


def suggested_dns_txt(mail_domain: str, policy_text: str) -> str:
    return f"v=STSv1; id={policy_id_hint(policy_text)}"


def _nginx_escape_double_quoted(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\r\n", "\\n")
        .replace("\n", "\\n")
        .replace("\r", "\\n")
    )


def generate_nginx_mta_sts_conf(
    *,
    enabled: bool,
    mail_domain: str | None,
    mode: str,
    mx_hosts: list[str],
    max_age: int,
    public_mail_domain: str | None = None,
) -> str:
    """HTTP :8080 server{} — TLS terminates on ACME :443 for the same Host."""
    if not enabled or not mail_domain:
        return (
            "# MTA-STS disabled — no mta-sts.* vhost\n"
            "# Configure in Admin → Général → Configuration → MTA-STS\n"
        )
    pub = (public_mail_domain or mail_domain).strip() or mail_domain
    fqdn_public = mta_sts_fqdn(pub)
    fqdn_internal = mta_sts_fqdn(mail_domain)
    names = [fqdn_public]
    if fqdn_internal != fqdn_public:
        names.append(fqdn_internal)
    server_names = " ".join(_nginx_escape_double_quoted(n) for n in names)
    policy = build_policy_text(mode=mode, mx_hosts=mx_hosts, max_age=max_age)
    body = _nginx_escape_double_quoted(policy)
    return "\n".join(
        [
            "# Generated by bastion-app — MTA-STS policy (RFC 8461)",
            "# https://mta-sts.<public_domain>/.well-known/mta-sts.txt",
            "# Do not edit; Admin → Configuration → MTA-STS + Apply infra (ACME).",
            "",
            "server {",
            # IPv4-only like portal vhost. Bare `listen 8080` / `[::]:8080` make nginx -t
            # fail on hosts without IPv6 (errno 97) and block all reloads / startup.
            "    listen 0.0.0.0:8080;",
            f"    server_name {server_names};",
            "    access_log /var/log/nginx/apps/mta-sts.access.log portal;",
            "    error_log  /var/log/nginx/apps/mta-sts.error.log warn;",
            "",
            "    # Static policy — no auth, no upstream.",
            "    location = /.well-known/mta-sts.txt {",
            '        default_type text/plain;',
            '        charset utf-8;',
            '        add_header Cache-Control "public, max-age=86400" always;',
            f'        return 200 "{body}";',
            "    }",
            "",
            "    location / {",
            "        default_type text/plain;",
            '        return 404 "MTA-STS host — only /.well-known/mta-sts.txt\\n";',
            "    }",
            "}",
            "",
        ]
    )


def write_mta_sts_nginx_export(db: Session, settings: Settings) -> Path:
    row = ensure_portal_settings(db, settings)
    exports = Path(settings.exports_dir)
    exports.mkdir(parents=True, exist_ok=True)
    path = exports / "nginx-mta-sts.conf"
    enabled = bool(getattr(row, "mta_sts_enabled", False))
    mail_domain = (getattr(row, "mta_sts_mail_domain", None) or "").strip() or None
    mode = (getattr(row, "mta_sts_mode", None) or "testing").strip().lower()
    mx_hosts = parse_mx_hosts(getattr(row, "mta_sts_mx_hosts", None))
    max_age = int(getattr(row, "mta_sts_max_age", None) or DEFAULT_MAX_AGE)
    if enabled and mail_domain:
        try:
            mail_domain = validate_mail_domain(mail_domain)
            mode = validate_mode(mode)
            mx_hosts = validate_mx_hosts(mx_hosts)
            max_age = validate_max_age(max_age)
        except ValueError as exc:
            logger.warning("mta-sts export skipped — invalid settings: %s", exc)
            enabled = False
    content = generate_nginx_mta_sts_conf(
        enabled=enabled,
        mail_domain=mail_domain,
        mode=mode,
        mx_hosts=mx_hosts,
        max_age=max_age,
        public_mail_domain=public_mail_domain_for_row(row) if enabled and mail_domain else None,
    )
    path.write_text(content, encoding="utf-8")
    return path


PROBE_FILENAME = "mta-sts-probe.json"
DEFAULT_PUBLIC_DNS = ("1.1.1.1", "9.9.9.9")
_IPV4 = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$"
)


def parse_public_dns_resolvers(raw: str | None) -> list[str]:
    """Parse admin textarea of public recursive DNS IPs (IPv4)."""
    out: list[str] = []
    seen: set[str] = set()
    for part in re.split(r"[\n,; ]+", raw or ""):
        token = part.strip()
        if not token or token.startswith("#"):
            continue
        if not _IPV4.match(token):
            raise ValueError(
                f"Résolveur DNS invalide: {token!r} — IPv4 uniquement "
                f"(ex. 1.1.1.1 ou 9.9.9.9)."
            )
        if token in seen:
            continue
        seen.add(token)
        out.append(token)
    return out


def default_public_dns_resolvers_text() -> str:
    return "\n".join(DEFAULT_PUBLIC_DNS)


def resolvers_for_row(row: PortalSettings) -> list[str]:
    raw = getattr(row, "mta_sts_public_dns_resolvers", None)
    if not (raw or "").strip():
        return list(DEFAULT_PUBLIC_DNS)
    try:
        parsed = parse_public_dns_resolvers(raw)
    except ValueError:
        return list(DEFAULT_PUBLIC_DNS)
    return parsed or list(DEFAULT_PUBLIC_DNS)


def public_mail_domain_for_row(row: PortalSettings) -> str:
    """Domain used for public DNS A/TXT, ACME and nginx server_name."""
    mail = (getattr(row, "mta_sts_mail_domain", None) or "").strip()
    same = bool(getattr(row, "mta_sts_same_public_domain", True))
    if same:
        return mail
    pub = (getattr(row, "mta_sts_public_mail_domain", None) or "").strip()
    return pub or mail


def _probe_path(settings: Settings) -> Path:
    return Path(settings.exports_dir) / PROBE_FILENAME


def load_mta_sts_probe(settings: Settings) -> dict[str, Any]:
    path = _probe_path(settings)
    if not path.is_file():
        return {}
    try:
        import json

        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def save_mta_sts_probe(settings: Settings, probe: dict[str, Any]) -> None:
    import json

    exports = Path(settings.exports_dir)
    exports.mkdir(parents=True, exist_ok=True)
    path = _probe_path(settings)
    payload = dict(probe)
    payload["saved_at"] = utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def clear_mta_sts_probe(settings: Settings) -> None:
    path = _probe_path(settings)
    try:
        if path.is_file():
            path.unlink()
    except OSError:
        pass


def _acme_local_status(settings: Settings, fqdn: str) -> dict[str, Any]:
    """Local Apply/ACME signals — no network (export + cert on data volume)."""
    in_manifest = False
    acme_path = Path(settings.exports_dir) / "acme-domains.json"
    if acme_path.is_file() and fqdn:
        try:
            import json

            data = json.loads(acme_path.read_text(encoding="utf-8"))
            domains = data.get("domains") if isinstance(data, dict) else None
            if isinstance(domains, list):
                in_manifest = any(
                    isinstance(d, dict)
                    and normalize_hostname(d.get("fqdn")) == fqdn
                    for d in domains
                )
        except (OSError, ValueError, TypeError):
            in_manifest = False
    cert_path = Path(settings.portal_data_dir) / "certs" / fqdn / "fullchain.pem"
    cert_ok = bool(fqdn) and cert_path.is_file() and cert_path.stat().st_size > 0
    return {
        "in_acme_manifest": in_manifest,
        "cert_present": cert_ok,
        "cert_path": str(cert_path) if fqdn else "",
        "ok": in_manifest and cert_ok,
    }


def _resolve_a_public(fqdn: str, nameservers: list[str]) -> tuple[bool, list[str], str]:
    try:
        import dns.resolver

        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = list(nameservers) or list(DEFAULT_PUBLIC_DNS)
        resolver.lifetime = 5.0
        answer = resolver.resolve(fqdn, "A")
        addrs = sorted({rdata.address for rdata in answer})
        return bool(addrs), addrs, ""
    except Exception as exc:
        return False, [], str(exc)


def _resolve_txt_public(
    name: str, expected: str, nameservers: list[str]
) -> tuple[bool, list[str], str]:
    try:
        import dns.resolver

        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = list(nameservers) or list(DEFAULT_PUBLIC_DNS)
        resolver.lifetime = 5.0
        answer = resolver.resolve(name, "TXT")
        values: list[str] = []
        for rdata in answer:
            joined = "".join(
                p.decode("utf-8") if isinstance(p, bytes) else str(p)
                for p in getattr(rdata, "strings", ())
            )
            if not joined and hasattr(rdata, "to_text"):
                joined = str(rdata.to_text()).strip('"')
            values.append(joined.strip())
        expected_n = (expected or "").strip()
        ok = any(expected_n and expected_n in v for v in values) or (
            bool(values) and not expected_n
        )
        return ok, values, ""
    except Exception as exc:
        return False, [], str(exc)


def _https_policy_via_ip(fqdn: str, ip: str, url_path: str = "/.well-known/mta-sts.txt") -> tuple[bool, str, str]:
    """HTTPS GET via public IP + SNI (bypass internal/split DNS)."""
    import socket
    import ssl

    ctx = ssl.create_default_context()
    try:
        raw = socket.create_connection((ip, 443), timeout=8)
        ssock = ctx.wrap_socket(raw, server_hostname=fqdn)
        req = (
            f"GET {url_path} HTTP/1.1\r\n"
            f"Host: {fqdn}\r\n"
            "User-Agent: bastion-mta-sts-probe\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        ssock.sendall(req.encode("ascii"))
        chunks: list[bytes] = []
        while True:
            data = ssock.recv(4096)
            if not data:
                break
            chunks.append(data)
            if sum(len(c) for c in chunks) > 16384:
                break
        ssock.close()
        raw_resp = b"".join(chunks).decode("utf-8", errors="replace")
        head, _, body = raw_resp.partition("\r\n\r\n")
        status_line = head.split("\r\n", 1)[0] if head else ""
        status = 0
        parts = status_line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
        if status == 200 and "version: STSv1" in body:
            return True, f"HTTPS {status} via {ip}", body[:400]
        return False, f"HTTPS {status or '?'} via {ip}", body[:400]
    except Exception as exc:
        return False, f"HTTPS échec via {ip}: {exc}", ""


def _step(
    *,
    sid: str,
    label: str,
    status: str,
    detail: str,
) -> dict[str, str]:
    return {"id": sid, "label": label, "status": status, "detail": detail}


def _build_setup_steps(
    *,
    enabled: bool,
    config_valid: bool,
    ready: bool,
    mode: str,
    mx_hosts: list[str],
    published_s: str,
    export_has_vhost: bool,
    fqdn: str,
    dns_name: str,
    dns_txt: str,
    policy_url: str,
    acme: dict[str, Any],
    probe: dict[str, Any],
) -> list[dict[str, str]]:
    if enabled and not config_valid:
        s1 = "failed"
        d1 = "Publication cochée mais domaine/MX invalides."
    elif ready and export_has_vhost:
        s1 = "done"
        d1 = (
            f"Mode {mode}, {len(mx_hosts)} MX"
            + (f", save {published_s}" if published_s else "")
            + " · export nginx actif"
        )
    elif config_valid:
        s1 = "current"
        d1 = (
            f"Mode {mode}, {len(mx_hosts)} MX — cochez Publier et Enregistrer."
            if not enabled
            else "Config OK — export nginx en attente."
        )
    else:
        s1 = "todo"
        d1 = "Sans publication cochée, nginx n’expose pas le fichier."

    def _net_status(key_ok: str, key_detail: str, locked_detail: str) -> tuple[str, str]:
        if not ready:
            return ("todo" if config_valid else "locked"), locked_detail
        if key_ok not in probe:
            return "current", "Cliquez « Vérifier DNS + HTTPS » (scan via les DNS publics configurés)."
        if probe.get(key_ok):
            return "done", str(probe.get(key_detail) or "OK")
        return "failed", str(probe.get(key_detail) or "Échec — voir Vérifier.")

    dns_a_s, dns_a_d = _net_status(
        "dns_a_ok",
        "dns_a_detail",
        "Chez le registrar → même IP publique que portal.* (DNS public, pas le DNS interne).",
    )
    dns_txt_s, dns_txt_d = _net_status(
        "dns_txt_ok",
        "dns_txt_detail",
        f"Valeur : {dns_txt}" if dns_txt else "Apparait après une config valide.",
    )

    if not ready:
        acme_s, acme_d = (
            ("todo" if config_valid else "locked"),
            "Admin → Infrastructure → Apply (FQDN mta-sts dans acme-domains.json + certificat).",
        )
    elif acme.get("ok"):
        acme_s, acme_d = "done", f"Certificat présent ({acme.get('cert_path', '')})."
    elif acme.get("in_acme_manifest") and not acme.get("cert_present"):
        acme_s, acme_d = (
            "failed",
            "Dans acme-domains.json mais certificat absent — Apply infra / attendre ACME DNS-01.",
        )
    elif not acme.get("in_acme_manifest"):
        acme_s, acme_d = (
            "failed",
            "FQDN absent de acme-domains.json — Enregistrer MTA-STS puis Apply infra.",
        )
    else:
        acme_s, acme_d = "current", "Apply infra pour émettre le certificat TLS."

    http_s, http_d = _net_status(
        "http_ok",
        "http_detail",
        policy_url or "https://mta-sts.<domaine>/.well-known/mta-sts.txt",
    )

    return [
        _step(sid="config", label="1. Remplir domaine + MX, cocher Publier, Enregistrer", status=s1, detail=d1),
        _step(
            sid="dns_a",
            label=f"2. DNS A/AAAA (public) : {fqdn or 'mta-sts.<domaine>'}",
            status=dns_a_s,
            detail=dns_a_d,
        ),
        _step(
            sid="dns_txt",
            label=f"3. DNS TXT (public) : {dns_name or '_mta-sts.<domaine>'}",
            status=dns_txt_s,
            detail=dns_txt_d if dns_txt_s != "todo" else (f"Valeur : {dns_txt}" if dns_txt else dns_txt_d),
        ),
        _step(sid="acme", label="4. Apply infra (certificat ACME TLS)", status=acme_s, detail=acme_d),
        _step(
            sid="verify",
            label="5. HTTPS public (via IP DNS public + SNI)",
            status=http_s,
            detail=http_d,
        ),
    ]


def _next_action_from_steps(steps: list[dict[str, str]], *, enabled: bool, config_valid: bool) -> str:
    if not config_valid:
        return "Renseignez un domaine mail et au moins un hôte MX, puis enregistrez."
    if not enabled:
        return "Cochez « Publier la politique… » puis Enregistrer & publier — sinon aucun vhost nginx."
    for step in steps:
        if step.get("status") in ("current", "failed", "todo"):
            return step.get("detail") or step.get("label") or "Poursuivez la checklist."
    return "Politique joignable en HTTPS public — MTA-STS opérationnel côté découverte."


def mta_sts_public_status(db: Session, settings: Settings) -> dict[str, Any]:
    row = ensure_portal_settings(db, settings)
    enabled = bool(getattr(row, "mta_sts_enabled", False))
    mail_domain = (getattr(row, "mta_sts_mail_domain", None) or "").strip()
    same_public = bool(getattr(row, "mta_sts_same_public_domain", True))
    public_mail_domain_raw = (getattr(row, "mta_sts_public_mail_domain", None) or "").strip()
    mode = (getattr(row, "mta_sts_mode", None) or "testing").strip().lower()
    mx_raw = getattr(row, "mta_sts_mx_hosts", None) or ""
    mx_hosts = parse_mx_hosts(mx_raw)
    max_age = int(getattr(row, "mta_sts_max_age", None) or DEFAULT_MAX_AGE)
    resolvers = resolvers_for_row(row)
    resolvers_text = (getattr(row, "mta_sts_public_dns_resolvers", None) or "").strip() or default_public_dns_resolvers_text()
    published = getattr(row, "mta_sts_published_at", None)
    published_s = ""
    if published is not None:
        try:
            published_s = published.strftime("%Y-%m-%d %H:%M UTC")
        except (TypeError, ValueError, AttributeError, OSError):
            published_s = str(published)

    policy_text = ""
    fqdn = ""
    fqdn_internal = ""
    policy_url = ""
    dns_txt = ""
    dns_name = ""
    config_valid = False
    domain_ok = ""
    public_ok = ""
    try:
        if mail_domain:
            domain_ok = validate_mail_domain(mail_domain)
        if not same_public:
            if not public_mail_domain_raw:
                raise ValueError(
                    "Domaine public DNS requis lorsque le domaine interne ≠ domaine public."
                )
            public_ok = validate_mail_domain(public_mail_domain_raw)
        else:
            public_ok = domain_ok
        if domain_ok and mx_hosts and public_ok:
            m = validate_mode(mode)
            mxs = validate_mx_hosts(mx_hosts)
            age = validate_max_age(max_age)
            policy_text = build_policy_text(mode=m, mx_hosts=mxs, max_age=age)
            fqdn = mta_sts_fqdn(public_ok)
            fqdn_internal = mta_sts_fqdn(domain_ok)
            policy_url = f"https://{fqdn}/.well-known/mta-sts.txt"
            dns_txt = suggested_dns_txt(public_ok, policy_text)
            dns_name = f"_mta-sts.{public_ok}"
            config_valid = True
    except ValueError:
        config_valid = False

    ready = bool(enabled and config_valid)
    exports = Path(settings.exports_dir)
    export_path = exports / "nginx-mta-sts.conf"
    export_exists = export_path.is_file()
    export_has_vhost = False
    if export_exists:
        try:
            export_has_vhost = "server {" in export_path.read_text(encoding="utf-8")
        except OSError:
            export_has_vhost = False

    acme = _acme_local_status(settings, fqdn) if fqdn else {
        "in_acme_manifest": False,
        "cert_present": False,
        "cert_path": "",
        "ok": False,
    }
    probe = load_mta_sts_probe(settings)
    # Invalidate stale probe when policy id / public FQDN / resolvers changed.
    stale = False
    if probe:
        if dns_txt and probe.get("expected_dns_txt") and probe.get("expected_dns_txt") != dns_txt:
            stale = True
        if fqdn and probe.get("fqdn") and probe.get("fqdn") != fqdn:
            stale = True
        if probe.get("resolvers") and list(probe.get("resolvers") or []) != list(resolvers):
            stale = True
    if stale:
        probe = {}
        clear_mta_sts_probe(settings)

    steps = _build_setup_steps(
        enabled=enabled,
        config_valid=config_valid,
        ready=ready,
        mode=mode,
        mx_hosts=mx_hosts,
        published_s=published_s,
        export_has_vhost=export_has_vhost,
        fqdn=fqdn,
        dns_name=dns_name,
        dns_txt=dns_txt,
        policy_url=policy_url,
        acme=acme,
        probe=probe,
    )
    probe_ok = bool(probe.get("ok")) if probe else False
    if ready and probe_ok:
        status_badge = "ok"
    elif ready:
        status_badge = "warn"
    elif enabled or config_valid:
        status_badge = "warn"
    else:
        status_badge = "off"

    return {
        "enabled": enabled,
        "mail_domain": mail_domain,
        "same_public_domain": same_public,
        "public_mail_domain": public_mail_domain_raw if not same_public else mail_domain,
        "public_dns_resolvers": resolvers_text,
        "public_dns_resolvers_list": resolvers,
        "mode": mode if mode in MTA_STS_MODES else "testing",
        "mx_hosts": mx_raw,
        "mx_list": mx_hosts,
        "max_age": max_age,
        "config_valid": config_valid,
        "ready": ready,
        "fqdn": fqdn,
        "fqdn_internal": fqdn_internal,
        "policy_url": policy_url,
        "policy_text": policy_text,
        "dns_name": dns_name,
        "dns_txt": dns_txt,
        "dns_a_preview": f"{fqdn} 3600 IN A <IP-bastion>" if fqdn else "",
        "published_at": published_s,
        "export_has_vhost": export_has_vhost,
        "setup_steps": steps,
        "acme": acme,
        "probe": probe,
        "status_badge": status_badge,
        "next_action": _next_action_from_steps(
            steps, enabled=enabled, config_valid=config_valid
        ),
    }


def probe_mta_sts_publication(db: Session, settings: Settings) -> dict[str, Any]:
    """Scan via configured public DNS resolvers + HTTPS pinned to resolved IP.

    Avoids false OK from split-horizon / internal DNS on the bastion host.
    Persists results so the checklist stays dynamic between page loads.
    """
    status = mta_sts_public_status(db, settings)
    resolvers = list(status.get("public_dns_resolvers_list") or DEFAULT_PUBLIC_DNS)
    lines: list[str] = [
        "$ bastion mta-sts verify",
        "# DNS publics: " + ", ".join(resolvers) + " (pas le DNS interne)",
    ]
    if not status.get("ready"):
        lines.append("✗ Publication inactive ou config incomplète — " + status["next_action"])
        return {"ok": False, "message": status["next_action"], "lines": lines, **status}

    fqdn = status["fqdn"]
    dns_name = status["dns_name"]
    dns_txt = status["dns_txt"]
    url = status["policy_url"]
    if status.get("fqdn_internal") and status.get("fqdn_internal") != fqdn:
        lines.append(f"FQDN public  {fqdn}")
        lines.append(f"FQDN interne {status['fqdn_internal']}")
    else:
        lines.append(f"FQDN {fqdn}")
    lines.append(f"URL  {url}")

    dns_a_ok, addrs, dns_a_err = _resolve_a_public(fqdn, resolvers)
    if dns_a_ok:
        lines.append("✓ DNS A (public) → " + ", ".join(addrs))
        dns_a_detail = "Public → " + ", ".join(addrs)
    else:
        lines.append(f"✗ DNS A (public) NXDOMAIN / échec ({dns_a_err})")
        lines.append("  → Chez le registrar public, pas seulement le DNS interne.")
        dns_a_detail = f"DNS public KO: {dns_a_err or 'NXDOMAIN'}"

    dns_txt_ok, txt_values, dns_txt_err = _resolve_txt_public(dns_name, dns_txt, resolvers)
    if dns_txt_ok:
        lines.append("✓ DNS TXT (public) → " + (txt_values[0] if txt_values else dns_txt))
        dns_txt_detail = "Public → " + (txt_values[0] if txt_values else "OK")
    else:
        found = ", ".join(txt_values) if txt_values else "(aucun)"
        lines.append(f"✗ DNS TXT (public) attendu {dns_txt!r} — trouvé: {found}")
        if dns_txt_err:
            lines.append(f"  ({dns_txt_err})")
        dns_txt_detail = f"TXT public KO — trouvé: {found}"

    acme = status.get("acme") or _acme_local_status(settings, fqdn)
    if acme.get("ok"):
        lines.append("✓ ACME local — certificat présent")
    elif acme.get("in_acme_manifest"):
        lines.append("⚠ ACME — dans acme-domains.json mais fullchain.pem absent")
    else:
        lines.append("✗ ACME — FQDN absent de acme-domains.json (Apply infra)")

    http_ok = False
    http_detail = "HTTPS non testé (DNS A public requis)."
    body_preview = ""
    if dns_a_ok and addrs:
        http_ok, http_detail, body_preview = _https_policy_via_ip(fqdn, addrs[0])
        if http_ok:
            lines.append(f"✓ {http_detail}")
            for line in body_preview.strip().splitlines()[:8]:
                lines.append("  " + line)
        else:
            lines.append(f"✗ {http_detail}")
            if body_preview:
                lines.append("  " + body_preview[:180].replace("\n", " "))

    ok = bool(dns_a_ok and dns_txt_ok and http_ok)
    probe = {
        "ok": ok,
        "dns_a_ok": dns_a_ok,
        "dns_a_detail": dns_a_detail,
        "dns_txt_ok": dns_txt_ok,
        "dns_txt_detail": dns_txt_detail,
        "http_ok": http_ok,
        "http_detail": http_detail,
        "resolved_addrs": addrs,
        "expected_dns_txt": dns_txt,
        "fqdn": fqdn,
        "resolvers": resolvers,
    }
    try:
        save_mta_sts_probe(settings, probe)
    except OSError:
        logger.exception("mta-sts: cannot persist probe")

    status = mta_sts_public_status(db, settings)
    message = (
        "Politique joignable en HTTPS public."
        if ok
        else (
            "DNS public OK mais HTTPS KO — certificat / edge."
            if dns_a_ok and not http_ok
            else "DNS public incomplet (A et/ou TXT) — le DNS interne ne compte pas pour MTA-STS."
        )
    )
    return {
        "ok": ok,
        "message": message,
        "lines": lines,
        "dns_ok": dns_a_ok,
        "dns_a_ok": dns_a_ok,
        "dns_txt_ok": dns_txt_ok,
        "http_ok": http_ok,
        "resolved_addrs": addrs,
        **status,
    }


def _next_action(*, enabled: bool, config_valid: bool, ready: bool) -> str:
    # Kept for callers/tests; prefer _next_action_from_steps.
    if not config_valid:
        return "Renseignez un domaine mail et au moins un hôte MX, puis enregistrez."
    if not enabled:
        return "Cochez « Publier la politique… » puis Enregistrer & publier — sinon aucun vhost nginx."
    if ready:
        return (
            "Créez les DNS A/AAAA + TXT chez le registrar public, puis "
            "« Vérifier DNS + HTTPS » (scan hors DNS interne)."
        )
    return "Enregistrez la configuration."


def update_mta_sts_settings(
    db: Session,
    settings: Settings,
    *,
    actor: str,
    ip_address: str | None = None,
    enabled: bool,
    mail_domain: str,
    mode: str,
    mx_hosts: str,
    max_age: int,
    same_public_domain: bool = True,
    public_mail_domain: str = "",
    public_dns_resolvers: str = "",
) -> PortalSettings:
    row = ensure_portal_settings(db, settings)
    enabled_b = bool(enabled)
    same = bool(same_public_domain)
    resolvers_raw = (public_dns_resolvers or "").strip()
    if resolvers_raw:
        resolvers_store = "\n".join(parse_public_dns_resolvers(resolvers_raw))
    else:
        resolvers_store = default_public_dns_resolvers_text()

    if enabled_b:
        domain = validate_mail_domain(mail_domain)
        mode_v = validate_mode(mode)
        mxs = validate_mx_hosts(parse_mx_hosts(mx_hosts))
        age = validate_max_age(max_age)
        pub = domain if same else validate_mail_domain(public_mail_domain)
        row.mta_sts_enabled = True
        row.mta_sts_mail_domain = domain
        row.mta_sts_same_public_domain = same
        row.mta_sts_public_mail_domain = None if same else pub
        row.mta_sts_public_dns_resolvers = resolvers_store
        row.mta_sts_mode = mode_v
        row.mta_sts_mx_hosts = "\n".join(mxs)
        row.mta_sts_max_age = age
        row.mta_sts_published_at = utcnow()
    else:
        # Keep last values for re-enable; only clear the flag.
        row.mta_sts_enabled = False
        row.mta_sts_same_public_domain = same
        row.mta_sts_public_dns_resolvers = resolvers_store
        if (mail_domain or "").strip():
            try:
                row.mta_sts_mail_domain = validate_mail_domain(mail_domain)
            except ValueError:
                pass
        if same:
            row.mta_sts_public_mail_domain = None
        elif (public_mail_domain or "").strip():
            try:
                row.mta_sts_public_mail_domain = validate_mail_domain(public_mail_domain)
            except ValueError:
                pass
        if (mode or "").strip():
            try:
                row.mta_sts_mode = validate_mode(mode)
            except ValueError:
                pass
        parsed = parse_mx_hosts(mx_hosts)
        if parsed:
            row.mta_sts_mx_hosts = "\n".join(parsed)
        try:
            row.mta_sts_max_age = validate_max_age(max_age)
        except ValueError:
            pass

    row.updated_at = utcnow()
    row.updated_by = actor
    db.commit()
    db.refresh(row)

    # Refresh edge exports immediately (watcher copies into conf.d).
    try:
        write_mta_sts_nginx_export(db, settings)
        from app.bastion.acme_domains_export import write_acme_domains_export
        from app.bastion.nginx_known_hosts_export import write_known_hosts_map

        write_known_hosts_map(db, settings)
        write_acme_domains_export(db, settings)
    except Exception:
        logger.exception("mta-sts: export refresh failed after save")

    # Policy / DNS id changed → force a fresh public scan.
    clear_mta_sts_probe(settings)

    pub_fqdn = None
    if row.mta_sts_enabled and row.mta_sts_mail_domain:
        pub_domain = public_mail_domain_for_row(row)
        if pub_domain:
            pub_fqdn = mta_sts_fqdn(pub_domain)

    log_action(
        db,
        actor=actor,
        action="mta_sts.settings_saved",
        target="portal_settings",
        details={
            "enabled": bool(row.mta_sts_enabled),
            "mail_domain": row.mta_sts_mail_domain,
            "same_public_domain": bool(getattr(row, "mta_sts_same_public_domain", True)),
            "public_mail_domain": getattr(row, "mta_sts_public_mail_domain", None),
            "mode": row.mta_sts_mode,
            "mx_count": len(parse_mx_hosts(row.mta_sts_mx_hosts)),
            "max_age": row.mta_sts_max_age,
            "fqdn": pub_fqdn,
            "dns_resolvers": resolvers_for_row(row),
        },
        ip_address=ip_address,
    )
    return row


def iter_mta_sts_acme_domains(db: Session, settings: Settings) -> list[dict[str, str]]:
    """FQDNs for acme-domains.json when MTA-STS publication is enabled."""
    row = ensure_portal_settings(db, settings)
    if not bool(getattr(row, "mta_sts_enabled", False)):
        return []
    domain = public_mail_domain_for_row(row)
    if not domain:
        return []
    try:
        domain = validate_mail_domain(domain)
    except ValueError:
        return []
    out = [
        {
            "fqdn": mta_sts_fqdn(domain),
            "slug": "mta-sts",
            "family": "mta_sts",
        }
    ]
    # Also request cert for internal name when split (optional SNI).
    internal = (getattr(row, "mta_sts_mail_domain", None) or "").strip()
    if internal and not bool(getattr(row, "mta_sts_same_public_domain", True)):
        try:
            internal = validate_mail_domain(internal)
            internal_fqdn = mta_sts_fqdn(internal)
            if internal_fqdn != out[0]["fqdn"]:
                out.append(
                    {
                        "fqdn": internal_fqdn,
                        "slug": "mta-sts-internal",
                        "family": "mta_sts",
                    }
                )
        except ValueError:
            pass
    return out
