"""CI bridge paths that must bypass portal SSO (Jenkins ↔ SonarQube).

Jenkins receives SonarQube quality-gate webhooks on ``/sonarqube-webhook/``
without a browser session. SonarQube accepts scanner traffic on ``/api/`` with
its own bearer token — Bastion SSO would 302 those calls to the portal login.
"""

from __future__ import annotations

from app.models import App


def _path_only(uri: str) -> str:
    raw = (uri or "").split("?", 1)[0].strip() or "/"
    if not raw.startswith("/"):
        raw = f"/{raw}"
    return raw.rstrip("/") or "/"


def _haystack(app: App | None) -> str:
    if app is None:
        return ""
    return " ".join(
        [
            (getattr(app, "slug", None) or "").strip().lower(),
            (getattr(app, "public_fqdn", None) or "").strip().lower(),
            (getattr(app, "label", None) or "").strip().lower(),
        ]
    )


def is_jenkins_ci_app(app: App | None) -> bool:
    return "jenkins" in _haystack(app)


def is_sonarqube_ci_app(app: App | None) -> bool:
    hay = _haystack(app)
    return "sonar" in hay


def is_jenkins_ci_webhook_uri(uri: str) -> bool:
    """True for Jenkins SonarQube plugin webhook endpoint."""
    path = _path_only(uri)
    return path == "/sonarqube-webhook"


def is_sonarqube_api_uri(uri: str) -> bool:
    """True for SonarQube Web API (scanner / token auth — not portal SSO)."""
    path = _path_only(uri)
    return path == "/api" or path.startswith("/api/")


def is_jenkins_ci_webhook_request(uri: str, app: App | None) -> bool:
    return is_jenkins_ci_app(app) and is_jenkins_ci_webhook_uri(uri)


def is_sonarqube_api_request(uri: str, app: App | None) -> bool:
    return is_sonarqube_ci_app(app) and is_sonarqube_api_uri(uri)
