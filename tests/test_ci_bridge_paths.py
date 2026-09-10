"""CI bridge path helpers (Jenkins webhook + SonarQube API)."""

from __future__ import annotations

from types import SimpleNamespace

from app.bastion.ci_bridge_paths import (
    is_jenkins_ci_app,
    is_jenkins_ci_webhook_request,
    is_jenkins_ci_webhook_uri,
    is_sonarqube_api_request,
    is_sonarqube_api_uri,
    is_sonarqube_ci_app,
)


def test_jenkins_ci_app_detection():
    assert is_jenkins_ci_app(SimpleNamespace(slug="jenkins", public_fqdn="", label=""))
    assert is_jenkins_ci_app(
        SimpleNamespace(slug="ci", public_fqdn="jenkins.example.com", label="")
    )
    assert not is_jenkins_ci_app(
        SimpleNamespace(slug="wiki", public_fqdn="wiki.example.com", label="Wiki")
    )


def test_sonarqube_ci_app_detection():
    assert is_sonarqube_ci_app(
        SimpleNamespace(slug="sonarqube", public_fqdn="", label="")
    )
    assert is_sonarqube_ci_app(
        SimpleNamespace(slug="quality", public_fqdn="sonar.example.com", label="")
    )
    assert not is_sonarqube_ci_app(
        SimpleNamespace(slug="wiki", public_fqdn="wiki.example.com", label="")
    )


def test_jenkins_webhook_uri():
    assert is_jenkins_ci_webhook_uri("/sonarqube-webhook")
    assert is_jenkins_ci_webhook_uri("/sonarqube-webhook/")
    assert is_jenkins_ci_webhook_uri("/sonarqube-webhook?foo=1")
    assert not is_jenkins_ci_webhook_uri("/job/bastion/build")


def test_sonarqube_api_uri():
    assert is_sonarqube_api_uri("/api/ce/submit")
    assert is_sonarqube_api_uri("/api/")
    assert not is_sonarqube_api_uri("/projects")


def test_request_helpers_require_matching_app():
    jenkins = SimpleNamespace(slug="jenkins", public_fqdn="jenkins.example.com", label="")
    sonar = SimpleNamespace(slug="sonarqube", public_fqdn="sonarqube.example.com", label="")
    wiki = SimpleNamespace(slug="wiki", public_fqdn="wiki.example.com", label="")

    assert is_jenkins_ci_webhook_request("/sonarqube-webhook/", jenkins)
    assert not is_jenkins_ci_webhook_request("/sonarqube-webhook/", wiki)
    assert is_sonarqube_api_request("/api/system/status", sonar)
    assert not is_sonarqube_api_request("/api/system/status", wiki)
