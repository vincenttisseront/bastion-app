"""Seed rules for migration 076 (legacy heuristics → declarative columns)."""

from __future__ import annotations

from app.bastion.m2m_policy import TELEPORT_SEED_BYPASS_PATHS


def _seed_row(
    *,
    slug: str,
    public_fqdn: str,
    label: str,
    robotic_driver: str | None,
    provisioning_driver: str | None,
) -> tuple[list[str], bool]:
    hay = " ".join(
        [
            (slug or "").strip().lower(),
            (public_fqdn or "").strip().lower(),
            (label or "").strip().lower(),
        ]
    )
    paths: list[str] = []
    long_timeout = False
    if "jenkins" in hay and "/sonarqube-webhook" not in paths:
        paths.append("/sonarqube-webhook")
    if "sonar" in hay and "/api/" not in paths:
        paths.append("/api/")
    driver = (robotic_driver or "").strip().lower()
    provision = (provisioning_driver or "").strip().lower()
    if driver == "teleport" or provision == "teleport":
        for p in TELEPORT_SEED_BYPASS_PATHS:
            if p not in paths:
                paths.append(p)
        long_timeout = True
    return paths, long_timeout


def test_seed_jenkins_and_sonar_and_teleport():
    j_paths, j_long = _seed_row(
        slug="jenkins",
        public_fqdn="ci.example.com",
        label="Jenkins",
        robotic_driver=None,
        provisioning_driver=None,
    )
    assert j_paths == ["/sonarqube-webhook"]
    assert j_long is False

    s_paths, _ = _seed_row(
        slug="code",
        public_fqdn="sonar.example.com",
        label="SQ",
        robotic_driver=None,
        provisioning_driver=None,
    )
    assert "/api/" in s_paths

    t_paths, t_long = _seed_row(
        slug="tp",
        public_fqdn="tp.example.com",
        label="TP",
        robotic_driver="teleport",
        provisioning_driver=None,
    )
    assert t_long is True
    assert "/webapi/find" in t_paths
    assert "/webapi/host/" in t_paths

    w_paths, w_long = _seed_row(
        slug="wiki",
        public_fqdn="wiki.example.com",
        label="Wiki",
        robotic_driver=None,
        provisioning_driver=None,
    )
    assert w_paths == []
    assert w_long is False
