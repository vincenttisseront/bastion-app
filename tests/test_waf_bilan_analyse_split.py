"""WAF bilan analyse vs configuration split."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import WafProfile

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}


def _seed_profile(db: Session) -> None:
    db.add(
        WafProfile(
            name="Production",
            mode="on",
            anomaly_threshold=5,
            ip_deny_min_occurrences=3,
            is_active=True,
        )
    )
    db.commit()


def test_waf_nav_splits_analyse_and_configuration(client: TestClient, db_session: Session):
    _seed_profile(db_session)
    resp = client.get("/admin/security/waf", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    html = resp.text
    assert 'data-waf-nav="analyse"' in html
    assert 'data-waf-nav="config"' in html
    assert "sentinel-threat-stack" in html
    assert "Blocages CRS" in html
    assert "Familles de menaces" in html
    assert "Top IP attaquantes" in html
    # Quick controls live under Profil (configuration), not Bilan analyse charts.
    assert html.index('id="profile"') < html.index("Contrôles rapides") or "Contrôles rapides" in html
    # Bilan panel should not contain the controls title before quarantine in analyse-only layout:
    bilan_start = html.index('id="bilan"')
    profile_start = html.index('id="profile"')
    bilan_html = html[bilan_start:profile_start]
    assert "Contrôles rapides" not in bilan_html
    assert "Contrôles rapides" in html[profile_start:]
