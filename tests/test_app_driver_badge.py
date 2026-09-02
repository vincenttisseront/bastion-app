"""Admin app list driver badge labels."""

from __future__ import annotations

from types import SimpleNamespace

from app.bastion.bastion_fields import app_driver_badge_label


def test_teleport_robotic_driver_badge():
    app = SimpleNamespace(robotic_driver="teleport", provisioning_driver=None)
    assert app_driver_badge_label(app) == "Teleport"


def test_crushftp_robotic_over_provisioning():
    app = SimpleNamespace(robotic_driver="crushftp", provisioning_driver="crushftp")
    assert app_driver_badge_label(app) == "CrushFTP"


def test_provisioning_only_crushftp():
    app = SimpleNamespace(robotic_driver=None, provisioning_driver="crushftp")
    assert app_driver_badge_label(app) == "CrushFTP"


def test_no_driver_no_badge():
    app = SimpleNamespace(robotic_driver=None, provisioning_driver=None)
    assert app_driver_badge_label(app) is None
