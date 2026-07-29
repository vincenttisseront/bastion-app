"""Host apply signal for Admin Infrastructure UI."""

from pathlib import Path

from app.admin.infra_host_apply import (
    STATUS_OK,
    STATUS_PENDING,
    read_host_apply_status,
    request_host_apply,
)
from app.sso_settings import Settings


def test_request_host_apply_writes_sentinel(tmp_path: Path):
    data = tmp_path / "data"
    exports = data / "exports"
    exports.mkdir(parents=True)
    settings = Settings(
        portal_data_dir=str(data),
        exports_dir=str(exports),
        vault_portal_internal_token="t",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
    )

    result = request_host_apply(settings, exported_files=7)
    assert result["ok"] is True
    assert result["pending"] is True
    assert (data / "apply-infra.request").is_file()
    assert "exports" in (data / "apply-infra.request").read_text(encoding="utf-8")
    assert (data / "apply-infra.status").read_text(encoding="utf-8").strip() == STATUS_PENDING

    host = read_host_apply_status(settings)
    assert host["status"] == STATUS_PENDING
    assert host["request_pending"] is True
    assert "Demande d'apply" in host["log_text"]


def test_read_host_apply_status_ok(tmp_path: Path):
    data = tmp_path / "data"
    exports = data / "exports"
    exports.mkdir(parents=True)
    (data / "apply-infra.status").write_text(STATUS_OK + "\n", encoding="utf-8")
    (data / "apply-infra.log").write_text("done\n", encoding="utf-8")
    settings = Settings(
        portal_data_dir=str(data),
        exports_dir=str(exports),
        vault_portal_internal_token="t",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
    )

    host = read_host_apply_status(settings)
    assert host["status"] == STATUS_OK
    assert host["badge"] == "ok"
    assert host["request_pending"] is False
    assert "done" in host["log_text"]
