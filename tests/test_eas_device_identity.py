"""Human labels derived from ActiveSync DeviceId / DeviceType / User-Agent."""

from app.subdomain.eas_device_identity import (
    apple_serial_from_device_id,
    describe_eas_device,
)


def test_apple_serial_from_appl_prefix():
    assert apple_serial_from_device_id("ApplC39ZH2VJJCM3") == "C39ZH2VJJCM3"
    assert apple_serial_from_device_id("applC39ZH2VJJCM3") == "C39ZH2VJJCM3"


def test_apple_serial_bare_when_device_type_is_iphone():
    assert (
        apple_serial_from_device_id("C39ZH2VJJCM3", device_type="iPhone")
        == "C39ZH2VJJCM3"
    )
    # 17-char opaque ids are not claimed as Apple serials.
    assert (
        apple_serial_from_device_id("LOGIL6A9414ONFM3TQ", device_type="iPhone") is None
    )


def test_describe_maps_apple_product_type():
    info = describe_eas_device(
        device_id="ApplC39ZH2VJJCM3",
        device_type="iPhone",
        user_agent="Apple-iPhone14,5/2001.78",
        client_kind="iphone",
    )
    assert info["apple_serial"] == "C39ZH2VJJCM3"
    assert info["model_label"] == "iPhone 13"
    assert "iPhone 13" in (info["display_name"] or "")
    assert "C39ZH2VJJCM3" in (info["display_name"] or "")
    assert "build 2001.78" in (info["ua_summary"] or "")


def test_describe_falls_back_to_device_type():
    info = describe_eas_device(
        device_id="LOGIL6A9414ONFM3TQ",
        device_type="iPhone",
        user_agent="Apple-iPhone/1601.405",
        client_kind="iphone",
    )
    assert info["apple_serial"] is None
    assert info["model_label"] in ("iPhone", "Apple-iPhone") or "iPhone" in (
        info["model_label"] or ""
    )
    assert "LOGIL6A" in (info["display_name"] or "")
