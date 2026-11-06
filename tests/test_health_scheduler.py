"""The scheduled probe cycle must not run its sync DB work on the main event loop."""

from __future__ import annotations

import asyncio
import threading

from app import health_scheduler


def test_scheduled_probe_cycle_runs_off_the_main_loop(monkeypatch):
    seen: dict = {}

    class FakeSession:
        closed = False

        def close(self) -> None:
            FakeSession.closed = True

    async def fake_probe_all(db):
        seen["thread"] = threading.get_ident()
        seen["loop"] = asyncio.get_running_loop()
        seen["db"] = db
        return {}

    monkeypatch.setattr(health_scheduler, "SessionLocal", FakeSession)
    monkeypatch.setattr(health_scheduler, "probe_all_enabled_apps", fake_probe_all)

    async def main():
        seen["main_loop"] = asyncio.get_running_loop()
        await health_scheduler._scheduled_probe_cycle()

    asyncio.run(main())
    assert seen["thread"] != threading.get_ident()
    assert seen["loop"] is not seen["main_loop"]
    assert isinstance(seen["db"], FakeSession)
    assert FakeSession.closed is True


def test_scheduled_probe_cycle_closes_session_on_error(monkeypatch):
    closed: list[bool] = []

    class FakeSession:
        def close(self) -> None:
            closed.append(True)

    async def boom(db):
        raise RuntimeError("probe failed")

    monkeypatch.setattr(health_scheduler, "SessionLocal", FakeSession)
    monkeypatch.setattr(health_scheduler, "probe_all_enabled_apps", boom)
    try:
        asyncio.run(health_scheduler._scheduled_probe_cycle())
    except RuntimeError:
        pass
    assert closed == [True]
