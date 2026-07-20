"""Abstract robotic SSO driver interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


class RoboticDriverError(Exception):
    """Base driver error — never include plaintext passwords."""


class RoboticLoginError(RoboticDriverError):
    """Login against the upstream application failed."""


DriverLoginError = RoboticLoginError


@dataclass(frozen=True)
class SetCookieSpec:
    """Cookie to set on the portal response after robotic login."""

    name: str
    value: str


@dataclass(frozen=True)
class DriverLoginResult:
    """Structured output from a vault robotic driver login attempt."""

    cookies: dict[str, str] = field(default_factory=dict)
    auth_header: str | None = None


class RoboticDriver(ABC):
    """Minimal interface for robotic (service-account) SSO drivers."""

    @abstractmethod
    async def login(self, base_url: str, username: str, password: str) -> Any:
        """Authenticate and return a structured session (cookies, etc.)."""

    @abstractmethod
    async def get_username(self, session: Any) -> str:
        """Fingerprint the connected identity after login."""

    @abstractmethod
    async def fingerprint(self, base_url: str) -> bool:
        """Lightweight probe that the upstream looks like the expected product."""
