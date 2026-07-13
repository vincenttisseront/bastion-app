"""oauth2-proxy port allocation and OS availability checks."""

from __future__ import annotations

import socket

from sqlalchemy.orm import Session

from app.models import RealmConfig
from app.sso_settings import Settings


class NoAvailablePortError(RuntimeError):
    pass


def port_range(settings: Settings) -> range:
    start = int(settings.oauth2_proxy_port_min)
    stop_inclusive = int(settings.oauth2_proxy_port_max)
    if start <= 0 or stop_inclusive <= 0 or start > stop_inclusive:
        return range(4180, 4300)
    return range(start, stop_inclusive + 1)


def get_next_available_port(db: Session, settings: Settings, *, exclude_realm_id: int | None = None) -> int:
    query = db.query(RealmConfig.oauth2_proxy_port)
    if exclude_realm_id is not None:
        query = query.filter(RealmConfig.id != exclude_realm_id)
    used_ports = {p for (p,) in query.all() if p is not None}

    for port in port_range(settings):
        if port not in used_ports:
            return port

    r = port_range(settings)
    raise NoAvailablePortError(
        f"Aucun port libre dans la plage {r.start}-{r.stop - 1}. Toutes les valeurs sont réservées."
    )


def test_port_available(port: int, host: str = "127.0.0.1") -> dict[str, object]:
    """OS-level check: attempt to bind port locally."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((host, port))
        return {"available": True, "message": f"Port {port} libre côté OS"}
    except OSError as exc:
        return {"available": False, "message": f"Port {port} déjà occupé : {exc}"}
    finally:
        sock.close()

