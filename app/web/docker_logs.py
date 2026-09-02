"""Read-only Docker container logs via an external socket proxy (never the raw sock)."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator

import httpx
from fastapi import HTTPException

from app.web.container_logs_settings import ContainerLogsConfig

logger = logging.getLogger(__name__)


def docker_logs_whitelist(cfg: ContainerLogsConfig) -> list[str]:
    return list(cfg.allowed_containers or [])


def docker_logs_enabled(cfg: ContainerLogsConfig) -> bool:
    return cfg.active


def assert_container_allowed(name: str, cfg: ContainerLogsConfig) -> str:
    """Return normalized name or raise 403 (never 404 — no existence leak)."""
    raw = (name or "").strip()
    allowed = {n.casefold(): n for n in docker_logs_whitelist(cfg)}
    key = raw.casefold()
    if not raw or key not in allowed:
        raise HTTPException(status_code=403, detail="Forbidden")
    return allowed[key]


def _proxy_base(cfg: ContainerLogsConfig) -> str:
    base = (cfg.proxy_url or "").strip().rstrip("/")
    if not cfg.enabled or not base:
        raise HTTPException(
            status_code=503,
            detail="Docker logs proxy not configured",
        )
    return base


def _demux_frames(buffer: bytearray) -> tuple[list[str], bytearray]:
    """Split Docker multiplexed log frames into text lines; return leftover buffer."""
    out: list[str] = []
    while len(buffer) >= 8:
        size = int.from_bytes(buffer[4:8], "big")
        if len(buffer) < 8 + size:
            break
        payload = bytes(buffer[8 : 8 + size])
        del buffer[: 8 + size]
        text = payload.decode("utf-8", errors="replace")
        if text:
            out.append(text)
    return out, buffer


async def fetch_container_log_snapshot(
    cfg: ContainerLogsConfig,
    container: str,
    *,
    tail: int | None = None,
) -> str:
    """Fetch last N lines (non-follow) from the read-only Docker API proxy."""
    name = assert_container_allowed(container, cfg)
    base = _proxy_base(cfg)
    n = tail if tail is not None else int(cfg.tail_lines or 200)
    params = {
        "stdout": "true",
        "stderr": "true",
        "timestamps": "false",
        "tail": str(max(1, min(n, 5000))),
        "follow": "false",
    }
    url = f"{base}/containers/{name}/logs"
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url, params=params)
    except httpx.HTTPError:
        logger.exception("docker logs proxy request failed container=%s", name)
        raise HTTPException(status_code=502, detail="Docker logs proxy unavailable") from None

    if resp.status_code == 404:
        raise HTTPException(status_code=403, detail="Forbidden")
    if resp.status_code >= 400:
        logger.warning(
            "docker logs proxy status=%s container=%s", resp.status_code, name
        )
        raise HTTPException(status_code=502, detail="Docker logs proxy error")

    buf = bytearray(resp.content)
    chunks, leftover = _demux_frames(buf)
    if leftover and not chunks:
        return leftover.decode("utf-8", errors="replace")
    if leftover:
        chunks.append(leftover.decode("utf-8", errors="replace"))
    return "".join(chunks)


async def run_container_logs_connectivity_test(
    cfg: ContainerLogsConfig,
    container: str | None = None,
    *,
    preview_tail: int = 5,
) -> tuple[bool, str, list[str]]:
    """Verify proxy reachability and log fetch for a whitelisted container."""
    lines: list[str] = ["$ bastion container-logs connectivity-test"]
    if not cfg.enabled:
        lines.append("✗ Logs containers désactivés — cochez et enregistrez.")
        return False, "Logs containers désactivés.", lines
    if not (cfg.proxy_url or "").strip():
        lines.append("✗ URL du proxy Docker manquante.")
        return False, "URL du proxy manquante.", lines

    allowed = docker_logs_whitelist(cfg)
    if not allowed:
        lines.append("✗ Liste blanche vide — ajoutez au moins un conteneur.")
        return False, "Liste blanche vide.", lines

    target: str | None = None
    if (container or "").strip():
        try:
            target = assert_container_allowed(container or "", cfg)
        except HTTPException:
            lines.append(f"✗ Conteneur « {container} » non autorisé.")
            return False, "Conteneur non autorisé.", lines
    else:
        target = allowed[0]

    tail = max(1, min(int(preview_tail or 5), 50))
    lines.append(f"→ proxy {cfg.proxy_url}")
    lines.append(f"→ conteneur {target} (tail={tail})")
    try:
        text = await fetch_container_log_snapshot(cfg, target, tail=tail)
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, str) else "Erreur proxy Docker"
        lines.append(f"✗ {detail}")
        return False, detail, lines

    preview = [ln for ln in text.splitlines() if ln.strip()]
    byte_count = len(text.encode("utf-8", errors="replace"))
    lines.append(f"✓ {len(preview)} ligne(s) lues ({byte_count} octets)")
    if preview:
        lines.append("--- extrait ---")
        for row in preview[:8]:
            lines.append(row[:240])
        if len(preview) > 8:
            lines.append(f"… ({len(preview) - 8} ligne(s) supplémentaire(s))")
    else:
        lines.append("(flux vide — conteneur joignable, aucun log récent)")
    return True, f"Logs récupérés pour {target}.", lines


async def iter_container_log_follow(
    cfg: ContainerLogsConfig,
    container: str,
    *,
    tail: int | None = None,
) -> AsyncIterator[str]:
    """Yield text chunks while following container logs via the proxy."""
    name = assert_container_allowed(container, cfg)
    base = _proxy_base(cfg)
    n = tail if tail is not None else int(cfg.tail_lines or 200)
    params = {
        "stdout": "true",
        "stderr": "true",
        "timestamps": "false",
        "tail": str(max(1, min(n, 5000))),
        "follow": "true",
    }
    url = f"{base}/containers/{name}/logs"
    buf = bytearray()
    try:
        async with httpx.AsyncClient(timeout=None) as client:
            async with client.stream("GET", url, params=params) as resp:
                if resp.status_code == 404:
                    raise HTTPException(status_code=403, detail="Forbidden")
                if resp.status_code >= 400:
                    raise HTTPException(
                        status_code=502, detail="Docker logs proxy error"
                    )
                async for raw in resp.aiter_bytes():
                    buf.extend(raw)
                    chunks, buf = _demux_frames(buf)
                    for chunk in chunks:
                        yield chunk
    except HTTPException:
        raise
    except httpx.HTTPError:
        logger.exception("docker logs follow failed container=%s", name)
        raise HTTPException(status_code=502, detail="Docker logs proxy unavailable") from None
