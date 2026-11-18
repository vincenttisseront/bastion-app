"""Companion IA — API for logged-in users (access / security / company contact).

* ``require_user`` on the whole router: no session, no companion (401). Break-glass
  sessions are refused (emergency access never reaches the LLM).
* Off unless an admin enabled it (``llm_companion_enabled``): 404 otherwise.
* Never a 5xx because of the model: any failure returns the static reply.
"""

from __future__ import annotations

import logging
from typing import Literal

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.api_errors import api_error_response
from app.database import get_db
from app.i18n.catalog import t
from app.i18n.middleware import get_request_locale
from app.llm import companion
from app.llm.service import companion_enabled
from app.request_client_ip import client_ip_from_request
from app.sso_settings import Settings, get_settings
from app.web.openapi_responses import RESP_401, RESP_403, RESP_404, RESP_422, RESP_429
from app.web.user_context import UserContext, is_portal_admin, require_user

logger = logging.getLogger(__name__)

router = APIRouter(tags=["companion"], dependencies=[Depends(require_user)])


class CompanionTurn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["user", "assistant"]
    content: str = Field(max_length=2000)


class CompanionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(min_length=1, max_length=companion.MAX_MESSAGE_CHARS)
    history: list[CompanionTurn] = Field(default_factory=list, max_length=12)


@router.post(
    "/api/companion/messages",
    responses=RESP_401 | RESP_403 | RESP_404 | RESP_422 | RESP_429,
)
async def companion_message(
    payload: CompanionRequest,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user),
):
    locale = get_request_locale(request)
    if user.is_breakglass:
        return api_error_response(
            status_code=403,
            message=t("Le compagnon n'est pas disponible pour cette session.", locale),
            code="forbidden",
        )
    if not companion_enabled(settings, db):
        return api_error_response(
            status_code=404,
            message=t("Le compagnon n'est pas activé.", locale),
            code="companion_disabled",
        )
    if not payload.message.strip():
        return api_error_response(
            status_code=422, message=t("Message vide.", locale), code="validation_error"
        )
    wait = companion.check_rate_limit(user.email or user.username)
    if wait is not None:
        seconds = max(1, int(wait) + 1)
        return api_error_response(
            status_code=429,
            message=t("Trop de messages en peu de temps. Réessayez dans {seconds} s.", locale,
                      seconds=seconds),
            code="too_many_requests",
            headers={"Retry-After": str(seconds)},
        )
    ip = client_ip_from_request(request)
    try:
        is_admin = is_portal_admin(user, db, settings)
        reply = await companion.ask(
            db,
            settings,
            user,
            payload.message,
            [turn.model_dump() for turn in payload.history],
            locale=locale,
            ip_address=ip,
            request=request,
            is_admin=is_admin,
        )
    except Exception:  # noqa: BLE001 — ask() never raises; belt and braces
        logger.warning("companion route failed", exc_info=True)
        reply = companion.fallback_reply(companion._branding(db), locale)
    return JSONResponse(reply.to_dict(), headers={"Cache-Control": "no-store"})
