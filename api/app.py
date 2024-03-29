"""
## Authentication
- To authenticate requests, the `Authorization` header must contain a valid access token (JWT which contains the user's
  ID and the session ID).
- The access token can be obtained by logging in to an exising account (see `POST /sessions` and `POST /sessions/oauth`)
  or by creating an account (see `POST /users`). This access token is only valid for a short period of time
  (usually 5 minutes).
- If the access token is expired, a new access token can be obtained by using the refresh token (see `PUT /session`)
  which is also returned when creating a session. This will also invalidate the refresh token and generate a new one.
- If the refresh token is not used to refresh the session within a configured period of time (usually 30 days) the
  session expires and the user must log in again on this device.

## Special parameters
- In addition to the usual user ids the `user_id` path parameter used in most endpoints also accepts the special values
  `me` and `self` which refer to the currently authenticated user.

## Requirements
Some endpoints require one or more of the following conditions to be met:
- **USER**: The user is authenticated and has a valid session.
- **VERIFIED**: The email of the authenticated user is verified (or the user is an admin). Requires **USER**.
- **SELF**: The authenticated user must be the same as the affected user (`user_id` parameter). Requires **USER**.
- **ADMIN**: The authenticated user must be an admin. Requires **USER**.
"""

import asyncio
from typing import Awaitable, Callable, TypeVar

from fastapi import FastAPI, HTTPException, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__
from .database import db, db_context
from .endpoints import ROUTER, TAGS
from .logger import get_logger, setup_sentry
from .models import User
from .models.session import clean_expired_sessions
from .settings import settings
from .utils.debug import check_responses
from .utils.docs import add_endpoint_links_to_openapi_docs


T = TypeVar("T")

logger = get_logger(__name__)

app = FastAPI(
    title="Bootstrap Academy Backend: Auth Microservice",
    description=__doc__,
    version=__version__,
    root_path=settings.root_path,
    root_path_in_servers=False,
    servers=[{"url": settings.root_path}] if settings.root_path else None,
    openapi_tags=TAGS,
)
app.include_router(ROUTER)

if settings.debug:
    app.middleware("http")(check_responses)


add_endpoint_links_to_openapi_docs(app.openapi())

if settings.sentry_dsn:
    logger.debug("initializing sentry")
    setup_sentry(app, settings.sentry_dsn, "auth-ms", __version__)

if settings.debug:
    app.add_middleware(
        CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"]
    )


@app.middleware("http")
async def db_session(request: Request, call_next: Callable[..., Awaitable[T]]) -> T:
    async with db_context():
        return await call_next(request)


@app.exception_handler(StarletteHTTPException)
async def rollback_on_exception(request: Request, exc: HTTPException) -> Response:
    await db.session.rollback()
    return await http_exception_handler(request, exc)


async def clean_expired_sessions_loop() -> None:
    while True:
        try:
            await clean_expired_sessions()
        except Exception as e:
            logger.exception(e)
        await asyncio.sleep(20 * 60)


@app.on_event("startup")
async def on_startup() -> None:
    asyncio.create_task(clean_expired_sessions_loop())

    async with db_context():
        await User.initialize()


@app.on_event("shutdown")
async def on_shutdown() -> None:
    pass


@app.head("/status", include_in_schema=False)
async def status() -> None:
    pass
