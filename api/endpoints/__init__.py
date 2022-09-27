from typing import Any

from fastapi import APIRouter

from . import contact, oauth, recaptcha, session, user
from .internal import INTERNAL_ROUTERS
from ..auth import internal_auth


ROUTER = APIRouter()
TAGS: list[dict[str, Any]] = []

for module in [user, session, oauth, recaptcha, contact]:
    name = module.__name__.split(".")[-1]
    router = APIRouter(tags=[name])
    router.include_router(module.router)
    ROUTER.include_router(router)

    TAGS.append({"name": name, "description": module.__doc__ or ""})

TAGS.append({"name": "internal", "description": "Internal endpoints"})

for r in INTERNAL_ROUTERS:
    router = APIRouter(prefix="/_internal", tags=["internal"], dependencies=[internal_auth])
    router.include_router(r)
    ROUTER.include_router(router)
