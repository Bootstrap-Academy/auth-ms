from fastapi import APIRouter

from . import user


INTERNAL_ROUTERS: list[APIRouter] = [module.router for module in [user]]
