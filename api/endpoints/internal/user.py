from typing import Any

from fastapi import APIRouter

from api import models
from api.auth import get_user
from api.exceptions.auth import internal_responses
from api.exceptions.user import UserNotFoundError
from api.schemas.user import User


router = APIRouter()


@router.get("/users/{user_id}", responses=internal_responses(User, UserNotFoundError))
async def get_user_by_id(user: models.User = get_user()) -> Any:
    return user.serialize
