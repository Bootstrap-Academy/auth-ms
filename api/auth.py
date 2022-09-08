from enum import Enum
from typing import Any, Awaitable, Callable

from fastapi import Depends, Request
from fastapi.openapi.models import HTTPBearer
from fastapi.security.base import SecurityBase
from sqlalchemy import Column

from .database import db
from .exceptions.auth import InvalidTokenError, PermissionDeniedError
from .exceptions.user import EmailNotVerifiedError, UserNotFoundError
from .models import Session, User
from .utils.jwt import decode_jwt


def get_token(request: Request) -> str:
    authorization: str = request.headers.get("Authorization", "")
    return authorization.removeprefix("Bearer ")


class PermissionLevel(Enum):
    PUBLIC = 0
    USER = 1
    ADMIN = 2


class HTTPAuth(SecurityBase):
    def __init__(self) -> None:
        self.model = HTTPBearer()
        self.scheme_name = self.__class__.__name__

    async def __call__(self, request: Request) -> Any:
        raise NotImplementedError


class JWTAuth(HTTPAuth):
    async def __call__(self, request: Request) -> dict[Any, Any]:
        if (data := decode_jwt(get_token(request))) is None:
            raise InvalidTokenError
        return data


class UserAuth(HTTPAuth):
    def __init__(self, min_level: PermissionLevel) -> None:
        super().__init__()

        self.min_level: PermissionLevel = min_level

    async def __call__(self, request: Request) -> Session | None:
        session: Session | None = await Session.from_access_token(get_token(request))

        if self.min_level == PermissionLevel.PUBLIC:
            return session

        if not session:
            raise InvalidTokenError

        if self.min_level == PermissionLevel.ADMIN and not session.user.admin:
            raise PermissionDeniedError

        return session


# static_token_auth = Depends(StaticTokenAuth("secret token"))
jwt_auth = Depends(JWTAuth())

public_auth = Depends(UserAuth(PermissionLevel.PUBLIC))
user_auth = Depends(UserAuth(PermissionLevel.USER))
admin_auth = Depends(UserAuth(PermissionLevel.ADMIN))


@Depends
async def is_admin(session: Session | None = public_auth) -> bool:
    return session is not None and session.user.admin


async def _require_verified_email(session: Session = user_auth) -> None:
    if not session.user.email_verified:
        raise EmailNotVerifiedError


require_verified_email = Depends(_require_verified_email)


def _get_user_dependency(*args: Column[Any]) -> Callable[[str, Session | None], Awaitable[User]]:
    async def default_dependency(user_id: str, session: Session | None = public_auth) -> User:
        if user_id.lower() in ["me", "self"] and session:
            user_id = session.user_id
        if not (user := await db.get(User, *args, id=user_id)):
            raise UserNotFoundError

        return user

    return default_dependency


def _get_user_privileged_dependency(*args: Column[Any]) -> Callable[[str, Session], Awaitable[User]]:
    async def self_or_admin_dependency(user_id: str, session: Session = user_auth) -> User:
        if user_id.lower() in ["me", "self"]:
            user_id = session.user_id
        if session.user_id != user_id and not session.user.admin:
            raise PermissionDeniedError

        return await _get_user_dependency(*args)(user_id, None)

    return self_or_admin_dependency


def get_user(*args: Column[Any], require_self_or_admin: bool = False) -> Any:
    return Depends(_get_user_privileged_dependency(*args) if require_self_or_admin else _get_user_dependency(*args))
