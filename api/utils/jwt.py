from datetime import timedelta
from typing import Any, cast

import jwt

from .utc import utcnow
from ..settings import settings


def encode_jwt(data: dict[Any, Any], ttl: timedelta) -> str:
    return jwt.encode({**data, "exp": utcnow() + ttl}, settings.jwt_secret, "HS256")


def decode_jwt(
    token: str, *, require: list[str] | None = None, audience: list[str] | None = None
) -> dict[Any, Any] | None:
    try:
        return cast(
            dict[Any, Any],
            jwt.decode(
                token,
                settings.jwt_secret,
                ["HS256"],
                audience=audience,
                options={"require": [*{*(require or []), "exp"}], "verify_aud": bool(audience)},
            ),
        )
    except jwt.InvalidTokenError:
        return None
