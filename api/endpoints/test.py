"""Test endpoints (to be removed later)"""

from typing import Any

from fastapi import APIRouter, Depends

from ..auth import require_verified_email, user_auth
from ..exceptions.auth import user_responses
from ..exceptions.user import EmailNotVerifiedError
from ..schemas.test import TestResponse
from ..utils.docs import responses


router = APIRouter(tags=["test"])


@router.get("/test", responses=responses(TestResponse))
async def test() -> Any:
    """Test endpoint."""

    return {"result": "hello world"}


@router.get("/auth", dependencies=[user_auth], responses=user_responses(list[int]))
async def test_auth() -> Any:
    """
    Test endpoint with authentication.

    *Requirements:* **USER**
    """

    return [1, 2, 3]


@router.get(
    "/verified", dependencies=[require_verified_email], responses=user_responses(TestResponse, EmailNotVerifiedError)
)
async def test_verified() -> Any:
    """
    Test endpoint with email verification.

    *Requirements:* **VERIFIED**
    """

    return {"result": "hello world"}
