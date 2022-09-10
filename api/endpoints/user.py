"""Endpoints for user management"""

import hashlib
from typing import Any, cast

from fastapi import APIRouter, Body, Query, Request
from pyotp import random_base32
from sqlalchemy import asc, func, or_

from .. import models
from ..auth import admin_auth, get_user, is_admin, user_auth
from ..database import db, filter_by, select
from ..exceptions.auth import PermissionDeniedError, admin_responses, user_responses
from ..exceptions.oauth import InvalidOAuthTokenError, RemoteAlreadyLinkedError
from ..exceptions.user import (
    CannotDeleteLastLoginMethodError,
    EmailAlreadyExistsError,
    EmailAlreadyVerifiedError,
    InvalidCodeError,
    InvalidEmailError,
    InvalidVerificationCodeError,
    MFAAlreadyEnabledError,
    MFANotEnabledError,
    MFANotInitializedError,
    NoLoginMethodError,
    OAuthRegistrationDisabledError,
    PasswordResetFailedError,
    RecaptchaError,
    RegistrationDisabledError,
    UserAlreadyExistsError,
    UserNotFoundError,
)
from ..redis import redis
from ..schemas.session import LoginResponse
from ..schemas.user import (
    MFA_CODE_REGEX,
    VERIFICATION_CODE_REGEX,
    CreateUser,
    RequestPasswordReset,
    ResetPassword,
    UpdateUser,
    User,
    UsersResponse,
)
from ..settings import settings
from ..utils.docs import responses
from ..utils.email import check_email_deliverability
from ..utils.mfa import check_mfa_code
from ..utils.recaptcha import check_recaptcha, recaptcha_enabled


router = APIRouter()


@router.get("/users", dependencies=[admin_auth], responses=admin_responses(UsersResponse))
async def get_users(
    limit: int = Query(100, ge=1, le=100, description="The maximum number of users to return"),
    offset: int = Query(0, ge=0, description="The number of users to skip for pagination"),
    name: str | None = Query(None, max_length=256, description="A search term to match against the user's name"),
    email: str | None = Query(None, max_length=256, description="A search term to match against the user's email"),
    enabled: bool | None = Query(None, description="Return only users with the given enabled status"),
    admin: bool | None = Query(None, description="Return only users with the given admin status"),
    mfa_enabled: bool | None = Query(None, description="Return only users with the given MFA status"),
) -> Any:
    """
    Return a list of all users matching the given criteria.

    *Requirements:* **ADMIN**
    """

    query = select(models.User)
    order = []
    if name:
        query = query.where(
            or_(
                func.lower(models.User.name).contains(name.lower(), autoescape=True),
                func.lower(models.User.display_name).contains(name.lower(), autoescape=True),
            )
        )
        order.append(asc(func.length(models.User.name)))
    if email:
        query = query.where(func.lower(models.User.email).contains(email.lower(), autoescape=True))
        order.append(asc(func.length(models.User.email)))
    if enabled is not None:
        query = query.where(models.User.enabled == enabled)
    if admin is not None:
        query = query.where(models.User.admin == admin)
    if mfa_enabled is not None:
        query = query.where(models.User.mfa_enabled == mfa_enabled)

    return {
        "total": await db.count(query),
        "users": [
            user.serialize
            async for user in await db.stream(
                query.order_by(*order, asc(models.User.registration)).limit(limit).offset(offset)
            )
        ],
    }


@router.get("/users/{user_id}", responses=admin_responses(User, UserNotFoundError))
async def get_user_by_id(user: models.User = get_user(require_self_or_admin=True)) -> Any:
    """
    Return a user by ID.

    *Requirements:* **SELF** or **ADMIN**
    """

    return user.serialize


@router.post(
    "/users",
    responses=user_responses(
        LoginResponse,
        UserAlreadyExistsError,
        RemoteAlreadyLinkedError,
        NoLoginMethodError,
        RegistrationDisabledError,
        OAuthRegistrationDisabledError,
        RecaptchaError,
        InvalidOAuthTokenError,
        InvalidEmailError,
    ),
)
async def create_user(data: CreateUser, request: Request, admin: bool = is_admin) -> Any:
    """
    Create a new user and a new session for them.

    If the **ADMIN** requirement is *not* met:
    - The user is always created as a regular user (`"enabled": true, "admin": false`).
    - A recaptcha response is required if recaptcha is enabled (see `GET /recaptcha`).

    The value of the `User-agent` header is used as the device name of the created session.
    """

    if not data.oauth_register_token and not data.password:
        raise NoLoginMethodError
    if not admin:
        if data.password and not settings.open_registration:
            raise RegistrationDisabledError
        if data.oauth_register_token and not settings.open_oauth_registration:
            raise OAuthRegistrationDisabledError

        if recaptcha_enabled() and not (data.recaptcha_response and await check_recaptcha(data.recaptcha_response)):
            raise RecaptchaError

        if not await check_email_deliverability(data.email):
            raise InvalidEmailError

    if await db.exists(models.User.filter_by_name(data.name)):
        raise UserAlreadyExistsError
    if await db.exists(models.User.filter_by_email(data.email)):
        raise EmailAlreadyExistsError

    if data.oauth_register_token:
        async with redis.pipeline() as pipe:
            await pipe.get(key1 := f"oauth_register_token:{data.oauth_register_token}:provider")
            await pipe.get(key2 := f"oauth_register_token:{data.oauth_register_token}:user_id")
            await pipe.get(key3 := f"oauth_register_token:{data.oauth_register_token}:display_name")
            provider_id, remote_user_id, display_name = await pipe.execute()

        if not provider_id or not remote_user_id:
            raise InvalidOAuthTokenError

        await redis.delete(key1, key2, key3)

        if await db.exists(
            filter_by(models.OAuthUserConnection, provider_id=provider_id, remote_user_id=remote_user_id)
        ):
            raise RemoteAlreadyLinkedError

    user = await models.User.create(
        data.name, data.display_name, data.email, data.password, data.enabled or not admin, data.admin and admin
    )

    if data.oauth_register_token:
        await models.OAuthUserConnection.create(user.id, provider_id, remote_user_id, display_name)

    session, access_token, refresh_token = await user.create_session(request.headers.get("User-agent", "")[:256])
    return {
        "user": user.serialize,
        "session": session.serialize,
        "access_token": access_token,
        "refresh_token": refresh_token,
    }


@router.patch(
    "/users/{user_id}",
    responses=admin_responses(
        User,
        UserNotFoundError,
        UserAlreadyExistsError,
        EmailAlreadyExistsError,
        InvalidEmailError,
        CannotDeleteLastLoginMethodError,
    ),
)
async def update_user(
    data: UpdateUser,
    user: models.User = get_user(models.User.sessions, models.User.oauth_connections, require_self_or_admin=True),
    admin: bool = is_admin,
    session: models.Session = user_auth,
) -> Any:
    """
    Update an existing user.

    - Changing the email address will also set it to unverified.
    - Setting `password` to `null` or omitting it will not change the user's password while setting it to
      the empty string will remove the user's password.
    - Disabling a user will also log them out.
    - A user can never change their own admin status.

    *Requirements:* **SELF** or **ADMIN**

    If the **ADMIN** requirement is *not* met:
    - The username cannot be changed.
    - The user cannot be enabled or disabled.
    - The email verification status cannot be changed.
    - The admin status cannot be changed.
    """

    if data.name is not None and data.name != user.name:
        if not admin:
            raise PermissionDeniedError
        if await db.exists(models.User.filter_by_name(data.name).where(models.User.id != user.id)):
            raise UserAlreadyExistsError

        user.name = data.name

    if data.display_name is not None and data.display_name != user.display_name:
        user.display_name = data.display_name

    if data.email is not None and data.email != user.email:
        if await db.exists(models.User.filter_by_email(data.email).where(models.User.id != user.id)):
            raise EmailAlreadyExistsError
        if not admin and not await check_email_deliverability(data.email):
            raise InvalidEmailError

        user.email = data.email
        user.email_verified = False
        await user.invalidate_access_tokens()

    if data.email_verified is not None and data.email_verified != user.email_verified:
        if not admin:
            raise PermissionDeniedError

        user.email_verified = data.email_verified
        await user.invalidate_access_tokens()

    if data.password is not None:
        if not data.password and not user.oauth_connections:
            raise CannotDeleteLastLoginMethodError

        await user.change_password(data.password)

    if data.enabled is not None and data.enabled != user.enabled:
        if user.id == session.user_id:
            raise PermissionDeniedError

        user.enabled = data.enabled
        if not user.enabled:
            await user.logout()

    if data.admin is not None and data.admin != user.admin:
        if user.id == session.user_id:
            raise PermissionDeniedError

        user.admin = data.admin
        await user.invalidate_access_tokens()

    return user.serialize


@router.post(
    "/users/{user_id}/email",
    responses=admin_responses(bool, UserNotFoundError, EmailAlreadyVerifiedError, InvalidEmailError),
)
async def request_verification_email(user: models.User = get_user(require_self_or_admin=True)) -> Any:
    """
    Request a verification email.

    This will send an email to the user's email address with a code for the `PUT /users/{user_id}/email` endpoint to
    verify their email address.

    *Requirements:* **SELF** or **ADMIN**
    """

    if user.email_verified:
        raise EmailAlreadyVerifiedError

    try:
        await user.send_verification_email()
    except ValueError:
        raise InvalidEmailError
    return True


@router.put(
    "/users/{user_id}/email",
    responses=admin_responses(User, UserNotFoundError, EmailAlreadyVerifiedError, InvalidVerificationCodeError),
)
async def verify_email(
    code: str = Body(embed=True, regex=VERIFICATION_CODE_REGEX, description="The code from the verification email"),
    user: models.User = get_user(models.User.sessions, require_self_or_admin=True),
) -> Any:
    """
    Verify a user's email address.

    To request a verification email, use the `POST /users/{user_id}/email` endpoint.

    *Requirements:* **SELF** or **ADMIN**
    """

    if user.email_verified:
        raise EmailAlreadyVerifiedError

    if code.lower() != cast(str, user.email_verification_code).lower():
        raise InvalidVerificationCodeError

    user.email_verified = True
    await user.invalidate_access_tokens()
    return user.serialize


@router.post("/users/{user_id}/mfa", responses=admin_responses(str, UserNotFoundError, MFAAlreadyEnabledError))
async def initialize_mfa(user: models.User = get_user(require_self_or_admin=True)) -> Any:
    """
    Initialize MFA for a user by generating a new TOTP secret.

    The TOTP secret generated by this endpoint should be used to configure the user's MFA app. After that the
    `PUT /users/{user_id}/mfa` endpoint can be used to enable MFA.

    *Requirements:* **SELF** or **ADMIN**
    """

    if user.mfa_enabled:
        raise MFAAlreadyEnabledError

    user.mfa_secret = random_base32(32)
    return user.mfa_secret


@router.put(
    "/users/{user_id}/mfa",
    responses=admin_responses(str, UserNotFoundError, MFAAlreadyEnabledError, MFANotInitializedError, InvalidCodeError),
)
async def enable_mfa(
    code: str = Body(embed=True, regex=MFA_CODE_REGEX, description="The 6-digit code generated by the user's MFA app"),
    user: models.User = get_user(require_self_or_admin=True),
) -> Any:
    """
    Enable MFA for a user and generate the recovery code.

    This endpoint should be used after initializing MFA (see `POST /users/{user_id}/mfa`) to actually enable it
    on the account.

    The recovery code generated by this endpoint can be used to login if the user has lost their MFA app and should
    therefore be kept in a safe place.

    *Requirements:* **SELF** or **ADMIN**
    """

    if user.mfa_enabled:
        raise MFAAlreadyEnabledError
    if not user.mfa_secret:
        raise MFANotInitializedError
    if not await check_mfa_code(code, user.mfa_secret):
        raise InvalidCodeError

    recovery_code = "-".join(random_base32()[:6] for _ in range(4))
    user.mfa_recovery_code = hashlib.sha256(recovery_code.encode()).hexdigest()
    user.mfa_enabled = True

    return recovery_code


@router.delete("/users/{user_id}/mfa", responses=admin_responses(bool, UserNotFoundError, MFANotEnabledError))
async def disable_mfa(user: models.User = get_user(require_self_or_admin=True)) -> Any:
    """
    Disable MFA for a user.

    *Requirements:* **SELF** or **ADMIN**
    """

    if not user.mfa_secret and not user.mfa_enabled:
        raise MFANotEnabledError

    user.mfa_enabled = False
    user.mfa_secret = None
    user.mfa_recovery_code = None
    return True


@router.delete("/users/{user_id}", responses=admin_responses(bool, UserNotFoundError))
async def delete_user(
    user: models.User = get_user(models.User.sessions, require_self_or_admin=True), admin: bool = is_admin
) -> Any:
    """
    Delete a user.

    If only one admin exists, this user cannot be deleted.

    *Requirements:* **SELF** or **ADMIN**
    """

    if not (settings.open_registration or settings.open_oauth_registration) and not admin:
        raise PermissionDeniedError

    if user.admin and not await db.exists(filter_by(models.User, admin=True).filter(models.User.id != user.id)):
        raise PermissionDeniedError

    await user.logout()
    await db.delete(user)
    return True


@router.post("/password_reset", responses=responses(bool, RecaptchaError, InvalidEmailError))
async def request_password_reset(data: RequestPasswordReset) -> Any:
    """
    Request a password reset email.

    This will send an email to the user's email address with a code for the `PUT /password_reset` endpoint to
    reset their password. This code expires after one hour.
    """

    if recaptcha_enabled() and not (data.recaptcha_response and await check_recaptcha(data.recaptcha_response)):
        raise RecaptchaError

    if user := await db.first(models.User.filter_by_email(data.email)):
        try:
            await user.send_password_reset_email()
        except ValueError:
            raise InvalidEmailError

    return True


@router.put("/password_reset", responses=responses(User, PasswordResetFailedError))
async def reset_password(data: ResetPassword) -> Any:
    """
    Reset a user's password.

    To request a password reset email, use the `POST /password_reset` endpoint.

    *Requirements:* **SELF** or **ADMIN**
    """

    user: models.User | None = await db.first(models.User.filter_by_email(data.email))
    if not user:
        raise PasswordResetFailedError

    if not await user.check_password_reset_code(data.code):
        raise PasswordResetFailedError

    await user.change_password(data.password)
    return user.serialize
