"""OAuth related endpoints"""

from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from aiohttp import BasicAuth, ClientSession
from fastapi import APIRouter

from .. import models
from ..auth import get_user
from ..database import db, filter_by
from ..exceptions.auth import admin_responses
from ..exceptions.oauth import (
    ConnectionNotFoundError,
    InvalidOAuthCodeError,
    ProviderNotFoundError,
    RemoteAlreadyLinkedError,
)
from ..exceptions.user import CannotDeleteLastLoginMethodError, UserNotFoundError
from ..schemas.oauth import OAuthConnection, OAuthLogin, OAuthProvider
from ..settings import settings
from ..utils.docs import responses


router = APIRouter()


def add_qs(url: str, q: dict[str, str]) -> str:
    scheme, netloc, path, params, query, fragment = urlparse(url)
    return urlunparse((scheme, netloc, path, params, urlencode(dict(parse_qsl(query)) | q), fragment))


async def resolve_code(login: OAuthLogin) -> tuple[str, str | None]:
    if login.provider_id not in settings.oauth_providers:
        raise ProviderNotFoundError

    provider = settings.oauth_providers[login.provider_id]
    async with (
        ClientSession() as session,
        session.post(
            provider.token_url,
            data={
                "grant_type": "authorization_code",
                "code": login.code,
                "redirect_uri": login.redirect_uri,
                "client_id": provider.client_id,
            },
            headers={"Accept": "application/json"},
            auth=BasicAuth(provider.client_id, provider.client_secret),
        ) as response,
    ):
        if response.status != 200:
            raise InvalidOAuthCodeError

        data = await response.json()

    access_token: str | None = data.get("access_token")
    if not access_token:
        raise InvalidOAuthCodeError

    def fmt(x: str) -> str:
        return x.format(access_token=access_token)

    async with (
        ClientSession() as session,
        session.get(
            fmt(provider.userinfo_url), headers={k: fmt(v) for k, v in provider.userinfo_headers.items()}
        ) as response,
    ):
        if response.status != 200:
            raise InvalidOAuthCodeError

        data = await response.json()

    remote_user_id = provider.userinfo_id_path.input(data).first()
    display_name = provider.userinfo_name_path.input(data).first()

    return str(remote_user_id), str(display_name) if display_name else None


@router.get("/oauth/providers", responses=responses(list[OAuthProvider]))
async def get_oauth_providers() -> Any:
    """Return a list of all available OAuth providers."""

    return [
        {
            "id": k,
            "name": v.name,
            "authorize_url": add_qs(v.authorize_url, {"response_type": "code", "client_id": v.client_id}),
        }
        for k, v in settings.oauth_providers.items()
    ]


@router.get("/oauth/links/{user_id}", responses=admin_responses(list[OAuthConnection], UserNotFoundError))
async def get_oauth_connections(
    user: models.User = get_user(models.User.oauth_connections, require_self_or_admin=True)
) -> Any:
    """
    Return a list of all OAuth connections for the given user.

    *Requirements:* **SELF** or **ADMIN**
    """

    return [connection.serialize for connection in user.oauth_connections]


@router.post(
    "/oauth/links/{user_id}",
    responses=admin_responses(
        OAuthConnection, UserNotFoundError, RemoteAlreadyLinkedError, ProviderNotFoundError, InvalidOAuthCodeError
    ),
)
async def create_oauth_connection(login: OAuthLogin, user: models.User = get_user(require_self_or_admin=True)) -> Any:
    """
    Create a new OAuth connection for the given user.

    The client can use almost the same procedure as described in the `POST /sessions/oauth` endpoint documentation.

    *Requirements:* **SELF** or **ADMIN**
    """

    user_id, display_name = await resolve_code(login)

    if await db.exists(filter_by(models.OAuthUserConnection, provider_id=login.provider_id, remote_user_id=user_id)):
        raise RemoteAlreadyLinkedError

    connection = await models.OAuthUserConnection.create(user.id, login.provider_id, user_id, display_name)

    return connection.serialize


@router.delete(
    "/oauth/links/{user_id}/{connection_id}",
    responses=admin_responses(bool, UserNotFoundError, CannotDeleteLastLoginMethodError, ConnectionNotFoundError),
)
async def delete_oauth_connection(
    connection_id: str, user: models.User = get_user(models.User.oauth_connections, require_self_or_admin=True)
) -> Any:
    """
    Delete an existing OAuth connection.

    *Requirements:* **SELF** or **ADMIN**
    """

    if not user.password and len(user.oauth_connections) <= 1:
        raise CannotDeleteLastLoginMethodError

    if not (connection := await db.get(models.OAuthUserConnection, id=connection_id, user_id=user.id)):
        raise ConnectionNotFoundError

    await db.delete(connection)
    return True
