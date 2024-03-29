from unittest.mock import AsyncMock, MagicMock

import pytest
from _pytest.monkeypatch import MonkeyPatch
from pytest_mock import MockerFixture
from sqlalchemy import func

from api.database import db, db_wrapper, select
from api.models import User
from api.settings import settings
from api.utils.passwords import verify_password
from api.utils.utc import utcfromtimestamp, utcnow


@pytest.mark.skip(reason="todo")
@pytest.mark.parametrize(
    "enabled,admin,password,mfa,verified,description,tags,newsletter",
    [
        (True, False, "asdf", False, True, None, [], True),
        (False, True, None, True, False, "Hello World!", ["foo", "bar"], False),
        (True, True, None, False, True, None, ["a", "b", "c", "d", "e", "f"], False),
    ],
)
async def test__serialize(
    enabled: bool,
    admin: bool,
    password: str | None,
    mfa: bool,
    verified: bool,
    description: str,
    tags: list[str],
    newsletter: bool,
) -> None:
    obj = User(
        id="user_id",
        name="user_name",
        display_name="User Name 42",
        email="user42@example.com",
        email_verification_code=None if verified else "asdf-1234",
        registration=utcfromtimestamp(123456),
        last_login=utcfromtimestamp(345678),
        last_name_change=utcfromtimestamp(378474),
        enabled=enabled,
        admin=admin,
        password=password,
        mfa_enabled=mfa,
        description=description,
        newsletter=newsletter,
    )
    obj.tags = tags

    assert obj.serialize == {
        "id": "user_id",
        "name": "user_name",
        "display_name": "User Name 42",
        "email": "user42@example.com",
        "email_verified": verified,
        "registration": 123456,
        "last_login": 345678,
        "last_name_change": 378474,
        "enabled": enabled,
        "admin": admin,
        "password": bool(password),
        "mfa_enabled": mfa,
        "description": description,
        "tags": tags,
        "newsletter": newsletter,
        "avatar_url": "https://www.gravatar.com/avatar/4954756b2cdeccd47bc819726b270303",
    }


@pytest.mark.parametrize("enabled,admin,password", [(True, False, "asdf"), (False, True, None), (True, True, None)])
@db_wrapper
async def test__create(enabled: bool, admin: bool, password: str | None) -> None:
    obj = await User.create("user_name", "User Name 42", "user42@example.com", password, enabled, admin)
    users = await db.all(select(User))
    assert users == [obj]

    assert obj.name == "user_name"
    assert obj.display_name == "User Name 42"
    assert obj.email == "user42@example.com"
    assert obj.email_verified is False

    if password:
        assert await verify_password(password, obj.password)
    else:
        assert obj.password is None

    assert abs(utcnow() - obj.registration).total_seconds() < 10
    assert obj.last_login is None
    assert obj.enabled == enabled
    assert obj.admin == admin
    assert obj.mfa_secret is None
    assert obj.mfa_enabled is False
    assert obj.mfa_recovery_code is None


async def test__filter_by_name() -> None:
    assert User.filter_by_name("UserName") == select(User).where(func.lower(User.name) == "username")


@pytest.mark.parametrize("first_user", [True, False])
@db_wrapper
async def test__initialize(first_user: bool, monkeypatch: MonkeyPatch, mocker: MockerFixture) -> None:
    monkeypatch.setattr(settings, "admin_username", "admin_username")
    monkeypatch.setattr(settings, "admin_email", "admin_email")
    monkeypatch.setattr(settings, "admin_password", "admin_password")
    check_email_deliverability = mocker.patch("api.models.user.check_email_deliverability", new_callable=AsyncMock)

    if not first_user:
        await User.create("other_user", "Other user", "other.user@example.com", "other_password", True, True)

    await User.initialize()

    users = await db.all(select(User))
    assert len(users) == 1
    assert users[0].name == "admin_username" if first_user else "other_user"

    if first_user:
        check_email_deliverability.assert_called_once_with("admin_email")


@pytest.mark.parametrize("arg,dbv,ok", [("foo", "foo", True), ("foo", "bar", False), ("foo", None, False)])
async def test__check_password(arg: str, dbv: str | None, ok: bool, mocker: MockerFixture) -> None:
    mocker.patch("api.models.user.verify_password", AsyncMock(side_effect=str.__eq__))

    user = User(password=dbv)
    assert await user.check_password(arg) == ok


@pytest.mark.parametrize("pw", ["asdf", None])
async def test__change_password(pw: str | None, mocker: MockerFixture) -> None:
    hash_password = mocker.patch("api.models.user.hash_password", new_callable=AsyncMock)

    user = User(password="foobar")  # noqa: S106
    await user.change_password(pw)

    if pw:
        hash_password.assert_called_once_with(pw)
        assert user.password == await hash_password()
    else:
        hash_password.assert_not_called()
        assert user.password is None


async def test__create_session(mocker: MockerFixture) -> None:
    create = mocker.patch("api.models.session.Session.create", new_callable=AsyncMock)

    user = User(id="my_user_id")
    session = await user.create_session("my device name")

    create.assert_called_once_with(user, "my device name")
    assert session == await create()
    assert user.last_login is not None
    assert abs(utcnow() - user.last_login).total_seconds() < 10


async def test__from_access_token__invalid_jwt(mocker: MockerFixture) -> None:
    decode_jwt = mocker.patch("api.models.user.decode_jwt", MagicMock(return_value=None))

    assert await User.from_access_token("my_token") is None
    decode_jwt.assert_called_once_with("my_token", require=["uid", "sid", "rt"])


async def test__from_access_token__logout(mocker: MockerFixture) -> None:
    data = {"rt": "my_refresh_token"}
    decode_jwt = mocker.patch("api.models.user.decode_jwt", MagicMock(return_value=data))
    exists = mocker.patch("api.models.user.redis.exists", AsyncMock(return_value=True))

    assert await User.from_access_token("my_token") is None
    decode_jwt.assert_called_once_with("my_token", require=["uid", "sid", "rt"])
    exists.assert_called_once_with("session_logout:my_refresh_token")


@pytest.mark.parametrize("user_exists", [True, False])
@db_wrapper
async def test__from_access_token__valid(user_exists: bool, mocker: MockerFixture) -> None:
    data = {"rt": "my_refresh_token", "uid": "my_uid"}
    decode_jwt = mocker.patch("api.models.user.decode_jwt", MagicMock(return_value=data))
    exists = mocker.patch("api.models.user.redis.exists", AsyncMock(return_value=False))

    (await User.create("other_user_name", "ou", "ou@example.com", "other_password", True, True)).id = "other_uid"
    user: User | None = None
    if user_exists:
        user = await User.create("my_user_name", "mu", "mu@example.com", "my_password", True, True)
        user.id = "my_uid"

    result = await User.from_access_token("my_token")

    decode_jwt.assert_called_once_with("my_token", require=["uid", "sid", "rt"])
    exists.assert_called_once_with("session_logout:my_refresh_token")

    assert result is user


async def test__logout() -> None:
    user = MagicMock()
    user.sessions = [AsyncMock() for _ in range(5)]

    await User.logout(user)

    for session in user.sessions:
        session.logout.assert_called_once_with()
