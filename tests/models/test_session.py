from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest
from _pytest.monkeypatch import MonkeyPatch
from pytest_mock import MockerFixture

from api.database import db, db_context, db_wrapper, select
from api.models import Session, User
from api.models import session as _session
from api.models.session import SessionExpiredError
from api.settings import settings
from api.utils.utc import utcfromtimestamp, utcnow


TEST_HASH = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"


async def _get_user() -> User:
    return await User.create("my_user_name", "mu", "mu@example.com", "my_password", True, True)


async def test__hash_token() -> None:
    assert _session._hash_token("test") == TEST_HASH


async def test__serialize() -> None:
    obj = Session(id="my_id", user_id="my_user_id", device_name="my_device_name", last_update=utcfromtimestamp(1234567))

    assert obj.serialize == {
        "id": "my_id",
        "user_id": "my_user_id",
        "device_name": "my_device_name",
        "last_update": 1234567,
    }


@db_wrapper
async def test__create(mocker: MockerFixture) -> None:
    generate_access_token = mocker.patch("api.models.session.Session._generate_access_token")
    user = await _get_user()

    obj, at, rt = await Session.create(user, "my_device_name")
    sessions = await db.all(select(Session))
    assert sessions == [obj]

    generate_access_token.assert_called_once_with()

    assert obj.user_id == user.id
    assert obj.device_name == "my_device_name"
    assert (utcnow() - obj.last_update).total_seconds() < 10
    assert obj.refresh_token == _session._hash_token(rt)
    assert at == generate_access_token()


async def test__generate_access_token(mocker: MockerFixture, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "access_token_ttl", 42)
    encode_jwt = mocker.patch("api.models.session.encode_jwt")
    user = MagicMock()

    session = Session(user_id=user.id, user=user, id="my_id", refresh_token="my_refresh_token")  # noqa: S106

    result = session._generate_access_token()

    encode_jwt.assert_called_once_with(
        {"uid": user.id, "sid": "my_id", "rt": "my_refresh_token", "data": user.jwt_data}, timedelta(seconds=42)
    )
    assert result == encode_jwt()


async def test__from_access_token__invalid_jwt(mocker: MockerFixture) -> None:
    decode_jwt = mocker.patch("api.models.session.decode_jwt", MagicMock(return_value=None))

    assert await Session.from_access_token("my_token") is None
    decode_jwt.assert_called_once_with("my_token", require=["uid", "sid", "rt"])


async def test__from_access_token__logout(mocker: MockerFixture) -> None:
    data = {"rt": "my_refresh_token"}
    decode_jwt = mocker.patch("api.models.session.decode_jwt", MagicMock(return_value=data))
    exists = mocker.patch("api.models.session.redis.exists", AsyncMock(return_value=True))

    assert await Session.from_access_token("my_token") is None
    decode_jwt.assert_called_once_with("my_token", require=["uid", "sid", "rt"])
    exists.assert_called_once_with("session_logout:my_refresh_token")


@pytest.mark.parametrize("session_exists", [True, False])
@db_wrapper
async def test__from_access_token__valid(session_exists: bool, mocker: MockerFixture) -> None:
    data = {"rt": "my_refresh_token", "sid": "my_sid"}
    decode_jwt = mocker.patch("api.models.session.decode_jwt", MagicMock(return_value=data))
    exists = mocker.patch("api.models.session.redis.exists", AsyncMock(return_value=False))

    user = await _get_user()
    await user.create_session("other_device_name")
    session: Session | None = None
    if session_exists:
        session, *_ = await user.create_session("my_device_name")
        session.id = "my_sid"

    result = await Session.from_access_token("my_token")

    decode_jwt.assert_called_once_with("my_token", require=["uid", "sid", "rt"])
    exists.assert_called_once_with("session_logout:my_refresh_token")

    assert result is session
    if result:
        assert result.user is user


@db_wrapper
async def test__refresh__invalid_refresh_token() -> None:
    with pytest.raises(ValueError):
        await Session.refresh("test")


@db_wrapper
async def test__refresh__session_expired(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "refresh_token_ttl", 42)

    user = await _get_user()
    session, _, rt = await user.create_session("my_device_name")
    session.last_update = utcnow() - timedelta(seconds=43)
    session.logout = AsyncMock()  # type: ignore

    with pytest.raises(SessionExpiredError):
        await Session.refresh(rt)

    session.logout.assert_called_once_with()


@db_wrapper
async def test__refresh__ok(mocker: MockerFixture, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "access_token_ttl", 1337)
    monkeypatch.setattr(settings, "refresh_token_ttl", 2)
    redis = mocker.patch("api.models.session.redis", new_callable=AsyncMock)

    user = await _get_user()
    session, _, old_rt = await user.create_session("my_device_name")
    session._generate_access_token = MagicMock()  # type: ignore

    result, at, rt = await Session.refresh(old_rt)

    redis.setex.assert_called_once_with(f"session_logout:{_session._hash_token(old_rt)}", 1337, 1)
    session._generate_access_token.assert_called_once_with()

    assert result == session
    assert (utcnow() - result.last_update).total_seconds() < 10
    assert result.refresh_token == _session._hash_token(rt)
    assert at == session._generate_access_token()


async def test__logout(mocker: MockerFixture, monkeypatch: MonkeyPatch) -> None:
    redis = mocker.patch("api.models.session.redis", new_callable=AsyncMock)
    monkeypatch.setattr(settings, "access_token_ttl", 1337)

    async with db_context():
        user = await _get_user()
        session, _, rt = await user.create_session("my_device_name")
        sid = session.id

    async with db_context():
        sess = await db.get(Session, id=sid)
        assert sess is not None
        await sess.logout()

        redis.setex.assert_called_once_with(f"session_logout:{_session._hash_token(rt)}", 1337, 1)
        assert await db.count(select(Session)) == 0


async def test__clean_expired_sessions(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "refresh_token_ttl", 42)

    async with db_context():
        user = await _get_user()
        (await user.create_session("dev1"))[0].last_update = utcnow() - timedelta(seconds=200)
        (await user.create_session("dev2"))[0].last_update = utcnow() - timedelta(seconds=50)
        (await user.create_session("dev3"))[0].last_update = utcnow() - timedelta(seconds=30)
        (await user.create_session("dev4"))[0].last_update = utcnow() - timedelta(seconds=20)

    await _session.clean_expired_sessions()

    async with db_context():
        sessions = await db.all(select(Session))
        assert len(sessions) == 2
        assert {s.device_name for s in sessions} == {"dev3", "dev4"}
