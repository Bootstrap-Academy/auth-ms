import asyncio
from typing import Any, Callable
from unittest.mock import AsyncMock, MagicMock

from _pytest.monkeypatch import MonkeyPatch
from httpx import AsyncClient
from pytest_mock import MockerFixture

from ._utils import import_module, mock_asynccontextmanager
from api import app
from api.settings import settings


def get_decorated_function(
    fastapi_patch: MagicMock, decorator_name: str, *decorator_args: Any, **decorator_kwargs: Any
) -> tuple[Any, Callable[..., Any]]:
    functions: list[Callable[..., Any]] = []
    decorator = MagicMock(side_effect=functions.append)
    getattr(fastapi_patch(), decorator_name).side_effect = (
        lambda *args, **kwargs: decorator if (args, kwargs) == (decorator_args, decorator_kwargs) else MagicMock()
    )
    fastapi_patch.reset_mock()

    module = import_module(app)

    decorator.assert_called_once()
    assert len(functions) == 1
    return module, functions[0]


async def test__setup_app__sentry(mocker: MockerFixture, monkeypatch: MonkeyPatch) -> None:
    from api import __version__

    setup_sentry_mock = mocker.patch("api.app.setup_sentry")
    app_mock = mocker.patch("api.app.app")
    monkeypatch.setattr(settings, "sentry_dsn", sentry_dsn_mock := MagicMock())
    monkeypatch.setattr(settings, "debug", False)

    app.setup_app()

    setup_sentry_mock.assert_called_once_with(app_mock, sentry_dsn_mock, "auth-ms", __version__)


async def test__setup_app__debug(mocker: MockerFixture, monkeypatch: MonkeyPatch) -> None:
    app_mock = mocker.patch("api.app.app")
    cors_middleware_mock = mocker.patch("api.app.CORSMiddleware")
    monkeypatch.setattr(settings, "sentry_dsn", None)
    monkeypatch.setattr(settings, "debug", True)

    app.setup_app()

    app_mock.add_middleware.assert_called_once_with(
        cors_middleware_mock, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"]
    )


async def test__db_session(mocker: MockerFixture) -> None:
    fastapi_patch = mocker.patch("fastapi.FastAPI")
    expected = MagicMock()
    request = MagicMock()

    module, db_session = get_decorated_function(fastapi_patch, "middleware", "http")

    module.db_context, [func_callback], assert_calls = mock_asynccontextmanager(1, None)
    call_next = AsyncMock(side_effect=lambda _: func_callback() or expected)

    result = await db_session(request, call_next)

    assert_calls()
    call_next.assert_called_once_with(request)
    assert result == expected


async def test__rollback_on_exception(mocker: MockerFixture) -> None:
    fastapi_patch = mocker.patch("fastapi.FastAPI")
    db_patch = mocker.patch("api.database.db")
    db_patch.session.rollback = AsyncMock()
    http_exception_patch = mocker.patch("starlette.exceptions.HTTPException")
    http_exception_handler_patch = mocker.patch("fastapi.exception_handlers.http_exception_handler", AsyncMock())

    _, rollback_on_exception = get_decorated_function(fastapi_patch, "exception_handler", http_exception_patch)

    result = await rollback_on_exception(request := MagicMock(), exc := MagicMock())

    db_patch.session.rollback.assert_called_once_with()
    http_exception_handler_patch.assert_called_once_with(request, exc)
    assert result == await http_exception_handler_patch()


async def test__clean_expired_sessions_loop() -> None:
    module: Any = import_module("api.app")

    real_sleep = asyncio.sleep
    cnt = 0

    async def clean_expired_sessions() -> None:
        nonlocal cnt
        cnt += 1
        if cnt % 2 == 0:
            raise Exception("test")

    module.asyncio.sleep = lambda _: real_sleep(0)
    module.clean_expired_sessions = clean_expired_sessions

    asyncio.create_task(module.clean_expired_sessions_loop())
    await real_sleep(0.2)
    assert cnt >= 100


async def test__on_startup(mocker: MockerFixture, monkeypatch: MonkeyPatch) -> None:
    fastapi_patch = mocker.patch("fastapi.FastAPI")
    db_patch = mocker.patch("api.database.db")
    create_task_mock = mocker.patch("asyncio.create_task")
    user_initialize_mock = mocker.patch("api.models.User.initialize")

    module, on_startup = get_decorated_function(fastapi_patch, "on_event", "startup")
    db_patch.create_tables = AsyncMock()
    monkeypatch.setattr(module, "setup_app", MagicMock())
    clean_expired_sessions_loop = module.clean_expired_sessions_loop = MagicMock()

    module.db_context, [user_initialize_mock.side_effect], assert_calls = mock_asynccontextmanager(1, None)

    await on_startup()

    module.setup_app.assert_called_once_with()
    db_patch.create_tables.assert_not_called()  # use alembic migrations instead
    clean_expired_sessions_loop.assert_called_once_with()
    create_task_mock.assert_called_once_with(clean_expired_sessions_loop())
    assert_calls()


async def test__on_shutdown(mocker: MockerFixture) -> None:
    fastapi_patch = mocker.patch("fastapi.FastAPI")

    _, on_shutdown = get_decorated_function(fastapi_patch, "on_event", "shutdown")

    await on_shutdown()


async def test__status(client: AsyncClient) -> None:
    response = await client.head("/status")
    assert response.status_code == 200
