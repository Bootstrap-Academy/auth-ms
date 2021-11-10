from contextlib import asynccontextmanager
from functools import wraps
from typing import Callable, TypeVar, Awaitable, Any, AsyncIterator

from .database import get_database, select, filter_by, exists, delete, Base

T = TypeVar("T")


@asynccontextmanager
async def db_context() -> AsyncIterator[None]:
    """Async context manager for database sessions."""

    db.create_session()
    try:
        yield
    finally:
        await db.commit()
        await db.close()


def db_wrapper(f: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
    """Decorator which wraps an async function in a database context."""

    @wraps(f)
    async def inner(*args: Any, **kwargs: Any) -> T:
        async with db_context():
            return await f(*args, **kwargs)

    return inner


# global database connection object
db = get_database()


__all__ = ["db_context", "db_wrapper", "select", "filter_by", "exists", "delete", "db", "Base"]
