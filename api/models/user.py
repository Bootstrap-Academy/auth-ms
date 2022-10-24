from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import TYPE_CHECKING, Any, cast
from uuid import uuid4

from sqlalchemy import Boolean, Column, String, func, or_
from sqlalchemy.orm import Mapped, relationship
from sqlalchemy.sql import Select

from ..database import Base, db, select
from ..database.database import UTCDateTime
from ..logger import get_logger
from ..redis import redis
from ..services.gravatar import get_gravatar_url
from ..settings import settings
from ..utils.email import check_email_deliverability, generate_verification_code, send_email
from ..utils.jwt import decode_jwt
from ..utils.passwords import hash_password, verify_password
from ..utils.utc import utcnow


if TYPE_CHECKING:
    from .oauth_user_connection import OAuthUserConnection
    from .session import Session

logger = get_logger(__name__)


class User(Base):
    __tablename__ = "auth_user"

    id: Mapped[str] = Column(String(36), primary_key=True, unique=True)
    name: Mapped[str] = Column(String(32), unique=True)
    display_name: Mapped[str] = Column(String(64))
    email: Mapped[str | None] = Column(String(254), unique=True)
    email_verification_code: Mapped[str | None] = Column(String(32), nullable=True)
    password: Mapped[str | None] = Column(String(128), nullable=True)
    registration: Mapped[datetime] = Column(UTCDateTime)
    last_login: Mapped[datetime | None] = Column(UTCDateTime, nullable=True)
    enabled: Mapped[bool] = Column(Boolean, default=True)
    admin: Mapped[bool] = Column(Boolean, default=False)
    mfa_secret: Mapped[str | None] = Column(String(32), nullable=True)
    mfa_enabled: Mapped[bool] = Column(Boolean, default=False)
    mfa_recovery_code: Mapped[str | None] = Column(String(64), nullable=True)
    description: Mapped[str | None] = Column(String(1024), nullable=True)
    _tags: Mapped[str] = Column(String(550))
    newsletter: Mapped[bool] = Column(Boolean)
    sessions: list[Session] = relationship("Session", back_populates="user", cascade="all, delete")
    oauth_connections: list[OAuthUserConnection] = relationship(
        "OAuthUserConnection", back_populates="user", cascade="all, delete"
    )

    @property
    def tags(self) -> list[str]:
        return cast(list[str], json.loads(self._tags)) if self._tags else []

    @tags.setter
    def tags(self, value: list[str]) -> None:
        self._tags = json.dumps(value)

    @property
    def email_verified(self) -> bool:
        return self.email_verification_code is None

    @email_verified.setter
    def email_verified(self, value: bool) -> None:
        if value:
            self.email_verification_code = None
        else:
            self.email_verification_code = generate_verification_code()

    @property
    def serialize(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "display_name": self.display_name,
            "email": self.email,
            "email_verified": self.email_verified,
            "registration": self.registration.timestamp(),
            "last_login": self.last_login.timestamp() if self.last_login else None,
            "enabled": self.enabled,
            "admin": self.admin,
            "password": bool(self.password),
            "mfa_enabled": self.mfa_enabled,
            "description": self.description,
            "tags": self.tags,
            "newsletter": self.newsletter,
            "avatar_url": get_gravatar_url(self.email) if self.email else None,
        }

    @property
    def jwt_data(self) -> dict[str, Any]:
        return {"email_verified": self.email_verified, "admin": self.admin}

    async def invalidate_access_tokens(self) -> None:
        for session in self.sessions:
            await session.invalidate_access_token()

    @staticmethod
    async def create(
        name: str, display_name: str, email: str, password: str | None, enabled: bool, admin: bool
    ) -> User:
        user = User(
            id=str(uuid4()),
            name=name,
            display_name=display_name,
            email=email,
            email_verification_code=generate_verification_code(),
            password=await hash_password(password) if password else None,
            registration=utcnow(),
            last_login=None,
            enabled=enabled,
            admin=admin,
            mfa_secret=None,
            mfa_enabled=False,
            mfa_recovery_code=None,
            description=None,
            newsletter=False,
        )
        user.tags = []
        await db.add(user)
        return user

    @staticmethod
    def filter_by_name(name: str) -> Select:
        return select(User).where(func.lower(User.name) == name.lower())

    @staticmethod
    def filter_by_email(email: str) -> Select:
        return select(User).where(func.lower(User.email) == email.lower())

    @staticmethod
    def login_filter(name_or_email: str) -> Select:
        return select(User).where(
            or_(func.lower(User.name) == name_or_email.lower(), func.lower(User.email) == name_or_email.lower())
        )

    @staticmethod
    async def initialize() -> None:
        if await db.exists(select(User)):
            return

        user = await User.create(
            settings.admin_username, settings.admin_username, settings.admin_email, settings.admin_password, True, True
        )
        user.email_verified = True
        logger.info(f"Admin user '{user.name}' ({user.email}) has been created!")
        if not await check_email_deliverability(user.email):
            logger.warning(f"Cannot send emails to '{user.email}'!")

    async def check_password(self, password: str) -> bool:
        if not self.password:
            return False

        return await verify_password(password, self.password)

    async def change_password(self, password: str | None) -> None:
        self.password = await hash_password(password) if password else None

    async def create_session(self, device_name: str) -> tuple[Session, str, str]:
        from .session import Session

        self.last_login = utcnow()
        return await Session.create(self, device_name)

    @staticmethod
    async def from_access_token(access_token: str) -> User | None:
        if (data := decode_jwt(access_token, require=["uid", "sid", "rt"])) is None:
            return None
        if await redis.exists(f"session_logout:{data['rt']}"):
            return None

        return await db.get(User, id=data["uid"], enabled=True)

    async def logout(self) -> None:
        for session in self.sessions:
            await session.logout()

    async def send_verification_email(self) -> None:
        if not self.email:
            raise ValueError("User has no email")
        if not self.email_verification_code:
            raise ValueError("User already verified")

        await send_email(self.email, "Verify your email", f"Your verification code: {self.email_verification_code}")

    async def send_password_reset_email(self) -> None:
        if not self.email:
            raise ValueError("User has no email")

        code = generate_verification_code()
        await redis.setex(f"password_reset:{self.id}", 3600, code)
        await send_email(self.email, "Reset your password", f"Your password reset code: {code}")

    async def check_password_reset_code(self, code: str) -> bool:
        value: str | None = await redis.get(key := f"password_reset:{self.id}")
        if not value or code.lower() != value.lower():
            return False

        await redis.delete(key)
        return True

    async def request_newsletter_email(self) -> None:
        if not self.email:
            raise ValueError("User has no email")

        code = generate_verification_code()
        await redis.setex(f"newsletter:{self.id}", 3600, code)
        await send_email(self.email, "Subscribe to the newsletter", f"code: {code}")

    async def check_newsletter_code(self, code: str) -> bool:
        value: str | None = await redis.get(key := f"newsletter:{self.id}")
        if not value or code.lower() != value.lower():
            return False

        await redis.delete(key)
        return True

    @staticmethod
    async def get_failed_logins(name_or_email: str) -> int:
        return int(
            await redis.get(f"failed_login_attempts:{hashlib.sha256(name_or_email.lower().encode()).hexdigest()}")
            or "0"
        )

    @staticmethod
    async def incr_failed_logins_anon(name_or_email: str) -> None:
        await redis.incr(f"failed_login_attempts:{hashlib.sha256(name_or_email.lower().encode()).hexdigest()}")

    async def incr_failed_logins(self) -> None:
        async with redis.pipeline() as pipe:
            for key in [self.name, self.email] if self.email else [self.name]:
                await pipe.incr(f"failed_login_attempts:{hashlib.sha256(key.lower().encode()).hexdigest()}")
            await pipe.execute()

    async def reset_failed_logins(self) -> None:
        await redis.delete(
            *[
                f"failed_login_attempts:{hashlib.sha256(key.lower().encode()).hexdigest()}"
                for key in ([self.name, self.email] if self.email else [self.name])
            ]
        )
