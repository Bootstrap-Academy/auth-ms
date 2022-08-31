from __future__ import annotations

import hashlib
from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from sqlalchemy import Boolean, Column, DateTime, String, func, or_
from sqlalchemy.orm import Mapped, relationship
from sqlalchemy.sql import Select

from ..database import Base, db, select
from ..environment import ADMIN_EMAIL, ADMIN_PASSWORD, ADMIN_USERNAME
from ..logger import get_logger
from ..redis import redis
from ..utils.email import check_email_deliverability, generate_verification_code, send_email
from ..utils.jwt import decode_jwt
from ..utils.passwords import hash_password, verify_password


if TYPE_CHECKING:
    from .oauth_user_connection import OAuthUserConnection
    from .session import Session

logger = get_logger(__name__)


class User(Base):
    __tablename__ = "user"

    id: Mapped[str] = Column(String(36), primary_key=True, unique=True)
    name: Mapped[str] = Column(String(32), unique=True)
    display_name: Mapped[str] = Column(String(64))
    email: Mapped[str] = Column(String(254), unique=True)
    email_verification_code: Mapped[str | None] = Column(String(32), nullable=True)
    password: Mapped[str | None] = Column(String(128), nullable=True)
    registration: Mapped[datetime] = Column(DateTime)
    last_login: Mapped[datetime | None] = Column(DateTime, nullable=True)
    enabled: Mapped[bool] = Column(Boolean, default=True)
    admin: Mapped[bool] = Column(Boolean, default=False)
    mfa_secret: Mapped[str | None] = Column(String(32), nullable=True)
    mfa_enabled: Mapped[bool] = Column(Boolean, default=False)
    mfa_recovery_code: Mapped[str | None] = Column(String(64), nullable=True)
    sessions: list[Session] = relationship("Session", back_populates="user", cascade="all, delete")
    oauth_connections: list[OAuthUserConnection] = relationship(
        "OAuthUserConnection", back_populates="user", cascade="all, delete"
    )

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
        }

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
            registration=datetime.utcnow(),
            last_login=None,
            enabled=enabled,
            admin=admin,
            mfa_secret=None,
            mfa_enabled=False,
            mfa_recovery_code=None,
        )
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

        user = await User.create(ADMIN_USERNAME, ADMIN_USERNAME, ADMIN_EMAIL, ADMIN_PASSWORD, True, True)
        user.email_verification_code = None
        logger.info(f"Admin user '{ADMIN_USERNAME}' ({ADMIN_EMAIL}) has been created!")
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

        self.last_login = datetime.utcnow()
        return await Session.create(self.id, device_name)

    @staticmethod
    async def from_access_token(access_token: str) -> User | None:
        if (data := decode_jwt(access_token, ["uid", "sid", "rt"])) is None:
            return None
        if await redis.exists(f"session_logout:{data['rt']}"):
            return None

        return await db.get(User, id=data["uid"], enabled=True)

    async def logout(self) -> None:
        for session in self.sessions:
            await session.logout()

    async def send_verification_email(self) -> None:
        if not self.email_verification_code:
            raise ValueError("User already verified")

        await send_email(self.email, "Verify your email", f"Your verification code: {self.email_verification_code}")

    async def send_password_reset_email(self) -> None:
        code = generate_verification_code()
        await redis.setex(f"password_reset:{self.id}", 3600, code)
        await send_email(self.email, "Reset your password", f"Your password reset code: {code}")

    async def check_password_reset_code(self, code: str) -> bool:
        value: str | None = await redis.get(key := f"password_reset:{self.id}")
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
            for key in [self.name, self.email]:
                await pipe.incr(f"failed_login_attempts:{hashlib.sha256(key.lower().encode()).hexdigest()}")
            await pipe.execute()

    async def reset_failed_logins(self) -> None:
        await redis.delete(
            *[
                f"failed_login_attempts:{hashlib.sha256(key.lower().encode()).hexdigest()}"
                for key in [self.name, self.email]
            ]
        )
