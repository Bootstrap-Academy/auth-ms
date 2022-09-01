from __future__ import annotations

from typing import Any
from uuid import uuid4

from sqlalchemy import Column, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, relationship

from .user import User
from ..database import Base, db


class OAuthUserConnection(Base):
    __tablename__ = "auth_oauth_user_connection"

    id: Mapped[str] = Column(String(36), primary_key=True, unique=True)
    user_id: Mapped[str] = Column(String(36), ForeignKey("auth_user.id"))
    user: User = relationship("User", back_populates="oauth_connections")
    provider_id: Mapped[str] = Column(String(64))
    remote_user_id: Mapped[str] = Column(Text)
    display_name: Mapped[str | None] = Column(Text, nullable=True)

    @property
    def serialize(self) -> dict[str, Any]:
        return {"id": self.id, "provider_id": self.provider_id, "display_name": self.display_name}

    @staticmethod
    async def create(
        user_id: str, provider_id: str, remote_user_id: str, display_name: str | None
    ) -> OAuthUserConnection:
        row = OAuthUserConnection(
            id=str(uuid4()),
            user_id=user_id,
            provider_id=provider_id,
            remote_user_id=remote_user_id,
            display_name=display_name,
        )
        await db.add(row)
        return row
