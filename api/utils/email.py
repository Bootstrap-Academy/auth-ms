import asyncio
import random
import string
from email.message import EmailMessage

import aiosmtplib
import email_validator

from .async_thread import run_in_thread
from ..logger import get_logger
from ..settings import settings


logger = get_logger(__name__)


@run_in_thread
def check_email_deliverability(email: str) -> bool:
    try:
        email_validator.validate_email(email)
    except email_validator.EmailNotValidError:
        return False
    return True


async def send_email(recipient: str, title: str, body: str, content_type: str = "text/plain") -> None:
    if not await check_email_deliverability(recipient):
        raise ValueError("Invalid email address")

    logger.debug(f"Sending email to {recipient} ({title})")

    message = EmailMessage()
    message["From"] = settings.smtp_from
    message["To"] = recipient
    message["Subject"] = title
    message.set_type(content_type)
    message.set_content(body)

    asyncio.create_task(
        aiosmtplib.send(
            message,
            hostname=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_user,
            password=settings.smtp_password,
            use_tls=settings.smtp_tls,
            start_tls=settings.smtp_starttls,
        )
    )


def generate_verification_code() -> str:
    return "-".join(
        "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(4)) for _ in range(4)  # noqa: S311
    )
