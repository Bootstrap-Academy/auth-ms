import asyncio
import random
import string
from email.message import EmailMessage

import aiosmtplib
import email_validator

from .async_thread import run_in_thread
from ..environment import SMTP_FROM, SMTP_HOST, SMTP_PASSWORD, SMTP_PORT, SMTP_STARTTLS, SMTP_TLS, SMTP_USER
from ..logger import get_logger


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
    message["From"] = SMTP_FROM
    message["To"] = recipient
    message["Subject"] = title
    message.set_type(content_type)
    message.set_content(body)

    asyncio.create_task(
        aiosmtplib.send(
            message,
            hostname=SMTP_HOST,
            port=SMTP_PORT,
            username=SMTP_USER,
            password=SMTP_PASSWORD,
            use_tls=SMTP_TLS,
            start_tls=SMTP_STARTTLS,
        )
    )


def generate_verification_code() -> str:
    return "-".join(
        "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(4)) for _ in range(4)  # noqa: S311
    )
