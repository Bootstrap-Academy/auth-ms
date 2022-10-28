import aiohttp

from api.logger import get_logger
from api.settings import settings


logger = get_logger(__name__)


def recaptcha_enabled() -> bool:
    return bool(settings.recaptcha_secret and settings.recaptcha_sitekey)


async def check_recaptcha(response: str) -> bool:
    async with aiohttp.ClientSession() as session:
        async with session.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={"secret": settings.recaptcha_secret, "response": response},
        ) as resp:
            if resp.status != 200:
                return False

            data = await resp.json()
            logger.debug(f"Recaptcha response: {data}")
            if not data.get("success"):
                return False
            if (score := data.get("score")) is None:
                return settings.recaptcha_min_score is None
            return settings.recaptcha_min_score is None or score < settings.recaptcha_min_score
