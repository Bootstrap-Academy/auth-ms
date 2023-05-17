import re

from httpx import AsyncClient


async def check_vat_id(vat_id: str) -> bool:
    if not (match := re.match(r"^([A-Z]{2}) *([0-9A-Z]+)$", vat_id)):
        return False

    async with AsyncClient() as client:
        resp = await client.get(f"https://ec.europa.eu/taxation_customs/vies/rest-api/ms/{match[1]}/vat/{match[2]}")
        if resp.status_code != 200:
            return False
        return resp.json()["isValid"] is True
