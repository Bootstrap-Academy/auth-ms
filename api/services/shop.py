from api.services.internal import InternalService


async def release_coins(user_id: str) -> None:
    async with InternalService.SHOP.client as client:
        await client.put(f"/coins/{user_id}/withheld")
