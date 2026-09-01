import os

import redis.asyncio as redis

REDIS_URL = os.environ["REDIS_URL"]

# `or "60"` guards against Compose passing an unset var through as an empty
# string instead of omitting it — this is what broke ACCESS_TOKEN_EXPIRE_MINUTES
# on day 12, so the same defensive pattern is used here from the start.
CACHE_TTL_SECONDS = int(os.environ.get("CACHE_TTL_SECONDS") or "60")

redis_client = redis.from_url(REDIS_URL, decode_responses=True)


async def cache_get(key: str) -> str | None:
    return await redis_client.get(key)


async def cache_set(key: str, value: str, ttl: int = CACHE_TTL_SECONDS) -> None:
    await redis_client.set(key, value, ex=ttl)


async def cache_delete(*keys: str) -> None:
    if keys:
        await redis_client.delete(*keys)
