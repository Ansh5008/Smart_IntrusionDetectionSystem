"""Redis connection with in-memory fallback."""
from __future__ import annotations
import logging
from collections import defaultdict
from typing import Any

from core.config import settings

logger = logging.getLogger(__name__)
_redis = None
_using_fallback = False
_counters: dict[str, int] = defaultdict(int)
_sets: dict[str, set] = defaultdict(set)


async def get_redis():
    global _redis, _using_fallback
    if _using_fallback:
        return None
    if _redis is not None:
        return _redis
    try:
        import redis.asyncio as aioredis
        _redis = aioredis.from_url(settings.redis_url, decode_responses=True)
        await _redis.ping()
        logger.info("Redis connected at %s", settings.redis_url)
        return _redis
    except Exception as exc:
        logger.warning("Redis unavailable (%s) — using in-memory fallback", exc)
        _using_fallback = True
        return None


async def incr(key: str, ttl: int = 60) -> int:
    r = await get_redis()
    if r:
        val = await r.incr(key)
        if val == 1:
            await r.expire(key, ttl)
        return val
    _counters[key] += 1
    return _counters[key]


async def sadd(key: str, *values: str) -> None:
    r = await get_redis()
    if r:
        await r.sadd(key, *values)
    else:
        _sets[key].update(values)


async def sismember(key: str, value: str) -> bool:
    r = await get_redis()
    if r:
        return await r.sismember(key, value)
    return value in _sets.get(key, set())


async def smembers(key: str) -> set[str]:
    r = await get_redis()
    if r:
        return await r.smembers(key)
    return _sets.get(key, set())


async def srem(key: str, *values: str) -> None:
    r = await get_redis()
    if r:
        await r.srem(key, *values)
    else:
        for v in values:
            _sets.get(key, set()).discard(v)
