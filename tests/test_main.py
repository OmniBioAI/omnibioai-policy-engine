"""Tests for app/main.py: _invalidation_subscriber and lifespan.

Developer: Manish Kumar <manish@omnibioai.org>
"""
import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# _invalidation_subscriber
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_subscriber_processes_valid_message():
    """_invalidation_subscriber invalidates the cache for the user id in a valid pubsub message."""
    mock_cache = MagicMock()
    message_data = json.dumps({"user_id": "u1"})
    processed = asyncio.Event()

    async def mock_listen():
        yield {"type": "subscribe", "data": 1}
        yield {"type": "message", "data": message_data}
        processed.set()
        await asyncio.sleep(9999)

    mock_pubsub = MagicMock()
    mock_pubsub.subscribe = AsyncMock()
    mock_pubsub.listen = mock_listen

    mock_client = MagicMock()
    mock_client.pubsub.return_value = mock_pubsub

    with patch("app.main._cache", mock_cache), \
         patch("app.main.aioredis") as mock_aioredis:
        mock_aioredis.from_url.return_value = mock_client

        from app.main import _invalidation_subscriber
        task = asyncio.create_task(_invalidation_subscriber())
        await processed.wait()
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    mock_cache.invalidate_user.assert_called_with("u1")


@pytest.mark.asyncio
async def test_subscriber_ignores_empty_user_id():
    """_invalidation_subscriber does not invalidate the cache for a message whose user_id is empty.
    """
    mock_cache = MagicMock()
    message_data = json.dumps({"user_id": ""})
    done = asyncio.Event()

    async def mock_listen():
        yield {"type": "message", "data": message_data}
        done.set()
        await asyncio.sleep(9999)

    mock_pubsub = MagicMock()
    mock_pubsub.subscribe = AsyncMock()
    mock_pubsub.listen = mock_listen

    mock_client = MagicMock()
    mock_client.pubsub.return_value = mock_pubsub

    with patch("app.main._cache", mock_cache), \
         patch("app.main.aioredis") as mock_aioredis:
        mock_aioredis.from_url.return_value = mock_client

        from app.main import _invalidation_subscriber
        task = asyncio.create_task(_invalidation_subscriber())
        await done.wait()
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    mock_cache.invalidate_user.assert_not_called()


@pytest.mark.asyncio
async def test_subscriber_swallows_invalid_json():
    """_invalidation_subscriber does not invalidate the cache and does not raise for a message whose
    data is not valid JSON.
    """
    mock_cache = MagicMock()
    done = asyncio.Event()

    async def mock_listen():
        yield {"type": "message", "data": "not-json"}
        done.set()
        await asyncio.sleep(9999)

    mock_pubsub = MagicMock()
    mock_pubsub.subscribe = AsyncMock()
    mock_pubsub.listen = mock_listen

    mock_client = MagicMock()
    mock_client.pubsub.return_value = mock_pubsub

    with patch("app.main._cache", mock_cache), \
         patch("app.main.aioredis") as mock_aioredis:
        mock_aioredis.from_url.return_value = mock_client

        from app.main import _invalidation_subscriber
        task = asyncio.create_task(_invalidation_subscriber())
        await done.wait()
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    mock_cache.invalidate_user.assert_not_called()


@pytest.mark.asyncio
async def test_subscriber_reconnects_on_exception():
    """When subscribe() raises, the except block calls asyncio.sleep(5)."""
    real_sleep = asyncio.sleep
    slept_5 = asyncio.Event()

    async def fast_sleep(t):
        if t == 5:
            slept_5.set()
        await real_sleep(0)  # yield to event loop without blocking

    mock_pubsub = MagicMock()

    async def always_fail(*a, **kw):
        raise ConnectionError("redis down")

    mock_pubsub.subscribe = always_fail
    mock_client = MagicMock()
    mock_client.pubsub.return_value = mock_pubsub

    with patch("app.main._cache", MagicMock()), \
         patch("app.main.aioredis") as mock_aioredis, \
         patch("asyncio.sleep", fast_sleep):
        mock_aioredis.from_url.return_value = mock_client

        from app.main import _invalidation_subscriber
        task = asyncio.create_task(_invalidation_subscriber())
        await slept_5.wait()  # blocks until sleep(5) is hit
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    assert slept_5.is_set()


# ---------------------------------------------------------------------------
# lifespan
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_lifespan_starts_and_stops_subscriber():
    """lifespan should start the subscriber task and cancel it cleanly."""
    with patch("app.main._invalidation_subscriber", new_callable=AsyncMock) as mock_sub:
        async def long_running():
            await asyncio.sleep(9999)

        mock_sub.side_effect = long_running

        from app.main import lifespan, app
        async with lifespan(app):
            pass  # startup → yield → shutdown


# ---------------------------------------------------------------------------
# App smoke test
# ---------------------------------------------------------------------------

def test_app_has_evaluate_route():
    """The app registers a policy evaluation route."""
    from app.main import app
    paths = [r.path for r in app.routes]
    assert any("evaluate" in p for p in paths)
