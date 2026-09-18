"""Shared pytest fixtures for the policy engine tests: stubs swagger_ui_bundle
when the optional package is not installed, and provides a PolicyEngine wired
to a mock Redis-backed cache so no test connects to a real Redis.

Developer: Manish Kumar <manish@omnibioai.org>
"""
import os
import sys
import tempfile
from unittest.mock import MagicMock, patch

# swagger_ui_bundle is an optional runtime dependency. Mock it before any
# app.main import so tests run without the package installed.
if "swagger_ui_bundle" not in sys.modules:
    _mock_swagger_dir = tempfile.mkdtemp()
    open(os.path.join(_mock_swagger_dir, "swagger-ui-bundle.js"), "w").close()
    open(os.path.join(_mock_swagger_dir, "swagger-ui.css"), "w").close()
    _mock_swagger = MagicMock()
    _mock_swagger.swagger_ui_path = _mock_swagger_dir
    sys.modules["swagger_ui_bundle"] = _mock_swagger

import pytest


@pytest.fixture
def mock_redis():
    """Provide a MagicMock standing in for a Redis client."""
    return MagicMock()


@pytest.fixture
def policy_cache(mock_redis):
    """Build a PolicyCache with its Redis client replaced by the mock."""
    with patch("app.services.cache.redis") as mock_redis_module:
        mock_redis_module.from_url.return_value = mock_redis
        from app.services.cache import PolicyCache
        cache = PolicyCache(redis_url="redis://localhost")
        cache.redis = mock_redis
        yield cache, mock_redis


@pytest.fixture
def policy_engine(policy_cache):
    """Build a PolicyEngine using the mocked policy cache, together with the cache and its mock
    Redis client.
    """
    cache, mock_redis = policy_cache
    from app.core.engine import PolicyEngine
    engine = PolicyEngine(cache=cache)
    return engine, cache, mock_redis
