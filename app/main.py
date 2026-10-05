"""
OmniBioAI app.main.

Purpose:
    Defines HTTP route handlers for app.main, including swagger_static, custom_swagger_ui and health.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

import asyncio
import json
import os
import pathlib
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from fastapi import FastAPI
from fastapi.responses import FileResponse, HTMLResponse, Response
from swagger_ui_bundle import swagger_ui_path

from app.api.routes_policy import router
from app.services.cache import PolicyCache

_swagger_js = pathlib.Path(swagger_ui_path, "swagger-ui-bundle.js").read_text()
_swagger_css = pathlib.Path(swagger_ui_path, "swagger-ui.css").read_text()

_redis_url = os.getenv("REDIS_URL", "redis://redis:6379")
_cache = PolicyCache(redis_url=_redis_url)


async def _invalidation_subscriber():
    """
    Subscribe to "policy:invalidate" pub/sub channel.
    On each message, evict the affected user's cached policy decisions so
    the next request re-evaluates from scratch (zero-trust on revocation).
    Restarts automatically on failure.
    """
    client = aioredis.from_url(_redis_url, decode_responses=True)
    while True:
        try:
            pubsub = client.pubsub()
            await pubsub.subscribe("policy:invalidate")
            async for message in pubsub.listen():
                if message["type"] == "message":
                    try:
                        data = json.loads(message["data"])
                        user_id = data.get("user_id", "")
                        if user_id:
                            _cache.invalidate_user(user_id)
                    except Exception:  # noqa: BLE001, S110 - isolate a bad event from the subscriber
                        pass
        except Exception:  # noqa: BLE001 - reconnect after any subscriber failure
            await asyncio.sleep(5)


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(_invalidation_subscriber())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(
    title="OmniBioAI Policy Engine",
    lifespan=lifespan,
    root_path="/_svc/policy",
    docs_url=None,
    redoc_url=None,
)
app.openapi_version = "3.0.3"

_MIME = {
    ".js": "application/javascript",
    ".css": "text/css",
    ".html": "text/html",
    ".png": "image/png",
    ".map": "application/json",
}


@app.get("/swagger-static/{path:path}", include_in_schema=False)
async def swagger_static(path: str) -> Response:
    full = os.path.join(swagger_ui_path, path)
    if not os.path.isfile(full):
        return Response(status_code=404)
    return FileResponse(full, media_type=_MIME.get(os.path.splitext(full)[1], "application/octet-stream"))


@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui() -> HTMLResponse:
    spec_json = json.dumps(app.openapi()).replace("</", "<\\/")
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>OmniBioAI Policy Engine</title>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>{_swagger_css}</style>
</head>
<body>
<div id="swagger-ui"></div>
<script>{_swagger_js}</script>
<script>
SwaggerUIBundle({{
    spec: {spec_json},
    dom_id: '#swagger-ui',
    presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
    layout: 'BaseLayout',
    deepLinking: true,
    validatorUrl: null,
}})
</script>
</body>
</html>"""
    return HTMLResponse(html)


@app.get("/health", include_in_schema=False)
async def health():
    return {"status": "ok"}


app.include_router(router, prefix="/policy")
