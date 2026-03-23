import json
import logging
import time
from typing import AsyncIterator

import httpx
from fastapi import HTTPException, status
from fastapi.responses import StreamingResponse

from config import MODEL_ENDPOINT, MODEL_API_KEY

logger = logging.getLogger(__name__)


async def _stream_chunks(response: httpx.Response) -> AsyncIterator[bytes]:
    async for chunk in response.aiter_bytes():
        yield chunk


async def forward_completion(body: dict, user: dict) -> StreamingResponse | dict:
    headers = {
        "Authorization": f"Bearer {MODEL_API_KEY}",
        "Content-Type": "application/json",
    }

    start = time.monotonic()

    if body.get("stream", False):
        async def generate():
            async with httpx.AsyncClient(timeout=120) as client:
                async with client.stream("POST", MODEL_ENDPOINT, json=body, headers=headers) as response:
                    if response.status_code != 200:
                        error_body = await response.aread()
                        logger.error(
                            "upstream error user_id=%s status=%d body=%s",
                            user["user_id"], response.status_code, error_body,
                        )
                        yield error_body
                        return
                    async for chunk in response.aiter_bytes():
                        yield chunk
            latency = (time.monotonic() - start) * 1000
            logger.info(
                "POST /v1/chat/completions user_id=%s stream=true status=200 latency=%.1fms",
                user["user_id"], latency,
            )

        return StreamingResponse(generate(), media_type="text/event-stream")

    else:
        async with httpx.AsyncClient(timeout=120) as client:
            try:
                response = await client.post(MODEL_ENDPOINT, json=body, headers=headers)
            except httpx.RequestError as exc:
                logger.error("upstream request failed: %s", exc)
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail={"error": "upstream request failed", "code": "UPSTREAM_ERROR"},
                )

        latency = (time.monotonic() - start) * 1000
        logger.info(
            "POST /v1/chat/completions user_id=%s stream=false status=%d latency=%.1fms",
            user["user_id"], response.status_code, latency,
        )

        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code,
                detail=response.json(),
            )

        return response.json()
