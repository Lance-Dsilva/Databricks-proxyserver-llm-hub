import asyncio
import logging
import time
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from proxy import forward_completion
from utils.database import AsyncSessionLocal, get_db, init_db
from utils.models import PlatformSettings, RequestLog, Token, User

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)

app = FastAPI(title="AI Gateway — Proxy")

bearer_scheme = HTTPBearer()

# platform token → (user_dict, cache_expires_monotonic)
_token_cache: dict[str, tuple[dict, float]] = {}
_CACHE_TTL = 60  # seconds

# rate-limit settings cache (refreshed every 5 minutes from DB)
_settings_cache: dict[str, int] = {"rate_limit": 30, "rate_window": 60}
_settings_cache_expires: float = 0.0
_SETTINGS_TTL = 300  # 5 minutes


async def _get_rate_settings() -> tuple[int, int]:
    global _settings_cache, _settings_cache_expires
    now = time.monotonic()
    if now < _settings_cache_expires:
        return _settings_cache["rate_limit"], _settings_cache["rate_window"]
    try:
        async with AsyncSessionLocal() as db:
            rows = (await db.execute(select(PlatformSettings))).scalars().all()
            kv = {r.key: int(r.value) for r in rows}
            _settings_cache = {
                "rate_limit":  kv.get("rate_limit",  30),
                "rate_window": kv.get("rate_window", 60),
            }
            _settings_cache_expires = now + _SETTINGS_TTL
    except Exception as exc:
        logging.getLogger(__name__).warning("settings cache refresh failed: %s", exc)
    return _settings_cache["rate_limit"], _settings_cache["rate_window"]


@app.on_event("startup")
async def startup() -> None:
    await init_db()


# ── request log (fire-and-forget) ────────────────────────────────────────────

async def _write_request_log(
    token_id:         int,
    user_id:          int,
    model:            str,
    status_code:      int,
    latency_ms:       float,
    prompt_tokens:    int,
    completion_tokens: int,
) -> None:
    try:
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(User).where(User.id == user_id))
            user   = result.scalar_one_or_none()
            team   = user.team if user else "unknown"
            db.add(RequestLog(
                token_id=token_id,
                user_id=user_id,
                team=team,
                model=model,
                status_code=status_code,
                latency_ms=latency_ms,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
            ))
            await db.commit()
    except Exception as exc:
        logging.getLogger(__name__).error("request log write failed: %s", exc)


# ── platform token validation (with 60s cache) ───────────────────────────────

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> dict:
    token = credentials.credentials
    now   = time.monotonic()

    cached = _token_cache.get(token)
    if cached and cached[1] > now:
        return cached[0]

    result   = await db.execute(select(Token).where(Token.platform_token == token))
    db_token = result.scalar_one_or_none()

    if not db_token or db_token.status != "active":
        _token_cache.pop(token, None)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid or revoked platform token", "code": "UNAUTHORIZED"},
        )

    expires_at = db_token.expires_at
    if expires_at:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(timezone.utc):
            _token_cache.pop(token, None)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": "platform token expired", "code": "TOKEN_EXPIRED"},
            )

    user_info = {
        "user_id":        db_token.user_id,
        "token_id":       db_token.id,
        "platform_token": token,
    }
    _token_cache[token] = (user_info, now + _CACHE_TTL)
    return user_info


# ── rate limiting ─────────────────────────────────────────────────────────────

async def enforce_rate_limit(
    user: dict = Depends(get_current_user),
    db:   AsyncSession = Depends(get_db),
) -> dict:
    result = await db.execute(select(Token).where(Token.id == user["token_id"]))
    token  = result.scalar_one_or_none()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "token not found", "code": "UNAUTHORIZED"},
        )

    rate_limit, rate_window = await _get_rate_settings()

    now          = datetime.now(timezone.utc)
    window_start = token.window_start
    if window_start and window_start.tzinfo is None:
        window_start = window_start.replace(tzinfo=timezone.utc)

    if window_start is None or (now - window_start).total_seconds() >= rate_window:
        token.window_start = now
        token.window_count = 1
    else:
        if token.window_count >= rate_limit:
            token.last_rate_limited_at = now
            await db.commit()
            retry_after = rate_window - int((now - window_start).total_seconds())
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                headers={"Retry-After": str(retry_after)},
                detail={"error": f"rate limit exceeded, retry after {retry_after} seconds", "code": "RATE_LIMITED"},
            )
        token.window_count += 1

    token.request_count += 1
    token.last_used_at   = now
    await db.commit()
    return user


# ── routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/v1/models")
async def list_models(_: dict = Depends(get_current_user)):
    return {
        "object": "list",
        "data": [
            {"id": "gpt-4o",      "object": "model", "owned_by": "openai"},
            {"id": "gpt-4o-mini", "object": "model", "owned_by": "openai"},
        ],
    }


@app.post("/v1/chat/completions")
async def chat_completions(body: dict, user: dict = Depends(enforce_rate_limit)):
    start  = time.monotonic()
    result = await forward_completion(body, user)
    latency_ms = (time.monotonic() - start) * 1000
    model  = body.get("model", "unknown")

    if isinstance(result, StreamingResponse):
        asyncio.create_task(_write_request_log(
            token_id=user["token_id"], user_id=user["user_id"],
            model=model, status_code=200, latency_ms=latency_ms,
            prompt_tokens=0, completion_tokens=0,
        ))
    else:
        usage = result.get("usage", {})
        asyncio.create_task(_write_request_log(
            token_id=user["token_id"], user_id=user["user_id"],
            model=model, status_code=200, latency_ms=latency_ms,
            prompt_tokens=usage.get("prompt_tokens", 0),
            completion_tokens=usage.get("completion_tokens", 0),
        ))

    return result
