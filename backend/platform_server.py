import logging
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sqlalchemy import delete as sql_delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from utils.auth import (
    create_jwt,
    decode_jwt,
    get_current_user_jwt,
    hash_password,
    verify_password,
)
from utils.database import get_db, init_db
from utils.models import PlatformSettings, RequestLog, Token, User

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)

app = FastAPI(title="AI Gateway — Platform")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501", "http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

TOKEN_EXPIRES_DAYS = 30
bearer_scheme = HTTPBearer()


@app.on_event("startup")
async def startup() -> None:
    await init_db()


# ── admin auth dependency ─────────────────────────────────────────────────────

async def get_admin_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> dict:
    payload = decode_jwt(credentials.credentials)
    if not payload.get("is_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "admin access required", "code": "FORBIDDEN"},
        )
    return payload


# ── health ────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok"}


# ── auth ──────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email:    str
    password: str


class RegisterRequest(BaseModel):
    email:    str
    password: str
    team:     str


@app.post("/auth/login")
async def auth_login(body: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == body.email))
    user   = result.scalar_one_or_none()
    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid credentials", "code": "INVALID_CREDENTIALS"},
        )
    return {"token": create_jwt(user), "is_admin": user.is_admin}


@app.post("/auth/register", status_code=status.HTTP_201_CREATED)
async def auth_register(body: RegisterRequest, db: AsyncSession = Depends(get_db)):
    existing = await db.execute(select(User).where(User.email == body.email))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "email already registered", "code": "EMAIL_TAKEN"},
        )
    user = User(
        email=body.email,
        team=body.team,
        hashed_password=hash_password(body.password),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return {"id": user.id, "email": user.email, "team": user.team}


# ── portal — token management ─────────────────────────────────────────────────

class TokenCreateRequest(BaseModel):
    tool: str  # cursor | claude_code


@app.post("/portal/token/create", status_code=status.HTTP_201_CREATED)
async def create_token(
    body:        TokenCreateRequest,
    jwt_payload: dict = Depends(get_current_user_jwt),
    db:          AsyncSession = Depends(get_db),
):
    if body.tool not in ("cursor", "claude_code"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "tool must be 'cursor' or 'claude_code'", "code": "INVALID_TOOL"},
        )

    platform_token = "plat_" + secrets.token_urlsafe(32)
    expires_at     = datetime.now(timezone.utc) + timedelta(days=TOKEN_EXPIRES_DAYS)

    token = Token(
        platform_token=platform_token,
        user_id=int(jwt_payload["sub"]),
        tool=body.tool,
        expires_at=expires_at,
    )
    db.add(token)
    await db.commit()
    await db.refresh(token)

    config_snippet = (
        f"# Cursor / Claude Code config\n"
        f"BASE_URL=http://localhost:8000\n"
        f"API_KEY={platform_token}\n"
    )
    return {
        "platform_token": platform_token,
        "tool":           token.tool,
        "expires_at":     expires_at.isoformat(),
        "config_snippet": config_snippet,
    }


@app.get("/portal/token/my")
async def my_token(
    jwt_payload: dict = Depends(get_current_user_jwt),
    db:          AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Token)
        .where(Token.user_id == int(jwt_payload["sub"]))
        .order_by(Token.created_at.desc())
    )
    tokens = result.scalars().all()
    return [
        {
            "id":            t.id,
            "tool":          t.tool,
            "status":        t.status,
            "request_count": t.request_count,
            "last_used_at":  t.last_used_at.isoformat() if t.last_used_at else None,
            "created_at":    t.created_at.isoformat(),
            "expires_at":    t.expires_at.isoformat() if t.expires_at else None,
        }
        for t in tokens
    ]


@app.delete("/portal/token/revoke")
async def revoke_token(
    jwt_payload: dict = Depends(get_current_user_jwt),
    db:          AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Token)
        .where(Token.user_id == int(jwt_payload["sub"]), Token.status == "active")
        .order_by(Token.created_at.desc())
    )
    token = result.scalars().first()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "no active token found", "code": "NO_TOKEN"},
        )
    token.status    = "revoked"
    token.revoked_at = datetime.now(timezone.utc)
    await db.commit()
    # Note: proxy's in-memory cache is separate (different process).
    # The revoked token will be rejected by the proxy within 60 seconds
    # when its cache entry expires.
    return {"revoked": True, "token_id": token.id}


# ── portal — usage metrics ────────────────────────────────────────────────────

@app.get("/portal/my-usage")
async def my_usage(
    jwt_payload: dict = Depends(get_current_user_jwt),
    db:          AsyncSession = Depends(get_db),
):
    user_id              = int(jwt_payload["sub"])
    now                  = datetime.now(timezone.utc)
    today_start          = now.replace(hour=0, minute=0, second=0, microsecond=0)
    seven_days_ago       = now - timedelta(days=7)
    twenty_four_hours_ago = now - timedelta(hours=24)

    # Latest token status
    token_result = await db.execute(
        select(Token)
        .where(Token.user_id == user_id)
        .order_by(Token.created_at.desc())
        .limit(1)
    )
    token = token_result.scalar_one_or_none()

    token_status     = "none"
    token_expires_at = None
    if token:
        if token.status == "revoked":
            token_status = "revoked"
        else:
            expires = token.expires_at
            if expires:
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)
                token_status = "expired" if expires < now else "active"
            else:
                token_status = token.status
        token_expires_at = token.expires_at.isoformat() if token.expires_at else None

    # Requests by day — last 7 days
    day_rows = (await db.execute(
        select(
            func.strftime('%Y-%m-%d', RequestLog.timestamp).label('date'),
            func.count().label('count'),
        )
        .where(RequestLog.user_id == user_id, RequestLog.timestamp >= seven_days_ago)
        .group_by(func.strftime('%Y-%m-%d', RequestLog.timestamp))
    )).all()

    day_map          = {row.date: row.count for row in day_rows}
    requests_by_day  = [
        {"date": (now - timedelta(days=i)).strftime('%Y-%m-%d'), "count": 0}
        for i in range(6, -1, -1)
    ]
    for entry in requests_by_day:
        entry["count"] = day_map.get(entry["date"], 0)

    # Requests by hour — last 24h
    hour_rows = (await db.execute(
        select(
            func.strftime('%H', RequestLog.timestamp).label('hour'),
            func.count().label('count'),
        )
        .where(RequestLog.user_id == user_id, RequestLog.timestamp >= twenty_four_hours_ago)
        .group_by(func.strftime('%H', RequestLog.timestamp))
    )).all()

    hour_map          = {int(row.hour): row.count for row in hour_rows}
    requests_by_hour  = [{"hour": h, "count": hour_map.get(h, 0)} for h in range(24)]

    # Totals
    total_today = (await db.execute(
        select(func.count()).select_from(RequestLog)
        .where(RequestLog.user_id == user_id, RequestLog.timestamp >= today_start)
    )).scalar_one()

    total_week = (await db.execute(
        select(func.count()).select_from(RequestLog)
        .where(RequestLog.user_id == user_id, RequestLog.timestamp >= seven_days_ago)
    )).scalar_one()

    avg_latency = (await db.execute(
        select(func.avg(RequestLog.latency_ms)).select_from(RequestLog)
        .where(RequestLog.user_id == user_id)
    )).scalar_one()

    rate_limit_hits = 0
    if token and token.last_rate_limited_at:
        last_rl = token.last_rate_limited_at
        if last_rl.tzinfo is None:
            last_rl = last_rl.replace(tzinfo=timezone.utc)
        if last_rl >= twenty_four_hours_ago:
            rate_limit_hits = 1

    return {
        "requests_by_day":      requests_by_day,
        "requests_by_hour":     requests_by_hour,
        "total_requests_today": total_today,
        "total_requests_week":  total_week,
        "avg_latency_ms":       round(avg_latency, 1) if avg_latency else 0,
        "rate_limit_hits":      rate_limit_hits,
        "token_status":         token_status,
        "token_expires_at":     token_expires_at,
    }


# ── admin — auth ──────────────────────────────────────────────────────────────

@app.post("/admin/auth/login")
async def admin_auth_login(body: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == body.email))
    user   = result.scalar_one_or_none()
    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid credentials", "code": "INVALID_CREDENTIALS"},
        )
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "admin access required", "code": "FORBIDDEN"},
        )
    return {"token": create_jwt(user), "is_admin": True}


# ── admin — users ─────────────────────────────────────────────────────────────

@app.get("/admin/users")
async def admin_users(
    _:  dict = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    users       = (await db.execute(select(User).order_by(User.created_at.desc()))).scalars().all()
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    result      = []

    for u in users:
        tokens = (await db.execute(select(Token).where(Token.user_id == u.id))).scalars().all()
        active = next((t for t in tokens if t.status == "active"), None)
        requests_today = (await db.execute(
            select(func.count()).select_from(RequestLog)
            .where(RequestLog.user_id == u.id, RequestLog.timestamp >= today_start)
        )).scalar_one()

        total_tokens = (await db.execute(
            select(func.sum(RequestLog.prompt_tokens + RequestLog.completion_tokens))
            .where(RequestLog.user_id == u.id)
        )).scalar_one()

        result.append({
            "id":                  u.id,
            "email":               u.email,
            "team":                u.team,
            "is_admin":            u.is_admin,
            "created_at":          u.created_at.isoformat(),
            "active_token_id":     active.id if active else None,
            "total_requests":      sum(t.request_count for t in tokens),
            "requests_today":      requests_today,
            "total_tokens":        int(total_tokens or 0),
            "token_status":        active.status if active else "none",
            "last_rate_limited_at": (
                active.last_rate_limited_at.isoformat()
                if active and active.last_rate_limited_at else None
            ),
        })
    return result


# ── admin — tokens ────────────────────────────────────────────────────────────

@app.get("/admin/tokens")
async def admin_tokens(
    _:  dict = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    tokens = (await db.execute(select(Token).order_by(Token.created_at.desc()))).scalars().all()
    result = []
    for t in tokens:
        user = (await db.execute(select(User).where(User.id == t.user_id))).scalar_one_or_none()
        result.append({
            "id":            t.id,
            "platform_token": t.platform_token[:12] + "...",  # masked
            "user_id":       t.user_id,
            "user_email":    user.email if user else "unknown",
            "team":          user.team  if user else "unknown",
            "tool":          t.tool,
            "status":        t.status,
            "request_count": t.request_count,
            "created_at":    t.created_at.isoformat(),
            "expires_at":    t.expires_at.isoformat()    if t.expires_at    else None,
            "last_used_at":  t.last_used_at.isoformat()  if t.last_used_at  else None,
            "revoked_at":    t.revoked_at.isoformat()    if t.revoked_at    else None,
        })
    return result


# ── admin — stats ─────────────────────────────────────────────────────────────

@app.get("/admin/stats")
async def admin_stats(
    _:  dict = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    now         = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    five_min_ago = now - timedelta(minutes=5)
    week_ago    = now - timedelta(days=7)

    active_tokens = (await db.execute(
        select(func.count()).select_from(Token).where(Token.status == "active")
    )).scalar_one()

    requests_today = (await db.execute(
        select(func.count()).select_from(RequestLog)
        .where(RequestLog.timestamp >= today_start)
    )).scalar_one()

    requests_last_5min = (await db.execute(
        select(func.count()).select_from(RequestLog)
        .where(RequestLog.timestamp >= five_min_ago)
    )).scalar_one()

    revocations_this_week = (await db.execute(
        select(func.count()).select_from(Token)
        .where(Token.status == "revoked", Token.revoked_at >= week_ago)
    )).scalar_one()

    return {
        "active_tokens":          active_tokens,
        "requests_today":         requests_today,
        "requests_last_5min":     requests_last_5min,
        "revocations_this_week":  revocations_this_week,
    }


# ── admin — usage by team ─────────────────────────────────────────────────────

@app.get("/admin/usage-by-team")
async def admin_usage_by_team(
    _:  dict = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    rows = (await db.execute(
        select(RequestLog.team, func.count().label("requests"))
        .group_by(RequestLog.team)
        .order_by(func.count().desc())
    )).all()
    return [{"team": team, "requests": count} for team, count in rows]


# ── admin — revoke token ──────────────────────────────────────────────────────

@app.delete("/admin/tokens/{token_id}")
async def admin_revoke_token(
    token_id: int,
    _:  dict = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Token).where(Token.id == token_id))
    token  = result.scalar_one_or_none()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "token not found", "code": "NOT_FOUND"},
        )
    if token.status == "revoked":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "token already revoked", "code": "ALREADY_REVOKED"},
        )
    token.status     = "revoked"
    token.revoked_at = datetime.now(timezone.utc)
    await db.commit()
    return {"revoked": True, "token_id": token.id}


# ── admin — rate limit alerts ─────────────────────────────────────────────────

@app.get("/admin/rate-limit-alerts")
async def admin_rate_limit_alerts(
    _:  dict = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
    tokens = (await db.execute(
        select(Token).where(
            Token.last_rate_limited_at != None,  # noqa: E711
            Token.last_rate_limited_at >= one_hour_ago,
        )
    )).scalars().all()

    result = []
    for t in tokens:
        user = (await db.execute(select(User).where(User.id == t.user_id))).scalar_one_or_none()
        result.append({
            "token_id":             t.id,
            "email":                user.email if user else "unknown",
            "team":                 user.team  if user else "unknown",
            "last_rate_limited_at": t.last_rate_limited_at.isoformat(),
        })
    return result


# ── admin — user management ───────────────────────────────────────────────────

class AdminCreateUserRequest(BaseModel):
    email:    str
    password: str
    team:     str
    is_admin: bool = False


class AdminUpdateUserRequest(BaseModel):
    team:     str | None = None
    is_admin: bool | None = None


@app.post("/admin/users", status_code=status.HTTP_201_CREATED)
async def admin_create_user(
    body: AdminCreateUserRequest,
    _:   dict = Depends(get_admin_user),
    db:  AsyncSession = Depends(get_db),
):
    existing = (await db.execute(select(User).where(User.email == body.email))).scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "email already registered", "code": "EMAIL_TAKEN"},
        )
    user = User(
        email=body.email,
        team=body.team,
        hashed_password=hash_password(body.password),
        is_admin=body.is_admin,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return {"id": user.id, "email": user.email, "team": user.team, "is_admin": user.is_admin}


@app.patch("/admin/users/{user_id}")
async def admin_update_user(
    user_id: int,
    body:    AdminUpdateUserRequest,
    _:       dict = Depends(get_admin_user),
    db:      AsyncSession = Depends(get_db),
):
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "user not found", "code": "NOT_FOUND"},
        )
    if body.team is not None:
        user.team = body.team
    if body.is_admin is not None:
        user.is_admin = body.is_admin
    await db.commit()
    return {"id": user.id, "email": user.email, "team": user.team, "is_admin": user.is_admin}


@app.delete("/admin/users/{user_id}")
async def admin_delete_user(
    user_id: int,
    _:  dict = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "user not found", "code": "NOT_FOUND"},
        )
    # Delete request logs, then tokens, then user (respect FK constraints)
    token_ids = (await db.execute(
        select(Token.id).where(Token.user_id == user_id)
    )).scalars().all()
    if token_ids:
        await db.execute(sql_delete(RequestLog).where(RequestLog.token_id.in_(token_ids)))
    await db.execute(sql_delete(RequestLog).where(RequestLog.user_id == user_id))
    await db.execute(sql_delete(Token).where(Token.user_id == user_id))
    await db.execute(sql_delete(User).where(User.id == user_id))
    await db.commit()
    return {"deleted": True, "user_id": user_id}


# ── admin — settings ──────────────────────────────────────────────────────────

_DEFAULTS = {"rate_limit": "30", "rate_window": "60"}


async def _get_setting(db: AsyncSession, key: str) -> str:
    row = (await db.execute(select(PlatformSettings).where(PlatformSettings.key == key))).scalar_one_or_none()
    return row.value if row else _DEFAULTS[key]


@app.get("/admin/settings")
async def admin_get_settings(
    _:  dict = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    return {
        "rate_limit":  int(await _get_setting(db, "rate_limit")),
        "rate_window": int(await _get_setting(db, "rate_window")),
    }


class SettingsUpdateRequest(BaseModel):
    rate_limit:  int | None = None
    rate_window: int | None = None


@app.put("/admin/settings")
async def admin_update_settings(
    body: SettingsUpdateRequest,
    _:   dict = Depends(get_admin_user),
    db:  AsyncSession = Depends(get_db),
):
    updates = {}
    if body.rate_limit is not None:
        updates["rate_limit"] = str(body.rate_limit)
    if body.rate_window is not None:
        updates["rate_window"] = str(body.rate_window)

    for key, val in updates.items():
        row = (await db.execute(select(PlatformSettings).where(PlatformSettings.key == key))).scalar_one_or_none()
        if row:
            row.value = val
        else:
            db.add(PlatformSettings(key=key, value=val))
    await db.commit()
    return {
        "rate_limit":  int(await _get_setting(db, "rate_limit")),
        "rate_window": int(await _get_setting(db, "rate_window")),
    }


# ── admin — analytics ─────────────────────────────────────────────────────────

@app.get("/admin/analytics")
async def admin_analytics(
    _:  dict = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    now              = datetime.now(timezone.utc)
    seven_days_ago   = now - timedelta(days=7)
    twenty_four_h    = now - timedelta(hours=24)

    # requests by day — last 7 days
    day_rows = (await db.execute(
        select(
            func.strftime('%Y-%m-%d', RequestLog.timestamp).label('date'),
            func.count().label('count'),
        )
        .where(RequestLog.timestamp >= seven_days_ago)
        .group_by(func.strftime('%Y-%m-%d', RequestLog.timestamp))
    )).all()
    day_map = {row.date: row.count for row in day_rows}
    requests_by_day = [
        {"date": (now - timedelta(days=i)).strftime('%Y-%m-%d'), "count": day_map.get((now - timedelta(days=i)).strftime('%Y-%m-%d'), 0)}
        for i in range(6, -1, -1)
    ]

    # requests by hour — last 24h
    hour_rows = (await db.execute(
        select(
            func.strftime('%H', RequestLog.timestamp).label('hour'),
            func.count().label('count'),
        )
        .where(RequestLog.timestamp >= twenty_four_h)
        .group_by(func.strftime('%H', RequestLog.timestamp))
    )).all()
    hour_map = {int(r.hour): r.count for r in hour_rows}
    requests_by_hour = [{"hour": h, "count": hour_map.get(h, 0)} for h in range(24)]

    # requests and tokens by model
    model_rows = (await db.execute(
        select(
            RequestLog.model,
            func.count().label('count'),
            func.sum(RequestLog.prompt_tokens + RequestLog.completion_tokens).label('tokens'),
        )
        .group_by(RequestLog.model)
        .order_by(func.count().desc())
    )).all()
    requests_by_model = [
        {"model": m, "count": c, "tokens": int(t or 0)}
        for m, c, t in model_rows
    ]

    # top users by request count
    top_users = (await db.execute(
        select(User.email, User.team, func.count(RequestLog.id).label('count'))
        .join(RequestLog, RequestLog.user_id == User.id)
        .group_by(User.id)
        .order_by(func.count(RequestLog.id).desc())
        .limit(10)
    )).all()
    top_users_list = [{"email": e, "team": t, "count": c} for e, t, c in top_users]

    return {
        "requests_by_day":   requests_by_day,
        "requests_by_hour":  requests_by_hour,
        "requests_by_model": requests_by_model,
        "top_users":         top_users_list,
    }
