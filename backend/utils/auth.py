from datetime import datetime, timezone

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from config import JWT_ALGORITHM, JWT_EXPIRE_MINUTES, SECRET_KEY
from utils.models import User

bearer_scheme = HTTPBearer()


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def create_jwt(user: User) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub":      str(user.id),
        "email":    user.email,
        "team":     user.team,
        "is_admin": user.is_admin,
        "iat":      now.timestamp(),
        "exp":      now.timestamp() + JWT_EXPIRE_MINUTES * 60,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_jwt(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid or expired JWT", "code": "UNAUTHORIZED"},
        )


async def get_current_user_jwt(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> dict:
    """Validates a JWT (issued at login) and returns its payload."""
    return decode_jwt(credentials.credentials)
