import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# Model endpoint — new names take priority, old names kept for backward compat
MODEL_API_KEY: str  = os.getenv("OPENAI_API_KEY",  os.getenv("MODEL_API_KEY",  ""))
MODEL_ENDPOINT: str = os.getenv("OPENAI_ENDPOINT", os.getenv("MODEL_ENDPOINT", ""))

_DB_PATH = Path(__file__).resolve().parent.parent / "gateway.db"
DATABASE_URL: str = f"sqlite+aiosqlite:///{_DB_PATH}"

SECRET_KEY: str       = os.getenv("SECRET_KEY",       "change-me-in-production")
ADMIN_SECRET_KEY: str = os.getenv("ADMIN_SECRET_KEY", SECRET_KEY)
JWT_ALGORITHM: str    = "HS256"
JWT_EXPIRE_MINUTES: int = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))
