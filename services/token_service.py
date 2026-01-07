import hashlib
from datetime import datetime, timedelta
from auth.auth_utils import create_access_token
from auth.db.token_repo import save_refresh_token, get_refresh_token, delete_refresh_token

REFRESH_TOKEN_DAYS = 30

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

async def issue_tokens(user_id: str, scopes: list[str]):
    access_token = create_access_token(
        data={"sub": user_id, "scope": scopes},
        expires_delta=timedelta(minutes=15)
    )

    refresh_raw = f"{user_id}.{datetime.utcnow().timestamp()}"
    refresh_hash = _hash_token(refresh_raw)

    await save_refresh_token(
        user_id=user_id,
        token_hash=refresh_hash,
        expires_at=datetime.utcnow() + timedelta(days=REFRESH_TOKEN_DAYS)
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_raw,
        "token_type": "bearer"
    }

async def refresh_access_token(refresh_token: str):
    token_hash = _hash_token(refresh_token)
    record = await get_refresh_token(token_hash)

    if not record:
        return None

    return create_access_token(
        data={"sub": record["user_id"], "scope": ["default"]},
        expires_delta=timedelta(minutes=15)
    )
