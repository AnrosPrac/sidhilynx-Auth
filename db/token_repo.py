from database import db
from datetime import datetime


async def save_refresh_token(
    user_id: str,
    client_id: str,
    token_hash: str,
    expires_at: datetime
):
    await db.refresh_tokens.insert_one({
        "user_id": user_id,
        "client_id": client_id,
        "token_hash": token_hash,
        "expires_at": expires_at,
        "created_at": datetime.utcnow()
    })


async def get_refresh_token(token_hash: str):
    return await db.refresh_tokens.find_one({"token_hash": token_hash})


async def delete_refresh_token(token_hash: str):
    await db.refresh_tokens.delete_one({"token_hash": token_hash})


async def delete_all_user_tokens(user_id: str):
    await db.refresh_tokens.delete_many({"user_id": user_id})
