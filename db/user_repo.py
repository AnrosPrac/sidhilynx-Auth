from core.database import db

async def get_user_by_email(email: str):
    return await db.users.find_one({"email": email})

async def get_user_by_id(user_id: str):
    return await db.users.find_one({"user_id": user_id})

async def create_user(user: dict):
    await db.users.insert_one(user)

async def get_user_by_sidhi_id(sidhi_id: str):
    return await db.users.find_one({"sidhi_id": sidhi_id})


from core.database import db
from datetime import datetime

async def set_reset_otp(user_id: str, otp_hash: str, expires_at: datetime):
    await db.users.update_one(
        {"user_id": user_id},
        {
            "$set": {
                "reset_otp_hash": otp_hash,
                "reset_otp_expires": expires_at,
                "reset_otp_attempts": 0
            }
        }
    )

async def increment_otp_attempts(user_id: str):
    await db.users.update_one(
        {"user_id": user_id},
        {"$inc": {"reset_otp_attempts": 1}}
    )

async def clear_reset_otp(user_id: str):
    await db.users.update_one(
        {"user_id": user_id},
        {
            "$unset": {
                "reset_otp_hash": "",
                "reset_otp_expires": "",
                "reset_otp_attempts": ""
            }
        }
    )
