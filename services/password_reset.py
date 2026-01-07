from datetime import datetime
import asyncio

from services.email_services import send_password_reset_otp
from db.user_repo import (
    get_user_by_email,
    get_user_by_sidhi_id,
    set_reset_otp,
    increment_otp_attempts,
    clear_reset_otp
)
from ustils.otp import (
    generate_otp,
    hash_otp,
    otp_expiry_time,
    MAX_OTP_ATTEMPTS
)
from ustils.security import hash_password
from auth.database import db


class PasswordResetError(Exception):
    pass


# =========================
# REQUEST PASSWORD RESET
# =========================
async def request_password_reset(identifier: str):
    # Resolve user by sidhi_id OR email
    if identifier.endswith("@sidhilynx.id"):
        user = await get_user_by_sidhi_id(identifier)
    else:
        user = await get_user_by_email(identifier)

    # Prevent email enumeration
    if not user:
        return

    otp = generate_otp()
    otp_hash = hash_otp(otp)

    await set_reset_otp(
        user_id=user["user_id"],
        otp_hash=otp_hash,
        expires_at=otp_expiry_time()
    )

    # Send OTP asynchronously (email always from DB)
    await asyncio.to_thread(
        send_password_reset_otp,
        user["email"],
        otp
    )


# =========================
# RESET PASSWORD
# =========================
async def reset_password(identifier: str, otp: str, new_password: str):
    # Resolve user again
    if identifier.endswith("@sidhilynx.id"):
        user = await get_user_by_sidhi_id(identifier)
    else:
        user = await get_user_by_email(identifier)

    if not user or not user.get("reset_otp_hash"):
        raise PasswordResetError("Invalid OTP or expired")

    if user["reset_otp_expires"] < datetime.utcnow():
        await clear_reset_otp(user["user_id"])
        raise PasswordResetError("OTP expired")

    if user.get("reset_otp_attempts", 0) >= MAX_OTP_ATTEMPTS:
        await clear_reset_otp(user["user_id"])
        raise PasswordResetError("Too many attempts")

    if hash_otp(otp) != user["reset_otp_hash"]:
        await increment_otp_attempts(user["user_id"])
        raise PasswordResetError("Invalid OTP")

    # OTP valid → reset password
    await db.users.update_one(
        {"user_id": user["user_id"]},
        {"$set": {"password_hash": hash_password(new_password)}}
    )

    await clear_reset_otp(user["user_id"])
