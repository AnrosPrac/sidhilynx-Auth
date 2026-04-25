from datetime import datetime
import re

from db.user_repo import (
    get_user_by_email,
    get_user_by_sidhi_id,
    create_user
)
from db.client_repo import (
    get_client_by_id,
    create_client,
    update_client_activity
)
from models.users import UserRegister, UserLogin
from ustils.security import hash_password, verify_password
from ustils.id_generator import generate_user_id
from services.token_service import issue_tokens
import os
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import random


class AuthError(Exception):
    pass


# =========================
# USERNAME NORMALIZATION
# =========================
def normalize_username(username: str) -> str:
    username = username.strip().lower()
    username = username.replace(" ", "")
    username = re.sub(r"[^a-z0-9._]", "", username)
    return username


def normalize_username_without_spaces(name: str) -> str:
    return re.sub(r"\s+", "", name).lower()


# =========================
# REGISTER
# =========================
# REPLACE the register_user function in auth_services.py

from services.email_services import send_registration_otp
from db.user_repo import set_registration_otp, get_pending_registration, increment_registration_otp_attempts, delete_pending_registration
from ustils.otp import generate_otp, hash_otp, otp_expiry_time, MAX_OTP_ATTEMPTS
import asyncio

async def register_user(data: UserRegister):
    """Step 1: Generate OTP and send email (don't create user yet)"""
    clean_username = normalize_username(data.username)
    sidhi_id = f"{clean_username}@sidhilynx.id"
    spaceless_username = normalize_username_without_spaces(data.username)

    # Check if email/username already registered
    if await get_user_by_email(data.email):
        raise AuthError("Email already registered")

    if await get_user_by_sidhi_id(sidhi_id):
        raise AuthError("Sidhilynx ID already taken")

    # Generate OTP
    otp = generate_otp()
    otp_hash = hash_otp(otp)

    # Store pending registration with user data
    user_data = {
        "user_id": generate_user_id(),
        "sidhi_id": sidhi_id,
        "username": spaceless_username,
        "email": data.email,
        "password_hash": hash_password(data.password),
        "created_at": datetime.utcnow(),
        "is_active": True,
        "auth_provider": "email"
    }

    await set_registration_otp(
        email=data.email,
        otp_hash=otp_hash,
        expires_at=otp_expiry_time(),
        user_data=user_data
    )

    # Send OTP email
    await asyncio.to_thread(
        send_registration_otp,
        data.email,
        otp,
        spaceless_username
    )

    return {
        "message": "OTP sent to your email. Please verify to complete registration.",
        "email": data.email
    }


async def verify_registration_otp(email: str, otp: str):
    """Step 2: Verify OTP and create user"""
    pending = await get_pending_registration(email)

    if not pending:
        raise AuthError("No pending registration found")

    if pending["otp_expires"] < datetime.utcnow():
        await delete_pending_registration(email)
        raise AuthError("OTP expired")

    if pending.get("otp_attempts", 0) >= MAX_OTP_ATTEMPTS:
        await delete_pending_registration(email)
        raise AuthError("Too many attempts")

    if hash_otp(otp) != pending["otp_hash"]:
        await increment_registration_otp_attempts(email)
        raise AuthError("Invalid OTP")

    # OTP valid → create user
    await create_user(pending["user_data"])
    await delete_pending_registration(email)

    return {
        "message": "Registration successful!",
        "sidhi_id": pending["user_data"]["sidhi_id"]
    }

# =========================
# LOGIN (CLIENT-AWARE + CRYPTO)
# =========================
async def login_user(
    data: UserLogin,
    client_id: str,
    public_key: str,        # 🔥 REQUIRED
    platform: str,
    app_id: str,
    app_name: str,
    app_version: str,
    ip_address: str
):
    # 1️⃣ Verify user
    user = await get_user_by_sidhi_id(data.sidhi_id)
    if not user:
        raise AuthError("Invalid credentials")

    if not verify_password(data.password, user["password_hash"]):
        raise AuthError("Invalid credentials")

    # 2️⃣ Client registry enforcement
    client = await get_client_by_id(client_id)

    if not client:
        # First time seeing this client → register it
        await create_client(
            client_id=client_id,
            user_id=user["user_id"],
            public_key=public_key,     # 🔥 STORE PUBLIC KEY
            platform=platform,
            app_id=app_id,
            app_name=app_name,
            app_version=app_version,
            ip_address=ip_address
        )
    else:
        # Existing client checks
        if client["user_id"] != user["user_id"]:
            raise AuthError("This device is already linked to another account")

        if client["status"] != "active":
            raise AuthError("This device has been revoked")

        await update_client_activity(client_id, ip_address)

    # 3️⃣ Issue client-bound tokens
    tokens = await issue_tokens(
        user_id=user["user_id"],
        client_id=client_id,
        scopes=["sidhilynx"]
    )

    return {
        **tokens,
        "sidhi_id": user["sidhi_id"]
    }

# =========================
# LOGIN WITH GOOGLE (CLIENT-AWARE)
# =========================
async def login_google_user(
    google_token: str,
    client_id: str,
    public_key: str,
    platform: str,
    app_id: str,
    app_name: str,
    app_version: str,
    ip_address: str
):
    try:
        # 1️⃣ Verify Google Token
        client_id_google = os.getenv("GOOGLE_CLIENT_ID")
        idinfo = id_token.verify_oauth2_token(
            google_token, google_requests.Request(), client_id_google
        )
        
        email = idinfo["email"]
        name = idinfo.get("name", email.split("@")[0])
        
        # 2️⃣ Check if user exists by email
        user = await get_user_by_email(email)
        is_new_user = not user

        if not user:
            # Auto-register if not found
            clean_username = normalize_username(name)
            sidhi_id = f"{clean_username}@sidhilynx.id"
            spaceless_username = normalize_username_without_spaces(name)
            
            # Handle sidhi_id collision
            if await get_user_by_sidhi_id(sidhi_id):
                sidhi_id = f"{clean_username}{random.randint(100,999)}@sidhilynx.id"
                
            user_data = {
                "user_id": generate_user_id(),
                "sidhi_id": sidhi_id,
                "username": spaceless_username,
                "email": email,
                "password_hash": hash_password(generate_user_id()), # Dummy password, can't login via email/pwd unless reset
                "created_at": datetime.utcnow(),
                "is_active": True,
                "auth_provider": "google"
            }
            await create_user(user_data)
            user = user_data
            
    except ValueError:
        raise AuthError("Invalid Google token")

    # 3️⃣ Client registry enforcement
    client = await get_client_by_id(client_id)

    if not client:
        await create_client(
            client_id=client_id,
            user_id=user["user_id"],
            public_key=public_key,
            platform=platform,
            app_id=app_id,
            app_name=app_name,
            app_version=app_version,
            ip_address=ip_address
        )
    else:
        if client["user_id"] != user["user_id"]:
            raise AuthError("This device is already linked to another account")

        if client["status"] != "active":
            raise AuthError("This device has been revoked")

        await update_client_activity(client_id, ip_address)

    # 4️⃣ Issue client-bound tokens
    tokens = await issue_tokens(
        user_id=user["user_id"],
        client_id=client_id,
        scopes=["sidhilynx"]
    )

    return {
        **tokens,
        "sidhi_id": user["sidhi_id"],
        "is_new_user": is_new_user
    }