from datetime import datetime, timedelta
from db.user_repo import (
    get_user_by_email,
    get_user_by_sidhi_id,
    create_user
)
from models.users import UserRegister, UserLogin
from ustils.security import hash_password, verify_password
from ustils.id_generator import generate_user_id
from auth_utils import create_access_token
from services.token_service import issue_tokens


import re

def normalize_username(username: str) -> str:
    """
    Convert user input into a valid Sidhilynx username.
    Rules:
    - lowercase
    - remove spaces
    - allow only a-z, 0-9, dot, underscore
    """
    username = username.strip().lower()
    username = username.replace(" ", "")
    username = re.sub(r"[^a-z0-9._]", "", username)
    return username

import re

def normalize_username_without_spaces(name: str) -> str:
    return re.sub(r"\s+", "", name).lower()



class AuthError(Exception):
    pass


# =========================
# REGISTER
# =========================
async def register_user(data: UserRegister):
    clean_username = normalize_username(data.username)
    sidhi_id = f"{clean_username}@sidhilynx.id"
    spaceless_username = normalize_username_without_spaces(data.username)

    # Check email uniqueness
    if await get_user_by_email(data.email):
        raise AuthError("Email already registered")

    # Check Sidhilynx ID uniqueness
    if await get_user_by_sidhi_id(sidhi_id):
        raise AuthError("Sidhilynx ID already taken")

    user = {
        "user_id": generate_user_id(),
        "sidhi_id": sidhi_id,
        "username": spaceless_username,
        "email": data.email,
        "password_hash": hash_password(data.password),
        "created_at": datetime.utcnow(),
        "is_active": True
    }

    await create_user(user)
    return {
        "message": "Registered successfully",
        "sidhi_id": sidhi_id
    }


# =========================
# LOGIN
# =========================
async def login_user(data: UserLogin):
    # 🔍 Find user by Sidhilynx ID
    user = await get_user_by_sidhi_id(data.sidhi_id)
    if not user:
        raise AuthError("Invalid credentials")

    # 🔐 Verify password
    if not verify_password(data.password, user["password_hash"]):
        raise AuthError("Invalid credentials")

    # 🎟 Issue access + refresh tokens
    tokens = await issue_tokens(
        user_id=user["user_id"],
        scopes=["sidhilynx"]   # future: ["lumetrix", "cadevel"]
    )

    return {
        **tokens,
        "sidhi_id": user["sidhi_id"]
    }
