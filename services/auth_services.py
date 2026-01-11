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
async def register_user(data: UserRegister):
    clean_username = normalize_username(data.username)
    sidhi_id = f"{clean_username}@sidhilynx.id"
    spaceless_username = normalize_username_without_spaces(data.username)

    if await get_user_by_email(data.email):
        raise AuthError("Email already registered")

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
# LOGIN (CLIENT-AWARE)
# =========================
async def login_user(
    data: UserLogin,
    client_id: str,
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
        # First time seeing this client_id → register it
        await create_client(
            client_id=client_id,
            user_id=user["user_id"],
            platform=platform,
            app_id=app_id,
            app_name=app_name,
            app_version=app_version,
            ip_address=ip_address
        )
    else:
        # Existing client_id checks
        if client["user_id"] != user["user_id"]:
            raise AuthError("This device is already linked to another account")

        if client["status"] != "active":
            raise AuthError("This device has been revoked")

        await update_client_activity(client_id, ip_address)

    # 3️⃣ Issue CLIENT-BOUND tokens
    tokens = await issue_tokens(
        user_id=user["user_id"],
        client_id=client_id,
        scopes=["sidhilynx"]
    )

    return {
        **tokens,
        "sidhi_id": user["sidhi_id"]
    }
