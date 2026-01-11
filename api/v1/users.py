from fastapi import APIRouter, HTTPException, Header, Request
from pydantic import BaseModel, EmailStr
import os

from services.auth_services import register_user, login_user, AuthError
from services.password_reset import (
    request_password_reset,
    reset_password,
    PasswordResetError
)
from security.client_crypto import derive_client_id, verify_signature
import time

from services.token_service import refresh_access_token

router = APIRouter()


# ---------- MODELS ----------
class RegisterReq(BaseModel):
    username: str
    email: EmailStr
    password: str


class LoginReq(BaseModel):
    sidhi_id: str
    password: str


class ForgotPasswordReq(BaseModel):
    identifier: str


class ResetPasswordReq(BaseModel):
    identifier: str
    otp: str
    new_password: str


# ---------- REGISTER ----------
@router.post("/register")
async def register(
    data: RegisterReq,
    x_register_key: str = Header(...)
):
    if x_register_key != os.getenv("REGISTER_API_KEY"):
        raise HTTPException(status_code=401, detail="Unauthorized")

    try:
        return await register_user(data)
    except AuthError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------- LOGIN (CLIENT IDENTITY WIRED) ----------

@router.post("/login")
async def login(
    data: LoginReq,
    request: Request,

    # 🔐 CRYPTO CLIENT IDENTITY
    x_client_public_key: str = Header(...),
    x_client_signature: str = Header(...),
    x_client_timestamp: str = Header(...),

    # 📦 APP METADATA
    x_platform: str = Header(...),
    x_app_id: str = Header(...),
    x_app_name: str = Header(...),
    x_app_version: str = Header(...)
):
    try:
        # 1️⃣ Reject replayed / stale requests (60s window)
        now = time.time()
        if abs(now - float(x_client_timestamp)) > 60:
            raise HTTPException(
                status_code=401,
                detail="Stale login request"
            )

        # 2️⃣ Verify client signature
        message = f"{x_client_timestamp}:{data.sidhi_id}".encode()

        if not verify_signature(
            public_key_hex=x_client_public_key,
            message=message,
            signature_hex=x_client_signature
        ):
            raise HTTPException(
                status_code=401,
                detail="Invalid client signature"
            )

        # 3️⃣ Derive client_id (SERVER-TRUSTED)
        client_id = derive_client_id(bytes.fromhex(x_client_public_key))

        # 4️⃣ Continue normal login (client-bound)
        return await login_user(
            data=data,
            client_id=client_id,
            platform=x_platform,
            app_id=x_app_id,
            app_name=x_app_name,
            app_version=x_app_version,
            ip_address=request.client.host
        )

    except AuthError as e:
        raise HTTPException(status_code=401, detail=str(e))


# ---------- REFRESH TOKEN ----------
@router.post("/refresh-token")
async def refresh_token(
    refresh_token: str,
    request: Request,

    # 🔐 CRYPTO CLIENT IDENTITY
    x_client_public_key: str = Header(...),
    x_client_signature: str = Header(...),
    x_client_timestamp: str = Header(...)
):
    # 1️⃣ Reject stale / replayed requests (60s window)
    now = time.time()
    if abs(now - float(x_client_timestamp)) > 60:
        raise HTTPException(
            status_code=401,
            detail="Stale refresh request"
        )

    # 2️⃣ Verify client signature
    message = f"{x_client_timestamp}:{refresh_token}".encode()

    if not verify_signature(
        public_key_hex=x_client_public_key,
        message=message,
        signature_hex=x_client_signature
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid client signature"
        )

    # 3️⃣ Derive client_id (SERVER-TRUSTED)
    client_id = derive_client_id(bytes.fromhex(x_client_public_key))

    # 4️⃣ Issue new access token (client-bound)
    token = await refresh_access_token(
        refresh_token=refresh_token,
        client_id=client_id
    )

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token"
        )

    return {
        "access_token": token,
        "token_type": "bearer"
    }


# ---------- FORGOT PASSWORD ----------
@router.post("/forgot-password")
async def forgot_password(data: ForgotPasswordReq):
    await request_password_reset(data.identifier)
    return {"message": "If the email exists, an OTP has been sent."}


# ---------- RESET PASSWORD ----------
@router.post("/reset-password")
async def reset_password_api(data: ResetPasswordReq):
    try:
        await reset_password(data.identifier, data.otp, data.new_password)
        return {"message": "Password reset successful"}
    except PasswordResetError as e:
        raise HTTPException(status_code=400, detail=str(e))
