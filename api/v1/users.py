from fastapi import APIRouter, HTTPException, Header, Request
from pydantic import BaseModel, EmailStr
import os
import time

from services.auth_services import register_user, verify_registration_otp, login_user, login_google_user, AuthError
from services.password_reset import request_password_reset, reset_password, PasswordResetError
from services.token_service import refresh_access_token
from security.client_crypto import derive_client_id, verify_signature
from rate_limit import limiter
from ustils.client_ip import get_client_ip

router = APIRouter()


# ---------- MODELS ----------
class RegisterReq(BaseModel):
    username: str
    email: EmailStr
    password: str

class VerifyRegistrationReq(BaseModel):
    email: EmailStr
    otp: str

class LoginReq(BaseModel):
    sidhi_id: str
    password: str

class GoogleLoginReq(BaseModel):
    google_token: str

class ForgotPasswordReq(BaseModel):
    identifier: str

class ResetPasswordReq(BaseModel):
    identifier: str
    otp: str
    new_password: str


# ---------- REGISTER ----------
@router.post("/register")
@limiter.limit("5/minute")
async def register(
    data: RegisterReq,
    request: Request,
    x_register_key: str = Header(...)
):
    if x_register_key != os.getenv("REGISTER_API_KEY"):
        raise HTTPException(status_code=401, detail="Unauthorized")

    try:
        return await register_user(data, ip_address=get_client_ip(request))
    except AuthError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------- VERIFY REGISTRATION OTP ----------
@router.post("/verify-registration")
@limiter.limit("10/minute")
async def verify_registration(data: VerifyRegistrationReq, request: Request):
    try:
        return await verify_registration_otp(data.email, data.otp)
    except AuthError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------- LOGIN ----------
@router.post("/login")
@limiter.limit("10/minute")
async def login(
    data: LoginReq,
    request: Request,
    x_client_public_key: str = Header(...),
    x_client_signature: str = Header(...),
    x_client_timestamp: str = Header(...),
    x_platform: str = Header(...),
    x_app_id: str = Header(...),
    x_app_name: str = Header(...),
    x_app_version: str = Header(...)
):
    try:
        now = time.time()
        if abs(now - float(x_client_timestamp)) > 60:
            raise HTTPException(status_code=401, detail="Stale login request")

        message = f"{x_client_timestamp}:{data.sidhi_id}".encode()
        if not verify_signature(
            public_key_hex=x_client_public_key,
            message=message,
            signature_hex=x_client_signature
        ):
            raise HTTPException(status_code=401, detail="Invalid client signature")

        client_id = derive_client_id(bytes.fromhex(x_client_public_key))

        return await login_user(
            data=data,
            client_id=client_id,
            public_key=x_client_public_key,
            platform=x_platform,
            app_id=x_app_id,
            app_name=x_app_name,
            app_version=x_app_version,
            ip_address=get_client_ip(request)
        )

    except AuthError as e:
        raise HTTPException(status_code=401, detail=str(e))


# ---------- LOGIN WITH GOOGLE ----------
@router.post("/login/google")
@limiter.limit("10/minute")
async def login_google(
    data: GoogleLoginReq,
    request: Request,
    x_client_public_key: str = Header(...),
    x_client_signature: str = Header(...),
    x_client_timestamp: str = Header(...),
    x_platform: str = Header(...),
    x_app_id: str = Header(...),
    x_app_name: str = Header(...),
    x_app_version: str = Header(...)
):
    try:
        now = time.time()
        if abs(now - float(x_client_timestamp)) > 60:
            raise HTTPException(status_code=401, detail="Stale login request")

        message = f"{x_client_timestamp}:{data.google_token}".encode()
        if not verify_signature(
            public_key_hex=x_client_public_key,
            message=message,
            signature_hex=x_client_signature
        ):
            raise HTTPException(status_code=401, detail="Invalid client signature")

        client_id = derive_client_id(bytes.fromhex(x_client_public_key))

        return await login_google_user(
            google_token=data.google_token,
            client_id=client_id,
            public_key=x_client_public_key,
            platform=x_platform,
            app_id=x_app_id,
            app_name=x_app_name,
            app_version=x_app_version,
            ip_address=get_client_ip(request)
        )

    except AuthError as e:
        raise HTTPException(status_code=401, detail=str(e))


# ---------- REFRESH TOKEN ----------
@router.post("/refresh-token")
@limiter.limit("20/minute")
async def refresh_token(
    refresh_token: str,
    request: Request,
    x_client_public_key: str = Header(...),
    x_client_signature: str = Header(...),
    x_client_timestamp: str = Header(...)
):
    now = time.time()
    if abs(now - float(x_client_timestamp)) > 60:
        raise HTTPException(status_code=401, detail="Stale refresh request")

    message = f"{x_client_timestamp}:{refresh_token}".encode()
    if not verify_signature(
        public_key_hex=x_client_public_key,
        message=message,
        signature_hex=x_client_signature
    ):
        raise HTTPException(status_code=401, detail="Invalid client signature")

    client_id = derive_client_id(bytes.fromhex(x_client_public_key))

    token = await refresh_access_token(
        refresh_token=refresh_token,
        client_id=client_id
    )

    if not token:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    return {
        "access_token": token,
        "token_type": "bearer"
    }


# ---------- FORGOT PASSWORD ----------
@router.post("/forgot-password")
@limiter.limit("5/minute")
async def forgot_password(data: ForgotPasswordReq, request: Request):
    await request_password_reset(data.identifier)
    return {"message": "If the email exists, an OTP has been sent."}


# ---------- RESET PASSWORD ----------
@router.post("/reset-password")
@limiter.limit("10/minute")
async def reset_password_api(data: ResetPasswordReq, request: Request):
    try:
        await reset_password(data.identifier, data.otp, data.new_password)
        return {"message": "Password reset successful"}
    except PasswordResetError as e:
        raise HTTPException(status_code=400, detail=str(e))