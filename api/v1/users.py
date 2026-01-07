from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel, EmailStr
import os

from auth.services.auth_services import register_user, login_user, AuthError
from auth.services.password_reset import (
    request_password_reset,
    reset_password,
    PasswordResetError
)

router = APIRouter()


# ---------- MODELS ----------
class RegisterReq(BaseModel):
    username: str
    email: EmailStr
    password: str


class LoginReq(BaseModel):
    sidhi_id:str
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


# ---------- LOGIN ----------
@router.post("/login")
async def login(data: LoginReq):
    try:
        return await login_user(data)
    except AuthError as e:
        raise HTTPException(status_code=401, detail=str(e))


# ---------- FORGOT PASSWORD (OTP) ----------
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


from auth.services.token_service import refresh_access_token

@router.post("/refresh-token")
async def refresh_token(refresh_token: str):
    token = await refresh_access_token(refresh_token)
    if not token:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    return {
        "access_token": token,
        "token_type": "bearer"
    }
