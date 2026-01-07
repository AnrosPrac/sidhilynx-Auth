from pydantic import BaseModel, EmailStr, Field
from datetime import datetime

class UserRegister(BaseModel):
    username: str = Field(min_length=3, max_length=30)
    email: EmailStr
    password: str = Field(min_length=8)

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserDB(BaseModel):
    user_id: str
    username: str
    email: EmailStr
    sidhi_id:str
    password_hash: str
    created_at: datetime
    is_active: bool
