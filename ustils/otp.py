import random
import hashlib
from datetime import datetime, timedelta

OTP_EXPIRY_MINUTES = 10
MAX_OTP_ATTEMPTS = 5

def generate_otp() -> str:
    return f"{random.randint(100000, 999999)}"

def hash_otp(otp: str) -> str:
    return hashlib.sha256(otp.encode()).hexdigest()

def otp_expiry_time():
    return datetime.utcnow() + timedelta(minutes=OTP_EXPIRY_MINUTES)
