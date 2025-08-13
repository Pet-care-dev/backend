from fastapi import APIRouter, HTTPException
from app.models.otp_model import OTPRequest, OTPVerify, ResetPassword
from app.utils.email import send_otp_email
from app.utils.auth import hash_password
from app.database import get_user_by_email, update_user_password
from datetime import datetime, timedelta
import random

# In-memory store (replace with DB for production)
otp_store = {}

router = APIRouter(prefix="/password", tags=["Password Reset"])

@router.post("/send-otp")
def send_otp(data: OTPRequest):
    user = get_user_by_email(data.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    otp = str(random.randint(100000, 999999))
    expiry = datetime.utcnow() + timedelta(minutes=10)
    otp_store[data.email] = {"otp": otp, "expires": expiry}
    send_otp_email(data.email, otp)
    return {"message": "OTP sent to email"}


@router.post("/verify-otp")
def verify_otp(data: OTPVerify):
    entry = otp_store.get(data.email)
    if not entry or entry["otp"] != data.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    if datetime.utcnow() > entry["expires"]:
        raise HTTPException(status_code=400, detail="OTP expired")
    return {"message": "OTP verified"}


@router.post("/reset")
def reset_password(data: ResetPassword):
    entry = otp_store.get(data.email)
    if not entry or entry["otp"] != data.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    if datetime.utcnow() > entry["expires"]:
        raise HTTPException(status_code=400, detail="OTP expired")

    password = hash_password(data.new_password)
    update_user_password(data.email, password)
    del otp_store[data.email]
    return {"message": "Password reset successful"}