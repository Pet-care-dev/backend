from fastapi import APIRouter, Depends
from app.utils.auth import get_current_user

router = APIRouter()

@router.get("/dashboard")
def get_dashboard(current_user=Depends(get_current_user)):
    return {
        "message": f"Welcome {current_user['first_name']}!",
        "first_name": current_user["first_name"],
        "last_name": current_user["last_name"],
        "email": current_user["email"]
    }
