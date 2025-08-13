from fastapi import APIRouter, HTTPException
from app.schemas.user import UserCreate, UserLogin
from app.utils.auth import (
    hash_password,
    verify_password,
    create_access_token,
)
from app.database import users_collection

router = APIRouter()

@router.post("/register")
def register(user: UserCreate):
    existing_user = users_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed = hash_password(user.password)
    new_user = {
        "first_name": user.first_name,
        "last_name": user.last_name,
        "email": user.email,
        "password": hashed,
    }
    users_collection.insert_one(new_user)
    return {"message": "User registered successfully"}

@router.post("/login")
def login(user: UserLogin): 
    db_user = users_collection.find_one({"email": user.email})
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not verify_password(user.password, db_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_access_token({"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}
