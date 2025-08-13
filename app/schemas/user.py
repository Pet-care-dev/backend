from pydantic import BaseModel, EmailStr
from typing import List

class UserCreate(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

# ✅ Pet schema
class Pet(BaseModel):
    name: str
    img: str

# ✅ Dashboard user response schema
class UserResponse(BaseModel):
    first_name: str
    pets: List[Pet]