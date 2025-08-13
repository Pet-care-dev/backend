from pydantic import BaseModel, EmailStr
from typing import Optional

class User(BaseModel):
    email: EmailStr
    password: str
    role: str = "user"  # 'user', 'store_owner', 'admin'
