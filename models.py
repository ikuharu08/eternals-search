from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class UserCreate(BaseModel):
    username: str
    full_name: str
    profile_pic: Optional[str] = None

class UserResponse(BaseModel):
    id: int
    username: str
    full_name: str
    profile_pic: Optional[str]
    created_at: datetime

class UserLogin(BaseModel):
    username: str
    password: str 