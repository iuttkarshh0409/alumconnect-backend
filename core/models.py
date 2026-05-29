from pydantic import BaseModel, ConfigDict, EmailStr
from typing import List, Optional
from datetime import datetime

class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    user_id: str
    email: EmailStr
    name: str
    picture: Optional[str] = None
    role: Optional[str] = None  # student, alumni, admin
    institute_id: Optional[str] = None
    department: Optional[str] = None
    status: str = "uninitialized"
    is_approved: bool = False
    created_at: datetime
    last_active: Optional[datetime] = None

