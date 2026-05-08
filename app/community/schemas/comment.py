from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional

class CommentBase(BaseModel):
    content: str = Field(..., min_length=1, max_length=500)

class CommentCreate(CommentBase):
    pass

class CommentRead(CommentBase):
    id: str
    post_id: str
    author_id: str
    author_name: str
    created_at: datetime
