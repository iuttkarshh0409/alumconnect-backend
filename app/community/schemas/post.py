from pydantic import BaseModel, Field
from datetime import datetime
from typing import List, Optional

class PostBase(BaseModel):
    content: str = Field(..., min_length=1, max_length=2000)

class PostCreate(PostBase):
    pass

class PostAuthor(BaseModel):
    id: str
    name: str
    avatar_url: Optional[str] = None

class PostRead(PostBase):
    id: str
    author: PostAuthor
    likes_count: int = 0
    comments_count: int = 0
    created_at: datetime
    has_liked: bool = False

class FeedResponse(BaseModel):
    posts: List[PostRead]
    next_cursor: Optional[str]
    has_more: bool
