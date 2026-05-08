from fastapi import APIRouter, Depends, HTTPException, Request
from typing import List
from core.database import get_database
from core.auth import get_current_user
from ..schemas.comment import CommentCreate, CommentRead
from ..services import comment_service
from ..core.socket import emit_new_comment

router = APIRouter()

@router.post("/{post_id}/comments/", response_model=CommentRead)
async def create_comment(request: Request, post_id: str, comment: CommentCreate, db = Depends(get_database), user = Depends(get_current_user)):
    new_comment = await comment_service.add_comment(db, post_id, comment, user.model_dump())
    await emit_new_comment(new_comment)
    return new_comment

@router.get("/{post_id}/comments/", response_model=List[CommentRead])
async def get_post_comments(post_id: str, db = Depends(get_database), user = Depends(get_current_user)):
    comments = await comment_service.get_comments(db, post_id)
    return comments
