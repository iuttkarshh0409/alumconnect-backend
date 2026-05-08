from fastapi import APIRouter, Depends, HTTPException, Request, Query
from typing import Optional
from core.database import get_database
from core.auth import get_current_user
from ..schemas.post import PostCreate, PostRead, FeedResponse
from ..services import post_service
from ..core.socket import emit_feed_update, emit_post_liked

router = APIRouter()

@router.post("/", response_model=PostRead)
async def create_new_post(request: Request, post: PostCreate, db = Depends(get_database), user = Depends(get_current_user)):
    new_post = await post_service.create_post(db, post, user.model_dump())
    await emit_feed_update(new_post)
    return new_post

@router.get("/", response_model=FeedResponse)
async def get_community_feed(
    request: Request,
    cursor: Optional[str] = Query(None),
    limit: int = Query(10, le=50),
    db = Depends(get_database),
    user = Depends(get_current_user)
):
    user_id = user.user_id
    posts, next_cursor, has_more = await post_service.get_feed(db, cursor, limit, user_id)
    return {
        "posts": posts,
        "next_cursor": next_cursor,
        "has_more": has_more
    }

@router.post("/{post_id}/like/")
async def like_post(request: Request, post_id: str, db = Depends(get_database), user = Depends(get_current_user)):
    user_id = user.user_id
    await post_service.toggle_like(db, post_id, user_id, "like")
    await emit_post_liked({"post_id": post_id, "user_id": user_id, "action": "like"})
    return {"message": "Liked successfully"}

@router.delete("/{post_id}/like/")
async def unlike_post(request: Request, post_id: str, db = Depends(get_database), user = Depends(get_current_user)):
    user_id = user.user_id
    await post_service.toggle_like(db, post_id, user_id, "unlike")
    return {"message": "Unliked successfully"}

@router.post("/{post_id}/flag/")
async def report_post(request: Request, post_id: str, db = Depends(get_database), user = Depends(get_current_user)):
    user_id = user.user_id
    await post_service.flag_post(db, post_id, user_id)
    return {"message": "Post reported successfully"}
