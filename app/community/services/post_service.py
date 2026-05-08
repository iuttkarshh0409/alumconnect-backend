from motor.motor_asyncio import AsyncIOMotorDatabase
from core.database import db
from bson import ObjectId
from datetime import datetime, timezone
from ..schemas.post import PostCreate, PostRead
from typing import List, Optional

async def create_post(db: AsyncIOMotorDatabase, post_data: PostCreate, user: dict):
    post_dict = post_data.dict()
    post_dict.update({
        "author_id": user["user_id"],
        "author_name": user["name"],
        "likes_count": 0,
        "comments_count": 0,
        "liked_by": [], # Array of user IDs for simple indexing
        "created_at": datetime.now(timezone.utc),
        "is_deleted": False
    })
    
    result = await db.posts.insert_one(post_dict)
    
    # Return formatted for PostRead schema
    return {
        "id": str(result.inserted_id),
        "content": post_dict["content"],
        "author": {
            "id": user["user_id"],
            "name": user["name"]
        },
        "likes_count": 0,
        "comments_count": 0,
        "created_at": post_dict["created_at"],
        "has_liked": False
    }

async def get_feed(db: AsyncIOMotorDatabase, cursor: Optional[str] = None, limit: int = 10, user_id: str = None):
    query = {"is_deleted": False}
    if cursor:
        query["_id"] = {"$lt": ObjectId(cursor)}
    
    # Fetch posts sorted by ID (which is chronological in MongoDB) descending
    cursor_obj = db.posts.find(query).sort("_id", -1).limit(limit + 1)
    posts_raw = await cursor_obj.to_list(length=limit + 1)
    
    has_more = len(posts_raw) > limit
    posts_to_return = posts_raw[:limit]
    
    formatted_posts = []
    for p in posts_to_return:
        formatted_posts.append({
            "id": str(p["_id"]),
            "content": p["content"],
            "author": {
                "id": p["author_id"],
                "name": p.get("author_name", "Anonymous")
            },
            "likes_count": p.get("likes_count", 0),
            "comments_count": p.get("comments_count", 0),
            "created_at": p["created_at"].replace(tzinfo=timezone.utc) if p["created_at"].tzinfo is None else p["created_at"],
            "has_liked": user_id in p.get("liked_by", []) if user_id else False
        })
    
    next_cursor = str(formatted_posts[-1]["id"]) if formatted_posts else None
    return formatted_posts, next_cursor, has_more

async def toggle_like(db: AsyncIOMotorDatabase, post_id: str, user_id: str, action: str):
    if action == "like":
        # Atomically add user to liked_by and increment likes_count
        await db.posts.update_one(
            {"_id": ObjectId(post_id), "liked_by": {"$ne": user_id}},
            {
                "$push": {"liked_by": user_id},
                "$inc": {"likes_count": 1}
            }
        )
    else:
        # Atomically remove user from liked_by and decrement likes_count
        await db.posts.update_one(
            {"_id": ObjectId(post_id), "liked_by": user_id},
            {
                "$pull": {"liked_by": user_id},
                "$inc": {"likes_count": -1}
            }
        )
    return True

async def flag_post(db: AsyncIOMotorDatabase, post_id: str, user_id: str):
    # Track who flagged it to prevent double-flagging from the same user
    # Also increment a flags_count for easy admin filtering
    await db.posts.update_one(
        {"_id": ObjectId(post_id), "flagged_by": {"$ne": user_id}},
        {
            "$push": {"flagged_by": user_id},
            "$inc": {"flags_count": 1}
        }
    )
    return True
