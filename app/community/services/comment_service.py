from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId
from datetime import datetime, timezone
from ..schemas.comment import CommentCreate

async def add_comment(db: AsyncIOMotorDatabase, post_id: str, comment_data: CommentCreate, user: dict):
    comment_dict = comment_data.dict()
    comment_dict.update({
        "post_id": ObjectId(post_id),
        "author_id": user["user_id"],
        "author_name": user["name"],
        "created_at": datetime.now(timezone.utc)
    })
    
    result = await db.comments.insert_one(comment_dict)
    
    # Increment comment count on the post atomically
    await db.posts.update_one(
        {"_id": ObjectId(post_id)},
        {"$inc": {"comments_count": 1}}
    )
    
    comment_dict["id"] = str(result.inserted_id)
    comment_dict["post_id"] = str(comment_dict["post_id"])
    return comment_dict

async def get_comments(db: AsyncIOMotorDatabase, post_id: str):
    cursor = db.comments.find({"post_id": ObjectId(post_id)}).sort("created_at", 1)
    comments = await cursor.to_list(length=100)
    
    for c in comments:
        c["id"] = str(c["_id"])
        c["post_id"] = str(c["post_id"])
        if "created_at" in c and c["created_at"].tzinfo is None:
            c["created_at"] = c["created_at"].replace(tzinfo=timezone.utc)
    
    return comments
