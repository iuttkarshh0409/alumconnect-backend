import os
import httpx
import requests
from jose import jwt
from jose.exceptions import JWTError
from fastapi import Request, HTTPException
from datetime import datetime, timezone
from .database import db
from .models import User

CLERK_API_BASE = "https://api.clerk.com/v1"
CLERK_SECRET_KEY = os.environ["CLERK_SECRET_KEY"]
CLERK_ISSUER = os.environ["CLERK_ISSUER"]
CLERK_JWKS_URL = f"{CLERK_ISSUER}/.well-known/jwks.json"

_jwks_cache = None

def get_clerk_jwks():
    global _jwks_cache
    if _jwks_cache is None:
        resp = requests.get(CLERK_JWKS_URL)
        resp.raise_for_status()
        _jwks_cache = resp.json()
    return _jwks_cache

async def fetch_clerk_user(clerk_user_id: str) -> dict:
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{CLERK_API_BASE}/users/{clerk_user_id}",
            headers={"Authorization": f"Bearer {CLERK_SECRET_KEY}"}
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=401, detail="Unable to fetch Clerk user")
        return resp.json()

async def get_current_user(request: Request) -> User:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    token = auth_header.replace("Bearer ", "")

    try:
        jwks = get_clerk_jwks()
        payload = jwt.decode(
            token,
            jwks,
            algorithms=["RS256"],
            issuer=CLERK_ISSUER,
            options={"verify_aud": False},
        )
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid Clerk token")

    clerk_user_id = payload["sub"]
    user_doc = await db.users.find_one({"user_id": clerk_user_id}, {"_id": 0})

    if not user_doc or not user_doc.get("email"):
        clerk_user = await fetch_clerk_user(clerk_user_id)
        email = clerk_user["email_addresses"][0].get("email_address") if clerk_user.get("email_addresses") else None
        
        if not email:
            raise HTTPException(status_code=400, detail="No email associated with Clerk user")

        name = f"{clerk_user.get('first_name', '')} {clerk_user.get('last_name', '')}".strip()
        
        # Admin Override
        is_master_admin = email == "utkarsh0907.edu@gmail.com"
        assigned_role = "admin" if is_master_admin else (user_doc.get("role") if user_doc else None)
        assigned_inst = "inst_IIPS" if is_master_admin else (user_doc.get("institute_id") if user_doc else None)

        user_doc = {
            "user_id": clerk_user_id,
            "email": email,
            "name": name or email.split("@")[0],
            "picture": clerk_user.get("image_url"),
            "role": assigned_role,
            "institute_id": assigned_inst,
            "department": user_doc.get("department") if user_doc else None,
            "created_at": user_doc.get("created_at") if user_doc else datetime.now(timezone.utc),
            "last_active": datetime.now(timezone.utc),
        }

        await db.users.update_one({"user_id": clerk_user_id}, {"$set": user_doc}, upsert=True)
    else:
        last_active = datetime.now(timezone.utc)
        await db.users.update_one({"user_id": clerk_user_id}, {"$set": {"last_active": last_active}})
        user_doc["last_active"] = last_active

    if user_doc.get("email") == "utkarsh0907.edu@gmail.com":
        user_doc["role"] = "admin"
        user_doc["institute_id"] = "inst_IIPS"

    return User(**user_doc)
