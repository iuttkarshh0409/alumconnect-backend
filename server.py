from jose import jwt
from jose.exceptions import JWTError
import requests
from fastapi import FastAPI, APIRouter, HTTPException, Cookie, Response, Request
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import httpx

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

CLERK_API_BASE = "https://api.clerk.com/v1"
CLERK_SECRET_KEY = os.environ["CLERK_SECRET_KEY"]


async def fetch_clerk_user(clerk_user_id: str) -> dict:
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{CLERK_API_BASE}/users/{clerk_user_id}",
            headers={
                "Authorization": f"Bearer {CLERK_SECRET_KEY}"
            }
        )

        if resp.status_code != 200:
            raise HTTPException(status_code=401, detail="Unable to fetch Clerk user")

        return resp.json()

CLERK_ISSUER = os.environ["CLERK_ISSUER"]
CLERK_JWKS_URL = f"{CLERK_ISSUER}/.well-known/jwks.json"

_jwks_cache = None

def get_clerk_public_key(token: str):
    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header.get("kid")

    if not kid:
        raise HTTPException(status_code=401, detail="Invalid token header")

    jwks = get_clerk_jwks()

    for key in jwks["keys"]:
        if key["kid"] == kid:
            return key

    raise HTTPException(status_code=401, detail="Public key not found")


def get_clerk_jwks():
    global _jwks_cache
    if _jwks_cache is None:
        resp = requests.get(CLERK_JWKS_URL)
        resp.raise_for_status()
        _jwks_cache = resp.json()
    return _jwks_cache


mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

app = FastAPI()
origins = [
    "http://localhost:3000",
    "https://alumconnect-frontend.vercel.app",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
api_router = APIRouter(prefix="/api")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# ===== MODELS =====

class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    user_id: str
    email: EmailStr
    name: str
    picture: Optional[str] = None
    role: Optional[str] = None  # student, alumni, admin
    institute_id: Optional[str] = None
    department: Optional[str] = None
    created_at: datetime

class AlumniProfile(BaseModel):
    model_config = ConfigDict(extra="ignore")
    user_id: str
    institute_id: str
    department: str
    graduation_year: int
    company: Optional[str] = None
    job_domain: Optional[str] = None  # SDE, PM, HR, etc.
    job_title: Optional[str] = None
    skills: List[str] = []
    bio: Optional[str] = None
    linkedin_url: Optional[str] = None
    is_verified: bool = False
    is_claimed: bool = False
    created_at: datetime
    updated_at: datetime

class StudentProfile(BaseModel):
    model_config = ConfigDict(extra="ignore")
    user_id: str
    institute_id: str
    department: str
    graduation_year: int
    bio: Optional[str] = None
    created_at: datetime

class MentorshipRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    request_id: str
    student_id: str
    mentor_id: str
    topic: str  # Mock Interview, Resume Review, Career Guidance, etc.
    description: str
    status: str = "pending"  # pending, accepted, rejected, expired
    created_at: datetime
    expires_at: datetime

class Institute(BaseModel):
    model_config = ConfigDict(extra="ignore")
    institute_id: str
    name: str
    departments: List[str] = []
    created_at: datetime


# ===== REQUEST/RESPONSE MODELS =====
class SetupProfileRequest(BaseModel):
    role: str
    institute_id: str
    department: str
    graduation_year: int
    bio: Optional[str] = None

class AlumniProfileUpdate(BaseModel):
    company: Optional[str] = None
    job_domain: Optional[str] = None
    job_title: Optional[str] = None
    skills: Optional[List[str]] = None
    bio: Optional[str] = None
    linkedin_url: Optional[str] = None

class CreateMentorshipRequest(BaseModel):
    mentor_id: str
    topic: str
    description: str

class UpdateRequestStatus(BaseModel):
    status: str  # accepted, rejected

class SendMessageRequest(BaseModel): #create table SendMessageRequest(conversation_id TEXT, content TEXT);
    conversation_id: str
    content: str




# ===== HELPER FUNCTIONS =====
async def get_current_user(request: Request) -> User:
    auth_header = request.headers.get("Authorization")
    print("AUTH HEADER RECEIVED:", auth_header)

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

    # 1️⃣ Try DB first
    user_doc = await db.users.find_one({"user_id": clerk_user_id}, {"_id": 0})

    # 2️⃣ If missing OR broken (email missing) → fetch from Clerk
    if not user_doc or not user_doc.get("email"):
        clerk_user = await fetch_clerk_user(clerk_user_id)

        email = None
        if clerk_user.get("email_addresses"):
            email = clerk_user["email_addresses"][0].get("email_address")

        if not email:
            raise HTTPException(
                status_code=400,
                detail="No email associated with Clerk user"
            )

        name = (
            f"{clerk_user.get('first_name', '')} {clerk_user.get('last_name', '')}"
        ).strip()

        user_doc = {
            "user_id": clerk_user_id,
            "email": email,
            "name": name or email.split("@")[0],
            "picture": clerk_user.get("image_url"),
            "role": user_doc.get("role") if user_doc else None,
            "institute_id": user_doc.get("institute_id") if user_doc else None,
            "department": user_doc.get("department") if user_doc else None,
            "created_at": user_doc.get("created_at") if user_doc else datetime.now(timezone.utc),
        }

        await db.users.update_one(
            {"user_id": clerk_user_id},
            {"$set": user_doc},
            upsert=True
        )

    return User(**user_doc)



def generate_conversation_id() -> str:
    return f"conv_{uuid.uuid4().hex[:12]}"

def generate_message_id() -> str:
    return f"msg_{uuid.uuid4().hex[:12]}"





# ===== AUTH ROUTES =====
@api_router.get("/auth/me", response_model=User)
async def get_current_user_info(
    request: Request,
    session_token: Optional[str] = Cookie(None),
) -> User:
    return await get_current_user(request)

@api_router.post("/auth/logout")
async def logout(request: Request, response: Response, session_token: Optional[str] = Cookie(None)):
    token = session_token or request.headers.get("Authorization", "").replace("Bearer ", "")
    if token:
        await db.user_sessions.delete_one({"session_token": token})
    
    response.delete_cookie(key="session_token", path="/")
    return {"message": "Logged out successfully"}

@api_router.post("/auth/setup")
async def setup_profile(request: Request, profile_data: SetupProfileRequest, session_token: Optional[str] = Cookie(None)):
    user = await get_current_user(request)
    
    if user.role:
        return JSONResponse(
            status_code=200, 
            content={
                "message": "Profile already set up",
                "role": user.role
                }
        )
    
    await db.users.update_one(
        {"user_id": user.user_id},
        {"$set": {
            "role": profile_data.role,
            "institute_id": profile_data.institute_id,
            "department": profile_data.department
        }}
    )
    
    if profile_data.role == "alumni":
        alumni_profile = {
            "user_id": user.user_id,
            "institute_id": profile_data.institute_id,
            "department": profile_data.department,
            "graduation_year": profile_data.graduation_year,
            "skills": [],
            "is_verified": False,
            "is_claimed": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "bio": profile_data.bio
        }
        await db.alumni_profiles.insert_one(alumni_profile)
    elif profile_data.role == "student":
        student_profile = {
            "user_id": user.user_id,
            "institute_id": profile_data.institute_id,
            "department": profile_data.department,
            "graduation_year": profile_data.graduation_year,
            "bio": profile_data.bio,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        await db.students.insert_one(student_profile)
    
    updated_user = await db.users.find_one({"user_id": user.user_id}, {"_id": 0})
    if isinstance(updated_user.get("created_at"), str):
        updated_user["created_at"] = datetime.fromisoformat(updated_user["created_at"])
    
    return User(**updated_user)


# ===== ALUMNI ROUTES =====

@api_router.get("/alumni")
async def get_alumni(
    request: Request,
    session_token: Optional[str] = Cookie(None),
    company: Optional[str] = None,
    job_domain: Optional[str] = None,
    graduation_year: Optional[int] = None,
    skills: Optional[str] = None
):
    user = await get_current_user(request)
    
    query = {"institute_id": user.institute_id, "is_claimed": True}
    if company:
        query["company"] = {"$regex": company, "$options": "i"}
    if job_domain:
        query["job_domain"] = job_domain
    if graduation_year:
        query["graduation_year"] = graduation_year
    if skills:
        query["skills"] = {"$in": skills.split(",")}
    
    alumni_profiles = await db.alumni_profiles.find(query, {"_id": 0}).to_list(1000)
    
    for profile in alumni_profiles:
        if isinstance(profile.get("created_at"), str):
            profile["created_at"] = datetime.fromisoformat(profile["created_at"])
        if isinstance(profile.get("updated_at"), str):
            profile["updated_at"] = datetime.fromisoformat(profile["updated_at"])
    
    alumni_with_users = []
    for profile in alumni_profiles:
        user_doc = await db.users.find_one({"user_id": profile["user_id"]}, {"_id": 0})
        if user_doc:
            if isinstance(user_doc.get("created_at"), str):
                user_doc["created_at"] = datetime.fromisoformat(user_doc["created_at"])
            alumni_with_users.append({**profile, "user": user_doc})
    
    return alumni_with_users

@api_router.get("/alumni/{user_id}")
async def get_alumni_profile(user_id: str, request: Request, session_token: Optional[str] = Cookie(None)):
    await get_current_user(request)
    
    profile = await db.alumni_profiles.find_one({"user_id": user_id}, {"_id": 0})
    if not profile:
        raise HTTPException(status_code=404, detail="Alumni profile not found")
    
    user_doc = await db.users.find_one({"user_id": user_id}, {"_id": 0})
    
    if isinstance(profile.get("created_at"), str):
        profile["created_at"] = datetime.fromisoformat(profile["created_at"])
    if isinstance(profile.get("updated_at"), str):
        profile["updated_at"] = datetime.fromisoformat(profile["updated_at"])
    if user_doc and isinstance(user_doc.get("created_at"), str):
        user_doc["created_at"] = datetime.fromisoformat(user_doc["created_at"])
    
    return {**profile, "user": user_doc}

@api_router.put("/alumni/{user_id}")
async def update_alumni_profile(
    user_id: str,
    profile_update: AlumniProfileUpdate,
    request: Request,
    session_token: Optional[str] = Cookie(None)
):
    user = await get_current_user(request)
    
    if user.user_id != user_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    
    update_data = profile_update.model_dump(exclude_none=True)
    update_data["updated_at"] = datetime.now(timezone.utc).isoformat()
    
    result = await db.alumni_profiles.update_one(
        {"user_id": user_id},
        {"$set": update_data}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Alumni profile not found")
    
    updated_profile = await db.alumni_profiles.find_one({"user_id": user_id}, {"_id": 0})
    if isinstance(updated_profile.get("created_at"), str):
        updated_profile["created_at"] = datetime.fromisoformat(updated_profile["created_at"])
    if isinstance(updated_profile.get("updated_at"), str):
        updated_profile["updated_at"] = datetime.fromisoformat(updated_profile["updated_at"])
    
    return updated_profile


# ===== MENTORSHIP ROUTES =====

@api_router.post("/mentorship/requests")
async def create_mentorship_request(
    request_data: CreateMentorshipRequest,
    request: Request,
    session_token: Optional[str] = Cookie(None)
):
    user = await get_current_user(request)
    
    if user.role != "student":
        raise HTTPException(status_code=403, detail="Only students can create mentorship requests")
    
    active_requests_count = await db.mentorship_requests.count_documents({
        "student_id": user.user_id,
        "status": "pending"
    })
    
    if active_requests_count >= 3:
        raise HTTPException(status_code=400, detail="Maximum 3 active requests allowed")
    
    request_id = f"req_{uuid.uuid4().hex[:12]}"
    mentorship_request = {
        "request_id": request_id,
        "student_id": user.user_id,
        "mentor_id": request_data.mentor_id,
        "topic": request_data.topic,
        "description": request_data.description,
        "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    }
    
    await db.mentorship_requests.insert_one(mentorship_request)
    
    created_request = await db.mentorship_requests.find_one({"request_id": request_id}, {"_id": 0})
    if isinstance(created_request.get("created_at"), str):
        created_request["created_at"] = datetime.fromisoformat(created_request["created_at"])
    if isinstance(created_request.get("expires_at"), str):
        created_request["expires_at"] = datetime.fromisoformat(created_request["expires_at"])
    
    return created_request

@api_router.get("/mentorship/requests")
async def get_mentorship_requests(request: Request, session_token: Optional[str] = Cookie(None)):
    user = await get_current_user(request)
    
    if user.role == "student":
        requests = await db.mentorship_requests.find({"student_id": user.user_id}, {"_id": 0}).to_list(1000)
    elif user.role == "alumni":
        requests = await db.mentorship_requests.find({"mentor_id": user.user_id}, {"_id": 0}).to_list(1000)
    else:
        requests = await db.mentorship_requests.find({}, {"_id": 0}).to_list(1000)
    
    for req in requests:
        if isinstance(req.get("created_at"), str):
            req["created_at"] = datetime.fromisoformat(req["created_at"])
        if isinstance(req.get("expires_at"), str):
            req["expires_at"] = datetime.fromisoformat(req["expires_at"])
        
        expires_at = req["expires_at"]
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(timezone.utc) and req["status"] == "pending":
            await db.mentorship_requests.update_one(
                {"request_id": req["request_id"]},
                {"$set": {"status": "expired"}}
            )
            req["status"] = "expired"
        
        student_doc = await db.users.find_one({"user_id": req["student_id"]}, {"_id": 0})
        mentor_doc = await db.users.find_one({"user_id": req["mentor_id"]}, {"_id": 0})
        
        if user.role == "student":
            req["mentor"] = mentor_doc
        else:
            req["student"] = student_doc
    
    return requests

@api_router.put("/mentorship/requests/{request_id}")
async def update_request_status(
    request_id: str,
    status_update: UpdateRequestStatus,
    request: Request,
    session_token: Optional[str] = Cookie(None)
):
    user = await get_current_user(request)
    
    req_doc = await db.mentorship_requests.find_one({"request_id": request_id}, {"_id": 0})
    if not req_doc:
        raise HTTPException(status_code=404, detail="Request not found")
    
    #AUTHORIZATION CHECK
    if user.user_id != req_doc["mentor_id"] and user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # STATE CHECK
    if req_doc["status"] != "pending":
        raise HTTPException(
            status_code=400,
            detail=f"Cannot update request in '{req_doc['status']}' state"
        )

    #UPDATE STATUS
    await db.mentorship_requests.update_one(
        {"request_id": request_id},
        {"$set": {"status": status_update.status}}
    )
    
    #CREATE CONVERSATION ON ACCEPT
    if status_update.status == "accepted":
        existing = await db.conversations.find_one({"request_id": request_id})
        if not existing:
            student = await db.users.find_one(
                {"user_id": req_doc["student_id"]},
                {"institute_id": 1, "_id": 0}
            )

            conversation_doc = {
                "conversation_id": generate_conversation_id(),
                "request_id": request_id,
                "student_id": req_doc["student_id"],
                "mentor_id": req_doc["mentor_id"],
                "institute_id": student["institute_id"],
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_message_at": None,
                "is_active": True
            }

            await db.conversations.insert_one(conversation_doc)

    updated_request = await db.mentorship_requests.find_one({"request_id": request_id}, {"_id": 0})
    if isinstance(updated_request.get("created_at"), str):
        updated_request["created_at"] = datetime.fromisoformat(updated_request["created_at"])
    if isinstance(updated_request.get("expires_at"), str):
        updated_request["expires_at"] = datetime.fromisoformat(updated_request["expires_at"])
    
    return updated_request

# ===== MESSAGES ROUTES =====

@api_router.post("/messages")
async def send_message(
    payload: SendMessageRequest,
    request: Request,
    session_token: Optional[str] = Cookie(None)
):
    user = await get_current_user(request)

    convo = await db.conversations.find_one(
        {"conversation_id": payload.conversation_id},
        {"_id": 0}
    )
    if not convo:
        raise HTTPException(status_code=404, detail="Conversation not found")

    if user.user_id not in [convo["student_id"], convo["mentor_id"]]:
        raise HTTPException(status_code=403, detail="Not a participant")

    receiver_id = (
        convo["mentor_id"]
        if user.user_id == convo["student_id"]
        else convo["student_id"]
    )

    message_doc = {
        "message_id": generate_message_id(),
        "conversation_id": payload.conversation_id,
        "sender_id": user.user_id,
        "receiver_id": receiver_id,
        "content": payload.content,
        "message_type": "text",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "read_at": None
    }

    # INSERT ONCE
    await db.messages.insert_one(message_doc)

    # UPDATE CONVERSATION
    await db.conversations.update_one(
        {"conversation_id": payload.conversation_id},
        {"$set": {"last_message_at": message_doc["created_at"]}}
    )

    # FETCH CLEAN VERSION (NO ObjectId)
    saved_message = await db.messages.find_one(
        {"message_id": message_doc["message_id"]},
        {"_id": 0}
    )

    saved_message["created_at"] = datetime.fromisoformat(saved_message["created_at"])
    return saved_message


@api_router.get("/conversations/{conversation_id}/messages")
async def get_messages(
    conversation_id: str,
    request: Request,
    session_token: Optional[str] = Cookie(None)
):
    user = await get_current_user(request)

    convo = await db.conversations.find_one(
        {"conversation_id": conversation_id},
        {"_id": 0}
    )
    if not convo:
        raise HTTPException(status_code=404, detail="Conversation not found")
    
    #AUTO MARK MESSAGES AS READ (receiver only)
    await db.messages.update_many(
        {
            "conversation_id": conversation_id,
            "receiver_id": user.user_id,
            "read_at": None
        },
        {
            "$set": {"read_at": datetime.now(timezone.utc).isoformat()}
        }
    )

    if user.user_id not in [convo["student_id"], convo["mentor_id"]]:
        raise HTTPException(status_code=403, detail="Not authorized")

    messages = await db.messages.find(
        {"conversation_id": conversation_id},
        {"_id": 0}
    ).sort("created_at", 1).to_list(500)

    for m in messages:
        if isinstance(m.get("created_at"), str):
            m["created_at"] = datetime.fromisoformat(m["created_at"])
        if m.get("read_at") and isinstance(m["read_at"], str):
            m["read_at"] = datetime.fromisoformat(m["read_at"])

    return messages

@api_router.post("/conversations/{conversation_id}/read")
async def mark_messages_read(
    conversation_id: str,
    request: Request,
    session_token: Optional[str] = Cookie(None)
):
    user = await get_current_user(request)

    convo = await db.conversations.find_one(
        {"conversation_id": conversation_id},
        {"_id": 0}
    )
    if not convo:
        raise HTTPException(status_code=404, detail="Conversation not found")

    if user.user_id not in [convo["student_id"], convo["mentor_id"]]:
        raise HTTPException(status_code=403, detail="Not authorized")

    now = datetime.now(timezone.utc).isoformat()

    result = await db.messages.update_many(
        {
            "conversation_id": conversation_id,
            "receiver_id": user.user_id,
            "read_at": None
        },
        {"$set": {"read_at": now}}
    )

    return {
        "conversation_id": conversation_id,
        "marked_read": result.modified_count
    }



# ===== ANALYTICS ROUTES =====

@api_router.get("/analytics/top-employers")
async def get_top_employers(request: Request, session_token: Optional[str] = Cookie(None)):
    user = await get_current_user(request)
    
    pipeline = [
        {"$match": {"institute_id": user.institute_id, "company": {"$ne": None}}},
        {"$group": {"_id": "$company", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10}
    ]
    
    top_employers = await db.alumni_profiles.aggregate(pipeline).to_list(10)
    return [{"company": item["_id"], "count": item["count"]} for item in top_employers]

@api_router.get("/analytics/skill-distribution")
async def get_skill_distribution(request: Request, session_token: Optional[str] = Cookie(None)):
    user = await get_current_user(request)
    
    pipeline = [
        {"$match": {"institute_id": user.institute_id}},
        {"$unwind": "$skills"},
        {"$group": {"_id": "$skills", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 20}
    ]
    
    skill_distribution = await db.alumni_profiles.aggregate(pipeline).to_list(20)
    return [{"skill": item["_id"], "count": item["count"]} for item in skill_distribution]

@api_router.get("/analytics/alumni-spotlight")
async def get_alumni_spotlight(request: Request, session_token: Optional[str] = Cookie(None)):
    user = await get_current_user(request)
    
    spotlight_alumni = await db.alumni_profiles.find(
        {"institute_id": user.institute_id, "is_verified": True},
        {"_id": 0}
    ).sort("graduation_year", -1).limit(5).to_list(5)
    
    for profile in spotlight_alumni:
        if isinstance(profile.get("created_at"), str):
            profile["created_at"] = datetime.fromisoformat(profile["created_at"])
        if isinstance(profile.get("updated_at"), str):
            profile["updated_at"] = datetime.fromisoformat(profile["updated_at"])
        user_doc = await db.users.find_one({"user_id": profile["user_id"]}, {"_id": 0})
        if user_doc and isinstance(user_doc.get("created_at"), str):
            user_doc["created_at"] = datetime.fromisoformat(user_doc["created_at"])
        profile["user"] = user_doc
    
    return spotlight_alumni

@app.get("/api/analytics/employment/status")
def get_employment_status():
    """
    Employment status distribution for analytics dashboard.
    Mock data for prototype.
    """
    return [
        {"status": "Employed", "count": 120},
        {"status": "Unemployed", "count": 10},
        {"status": "Higher Studies", "count": 3},
    ]

@app.get("/api/analytics/industry/domains")
def get_industry_domains():
    """
    Industry domain distribution for analytics dashboard.
    Mock data for prototype. Replace with real aggregation later.
    """
    return [
        {"domain": "Software Engineering", "count": 42},
        {"domain": "Data & Analytics", "count": 18},
        {"domain": "IT Consulting", "count": 12},
        {"domain": "Product Management", "count": 9},
        {"domain": "Cloud & DevOps", "count": 6},
    ]


@app.get("/api/analytics/industry/roles")
def get_industry_roles():
    """
    Role distribution across industries.
    Mock data for prototype.
    """
    return [
        {"role": "Software Engineer", "count": 30},
        {"role": "Data Analyst", "count": 15},
        {"role": "Consultant", "count": 12},
        {"role": "Product Manager", "count": 8},
        {"role": "DevOps Engineer", "count": 6},
    ]

@app.get("/api/analytics/progression/levels")
def get_career_progression_levels():
    """
    Career level distribution for analytics dashboard.
    Mock data for prototype. Replace with real aggregation later.
    """
    return [
        {"level": "Entry", "count": 45},
        {"level": "Mid", "count": 52},
        {"level": "Senior", "count": 28},
        {"level": "Leadership", "count": 8},
    ]

@app.get("/api/analytics/programs/count")
def get_programs_count():
    """
    Alumni count by academic program.
    Mock data for prototype.
    """
    return [
        {"program": "MCA", "count": 65},
        {"program": "B.Tech", "count": 42},
        {"program": "M.Tech", "count": 26},
        {"program": "MBA", "count": 18},
    ]


@app.get("/api/analytics/programs/employment-rate")
def get_programs_employment_rate():
    """
    Employment rate by academic program (percentage).
    Mock data for prototype.
    """
    return [
        {"program": "MCA", "rate": 92},
        {"program": "B.Tech", "rate": 88},
        {"program": "M.Tech", "rate": 95},
        {"program": "MBA", "rate": 90},
    ]

@app.get("/api/analytics/trends/employment")
def get_employment_trends():
    """
    Employment trend over time.
    Mock data for prototype. Replace with real year-wise aggregation later.
    """
    return [
        {"year": 2019, "employed": 10},
        {"year": 2020, "employed": 15},
        {"year": 2021, "employed": 22},
        {"year": 2022, "employed": 35},
        {"year": 2023, "employed": 48},
    ]



# ===== ADMIN ROUTES =====

@api_router.get("/admin/users")
async def get_all_users(request: Request, session_token: Optional[str] = Cookie(None)):
    user = await get_current_user(request)
    
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    users = await db.users.find({"institute_id": user.institute_id}, {"_id": 0}).to_list(1000)
    for u in users:
        if isinstance(u.get("created_at"), str):
            u["created_at"] = datetime.fromisoformat(u["created_at"])
    
    return users

@api_router.put("/admin/users/{user_id}/status")
async def update_user_status(
    user_id: str,
    request: Request,
    session_token: Optional[str] = Cookie(None),
    is_verified: Optional[bool] = None
):
    user = await get_current_user(request)
    
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if is_verified is not None:
        await db.alumni_profiles.update_one(
            {"user_id": user_id},
            {"$set": {"is_verified": is_verified}}
        )
    
    return {"message": "User status updated"}

@api_router.get("/admin/stats")
async def get_admin_stats(request: Request, session_token: Optional[str] = Cookie(None)):
    user = await get_current_user(request)
    
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    total_users = await db.users.count_documents({"institute_id": user.institute_id})
    total_alumni = await db.alumni_profiles.count_documents({"institute_id": user.institute_id})
    total_students = await db.students.count_documents({"institute_id": user.institute_id})
    total_requests = await db.mentorship_requests.count_documents({})
    
    return {
        "total_users": total_users,
        "total_alumni": total_alumni,
        "total_students": total_students,
        "total_requests": total_requests
    }

@app.get("/api/analytics/overview/trends")
def get_overview_trends():
    """
    Overview trend data for analytics dashboard.
    Mock data for prototype. Replace logic later with real aggregation.
    """
    return [
        {"year": 2019, "count": 12},
        {"year": 2020, "count": 18},
        {"year": 2021, "count": 25},
        {"year": 2022, "count": 40},
        {"year": 2023, "count": 55},
    ]


# ===== INSTITUTE ROUTES =====

@api_router.get("/institutes")
async def get_institutes():
    institutes = await db.institutes.find({}, {"_id": 0}).to_list(1000)
    for inst in institutes:
        if isinstance(inst.get("created_at"), str):
            inst["created_at"] = datetime.fromisoformat(inst["created_at"])
    return institutes


@api_router.get("/conversations")
async def get_conversations(
    request: Request,
    session_token: Optional[str] = Cookie(None)
):
    user = await get_current_user(request)

    if user.role == "student":
        query = {"student_id": user.user_id}
    elif user.role == "alumni":
        query = {"mentor_id": user.user_id}
    elif user.role == "admin":
        query = {"institute_id": user.institute_id}
    else:
        raise HTTPException(status_code=403, detail="Invalid role")

    conversations = await db.conversations.find(
        query,
        {"_id": 0}
    ).sort("created_at", -1).to_list(100)

    return conversations


app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()