"""
AlumConnect Backend Entrypoint (server.py)
===========================================
This is the core FastAPI application server for AlumConnect.
It handles application routing, database lifecycle events, WebSockets for live chat, 
AI-based mentorship recommendations, analytics queries, and admin control dashboards.

Structure:
1. IMPORTS & DEPENDENCIES
2. ENVIRONMENT & UTILITIES SETUP
3. APPLICATION & MIDDLEWARE DEFINITION
4. ROUTER INITIALIZATION
5. LIFECYCLE EVENTS (STARTUP / SHUTDOWN)
6. PYDANTIC SCHEMAS (DATA MODELS)
7. HELPER FUNCTIONS & CLASS DEFINITIONS
8. ROUTE DEFINITIONS
   - Diagnostics
   - Authentication
   - Alumni Profile & Management
   - Mentorship Request Flows
   - Messaging & WebSocket Channels
   - Wisdom Sharing & Applause
   - Admin Controls
   - Analytics & Reports
   - Metadata / General
   - AI Chatbot (AlumAssist)
"""

# ==============================================================================
# 1. IMPORTS & DEPENDENCIES
# ==============================================================================

# Standard Library Imports
import json
import logging
import os
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Optional

# Third-Party Frameworks & Utilities
import httpx
import requests
from dotenv import load_dotenv
from fastapi import FastAPI, APIRouter, HTTPException, Cookie, Response, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from groq import Groq
from jose import jwt
from jose.exceptions import JWTError
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, ConfigDict, EmailStr

# Local Module Imports (Core & Features)
from core.database import db, client  # 'client' imported to clean up connections on shutdown
from core.auth import get_current_user, User, get_clerk_jwks, CLERK_ISSUER  # Auth helpers
from app.community.core.socket import socket_app
from app.community.api import posts as community_posts, comments as community_comments
from core.admin_moderation import router as admin_router


# ==============================================================================
# 2. ENVIRONMENT & UTILITIES SETUP
# ==============================================================================

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# Initialize Groq client if an API key is available
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
groq_client = None
if GROQ_API_KEY:
    groq_client = Groq(api_key=GROQ_API_KEY)
else:
    logging.warning("WARNING: GROQ_API_KEY not found in environment variables.")


# ==============================================================================
# 3. APPLICATION & MIDDLEWARE DEFINITION
# ==============================================================================

app = FastAPI(
    title="AlumConnect API",
    description="Backend API serving students, alumni, and institute administrators.",
    version="1.0.0"
)

# Mount Socket.io app at /socket.io for community socket flows
app.mount("/socket.io", socket_app)

# CORS Configuration
origins = os.environ.get("CORS_ORIGINS", "http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==============================================================================
# 4. ROUTER INITIALIZATION & ROUTE REGISTRATION
# ==============================================================================

api_router = APIRouter(prefix="/api")

# Include sub-routers from separate feature modules
api_router.include_router(community_posts.router, prefix="/community/posts", tags=["community"])
api_router.include_router(community_comments.router, prefix="/community/posts", tags=["community"])
api_router.include_router(admin_router, tags=["admin"])


# ==============================================================================
# 5. LIFECYCLE EVENTS (STARTUP / SHUTDOWN)
# ==============================================================================

@app.on_event("startup")
async def create_indexes():
    """
    Initialize Database Indexes.
    Runs on application startup to ensure optimal query performance for messaging and search.
    """
    # Conversations Indexes
    await db.conversations.create_index([("student_id", 1)])
    await db.conversations.create_index([("mentor_id", 1)])
    await db.conversations.create_index([("institute_id", 1)])
    
    # Messages Indexes
    await db.messages.create_index([("conversation_id", 1), ("created_at", 1)])
    await db.messages.create_index([("conversation_id", 1), ("receiver_id", 1), ("read_at", 1)])


@app.on_event("shutdown")
async def shutdown_db_client():
    """
    Gracefully closes the MongoDB client connection when the app server stops.
    """
    client.close()


# ==============================================================================
# 6. PYDANTIC SCHEMAS (DATA MODELS)
# ==============================================================================

# --- Core Database Profile Schemas ---

class AlumniProfile(BaseModel):
    """Schema defining a registered Alumnus Profile."""
    model_config = ConfigDict(extra="ignore")
    user_id: str
    institute_id: str
    department: str
    graduation_year: int
    company: Optional[str] = None
    job_domain: Optional[str] = None  # e.g., SDE, PM, HR, Data Science
    job_title: Optional[str] = None
    skills: List[str] = []
    bio: Optional[str] = None
    linkedin_url: Optional[str] = None
    is_verified: bool = False
    is_claimed: bool = False
    open_to_refer: bool = False
    is_live: bool = False
    created_at: datetime
    updated_at: datetime


class StudentProfile(BaseModel):
    """Schema defining a registered Student Profile."""
    model_config = ConfigDict(extra="ignore")
    user_id: str
    institute_id: str
    department: str
    graduation_year: int
    bio: Optional[str] = None
    created_at: datetime


class MentorshipRequest(BaseModel):
    """Schema representing an active or completed Mentorship Request."""
    model_config = ConfigDict(extra="ignore")
    request_id: str
    student_id: str
    mentor_id: str
    topic: str  # e.g., Mock Interview, Resume Review, Career Guidance
    description: str
    status: str = "pending"  # pending, accepted, rejected, expired
    created_at: datetime
    expires_at: datetime


class Institute(BaseModel):
    """Schema representing an affiliated Academic Institution."""
    model_config = ConfigDict(extra="ignore")
    institute_id: str
    name: str
    departments: List[str] = []
    created_at: datetime


# --- Request & Response Payloads ---

class SetupProfileRequest(BaseModel):
    """Payload to initialize a user profile during onboarding."""
    role: str  # student, alumni, admin
    institute_id: Optional[str] = None
    department: Optional[str] = None
    graduation_year: Optional[int] = None
    bio: Optional[str] = None
    verification_type: Optional[str] = None
    verification_value: Optional[str] = None
    designation: Optional[str] = None
    access_code: Optional[str] = None  # Required for Admin signup validation
    name: Optional[str] = None


class AlumniProfileUpdate(BaseModel):
    """Payload containing subset of fields allowed for updating alumni profile info."""
    company: Optional[str] = None
    job_domain: Optional[str] = None
    job_title: Optional[str] = None
    skills: Optional[List[str]] = None
    bio: Optional[str] = None
    linkedin_url: Optional[str] = None
    open_to_refer: Optional[bool] = None
    is_live: Optional[bool] = None


class CreateMentorshipRequest(BaseModel):
    """Payload sent by a student to request mentorship from an alumnus."""
    mentor_id: str
    topic: str
    description: str


class UpdateRequestStatus(BaseModel):
    """Payload to update the status of a mentorship request."""
    status: str  # accepted, rejected


class PhotoUpdate(BaseModel):
    """Payload to update a user's profile picture URI."""
    picture: str


class WisdomTipRequest(BaseModel):
    """Payload for alumni to publish a piece of wisdom/advice."""
    wisdom: str


class SendMessageRequest(BaseModel):
    """Payload containing chat message parameters."""
    conversation_id: str
    content: str


class ReportAlumniRequest(BaseModel):
    """Payload to file a report against a profile."""
    reason: str


class ChatMessage(BaseModel):
    """Schema representing a single message in the chatbot message list."""
    role: str  # user, system, assistant
    content: str


class ChatRequest(BaseModel):
    """Payload sent to query the AI chatbot module."""
    messages: List[ChatMessage]


# ==============================================================================
# 7. HELPER FUNCTIONS & CLASS DEFINITIONS
# ==============================================================================

def generate_conversation_id() -> str:
    """Generates a unique conversation token prefix."""
    return f"conv_{uuid.uuid4().hex[:12]}"


def generate_message_id() -> str:
    """Generates a unique message token prefix."""
    return f"msg_{uuid.uuid4().hex[:12]}"


class ConnectionManager:
    """
    Manages active WebSocket connections mapped per-conversation
    to enable real-time bidirectional chatting.
    """
    def __init__(self):
        # Maps conversation_id -> list of active WebSockets
        self.active_connections: dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, conversation_id: str):
        """Register a new websocket connection to a specific conversation room."""
        await websocket.accept()
        if conversation_id not in self.active_connections:
            self.active_connections[conversation_id] = []
        self.active_connections[conversation_id].append(websocket)

    def disconnect(self, websocket: WebSocket, conversation_id: str):
        """Remove a websocket connection from a conversation room."""
        if conversation_id in self.active_connections:
            if websocket in self.active_connections[conversation_id]:
                self.active_connections[conversation_id].remove(websocket)
            if not self.active_connections[conversation_id]:
                del self.active_connections[conversation_id]

    async def broadcast(self, message: dict, conversation_id: str):
        """Broadcasting json messages to all connected endpoints in a conversation room."""
        if conversation_id in self.active_connections:
            for connection in self.active_connections[conversation_id]:
                try:
                    await connection.send_json(message)
                except Exception:
                    pass  # Silent drop of disconnected / stale websockets


# Instantiate global connection manager for messaging
manager = ConnectionManager()


# ==============================================================================
# 8. ROUTE DEFINITIONS
# ==============================================================================

# ------------------------------------------------------------------------------
# Diagnostics Routes
# ------------------------------------------------------------------------------

@app.get("/ping")
def ping():
    """Simple health ping check. Returns verification signal."""
    return {"message": "pong", "signal": "RADAR_READY_V2"}


@app.get("/health")
def health():
    """Application status healthcheck."""
    return {"status": "ok"}


# ------------------------------------------------------------------------------
# Authentication Routes
# ------------------------------------------------------------------------------

@api_router.get("/auth/me", response_model=User)
async def get_current_user_info(
    request: Request,
    session_token: Optional[str] = Cookie(None),
) -> User:
    """
    Retrieves the currently authenticated user's session profile.
    """
    return await get_current_user(request)


@api_router.post("/auth/logout")
async def logout(request: Request, response: Response, session_token: Optional[str] = Cookie(None)):
    """
    Invalidates current session token in db and deletes the session cookie.
    """
    token = session_token or request.headers.get("Authorization", "").replace("Bearer ", "")
    if token:
        await db.user_sessions.delete_one({"session_token": token})
    
    response.delete_cookie(key="session_token", path="/")
    return {"message": "Logged out successfully"}


@api_router.post("/auth/setup")
async def setup_profile(request: Request, profile_data: SetupProfileRequest, session_token: Optional[str] = Cookie(None)):
    """
    Performs initial user profile configuration (student/alumni/admin).
    Administrators are validated via a unique access code validation mechanism.
    """
    user = await get_current_user(request)
    
    if user.status != "uninitialized":
        return JSONResponse(
            status_code=200, 
            content={
                "message": "Profile already set up or pending approval",
                "role": user.role,
                "status": user.status
                }
        )
    
    # Handle Administrator Account Verification
    if profile_data.role == "admin":
        if profile_data.access_code != "LV088RRLO":
            raise HTTPException(status_code=400, detail="Invalid administrator access code")
        
        update_doc = {
            "role": "admin",
            "designation": profile_data.designation,
            "status": "approved",
            "is_approved": True
        }
        if profile_data.name:
            update_doc["name"] = profile_data.name

        await db.users.update_one(
            {"user_id": user.user_id},
            {"$set": update_doc}
        )
    # Handle Standard User (Student / Alumni) Application
    else:
        update_doc = {
            "role": profile_data.role,
            "institute_id": profile_data.institute_id,
            "department": profile_data.department,
            "graduation_year": profile_data.graduation_year,
            "bio": profile_data.bio,
            "verification_type": profile_data.verification_type,
            "verification_value": profile_data.verification_value,
            "status": "pending",
            "is_approved": False
        }
        if profile_data.name:
            update_doc["name"] = profile_data.name

        await db.users.update_one(
            {"user_id": user.user_id},
            {"$set": update_doc}
        )
    
    updated_user = await db.users.find_one({"user_id": user.user_id}, {"_id": 0})
    if isinstance(updated_user.get("created_at"), str):
        updated_user["created_at"] = datetime.fromisoformat(updated_user["created_at"])
    
    return User(**updated_user)


# ------------------------------------------------------------------------------
# Alumni Profile & Management Routes
# ------------------------------------------------------------------------------

@api_router.get("/alumni")
async def get_alumni(
    request: Request,
    session_token: Optional[str] = Cookie(None),
    company: Optional[str] = None,
    job_domain: Optional[str] = None,
    graduation_year: Optional[int] = None,
    skills: Optional[str] = None
):
    """
    Lists and filters verified alumni profiles within the active user's educational institute.
    """
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
            
            # Inject latest wisdom tip published by the alumni
            latest_wisdom = await db.wisdom_tips.find_one(
                {"user_id": profile["user_id"]},
                {"text": 1, "_id": 0},
                sort=[("created_at", -1)]
            )
            
            alumni_with_users.append({
                **profile, 
                "user": user_doc,
                "latest_wisdom": latest_wisdom.get("text") if latest_wisdom else None
            })
    
    return alumni_with_users


@api_router.get("/alumni/talent-radar")
async def get_talent_radar(request: Request):
    """
    Returns student recommendations (matching the alumnus's department) for the Talent Radar view.
    """
    user = await get_current_user(request)
    if not user or user.role != "alumni":
        raise HTTPException(status_code=403, detail="Only alumni can access talent radar")
    
    alumnus = await db.alumni_profiles.find_one({"user_id": user.user_id})
    if not alumnus or not alumnus.get("department"):
        return []
    
    # CASE-INSENSITIVE SEARCH: Match "MCA" or similar department strings
    query = {"department": {"$regex": f"^{alumnus['department']}$", "$options": "i"}}
    
    students_docs = await db.students.find(query, {"_id": 0}).limit(10).to_list(10)
    
    radar_data = []
    for s in students_docs:
        if s["user_id"] == user.user_id: 
            continue
            
        s_user = await db.users.find_one({"user_id": s["user_id"]}, {"_id": 0})
        if s_user:
            # Stable coordinate generation based on user ID seed
            seed = sum(ord(c) for c in s["user_id"])
            radar_data.append({
                "user_id": s["user_id"],
                "name": s_user["name"],
                "picture": s_user.get("picture"),
                "department": s["department"],
                "grad_year": s["graduation_year"],
                "match_score": 85 + (seed % 15),
                "distance": 0.3 + (seed % 60) / 100, 
                "angle": seed % 360 
            })
            
    return radar_data


@api_router.get("/alumni/{user_id}")
async def get_alumni_profile(user_id: str, request: Request, session_token: Optional[str] = Cookie(None)):
    """
    Retrieves detail info on a specific alumni profile.
    """
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
    """
    Updates the calling alumni user's profile details.
    """
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


@api_router.post("/alumni/{user_id}/report")
async def report_alumni_profile(
    user_id: str,
    payload: ReportAlumniRequest,
    request: Request
):
    """
    Files an abuse or spam report against an alumni profile.
    """
    user = await get_current_user(request)
    
    report_id = f"rep_{uuid.uuid4().hex[:12]}"
    report_doc = {
        "report_id": report_id,
        "reporter_id": user.user_id,
        "target_alumni_id": user_id,
        "reason": payload.reason,
        "status": "pending_review",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.profile_reports.insert_one(report_doc)
    return {"status": "success", "message": "Alumni profile reported successfully"}


# ------------------------------------------------------------------------------
# Mentorship Request Flows
# ------------------------------------------------------------------------------

@api_router.post("/mentorship/requests")
async def create_mentorship_request(
    request_data: CreateMentorshipRequest,
    request: Request,
    session_token: Optional[str] = Cookie(None)
):
    """
    Allows a student to request a mentorship session.
    Maximum of 3 active pending requests are enforced.
    """
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
        "admin_approval_status": "pending_admin_approval",
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
    """
    Lists mentorship requests related to the logged in user based on their specific role 
    (Student requests made, Alumni requests received, Admin institute-wide requests).
    Auto-expires pending requests past their expiration date.
    """
    user = await get_current_user(request)
    
    if user.role == "student":
        requests = await db.mentorship_requests.find({"student_id": user.user_id}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    elif user.role == "alumni":
        requests = await db.mentorship_requests.find({"mentor_id": user.user_id, "admin_approval_status": "approved_by_admin"}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    elif user.role == "admin":
        query = {}
        if user.institute_id:
            students = await db.users.find({"institute_id": user.institute_id}).to_list(5000)
            student_ids = [s["user_id"] for s in students]
            query["student_id"] = {"$in": student_ids}
        requests = await db.mentorship_requests.find(query, {"_id": 0}).sort("created_at", -1).to_list(1000)
    else:
        requests = await db.mentorship_requests.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)

    for req in requests:
        if isinstance(req.get("created_at"), str):
            req["created_at"] = datetime.fromisoformat(req["created_at"])
        if isinstance(req.get("expires_at"), str):
            req["expires_at"] = datetime.fromisoformat(req["expires_at"])
        
        expires_at = req["expires_at"]
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
            
        # Enforce automatic expiry
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
    """
    Accept or reject a mentorship request. 
    Accepting automatically spins up an active chat Conversation.
    """
    user = await get_current_user(request)
    
    req_doc = await db.mentorship_requests.find_one({"request_id": request_id}, {"_id": 0})
    if not req_doc:
        raise HTTPException(status_code=404, detail="Request not found")
    
    if user.user_id != req_doc["mentor_id"] and user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    
    if req_doc["status"] != "pending":
        raise HTTPException(
            status_code=400,
            detail=f"Cannot update request in '{req_doc['status']}' state"
        )

    await db.mentorship_requests.update_one(
        {"request_id": request_id},
        {"$set": {"status": status_update.status}}
    )
    
    # If accepted, provision conversation document
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


@api_router.delete("/mentorship/requests/{request_id}")
async def withdraw_mentorship_request(request_id: str, request: Request):
    """
    Allows a student to withdraw their pending mentorship request.
    """
    user = await get_current_user(request)
    
    if user.role != "student":
        raise HTTPException(status_code=403, detail="Only students can withdraw requests")
    
    req_doc = await db.mentorship_requests.find_one({"request_id": request_id})
    if not req_doc:
        raise HTTPException(status_code=404, detail="Request not found")
        
    if req_doc["student_id"] != user.user_id:
        raise HTTPException(status_code=403, detail="Not authorized to withdraw this request")
        
    if req_doc["status"] != "pending":
        raise HTTPException(status_code=400, detail="Only pending requests can be withdrawn")
    
    await db.mentorship_requests.delete_one({"request_id": request_id})
    return {"status": "success", "message": "Request withdrawn successfully"}


# ------------------------------------------------------------------------------
# Messaging & WebSocket Channels
# ------------------------------------------------------------------------------

@api_router.post("/messages")
async def send_message(
    payload: SendMessageRequest,
    request: Request,
    session_token: Optional[str] = Cookie(None)
):
    """
    Sends a HTTP-based text message inside a conversation room. 
    Broadcasts message metadata via WebSocket connection.
    """
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

    await db.messages.insert_one(message_doc)

    await db.conversations.update_one(
        {"conversation_id": payload.conversation_id},
        {"$set": {
            "last_message_at": message_doc["created_at"],
            "last_message": {
                "content": payload.content,
                "sender_id": user.user_id,
                "created_at": message_doc["created_at"]
            }
        }}
    )

    saved_message = await db.messages.find_one(
        {"message_id": message_doc["message_id"]},
        {"_id": 0}
    )

    broadcast_msg = {**saved_message}
    saved_message["created_at"] = datetime.fromisoformat(saved_message["created_at"])
    
    if 'manager' in globals():
        await manager.broadcast(broadcast_msg, payload.conversation_id)
        
    return saved_message


@api_router.get("/conversations/{conversation_id}/messages")
async def get_messages(
    conversation_id: str,
    request: Request,
    session_token: Optional[str] = Cookie(None)
):
    """
    Retrieves message history for a conversation. Automatically flags unread messages 
    received by the requesting user as read.
    """
    user = await get_current_user(request)

    convo = await db.conversations.find_one(
        {"conversation_id": conversation_id},
        {"_id": 0}
    )
    if not convo:
        raise HTTPException(status_code=404, detail="Conversation not found")
    
    if user.user_id not in [convo["student_id"], convo["mentor_id"]]:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Mark incoming messages as read
    result = await db.messages.update_many(
        {
            "conversation_id": conversation_id,
            "receiver_id": user.user_id,
            "read_at": None
        },
        {
            "$set": {"read_at": datetime.now(timezone.utc).isoformat()}
        }
    )

    # Broadcast read status receipt to socket peers
    if result.modified_count > 0 and 'manager' in globals():
        await manager.broadcast({
            "type": "read_receipt",
            "reader_id": user.user_id,
            "conversation_id": conversation_id
        }, conversation_id)

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
    """
    Explicitly marks all unread messages in a conversation as read.
    """
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

    if result.modified_count > 0 and 'manager' in globals():
        await manager.broadcast({
            "type": "read_receipt",
            "reader_id": user.user_id,
            "conversation_id": conversation_id
        }, conversation_id)

    return {
        "conversation_id": conversation_id,
        "marked_read": result.modified_count
    }


@app.websocket("/ws/{conversation_id}")
async def websocket_endpoint(websocket: WebSocket, conversation_id: str, token: str):
    """
    WebSocket endpoint for real-time bi-directional messaging.
    Connection URL: /ws/{conversation_id}?token={clerk_token}
    """
    # 1. Authenticate JWT token via Clerk public keys
    try:
        jwks = get_clerk_jwks()
        payload = jwt.decode(
            token,
            jwks,
            algorithms=["RS256"],
            issuer=CLERK_ISSUER,
            options={"verify_aud": False},
        )
        user_id = payload["sub"]
    except Exception:
        await websocket.close(code=1008)  # Policy violation close
        return

    # 2. Check conversation access permissions
    convo = await db.conversations.find_one({"conversation_id": conversation_id}, {"_id": 0})
    if not convo:
        await websocket.close(code=1008)
        return

    if user_id not in [convo["student_id"], convo["mentor_id"]]:
        await websocket.close(code=1008)
        return

    # 3. Connect socket connection
    await manager.connect(websocket, conversation_id)

    try:
        while True:
            # Handle incoming WebSocket frames
            data = await websocket.receive_text()
            try:
                payload_data = json.loads(data)
                msg_type = payload_data.get("type", "message")
                
                # Handle Typing Indicators
                if msg_type == "typing":
                    await manager.broadcast({
                        "type": "typing",
                        "sender_id": user_id,
                        "is_typing": payload_data.get("is_typing", False),
                        "conversation_id": conversation_id
                    }, conversation_id)
                    continue
                
                # Handle Message Delivery
                content = payload_data.get("content")
                if content:
                    receiver_id = convo["mentor_id"] if user_id == convo["student_id"] else convo["student_id"]
                    
                    message_doc = {
                        "message_id": generate_message_id(),
                        "conversation_id": conversation_id,
                        "sender_id": user_id,
                        "receiver_id": receiver_id,
                        "content": content,
                        "message_type": "text",
                        "created_at": datetime.now(timezone.utc).isoformat(),
                        "read_at": None
                    }
                    
                    await db.messages.insert_one(message_doc)
                    await db.conversations.update_one(
                        {"conversation_id": conversation_id},
                        {"$set": {
                            "last_message_at": message_doc["created_at"],
                            "last_message": {
                                "content": content,
                                "sender_id": user_id,
                                "created_at": message_doc["created_at"]
                            }
                        }}
                    )
                    
                    clean_msg = {**message_doc}
                    if "_id" in clean_msg:
                        del clean_msg["_id"]
                    await manager.broadcast(clean_msg, conversation_id)
            except Exception:
                pass  # Safely ignore invalid frame payloads
    except WebSocketDisconnect:
        manager.disconnect(websocket, conversation_id)


# ------------------------------------------------------------------------------
# Wisdom Sharing & Applause Routes
# ------------------------------------------------------------------------------

@api_router.post("/alumni/wisdom")
async def post_alumni_wisdom(request: Request, wisdom_data: WisdomTipRequest):
    """
    Publish a piece of professional advice or career wisdom. (Alumni role only)
    """
    user = await get_current_user(request)
    
    if user.role != "alumni":
        raise HTTPException(status_code=403, detail="Only alumni can post wisdom")
    
    wisdom_tip = {
        "tip_id": str(uuid.uuid4()),
        "user_id": user.user_id,
        "author_name": user.name,
        "author_company": user.picture, # Reuses picture URI if needed
        "text": wisdom_data.wisdom,
        "created_at": datetime.now(timezone.utc)
    }
    
    await db.wisdom_tips.insert_one(wisdom_tip)
    return {"status": "success", "message": "Wisdom saved to cloud DB"}


@api_router.get("/alumni/wisdom")
@api_router.get("/student/wisdom")
async def get_alumni_wisdom(request: Request):
    """
    Fetches the 10 most recently published wisdom tips. 
    Annotates each tip with applause (high-five) counters and user-interacted states.
    """
    user = await get_current_user(request)
    tips = await db.wisdom_tips.find({}, {"_id": 0}).sort("created_at", -1).to_list(10)
    
    for tip in tips:
        applauds = tip.get("applauds", [])
        tip["applauds_count"] = len(applauds)
        tip["has_applauded"] = user.user_id in applauds if user else False
        if "applauds" in tip:
            del tip["applauds"]  # Sanitizes active user array list
            
    return tips


@api_router.post("/wisdom/{tip_id}/high-five")
async def toggle_high_five(tip_id: str, request: Request):
    """
    Toggles a high-five/applause indicator on a wisdom tip.
    """
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
        
    tip = await db.wisdom_tips.find_one({"tip_id": tip_id})
    if not tip:
        raise HTTPException(status_code=404, detail="Tip not found")
        
    applauds = tip.get("applauds", [])
    if user.user_id in applauds:
        await db.wisdom_tips.update_one(
            {"tip_id": tip_id},
            {"$pull": {"applauds": user.user_id}}
        )
        return {"status": "un-high-fived"}
    else:
        await db.wisdom_tips.update_one(
            {"tip_id": tip_id},
            {"$push": {"applauds": user.user_id}}
        )
        return {"status": "high-fived"}


@api_router.post("/alumni/toggle-live")
async def toggle_live_status(request: Request):
    """
    Toggles the 'is_live' active state status for an alumni member.
    """
    user = await get_current_user(request)
    if user.role != "alumni":
        raise HTTPException(status_code=403, detail="Only alumni can toggle live status")
        
    profile = await db.alumni_profiles.find_one({"user_id": user.user_id})
    new_status = not profile.get("is_live", False)
    
    await db.alumni_profiles.update_one(
        {"user_id": user.user_id},
        {"$set": {"is_live": new_status, "updated_at": datetime.now(timezone.utc).isoformat()}}
    )
    
    return {"status": "success", "is_live": new_status}


@api_router.get("/alumni/stats/me")
async def get_my_alumni_stats(request: Request):
    """
    Retrieves personal statistics for the logged-in alumni profile 
    (aggregated high-fives count, active mentorship request totals).
    """
    user = await get_current_user(request)
    if user.role != "alumni":
        raise HTTPException(status_code=403, detail="Access denied")
        
    # Aggrated High-Fives count
    tips = await db.wisdom_tips.find({"user_id": user.user_id}).to_list(100)
    total_high_fives = sum(len(tip.get("applauds", [])) for tip in tips)
    
    # Mentorship session status counts
    accepted = await db.mentorship_requests.count_documents({"mentor_id": user.user_id, "status": "accepted"})
    pending = await db.mentorship_requests.count_documents({"mentor_id": user.user_id, "status": "pending"})
    
    profile = await db.alumni_profiles.find_one({"user_id": user.user_id})
    is_live = profile.get("is_live", False) if profile else False
    
    return {
        "total_high_fives": total_high_fives,
        "accepted_sessions": accepted,
        "pending_requests": pending,
        "is_live": is_live
    }


# ------------------------------------------------------------------------------
# Admin & Moderation Routes
# ------------------------------------------------------------------------------

@api_router.get("/admin/users")
async def get_all_users(request: Request, session_token: Optional[str] = Cookie(None)):
    """
    Lists all users registered within the administrator's affiliated institute. (Admin role only)
    """
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
    """
    Updates the verification and moderation state of a user. (Admin role only)
    """
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
    """
    Retrieves high-level platform statistics scoped to the administrator's institute.
    """
    user = await get_current_user(request)
    
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    query = {}
    if user.institute_id:
        query["institute_id"] = user.institute_id
        
    total_users = await db.users.count_documents(query)
    total_alumni = await db.alumni_profiles.count_documents(query)
    total_students = await db.students.count_documents(query)
    
    # Scope mentorship requests to matching student pool
    mentor_query = {}
    if user.institute_id:
        students_list = await db.users.find({"institute_id": user.institute_id}).to_list(5000)
        student_ids = [s["user_id"] for s in students_list]
        mentor_query["student_id"] = {"$in": student_ids}
    total_requests = await db.mentorship_requests.count_documents(mentor_query)
    
    return {
        "total_users": total_users,
        "total_alumni": total_alumni,
        "total_students": total_students,
        "total_requests": total_requests
    }


# ------------------------------------------------------------------------------
# Analytics & Trends Routes
# ------------------------------------------------------------------------------

@api_router.get("/analytics/top-employers")
async def get_top_employers(request: Request, session_token: Optional[str] = Cookie(None)):
    """
    Retrieves the top 10 companies employing alumni from the active user's institute.
    """
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
    """
    Retrieves the distribution of top 20 technical skills among alumni in the active user's institute.
    """
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
    """
    Fetches details of 5 verified spotlight alumni, ordered by recent graduation classes.
    """
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


@api_router.get("/student/stats")
async def get_student_dashboard_stats(request: Request):
    """
    Returns generic student stats (verified alumni count in active institute, user activity).
    """
    user = await get_current_user(request)
    
    verified_count = await db.alumni_profiles.count_documents({
        "institute_id": user.institute_id,
        "is_verified": True
    })
    
    return {
        "verified_alumni_count": verified_count,
        "last_active": user.last_active
    }


@app.get("/api/analytics/employment/status")
def get_employment_status():
    """
    Employment status distribution for analytics dashboard.
    (Mock data for prototype visualization)
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
    (Mock data for prototype visualization)
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
    Role distribution across industries for analytics dashboard.
    (Mock data for prototype visualization)
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
    (Mock data for prototype visualization)
    """
    return [
        {"level": "Entry", "count": 45},
        {"level": "Mid", "count": 52},
        {"level": "Senior", "count": 28},
        {"level": "Leadership", "count": 8},
    ]


@api_router.get("/analytics/programs/count")
async def get_programs_count(request: Request):
    """
    Alumni count by academic program.
    (Mock data for prototype visualization)
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
    Employment percentage rate by academic program.
    (Mock data for prototype visualization)
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
    Employment trends over time years.
    (Mock data for prototype visualization)
    """
    return [
        {"year": 2019, "employed": 10},
        {"year": 2020, "employed": 15},
        {"year": 2021, "employed": 22},
        {"year": 2022, "employed": 35},
        {"year": 2023, "employed": 48},
    ]


@api_router.post("/alumni/update-photo")
async def update_profile_photo(request: Request, photo_data: PhotoUpdate):
    """
    Updates profile image link of the authenticated user.
    """
    user = await get_current_user(request)
    
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    await db.users.update_one(
        {"user_id": user.user_id},
        {"$set": {"picture": photo_data.picture}}
    )
    
    return {"status": "success", "picture": photo_data.picture}


@api_router.get("/admin/stats/overview/trends")  # Maps /api/analytics/overview/trends internally if included
@app.get("/api/analytics/overview/trends")
def get_overview_trends():
    """
    Overview aggregate account trend counts.
    (Mock data for prototype visualization)
    """
    return [
        {"year": 2019, "count": 12},
        {"year": 2020, "count": 18},
        {"year": 2021, "count": 25},
        {"year": 2022, "count": 40},
        {"year": 2023, "count": 55},
    ]


# ------------------------------------------------------------------------------
# Metadata & General Info Routes
# ------------------------------------------------------------------------------

@api_router.get("/institutes")
async def get_institutes():
    """
    Retrieves all available academic institutions registered on the platform.
    """
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
    """
    Lists active and past chat conversations scoped by role.
    Returns recipient status and unread counter metadata.
    """
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

    enriched_conversations = []
    for convo in conversations:
        # Provide Unread count scoped to recipient
        if user.user_id in [convo["student_id"], convo["mentor_id"]]:
            unread_count = await db.messages.count_documents({
                "conversation_id": convo["conversation_id"],
                "receiver_id": user.user_id,
                "read_at": None
            })
            convo["unread_count"] = unread_count
        else:
            convo["unread_count"] = 0

        # Inject details of the other participant
        if user.role != "admin":
            other_user_id = convo["mentor_id"] if user.user_id == convo["student_id"] else convo["student_id"]
            other_user = await db.users.find_one({"user_id": other_user_id}, {"_id": 0, "name": 1, "picture": 1, "role": 1})
            convo["other_participant"] = other_user
        else:
            # Diagnostics details for administration oversight
            student = await db.users.find_one({"user_id": convo["student_id"]}, {"_id": 0, "name": 1, "picture": 1})
            mentor = await db.users.find_one({"user_id": convo["mentor_id"]}, {"_id": 0, "name": 1, "picture": 1})
            convo["student"] = student
            convo["mentor"] = mentor

        enriched_conversations.append(convo)

    return enriched_conversations


# ------------------------------------------------------------------------------
# AI Chatbot (AlumAssist) Routes
# ------------------------------------------------------------------------------

SYSTEM_PROMPT = """
You are AlumAssist, an experienced alumni mentor.

IDENTITY:
- Friendly but brutally honest
- Direct, practical, and grounded
- No fluff, no motivational nonsense

PRIMARY PURPOSE:
- Help students with:
  - Career guidance
  - Skills roadmap
  - Internship advice
  - Project suggestions
  - Career switching

CORE RULES:
- Do NOT act like a general AI assistant
- Do NOT answer unrelated questions
- Do NOT ask personal questions
- Avoid generic or vague answers

RESPONSE BEHAVIOR:
- Structure & Formatting: Use bullet points, keep it clean.
- Answer Depth: Direct for simple, step-by-step for complex.
- Decision Making: Recommend ONE practical direction if user is confused.
- Tone: Slightly assertive, senior-to-junior vibe.
"""

@api_router.post("/chat")
async def chatbot_endpoint(request: ChatRequest):
    """
    Primary chat query gateway connecting to AlumAssist AI mentor agent.
    Utilizes the Groq Llama model for responding to career queries.
    """
    if not groq_client:
        raise HTTPException(status_code=503, detail="Chat service currently unavailable (API key missing)")
    
    formatted_messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    for msg in request.messages:
        if msg.role != "system":
            formatted_messages.append({"role": msg.role, "content": msg.content})

    try:
        response = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=formatted_messages
        )
        reply = response.choices[0].message.content
        return {"reply": reply}
    except Exception as e:
        logging.error(f"Chatbot error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get response from AI")


# Include registered api routes inside main application scope
app.include_router(api_router)
