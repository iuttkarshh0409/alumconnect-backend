from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from .core.config import settings
from .core.database import connect_to_mongo, close_mongo_connection
from .api import posts, comments
from .core.socket import socket_app

app = FastAPI(title="AlumConnect Community API", version="1.0.0")

# Mount Socket.io app
app.mount("/socket.io", socket_app)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mock Auth Middleware (Temporary)
@app.middleware("http")
async def mock_auth_middleware(request: Request, call_next):
    # In a real scenario, this would verify a JWT from Clerk
    # For now, we inject a mock user into the request state
    request.state.user = {
        "id": "user_mock_123",
        "email": "alumni@example.com",
        "name": "Jane Alum",
        "role": "alumni"
    }
    response = await call_next(request)
    return response

@app.on_event("startup")
async def startup_db_client():
    await connect_to_mongo()

@app.on_event("shutdown")
async def shutdown_db_client():
    await close_mongo_connection()

# Root endpoint
@app.get("/")
async def root():
    return {"message": "AlumConnect Community Feed API is running", "status": "ok"}

# Register Routers
app.include_router(posts.router, prefix="/api/v1/posts", tags=["Posts"])
app.include_router(comments.router, prefix="/api/v1/posts", tags=["Comments"])
