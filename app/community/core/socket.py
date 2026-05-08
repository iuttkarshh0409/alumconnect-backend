import socketio
import json
import os
from datetime import datetime
from bson import ObjectId

# Create a Socket.io server
# Enable CORS for all origins or specific frontend origins
origins = os.environ.get("CORS_ORIGINS", "http://localhost:3000").split(",")
sio = socketio.AsyncServer(
    async_mode='asgi', 
    cors_allowed_origins='*' # For local dev, * is easiest. Or use `origins`
)

# Create an ASGI app for Socket.io
# When mounting at /socket.io in server.py, socketio_path should be empty 
# because the client appends /socket.io automatically to the base URL.
socket_app = socketio.ASGIApp(sio, socketio_path='')

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, ObjectId):
            return str(obj)
        return super().default(obj)

@sio.event
async def connect(sid, environ):
    print(f"Client connected: {sid}")

@sio.event
async def disconnect(sid):
    print(f"Client disconnected: {sid}")

async def emit_feed_update(data: dict):
    serializable_data = json.loads(json.dumps(data, cls=DateTimeEncoder))
    await sio.emit('feed_update', serializable_data)

async def emit_post_liked(data: dict):
    await sio.emit('post_liked', data)

async def emit_new_comment(data: dict):
    serializable_data = json.loads(json.dumps(data, cls=DateTimeEncoder))
    await sio.emit('new_comment', serializable_data)
