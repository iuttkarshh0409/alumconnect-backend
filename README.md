# AlumConnect Backend

AlumConnect Backend is a production-level FastAPI application engineered to support high-performance APIs, real-time bidirectional communication, AI-driven wisdom insights, and tenant-scoped admin moderation. It connects students and institute alumni under a secure, authenticated interface.

---

## 🚀 Key Features

* **Async MongoDB Integration**: Utilizes Motor (async driver) and Pymongo, featuring automated compound index creation on startup to speed up message search queries.
* **Real-time WebSockets**: Integrated custom `ConnectionManager` using Socket.io to route real-time chat messages, deliver active typing indications, and broadcast instant read receipts.
* **Role-Based Access Control (RBAC)**: Custom FastAPI dependency guards ensuring API access is securely restricted to designated roles: `admin`, `alumni`, or `student`.
* **Cross-Tenant Security**: Scoped admin query capabilities restricting actions strictly to the admin's owned `institute_id` (cross-tenant validation protection).
* **AI Wisdom Tips Engine**: Integrated Groq client using LLM invocation to generate and supply custom wisdom/career advice snippets for alumni profiles.
* **Moderation Pipeline**: Endpoints supporting post flagging, soft deletion, comment removal, and profile report resolution (such as stripping verified badges for false information).
* **Mentorship Management**: Expiration tracker for mentorship requests (expires after 7 days) and automated chat channel generation upon request acceptance.

---

## 🛠️ Technology Stack

* **Web Framework**: FastAPI (v0.110.1)
* **ASGI Server**: Uvicorn (v0.25.0)
* **Database Client**: Motor (v3.3.1) & PyMongo (v4.5.0)
* **Authentication**: Clerk JWT validation & verification via `python-jose` (v3.5.0)
* **Real-time Networking**: python-socketio (v5.11.1)
* **AI Engine**: Groq (v0.11.0) & Google Generative AI
* **JSON Validation**: Pydantic (v2.12.5)
* **Environment Configuration**: python-dotenv (v1.2.1)

---

## 📁 Project Structure

```text
alumconnect-backend/
├── app/
│   └── community/
│       ├── api/            # API routers for posts & comments
│       ├── core/           # Socket.io configurations & mounting
│       ├── models/         # MongoDB collection models
│       ├── schemas/        # Pydantic schemas for request/response bodies
│       ├── services/       # Core business logic handlers
│       └── main.py         # App routers merger
├── core/
│   ├── admin_moderation.py # Moderation & admin operations
│   ├── auth.py             # Auth dependencies & Clerk validation
│   ├── database.py         # Async database client connection
│   └── models.py           # Shared base models
├── server.py               # Main application entrance point & WebSockets
├── requirements.txt        # PIP dependencies manifest
└── .env                    # System configurations (gitignored)
```

---

## ⚙️ Environment Variables

Create a `.env` file in the root of the `alumconnect-backend` directory:

```env
# MongoDB Connection URL & Target Database
MONGO_URL="mongodb://127.0.0.1:27017"
DB_NAME="alumconnect_db"

# Allowed Cross-Origin Origins
CORS_ORIGINS="http://localhost:3000,https://alumconnectiips.app"

# Auth Mode (set to true for development bypasses, false in production)
DEV_AUTH=true

# Clerk Auth Configs
CLERK_ISSUER="https://your-clerk-app-issuer.clerk.accounts.dev"
CLERK_SECRET_KEY="sk_test_..."

# Groq API Key (AI Wisdom Feature)
GROQ_API_KEY="gsk_..."
```

---

## 💻 Local Setup & Development

### Prerequisites

* **Python 3.10** or higher
* **MongoDB** (running locally or a remote atlas URI)
* **Virtualenv** / **pip** package managers

### 1. Setup Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate on Windows (PowerShell)
.\venv\Scripts\Activate.ps1

# Or activate on Git Bash / Linux / macOS
source venv/bin/activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the Backend Server

Start the FastAPI application with auto-reload:

```bash
uvicorn server:app --reload --host 127.0.0.1 --port 8000
```

---

## 🔍 API Testing & Interactive Documentation

Once the server is up, visit the following URLs in your browser to inspect or test endpoints:

* **Swagger UI Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
* **ReDoc Docs**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)
* **Health Check**: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)
