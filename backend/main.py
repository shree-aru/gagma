"""
GAGMA — Graph-Augmented GenAI Malware Analyst
Main FastAPI application entry point.

Phase 2: Industry-grade with persistent DB, rate limiting,
API key auth, security headers, and audit logging.
"""
from __future__ import annotations

import logging
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from config import CORS_ORIGINS
from services.graph_service import setup_schema, close_driver
from services.database import init_db
from middleware.auth import add_security_headers
from routers import analysis, chat, demo, prevention, webhooks

# ── Logging ────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(name)-25s │ %(levelname)-7s │ %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("gagma")


# ── Rate Limiter ───────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["120/minute"])


# ── Lifespan ───────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    logger.info("GAGMA starting up...")
    logger.info("=" * 60)
    logger.info("  Graph-Augmented GenAI Malware Analyst")
    logger.info("  Enterprise Edition v2.0")
    logger.info("=" * 60)

    # Initialize SQLite database
    init_db()
    logger.info("Database initialized (SQLite persistent storage)")

    # Try to set up Neo4j schema
    try:
        setup_schema()
        logger.info("Neo4j connected and schema ready")
    except Exception as e:
        logger.warning(f"Neo4j not available: {e}")
        logger.info("   Running in offline mode (graph viz still works)")

    yield

    # Cleanup
    close_driver()
    logger.info("GAGMA shut down")


# ── App ────────────────────────────────────────────────
app = FastAPI(
    title="GAGMA — Graph-Augmented GenAI Malware Analyst",
    description="Enterprise APK malware analysis with GenAI, graph intelligence, and banking fraud prevention",
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── Rate Limiter Registration ──────────────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── Security Headers ───────────────────────────────────
app.middleware("http")(add_security_headers)

# ── CORS (locked down — only same-origin + configured origins) ──
cors_origins = [o.strip() for o in CORS_ORIGINS if o.strip() and o.strip() != "*"]
if not cors_origins:
    # Default: allow same-origin only (secure default)
    cors_origins = ["http://localhost:8001", "http://127.0.0.1:8001", "http://localhost:8000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ── Routers ────────────────────────────────────────────
app.include_router(analysis.router)
app.include_router(chat.router)
app.include_router(demo.router)
app.include_router(prevention.router)
app.include_router(webhooks.router)

# ── Serve Frontend ─────────────────────────────────────
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
if FRONTEND_DIR.exists():
    for subdir in ["assets", "css", "js"]:
        dir_path = FRONTEND_DIR / subdir
        dir_path.mkdir(parents=True, exist_ok=True)
        app.mount(f"/{subdir}", StaticFiles(directory=str(dir_path)), name=subdir)

    @app.get("/")
    async def serve_frontend():
        """Serve the main frontend page."""
        return FileResponse(str(FRONTEND_DIR / "index.html"))

    @app.get("/health")
    async def health_check():
        """Health check endpoint for monitoring (ALB, CloudWatch)."""
        from services.database import count_blocked, list_analyses
        return {
            "status": "healthy",
            "version": "2.0.0",
            "analyses_count": len(list_analyses()),
            "blocked_count": count_blocked(),
        }
else:
    @app.get("/")
    async def root():
        return {
            "name": "GAGMA API",
            "version": "2.0.0",
            "docs": "/docs",
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
