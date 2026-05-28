"""
GAGMA Configuration — Environment Variables & Settings
"""
import os
from pathlib import Path
from dotenv import load_dotenv
# ── Paths ──────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = BASE_DIR / "data" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Load env file from root folder
load_dotenv(dotenv_path=BASE_DIR / ".env", override=True)

# ── Neo4j ──────────────────────────────────────────────
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", os.getenv("NEO4J_USERNAME", "neo4j"))
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")
NEO4J_DATABASE = os.getenv("NEO4J_DATABASE", "neo4j")

# ── LLM ────────────────────────────────────────────────
# Supported: "gemini", "openai", "groq"
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "gemini")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

# Model names per provider
LLM_MODELS = {
    "gemini": os.getenv("GEMINI_MODEL", "gemini-2.0-flash"),
    "openai": os.getenv("OPENAI_MODEL", "gpt-4.1-mini"),
    "groq": os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
}

# ── Threat Intelligence ────────────────────────────────
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

# ── App Settings ───────────────────────────────────────
MAX_UPLOAD_SIZE_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "50"))
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")
