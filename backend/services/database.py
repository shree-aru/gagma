"""
GAGMA Database Service — Persistent SQLite storage for production use.

Replaces in-memory Python dicts with SQLAlchemy + SQLite.
All analyses, reports, blocked hashes, and audit logs persist across restarts.

For AWS production: swap the DATABASE_URL to PostgreSQL with zero code changes.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from contextlib import contextmanager

from sqlalchemy import create_engine, Column, String, Float, Text, DateTime, Integer, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker, Session

logger = logging.getLogger(__name__)

# ── Database Setup ─────────────────────────────────────
DB_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "gagma.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(DATABASE_URL, echo=False, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()


# ── Models ─────────────────────────────────────────────

class AnalysisRecord(Base):
    """Persistent analysis record."""
    __tablename__ = "analyses"

    analysis_id = Column(String(64), primary_key=True, index=True)
    status = Column(String(20), default="PENDING")
    package_name = Column(String(256), default="")
    risk_score = Column(Float, nullable=True)
    risk_level = Column(String(20), nullable=True)
    filename = Column(String(256), default="")
    file_size = Column(Integer, default=0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)

    # JSON-serialized full analysis response
    result_json = Column(Text, default="{}")
    report_markdown = Column(Text, default="")


class BlockedHash(Base):
    """Enterprise blocklist entry."""
    __tablename__ = "blocked_hashes"

    sha256 = Column(String(64), primary_key=True, index=True)
    package_name = Column(String(256), default="")
    risk_score = Column(Float, default=0)
    risk_level = Column(String(20), default="")
    reason = Column(Text, default="")
    banking_flags_json = Column(Text, default="[]")
    blocked_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    blocked_by = Column(String(64), default="system")


class AuditLog(Base):
    """Audit trail for compliance — every significant action logged."""
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    action = Column(String(64))        # UPLOAD, ANALYZE, BLOCK, CHAT, EXPORT
    actor = Column(String(128))        # API key identifier or "anonymous"
    resource_id = Column(String(64))   # analysis_id, hash, etc.
    detail = Column(Text, default="")
    ip_address = Column(String(45), default="")


class APIKey(Base):
    """Registered API keys for bank partners."""
    __tablename__ = "api_keys"

    key_hash = Column(String(128), primary_key=True)
    name = Column(String(128))         # "HDFC Bank SOC", "SBI CERT"
    org = Column(String(128), default="")
    role = Column(String(20), default="analyst")  # analyst, admin
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_used = Column(DateTime, nullable=True)
    rate_limit = Column(Integer, default=60)  # requests per minute


class SystemSetting(Base):
    """System configuration parameters (e.g. SIEM Webhook URL)."""
    __tablename__ = "system_settings"

    key = Column(String(64), primary_key=True)
    value = Column(Text, default="")


# ── Create Tables ──────────────────────────────────────

def init_db():
    """Create all tables if they don't exist."""
    Base.metadata.create_all(bind=engine)
    logger.info(f"Database initialized at {DB_PATH}")


def get_db() -> Session:
    """Get a database session (for FastAPI dependency injection)."""
    db = SessionLocal()
    try:
        return db
    except Exception:
        db.close()
        raise


@contextmanager
def get_db_session():
    """Context manager for database sessions."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


# ── Helper Functions ───────────────────────────────────

def save_analysis(analysis_id: str, status: str, result_dict: dict, report: str = ""):
    """Save or update an analysis in the database."""
    with get_db_session() as db:
        record = db.query(AnalysisRecord).filter_by(analysis_id=analysis_id).first()
        if not record:
            record = AnalysisRecord(analysis_id=analysis_id)
            db.add(record)

        record.status = status
        record.result_json = json.dumps(result_dict, default=str)
        record.report_markdown = report

        # Extract key fields for quick queries
        static = result_dict.get("static_analysis", {})
        meta = static.get("metadata", {})
        record.package_name = meta.get("package_name", "")
        record.file_size = meta.get("file_size", 0)

        risk = result_dict.get("risk_score", {})
        if risk:
            record.risk_score = risk.get("total_score")
            record.risk_level = risk.get("risk_level")

        if status == "COMPLETE":
            record.completed_at = datetime.now(timezone.utc)


def load_analysis(analysis_id: str) -> dict | None:
    """Load an analysis from the database."""
    with get_db_session() as db:
        record = db.query(AnalysisRecord).filter_by(analysis_id=analysis_id).first()
        if not record:
            return None
        return json.loads(record.result_json)


def load_report(analysis_id: str) -> str | None:
    """Load a report from the database."""
    with get_db_session() as db:
        record = db.query(AnalysisRecord).filter_by(analysis_id=analysis_id).first()
        if not record:
            return None
        return record.report_markdown


def list_analyses() -> list[dict]:
    """List all analyses (summary view)."""
    with get_db_session() as db:
        records = db.query(AnalysisRecord).order_by(AnalysisRecord.created_at.desc()).all()
        return [
            {
                "analysis_id": r.analysis_id,
                "status": r.status,
                "package_name": r.package_name,
                "risk_score": r.risk_score,
                "risk_level": r.risk_level,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in records
        ]


def save_blocked_hash(sha256: str, data: dict):
    """Add a hash to the enterprise blocklist."""
    with get_db_session() as db:
        record = db.query(BlockedHash).filter_by(sha256=sha256).first()
        if not record:
            record = BlockedHash(sha256=sha256)
            db.add(record)
        record.package_name = data.get("package_name", "")
        record.risk_score = data.get("risk_score", 0)
        record.risk_level = data.get("risk_level", "")
        record.reason = data.get("reason", "")
        record.banking_flags_json = json.dumps(data.get("banking_flags", []))


def get_blocked_hash(sha256: str) -> dict | None:
    """Check if a hash is in the blocklist."""
    with get_db_session() as db:
        record = db.query(BlockedHash).filter_by(sha256=sha256).first()
        if not record:
            return None
        return {
            "sha256": record.sha256,
            "package_name": record.package_name,
            "risk_score": record.risk_score,
            "risk_level": record.risk_level,
            "reason": record.reason,
            "banking_flags": json.loads(record.banking_flags_json),
            "blocked_at": record.blocked_at.isoformat() if record.blocked_at else None,
        }


def list_blocked_hashes() -> list[dict]:
    """List all blocked hashes."""
    with get_db_session() as db:
        records = db.query(BlockedHash).order_by(BlockedHash.blocked_at.desc()).all()
        return [
            {
                "sha256": r.sha256,
                "package_name": r.package_name,
                "risk_score": r.risk_score,
                "risk_level": r.risk_level,
                "reason": r.reason,
                "banking_flags": json.loads(r.banking_flags_json),
                "blocked_at": r.blocked_at.isoformat() if r.blocked_at else None,
            }
            for r in records
        ]


def count_blocked() -> int:
    """Count blocked hashes."""
    with get_db_session() as db:
        return db.query(BlockedHash).count()


def log_audit(action: str, actor: str = "anonymous", resource_id: str = "",
              detail: str = "", ip_address: str = ""):
    """Write an audit log entry."""
    with get_db_session() as db:
        entry = AuditLog(
            action=action,
            actor=actor,
            resource_id=resource_id,
            detail=detail,
            ip_address=ip_address,
        )
        db.add(entry)


def get_system_setting(key: str) -> str:
    """Get a system setting value."""
    with get_db_session() as db:
        record = db.query(SystemSetting).filter_by(key=key).first()
        return record.value if record else ""


def save_system_setting(key: str, value: str):
    """Save a system setting."""
    with get_db_session() as db:
        record = db.query(SystemSetting).filter_by(key=key).first()
        if not record:
            record = SystemSetting(key=key)
            db.add(record)
        record.value = value
