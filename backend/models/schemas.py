"""
GAGMA Pydantic Models — Request/Response schemas
"""
from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Optional
from enum import Enum


# ── Enums ──────────────────────────────────────────────

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AnalysisStatus(str, Enum):
    PENDING = "PENDING"
    DECOMPILING = "DECOMPILING"
    EXTRACTING = "EXTRACTING"
    BUILDING_GRAPH = "BUILDING_GRAPH"
    ANALYZING = "ANALYZING"
    SCORING = "SCORING"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"


# ── Permission Classification ─────────────────────────

class PermissionInfo(BaseModel):
    name: str
    protection_level: str = "normal"  # normal, dangerous, signature
    description: str = ""
    is_suspicious: bool = False


# ── APK Metadata ───────────────────────────────────────

class APKMetadata(BaseModel):
    package_name: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: int = 0
    target_sdk: int = 0
    main_activity: str = ""
    md5: str = ""
    sha256: str = ""
    file_size: int = 0


# ── Analysis Results ───────────────────────────────────

class SuspiciousAPICall(BaseModel):
    method: str
    api_call: str
    category: str  # e.g., "sms", "crypto", "network", "reflection", "exec"
    severity: str = "medium"
    description: str = ""


class BehavioralFinding(BaseModel):
    pattern_name: str
    severity: str  # low, medium, high, critical
    description: str
    evidence: list[str] = Field(default_factory=list)
    graph_paths: list[str] = Field(default_factory=list)
    # MITRE ATT&CK for Mobile mapping
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)


class BankingRiskFlag(BaseModel):
    """Specific banking-sector risk indicator."""
    flag_type: str           # e.g., "UPI_OVERLAY", "OTP_INTERCEPTION", "APP_IMPERSONATION"
    title: str
    detail: str
    severity: str            # critical, high, medium
    affected_apps: list[str] = Field(default_factory=list)  # targeted banking apps


class KillChainStep(BaseModel):
    """One step in the malware attack kill chain."""
    stage: int
    name: str                # e.g., "Install", "Persist", "Overlay", "Steal", "Exfiltrate"
    description: str
    technique: str           # MITRE technique ID


class RiskScoreBreakdown(BaseModel):
    permissions_score: float = 0
    api_calls_score: float = 0
    behavioral_score: float = 0
    threat_intel_score: float = 0
    total_score: float = 0
    risk_level: RiskLevel = RiskLevel.LOW


class StaticAnalysisResult(BaseModel):
    metadata: APKMetadata = Field(default_factory=APKMetadata)
    permissions: list[PermissionInfo] = Field(default_factory=list)
    activities: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    receivers: list[str] = Field(default_factory=list)
    providers: list[str] = Field(default_factory=list)
    suspicious_api_calls: list[SuspiciousAPICall] = Field(default_factory=list)
    extracted_urls: list[str] = Field(default_factory=list)
    extracted_ips: list[str] = Field(default_factory=list)
    extracted_strings: list[str] = Field(default_factory=list)
    classes_count: int = 0
    methods_count: int = 0
    call_graph_edges: int = 0


# ── Full Analysis Response ─────────────────────────────

class AnalysisResponse(BaseModel):
    analysis_id: str
    status: AnalysisStatus = AnalysisStatus.PENDING
    static_analysis: Optional[StaticAnalysisResult] = None
    risk_score: Optional[RiskScoreBreakdown] = None
    behavioral_findings: list[BehavioralFinding] = Field(default_factory=list)
    banking_flags: list[BankingRiskFlag] = Field(default_factory=list)
    kill_chain: list[KillChainStep] = Field(default_factory=list)
    ai_summary: str = ""
    graph_data: Optional[dict] = None  # For vis.js visualization
    threat_intel: Optional[dict] = None  # Raw threat intel data for frontend
    dynamic_analysis: Optional[dict] = None  # Emulated dynamic analysis results


# ── Chat ───────────────────────────────────────────────

class ChatRequest(BaseModel):
    analysis_id: str
    message: str


class ChatResponse(BaseModel):
    response: str
    evidence: list[str] = Field(default_factory=list)
    graph_highlights: list[str] = Field(default_factory=list)
