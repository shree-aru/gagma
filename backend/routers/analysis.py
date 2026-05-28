"""
GAGMA Analysis Router — APK upload & analysis endpoints
"""
from __future__ import annotations

import uuid
import asyncio
import logging
from pathlib import Path

from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse

from config import UPLOAD_DIR, MAX_UPLOAD_SIZE_MB
from models.schemas import AnalysisResponse, AnalysisStatus, StaticAnalysisResult
from services.apk_analyzer import analyze_apk
from services.graph_service import ingest_analysis, is_connected
from services.risk_scorer import calculate_risk_score
from services.report_generator import generate_report
from agents.behavior_agent import analyze_behavior, get_ai_behavioral_analysis, analyze_banking_flags
from agents.threat_intel_agent import enrich_analysis
from services.dynamic_analyzer import emulate_dynamic_analysis

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["analysis"])

# ── In-memory analysis store (for hackathon — use DB in production) ──
analyses: dict[str, AnalysisResponse] = {}
reports: dict[str, str] = {}


@router.post("/analyze")
async def upload_and_analyze(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
):
    """Upload an APK file and start analysis."""
    # Validate file
    if not file.filename or not file.filename.lower().endswith(".apk"):
        raise HTTPException(400, "Only APK files are accepted")

    # Read file content
    content = await file.read()
    if len(content) > MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(400, f"File too large (max {MAX_UPLOAD_SIZE_MB}MB)")

    # Save to disk
    analysis_id = str(uuid.uuid4())[:8]
    file_path = UPLOAD_DIR / f"{analysis_id}.apk"
    file_path.write_bytes(content)

    # Initialize analysis record
    analyses[analysis_id] = AnalysisResponse(
        analysis_id=analysis_id,
        status=AnalysisStatus.PENDING,
    )

    # Run analysis in background
    background_tasks.add_task(_run_full_analysis, analysis_id, file_path)

    return {"analysis_id": analysis_id, "status": "PENDING"}


@router.get("/status/{analysis_id}")
async def get_status(analysis_id: str):
    """Get the current status and results of an analysis."""
    if analysis_id not in analyses:
        raise HTTPException(404, "Analysis not found")

    analysis = analyses[analysis_id]
    return analysis.model_dump()


@router.get("/report/{analysis_id}")
async def get_report(analysis_id: str):
    """Get the full Markdown report for an analysis."""
    if analysis_id not in reports:
        raise HTTPException(404, "Report not found")

    return {"report": reports[analysis_id]}


@router.get("/status/{analysis_id}/yara")
async def get_yara_rule(analysis_id: str):
    """Retrieve custom dynamically generated YARA signature for the analyzed sample."""
    if analysis_id not in analyses:
        raise HTTPException(404, "Analysis not found")

    analysis = analyses[analysis_id]
    if not analysis.static_analysis:
        raise HTTPException(400, "Analysis is not complete or static data missing")

    from services.yara_generator import generate_yara_rule
    yara_text = generate_yara_rule(analysis_id, analysis.model_dump())

    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(content=yara_text, media_type="text/plain")


@router.get("/graph/campaign-clustering")
async def get_campaign_clustering():
    """Build a campaign-wide clustering graph from all analyzed APKs."""
    completed = [
        {"analysis_id": a.analysis_id}
        for a in analyses.values()
        if a.status == AnalysisStatus.COMPLETE
    ]

    # Fallback to SQLite DB if memory is empty
    if not completed:
        try:
            from services.database import list_analyses as db_list_analyses
            db_records = db_list_analyses()
            # De-duplicate
            seen = set()
            for r in db_records:
                aid = r.get("analysis_id")
                if aid and aid not in seen:
                    seen.add(aid)
                    completed.append({"analysis_id": aid})
        except Exception:
            pass

    from services.graph_service import generate_campaign_clustering_graph
    graph_data = generate_campaign_clustering_graph(completed[:6])
    return graph_data


@router.get("/analyses")
async def list_analyses():
    """List all analyses."""
    return [
        {
            "analysis_id": a.analysis_id,
            "status": a.status.value,
            "package_name": a.static_analysis.metadata.package_name if a.static_analysis else "",
            "risk_score": a.risk_score.total_score if a.risk_score else None,
            "risk_level": a.risk_score.risk_level.value if a.risk_score else None,
        }
        for a in analyses.values()
    ]


async def _run_full_analysis(analysis_id: str, file_path: Path):
    """Run the complete analysis pipeline."""
    try:
        analysis = analyses[analysis_id]

        # Step 1: Static Analysis
        analysis.status = AnalysisStatus.DECOMPILING
        logger.info(f"[{analysis_id}] Starting static analysis...")

        # Run CPU-bound analysis in thread pool
        loop = asyncio.get_event_loop()
        static_result = await loop.run_in_executor(None, analyze_apk, file_path)
        analysis.static_analysis = static_result
        analysis.status = AnalysisStatus.EXTRACTING
        logger.info(f"[{analysis_id}] Static analysis complete. "
                     f"Found {len(static_result.permissions)} permissions, "
                     f"{len(static_result.suspicious_api_calls)} suspicious APIs")

        # Step 2: Graph Ingestion
        analysis.status = AnalysisStatus.BUILDING_GRAPH
        logger.info(f"[{analysis_id}] Building knowledge graph...")

        graph_data = await loop.run_in_executor(
            None, ingest_analysis, analysis_id, static_result
        )
        analysis.graph_data = graph_data
        logger.info(f"[{analysis_id}] Graph built with "
                     f"{len(graph_data.get('nodes', []))} nodes, "
                     f"{len(graph_data.get('edges', []))} edges")

        # Steps 3-5: Run behavioral analysis, AI summary, and threat intel in parallel
        analysis.status = AnalysisStatus.ANALYZING
        logger.info(f"[{analysis_id}] Running behavioral + threat intel (parallel)...")

        # Behavioral analysis (CPU-bound, runs in thread pool)
        findings = await loop.run_in_executor(
            None, analyze_behavior, static_result
        )
        analysis.behavioral_findings = findings
        logger.info(f"[{analysis_id}] Found {len(findings)} behavioral patterns")

        # Banking-specific flags and kill chain
        banking_flags, kill_chain = await loop.run_in_executor(
            None, analyze_banking_flags, static_result
        )
        analysis.banking_flags = banking_flags
        analysis.kill_chain = kill_chain
        if banking_flags:
            logger.info(f"[{analysis_id}] Banking flags: {[f.flag_type for f in banking_flags]}")

        # AI summary + Threat intel run concurrently
        ai_task = loop.run_in_executor(
            None, get_ai_behavioral_analysis, static_result, findings
        )
        threat_task = enrich_analysis(
            static_result.metadata.sha256,
            static_result.extracted_ips,
        )
        ai_summary, threat_intel = await asyncio.gather(ai_task, threat_task)
        analysis.ai_summary = ai_summary
        analysis.threat_intel = threat_intel  # Store for frontend

        # Step 5b: Dynamic Analysis Emulation
        logger.info(f"[{analysis_id}] Running dynamic analysis emulation...")
        dynamic_results = await loop.run_in_executor(
            None, emulate_dynamic_analysis, static_result
        )
        analysis.dynamic_analysis = dynamic_results
        logger.info(f"[{analysis_id}] Dynamic emulation: {dynamic_results['sandbox_verdict']} "
                     f"({dynamic_results['total_findings']} findings)")

        # Step 6: Risk Scoring
        analysis.status = AnalysisStatus.SCORING
        risk_score = calculate_risk_score(static_result, findings, threat_intel)
        analysis.risk_score = risk_score
        logger.info(f"[{analysis_id}] Risk score: {risk_score.total_score}/100 "
                     f"({risk_score.risk_level.value})")

        # Step 7: Generate Report
        report = generate_report(
            analysis_id, static_result, risk_score,
            findings, ai_summary, threat_intel,
            banking_flags=banking_flags, kill_chain=kill_chain,
        )
        reports[analysis_id] = report

        # Done!
        analysis.status = AnalysisStatus.COMPLETE
        logger.info(f"[{analysis_id}] Analysis complete!")

        # Dispatch SIEM Webhook in the background
        try:
            from services.webhook_service import dispatch_webhook
            webhook_payload = {
                "analysis_id": analysis_id,
                "apk_name": file_path.name,
                "apk_hash": static_result.metadata.sha256,
                "package_name": static_result.metadata.package_name,
                "risk_score": risk_score.total_score,
                "risk_level": risk_score.risk_level.value,
                "details": {
                    "danger_permissions": [p.name for p in static_result.permissions if p.protection_level == "dangerous"],
                    "suspicious_apis": [api.model_dump() for api in static_result.suspicious_api_calls],
                    "banking_flags": [f.flag_type for f in banking_flags] if banking_flags else []
                }
            }
            asyncio.create_task(dispatch_webhook("threat.detected", webhook_payload))
        except Exception as webhook_err:
            logger.error(f"[{analysis_id}] Webhook dispatch setup failed: {webhook_err}")

        # Dispatch Automated WhatsApp Alert in the background
        try:
            from services.whatsapp_service import auto_dispatch_whatsapp_alert
            asyncio.create_task(auto_dispatch_whatsapp_alert(
                analysis_id=analysis_id,
                package_name=static_result.metadata.package_name,
                risk_score=risk_score.total_score,
                risk_level=risk_score.risk_level.value
            ))
        except Exception as wa_err:
            logger.error(f"[{analysis_id}] WhatsApp dispatch setup failed: {wa_err}")

    except Exception as e:
        logger.error(f"[{analysis_id}] Analysis failed: {e}", exc_info=True)
        if analysis_id in analyses:
            analyses[analysis_id].status = AnalysisStatus.FAILED
