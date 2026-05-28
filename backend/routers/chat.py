"""
GAGMA Chat Router — Natural language querying of analysis results
"""
from __future__ import annotations

import logging
from fastapi import APIRouter, HTTPException

from models.schemas import ChatRequest, ChatResponse
from agents.graph_query_agent import query_graph
from services.llm_service import call_llm
from services.graph_service import is_connected

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["chat"])


@router.post("/chat", response_model=ChatResponse)
def chat_with_agent(request: ChatRequest):
    """
    Chat with GAGMA's AI agents about the analyzed APK.
    Routes queries to the appropriate agent.
    """
    # Import here to avoid circular imports
    from routers.analysis import analyses

    analysis_id = request.analysis_id
    message = request.message.strip()

    if not message:
        raise HTTPException(400, "Message cannot be empty")

    # Get analysis context
    analysis = analyses.get(analysis_id)
    if not analysis:
        raise HTTPException(404, "Analysis not found")

    if not analysis.static_analysis:
        return ChatResponse(
            response="Analysis is still in progress. Please wait for it to complete.",
        )

    # Build context from analysis
    context = _build_context(analysis)

    # Route to appropriate agent
    if _is_graph_query(message):
        # Use Graph Query Agent for graph-specific questions
        result = query_graph(message, analysis_id)
        return ChatResponse(
            response=result["answer"],
            evidence=[result.get("cypher", "")],
        )
    else:
        # General analysis question — use direct LLM with full context
        response = _answer_general_question(message, context)
        return ChatResponse(response=response)


def _is_graph_query(message: str) -> bool:
    """Detect if a message should be routed to the graph query agent."""
    graph_keywords = [
        "graph", "cypher", "query", "relationship", "connected",
        "calls", "invokes", "node", "path", "traverse",
        "which methods", "which classes", "what calls",
        "find all", "show me", "list all",
    ]
    message_lower = message.lower()
    return any(kw in message_lower for kw in graph_keywords) and is_connected()


def _build_context(analysis) -> str:
    """Build a context string from analysis results for the LLM."""
    sa = analysis.static_analysis
    lines = [
        f"APK Package: {sa.metadata.package_name}",
        f"Risk Score: {analysis.risk_score.total_score}/100 ({analysis.risk_score.risk_level.value})" if analysis.risk_score else "",
        f"\nDangerous Permissions: {', '.join(p.name.split('.')[-1] for p in sa.permissions if p.is_suspicious)}",
        f"\nSuspicious APIs: {', '.join(f'{a.api_call} ({a.category})' for a in sa.suspicious_api_calls[:10])}",
        f"\nURLs: {', '.join(sa.extracted_urls[:5])}",
        f"\nIPs: {', '.join(sa.extracted_ips[:5])}",
        f"\nComponents: {len(sa.activities)} activities, {len(sa.services)} services, {len(sa.receivers)} receivers",
    ]

    if analysis.behavioral_findings:
        lines.append(f"\nBehavioral Findings:")
        for f in analysis.behavioral_findings:
            lines.append(f"  - [{f.severity.upper()}] {f.pattern_name}: {f.description}")

    if analysis.ai_summary:
        lines.append(f"\nPrevious AI Analysis:\n{analysis.ai_summary[:500]}")

    return "\n".join(lines)


def _answer_general_question(question: str, context: str) -> str:
    """Answer a general question about the APK using the LLM."""
    system_prompt = """You are GAGMA — a Graph-Augmented GenAI Malware Analyst.
Answer the cybersecurity analyst's question based on the provided APK analysis context.
Be technical, extremely concise, and direct. Keep response under 100 words."""
 
    user_prompt = f"""ANALYSIS CONTEXT:
{context}
 
ANALYST'S QUESTION:
{question}
 
Provide a clear, technical response under 100 words."""
 
    return call_llm(system_prompt, user_prompt, temperature=0.3)
