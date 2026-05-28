"""
GAGMA Graph Query Agent — Translates natural language to Cypher queries
and interprets results from the Neo4j Malware Knowledge Graph.
"""
from __future__ import annotations

import logging
from services.llm_service import call_llm
from services.graph_service import run_cypher, get_graph_schema, is_connected

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are GAGMA's Graph Query Agent — a specialized cybersecurity AI that queries
a Neo4j Malware Knowledge Graph to answer questions about analyzed Android APKs.

You have access to a Neo4j graph database with the following schema:
{schema}

Your job:
1. Understand the user's question about the APK
2. Generate a valid Cypher query to answer it
3. Interpret the results in cybersecurity context

RULES:
- Always output valid Cypher queries
- Use MATCH, WHERE, RETURN patterns
- Never use DETACH DELETE or any destructive operations
- If the question is about permissions, query Permission nodes
- If about API calls, query APICall nodes
- If about network, query URL and IPAddress nodes
- Always limit results to 50 max

OUTPUT FORMAT:
Return your response as JSON with exactly these fields:
{{"cypher": "YOUR CYPHER QUERY", "explanation": "What this query does"}}
"""


def query_graph(question: str, analysis_id: str = "") -> dict:
    """
    Translate a natural language question into a Cypher query,
    execute it, and interpret the results.
    """
    schema = get_graph_schema()

    if not is_connected():
        return {
            "answer": "Graph database is not connected. Cannot query the knowledge graph.",
            "cypher": "",
            "raw_results": [],
        }

    # Step 1: Generate Cypher query
    prompt = f"""Question about the analyzed APK: "{question}"

Generate a Cypher query to answer this question. The analysis_id for the current APK is: "{analysis_id}"

Return JSON: {{"cypher": "CYPHER QUERY", "explanation": "explanation"}}"""

    llm_response = call_llm(
        SYSTEM_PROMPT.format(schema=schema),
        prompt,
        temperature=0.1,
    )

    # Step 2: Parse the Cypher query
    cypher = _extract_cypher(llm_response)
    if not cypher:
        return {
            "answer": "I couldn't generate a valid query for that question. Please try rephrasing.",
            "cypher": "",
            "raw_results": [],
        }

    # Step 3: Execute the query
    try:
        results = run_cypher(cypher)
    except Exception as e:
        logger.error(f"Cypher execution failed: {e}")
        return {
            "answer": f"Query execution failed: {str(e)}. The generated query may be invalid.",
            "cypher": cypher,
            "raw_results": [],
        }

    # Step 4: Interpret results
    interpretation = _interpret_results(question, cypher, results)

    return {
        "answer": interpretation,
        "cypher": cypher,
        "raw_results": results[:20],
    }


def _extract_cypher(llm_response: str) -> str:
    """Extract Cypher query from LLM response."""
    import json as json_mod
    import re

    # Try JSON parsing
    try:
        # Find JSON block
        json_match = re.search(r'\{[^{}]*"cypher"[^{}]*\}', llm_response, re.DOTALL)
        if json_match:
            data = json_mod.loads(json_match.group())
            return data.get("cypher", "")
    except (json_mod.JSONDecodeError, KeyError):
        pass

    # Try extracting from code block
    code_match = re.search(r'```(?:cypher)?\s*\n?(.*?)\n?```', llm_response, re.DOTALL)
    if code_match:
        return code_match.group(1).strip()

    # Try finding MATCH pattern
    match = re.search(r'(MATCH\s+.*?RETURN\s+.*?)(?:\n|$)', llm_response, re.DOTALL | re.IGNORECASE)
    if match:
        return match.group(1).strip()

    return ""


def _interpret_results(question: str, cypher: str, results: list[dict]) -> str:
    """Use LLM to interpret query results in cybersecurity context."""
    if not results:
        return "No results found for this query. The APK may not contain the requested information."

    results_str = str(results[:10])

    prompt = f"""A cybersecurity analyst asked: "{question}"

The Cypher query was: {cypher}

The results from the Malware Knowledge Graph are:
{results_str}

Provide a clear, concise cybersecurity analysis of these results. Focus on:
- What the results mean in terms of potential malicious behavior
- Any security implications
- Severity assessment

Keep the response under 200 words. Be direct and technical."""

    return call_llm(
        "You are a cybersecurity expert analyzing Android malware. Provide clear, actionable analysis.",
        prompt,
        temperature=0.3,
    )
