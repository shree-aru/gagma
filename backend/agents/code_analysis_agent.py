"""
GAGMA Code Analysis Agent — Interprets decompiled code snippets
using LLM with graph context for malware detection.
"""
from __future__ import annotations

import logging
from services.llm_service import call_llm

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are GAGMA's Code Interpretation Agent — a senior Android reverse engineer
and malware analyst. You analyze decompiled Android code snippets to identify:

1. Malicious intent (data theft, privilege escalation, C2 communication)
2. Obfuscation techniques (string encoding, reflection-based calls, dynamic class loading)
3. Anti-analysis techniques (emulator detection, debugger detection, root detection)
4. Suspicious coding patterns (hardcoded IPs/URLs, base64 encoded strings, encrypted payloads)

RULES:
- Be precise and technical
- Reference specific code lines and patterns
- Rate each finding: LOW / MEDIUM / HIGH / CRITICAL severity
- Don't make assumptions without evidence in the code
- Consider the graph context (what permissions and APIs the APK uses)
"""


def analyze_code_snippet(
    code: str,
    context: str = "",
    file_name: str = "unknown",
) -> dict:
    """
    Analyze a code snippet for malicious indicators.

    Args:
        code: The decompiled Java/Smali code to analyze
        context: Graph context (permissions, related API calls)
        file_name: Source file name for reference

    Returns:
        dict with 'analysis', 'findings', and 'severity'
    """
    prompt = f"""Analyze this decompiled Android code for malicious behavior:

FILE: {file_name}

CODE:
```java
{code[:3000]}
```

GRAPH CONTEXT (permissions and APIs this APK uses):
{context or "No additional context available"}

Provide your analysis in this format:
1. **Purpose**: What does this code do?
2. **Suspicious Indicators**: List specific malicious patterns found
3. **Obfuscation**: Any anti-analysis or obfuscation techniques?
4. **Risk Level**: LOW / MEDIUM / HIGH / CRITICAL
5. **Evidence**: Specific code lines that support your findings

Be concise (under 250 words)."""

    analysis = call_llm(SYSTEM_PROMPT, prompt, temperature=0.2)

    return {
        "analysis": analysis,
        "file_name": file_name,
        "code_length": len(code),
    }


def analyze_suspicious_strings(strings: list[str]) -> dict:
    """
    Analyze a collection of suspicious strings extracted from the APK.
    """
    if not strings:
        return {"analysis": "No suspicious strings to analyze.", "findings": []}

    strings_sample = strings[:50]
    strings_text = "\n".join(f"- {s}" for s in strings_sample)

    prompt = f"""Analyze these strings extracted from an Android APK for malicious indicators:

EXTRACTED STRINGS:
{strings_text}

Look for:
1. Command & Control (C2) server URLs
2. Hardcoded credentials or API keys
3. Base64-encoded payloads
4. Suspicious domain names or IPs
5. Crypto-related strings (ransomware indicators)
6. Known malware family signatures
7. Anti-analysis strings (emulator names, debugger packages)

Categorize each finding with severity (LOW/MEDIUM/HIGH/CRITICAL).
Be concise (under 200 words)."""

    analysis = call_llm(SYSTEM_PROMPT, prompt, temperature=0.2)

    return {
        "analysis": analysis,
        "strings_analyzed": len(strings_sample),
    }
