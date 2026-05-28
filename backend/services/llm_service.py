"""
GAGMA Agent Service — Orchestrates all GenAI agents
Supports Gemini (free), OpenAI, and Groq backends.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Optional

from config import (
    LLM_PROVIDER,
    GEMINI_API_KEY,
    OPENAI_API_KEY,
    GROQ_API_KEY,
    LLM_MODELS,
)

logger = logging.getLogger(__name__)

# ── LLM Client Abstraction ────────────────────────────

_llm_client = None


def _get_llm_client():
    """Initialize the LLM client based on configured provider."""
    global _llm_client
    if _llm_client is not None:
        return _llm_client

    provider = LLM_PROVIDER.lower()

    if provider == "gemini" and GEMINI_API_KEY:
        try:
            import google.generativeai as genai
            genai.configure(api_key=GEMINI_API_KEY)
            _llm_client = ("gemini", genai)
            logger.info(f"Using Gemini model: {LLM_MODELS['gemini']}")
            return _llm_client
        except ImportError:
            logger.warning("google-generativeai not installed")

    elif provider == "openai" and OPENAI_API_KEY:
        try:
            from openai import OpenAI
            client = OpenAI(api_key=OPENAI_API_KEY)
            _llm_client = ("openai", client)
            logger.info(f"Using OpenAI model: {LLM_MODELS['openai']}")
            return _llm_client
        except ImportError:
            logger.warning("openai not installed")

    elif provider == "groq" and GROQ_API_KEY:
        try:
            from groq import Groq
            client = Groq(api_key=GROQ_API_KEY)
            _llm_client = ("groq", client)
            logger.info(f"Using Groq model: {LLM_MODELS['groq']}")
            return _llm_client
        except ImportError:
            logger.warning("groq not installed")

    logger.warning(f"No LLM configured (provider={provider}). Agents will use fallback analysis.")
    _llm_client = ("none", None)
    return _llm_client


def call_llm(system_prompt: str, user_prompt: str, temperature: float = 0.3) -> str:
    """Call the configured LLM with a system + user prompt."""
    provider, client = _get_llm_client()

    try:
        if provider == "gemini":
            model = client.GenerativeModel(
                model_name=LLM_MODELS["gemini"],
                system_instruction=system_prompt,
            )
            response = model.generate_content(
                user_prompt,
                generation_config={"temperature": temperature, "max_output_tokens": 1500},
            )
            return response.text
 
        elif provider == "openai":
            response = client.chat.completions.create(
                model=LLM_MODELS["openai"],
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=temperature,
                max_tokens=1500,
            )
            return response.choices[0].message.content
 
        elif provider == "groq":
            response = client.chat.completions.create(
                model=LLM_MODELS["groq"],
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=temperature,
                max_tokens=1500,
            )
            return response.choices[0].message.content

        else:
            return _fallback_response(user_prompt)

    except Exception as e:
        logger.error(f"LLM call failed: {e}")
        return _fallback_response(user_prompt)


def _fallback_response(prompt: str) -> str:
    """Provide a basic response when no LLM is available."""
    return (
        "⚠️ AI analysis unavailable (no LLM configured). "
        "Please set up an API key in the .env file. "
        "Supported providers: Gemini (GEMINI_API_KEY), "
        "OpenAI (OPENAI_API_KEY), or Groq (GROQ_API_KEY)."
    )
