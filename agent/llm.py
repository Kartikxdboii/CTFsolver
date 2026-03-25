"""
LLM Reasoning Engine — Anthropic Claude API wrapper.

Provides prompt templates for challenge classification, code analysis,
puzzle solving, and general CTF reasoning.
"""

from __future__ import annotations

import json
from typing import Optional

import anthropic

from agent.config import (
    ANTHROPIC_API_KEY,
    LLM_MODEL,
    LLM_TEMPERATURE,
    LLM_MAX_TOKENS,
    CATEGORIES,
    VERBOSE,
)


# ── Client singleton ──────────────────────────────────────────────────────
_client: Optional[anthropic.Anthropic] = None


def _get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        _client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    return _client


def chat(
    system: str,
    user: str,
    *,
    model: str | None = None,
    temperature: float | None = None,
    max_tokens: int | None = None,
) -> str:
    """Send a message to Claude and return the response."""
    client = _get_client()
    if VERBOSE:
        print(f"  [LLM] {user[:120]}...")

    resp = client.messages.create(
        model=model or LLM_MODEL,
        max_tokens=max_tokens or LLM_MAX_TOKENS,
        temperature=temperature if temperature is not None else LLM_TEMPERATURE,
        system=system,
        messages=[
            {"role": "user", "content": user},
        ],
    )
    return resp.content[0].text.strip()


# ── Prompt Templates ──────────────────────────────────────────────────────

def classify_challenge(
    description: str,
    file_info: str = "",
    strings_sample: str = "",
) -> dict:
    """
    Ask Claude to classify a challenge into one of the known categories.

    Returns {"category": str, "confidence": float, "reasoning": str}
    """
    system = (
        "You are an expert CTF player. Given information about a challenge, "
        "classify it into exactly ONE of these categories: "
        f"{', '.join(CATEGORIES)}.\n\n"
        "Respond with ONLY a JSON object: "
        '{"category": "<cat>", "confidence": 0.0-1.0, "reasoning": "..."}'
    )

    user_parts = [f"**Challenge description:**\n{description}"]
    if file_info:
        user_parts.append(f"\n**File info:**\n{file_info}")
    if strings_sample:
        user_parts.append(f"\n**Strings sample (first 80 lines):**\n{strings_sample}")

    raw = chat(system, "\n".join(user_parts))

    # Parse JSON from response (handle markdown code fences)
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[-1].rsplit("```", 1)[0]

    try:
        result = json.loads(raw)
    except json.JSONDecodeError:
        result = {"category": "misc", "confidence": 0.3, "reasoning": raw}

    return result


def analyze_code(code: str, language: str = "C") -> str:
    """Ask Claude to explain decompiled / source code for vulnerabilities."""
    system = (
        "You are an expert reverse engineer and exploit developer. "
        "Analyze the following code. Identify vulnerabilities, hidden flags, "
        "or interesting logic. Be concise and actionable."
    )
    return chat(system, f"```{language}\n{code}\n```")


def solve_puzzle(description: str, context: str = "") -> str:
    """Ask Claude to solve a logic/math/trivia CTF puzzle."""
    system = (
        "You are an expert CTF player. Solve the following challenge. "
        "If the answer is a flag, output it clearly on its own line. "
        "Show your reasoning step by step."
    )
    user = description
    if context:
        user += f"\n\nAdditional context:\n{context}"
    return chat(system, user)


def identify_encoding(data: str) -> str:
    """Ask Claude to identify the encoding/cipher of a data string."""
    system = (
        "You are a cryptanalysis expert. Identify the encoding or cipher "
        "used in the following data. Suggest decoding steps. "
        "If you can decode it directly, provide the decoded output."
    )
    return chat(system, f"```\n{data}\n```")


def suggest_strategies(
    category: str,
    description: str,
    file_info: str = "",
) -> list[str]:
    """
    Ask Claude to suggest ranked strategies for a challenge.

    Returns a list of strategy names the solver should try.
    """
    system = (
        "You are an expert CTF player. Given a challenge category and "
        "description, suggest a ranked list of strategies to solve it. "
        "Return a JSON array of short strategy names, e.g.:\n"
        '["base64_decode", "xor_bruteforce", "rsa_small_e"]'
    )
    user = f"Category: {category}\nDescription: {description}"
    if file_info:
        user += f"\nFile info: {file_info}"

    raw = chat(system, user)
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[-1].rsplit("```", 1)[0]

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return []
