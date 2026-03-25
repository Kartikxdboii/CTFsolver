"""
Central configuration for the CTF Agent.

Loads settings from environment variables / .env file, and defines
constants used across the agent.
"""

import os
import re
from pathlib import Path
from dotenv import load_dotenv

# ── Load .env ──────────────────────────────────────────────────────────────
load_dotenv()

# ── Paths ──────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
CHALLENGES_DIR = PROJECT_ROOT / "challenges"
REPORTS_DIR = PROJECT_ROOT / "reports"
WORDLISTS_DIR = PROJECT_ROOT / "wordlists"
WORK_DIR = PROJECT_ROOT / "workdir"          # temp extraction / analysis

for _d in (CHALLENGES_DIR, REPORTS_DIR, WORDLISTS_DIR, WORK_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# ── LLM (Anthropic Claude) ─────────────────────────────────────────────────
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
LLM_MODEL = os.getenv("LLM_MODEL", "claude-sonnet-4-20250514")
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.2"))
LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "4096"))

# ── Flag Format ────────────────────────────────────────────────────────────
DEFAULT_FLAG_PATTERN = os.getenv("CTF_FLAG_FORMAT", r"flag\{.*?\}")
FLAG_PATTERNS = [
    DEFAULT_FLAG_PATTERN,
    r"CTF\{.*?\}",
    r"ctf\{.*?\}",
    r"FLAG\{.*?\}",
    r"picoCTF\{.*?\}",
    r"HTB\{.*?\}",
    r"FLAG-[a-zA-Z0-9\-]+",
    r"[a-f0-9]{32}",                         # md5
]
COMPILED_FLAG_PATTERNS = [re.compile(p, re.DOTALL) for p in FLAG_PATTERNS]

# ── Tool Execution ─────────────────────────────────────────────────────────
TOOL_TIMEOUT = int(os.getenv("CTF_TIMEOUT", "120"))         # seconds
MAX_OUTPUT_SIZE = 1024 * 512                                 # 512 KB

# ── External Tool Paths (override via env) ─────────────────────────────────
GHIDRA_PATH = os.getenv("GHIDRA_PATH", "analyzeHeadless")
VOLATILITY_PATH = os.getenv("VOLATILITY_PATH", "vol.py")

# ── Agent Behaviour ────────────────────────────────────────────────────────
VERBOSE = os.getenv("CTF_VERBOSE", "false").lower() == "true"
MAX_STRATEGIES_PER_SOLVER = 20   # give up after N strategies in one solver

# ── Categories ─────────────────────────────────────────────────────────────
CATEGORIES = [
    "crypto",
    "web",
    "forensics",
    "reversing",
    "pwn",
    "stego",
    "misc",
    "osint",
]
