"""
Challenge Analyzer — detects file types, parses descriptions,
and classifies challenges into CTF categories.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from agent import tools
from agent.config import VERBOSE
from agent import llm


@dataclass
class ChallengeInfo:
    """All information gathered about a challenge."""
    path: Optional[Path] = None
    url: Optional[str] = None
    description: str = ""
    file_type: str = ""
    file_extension: str = ""
    strings_sample: str = ""
    category: str = "misc"
    confidence: float = 0.0
    reasoning: str = ""

    @property
    def name(self) -> str:
        if self.path:
            return self.path.stem
        if self.url:
            return self.url.split("/")[-1] or "web_challenge"
        return "unknown_challenge"

    @property
    def is_file(self) -> bool:
        return self.path is not None and self.path.exists()

    @property
    def is_url(self) -> bool:
        return self.url is not None


# ── Keyword heuristics ────────────────────────────────────────────────────

_KEYWORD_MAP: dict[str, list[str]] = {
    "crypto": [
        "rsa", "aes", "cipher", "encrypt", "decrypt", "key", "modulus",
        "base64", "xor", "hash", "md5", "sha", "caesar", "vigenere",
        "diffie", "elliptic", "prime", "modular",
    ],
    "web": [
        "http", "url", "cookie", "session", "sql", "injection", "xss",
        "csrf", "jwt", "api", "login", "admin", "php", "html", "javascript",
        "robots.txt", "directory", "lfi", "rfi", "ssrf",
    ],
    "forensics": [
        "pcap", "wireshark", "capture", "disk", "image", "memory",
        "volatility", "autopsy", "carve", "recover", "deleted", "exif",
        "metadata", "network", "packet",
    ],
    "reversing": [
        "reverse", "binary", "elf", "pe", "exe", "decompile",
        "disassemble", "assembly", "ghidra", "ida", "radare",
        "obfuscated", "packed", "upx",
    ],
    "pwn": [
        "buffer", "overflow", "exploit", "shellcode", "rop", "stack",
        "heap", "format string", "bof", "ret2", "libc", "canary",
        "nx", "aslr", "pwntools",
    ],
    "stego": [
        "steg", "hidden", "lsb", "pixel", "image", "audio",
        "spectrogram", "steghide", "zsteg", "embed", "watermark",
    ],
    "misc": [
        "osint", "trivia", "qr", "barcode", "esoteric", "brainfuck",
        "whitespace", "piet", "malbolge",
    ],
}

# file extension → likely category
_EXT_MAP: dict[str, str] = {
    ".pcap": "forensics",
    ".pcapng": "forensics",
    ".cap": "forensics",
    ".mem": "forensics",
    ".raw": "forensics",
    ".img": "forensics",
    ".dd": "forensics",
    ".E01": "forensics",
    ".png": "stego",
    ".jpg": "stego",
    ".jpeg": "stego",
    ".bmp": "stego",
    ".gif": "stego",
    ".wav": "stego",
    ".mp3": "stego",
    ".flac": "stego",
    ".elf": "reversing",
    ".exe": "reversing",
    ".dll": "reversing",
    ".so": "reversing",
    ".class": "reversing",
    ".jar": "reversing",
    ".apk": "reversing",
    ".py": "crypto",
    ".sage": "crypto",
    ".pem": "crypto",
    ".pub": "crypto",
    ".php": "web",
    ".html": "web",
    ".js": "web",
}


def _keyword_score(text: str) -> dict[str, float]:
    """Score each category based on keyword frequency in text."""
    text_lower = text.lower()
    scores: dict[str, float] = {}
    for category, keywords in _KEYWORD_MAP.items():
        hits = sum(1 for kw in keywords if kw in text_lower)
        scores[category] = hits / len(keywords) if keywords else 0
    return scores


def analyze(
    path: Optional[str | Path] = None,
    url: Optional[str] = None,
    description: str = "",
) -> ChallengeInfo:
    """
    Analyze a challenge from a file path, URL, or text description.

    Returns a ChallengeInfo with category classification.
    """
    info = ChallengeInfo(
        path=Path(path) if path else None,
        url=url,
        description=description,
    )

    all_text = description

    # ── File-based analysis ────────────────────────────────────────────
    if info.is_file:
        info.file_extension = info.path.suffix.lower()

        # `file` command
        result = tools.run("file", [str(info.path)])
        if result.success:
            info.file_type = result.stdout.strip()
            all_text += f"\n{info.file_type}"

        # `strings` sample
        result = tools.run("strings", [str(info.path)])
        if result.success:
            lines = result.stdout.split("\n")[:80]
            info.strings_sample = "\n".join(lines)
            all_text += f"\n{info.strings_sample}"

        # Extension heuristic
        if info.file_extension in _EXT_MAP:
            info.category = _EXT_MAP[info.file_extension]
            info.confidence = 0.6
            info.reasoning = f"Extension '{info.file_extension}' maps to {info.category}"

    # ── URL-based analysis ─────────────────────────────────────────────
    if info.is_url:
        info.category = "web"
        info.confidence = 0.7
        info.reasoning = "Target is a URL → web challenge"

    # ── Keyword scoring ────────────────────────────────────────────────
    if all_text:
        scores = _keyword_score(all_text)
        best_cat = max(scores, key=scores.get)
        best_score = scores[best_cat]

        if best_score > info.confidence:
            info.category = best_cat
            info.confidence = min(best_score + 0.4, 0.85)
            info.reasoning = f"Keyword analysis: highest score for {best_cat}"

    # ── LLM classification (for ambiguous cases) ───────────────────────
    if info.confidence < 0.7 and all_text:
        try:
            llm_result = llm.classify_challenge(
                description=all_text,
                file_info=info.file_type,
                strings_sample=info.strings_sample[:2000],
            )
            llm_conf = float(llm_result.get("confidence", 0))
            if llm_conf > info.confidence:
                info.category = llm_result.get("category", info.category)
                info.confidence = llm_conf
                info.reasoning = llm_result.get("reasoning", "LLM classification")
        except Exception as exc:
            if VERBOSE:
                print(f"  [WARN] LLM classification failed: {exc}")

    if VERBOSE:
        print(
            f"  [ANALYZER] {info.name} → {info.category} "
            f"(confidence={info.confidence:.2f})"
        )

    return info
