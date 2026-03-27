"""
Tool Manager — safe subprocess execution of external CLI tools.

Each tool is registered with its command name and optional availability
check.  Execution is wrapped with timeouts and output-size limits.
"""

import shutil
import subprocess
import platform
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path

from agent.config import TOOL_TIMEOUT, MAX_OUTPUT_SIZE, VERBOSE


@dataclass
class ToolResult:
    """Result of an external tool invocation."""
    tool: str
    command: str
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    available: bool = True

    @property
    def success(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    @property
    def output(self) -> str:
        """Combined stdout + stderr."""
        parts = []
        if self.stdout:
            parts.append(self.stdout)
        if self.stderr:
            parts.append(self.stderr)
        return "\n".join(parts)


@dataclass
class ToolInfo:
    """Metadata about a registered tool."""
    name: str
    command: str
    check_args: list = field(default_factory=lambda: ["--version"])
    description: str = ""


# ── Global tool registry ──────────────────────────────────────────────────
_REGISTRY: dict[str, ToolInfo] = {}


def register(name: str, command: str,
             check_args: list | None = None,
             description: str = "") -> None:
    """Register a tool so the agent can discover and use it."""
    _REGISTRY[name] = ToolInfo(
        name=name,
        command=command,
        check_args=check_args or ["--version"],
        description=description,
    )


def is_available(name: str) -> bool:
    """Check whether a tool is installed and reachable on PATH or via WSL."""
    info = _REGISTRY.get(name)
    if info is None:
        return False
        
    # 1. Check native Windows/Linux PATH
    if shutil.which(info.command) is not None:
        return True
        
    # 2. Check WSL fallback on Windows
    if platform.system() == "Windows":
        try:
            # Check if command exists in WSL (returns 0 if found)
            proc = subprocess.run(
                ["wsl", "which", info.command],
                capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return proc.returncode == 0
        except FileNotFoundError:
            pass
            
    return False


def list_tools() -> dict[str, bool]:
    """Return {tool_name: available} for every registered tool."""
    return {name: is_available(name) for name in _REGISTRY}


def run(
    name: str,
    args: list[str],
    *,
    cwd: Optional[Path] = None,
    timeout: Optional[int] = None,
    stdin_data: Optional[bytes] = None,
) -> ToolResult:
    """
    Execute a registered tool with the given arguments.
    Routes through WSL automatically on Windows if necessary.

    Returns a ToolResult with captured stdout/stderr, truncated
    to MAX_OUTPUT_SIZE to avoid memory issues.
    """
    info = _REGISTRY.get(name)
    if info is None:
        return ToolResult(
            tool=name, command=name, returncode=-1,
            stdout="", stderr=f"Tool '{name}' is not registered.",
            available=False,
        )

    if not is_available(name):
        return ToolResult(
            tool=name, command=info.command, returncode=-1,
            stdout="", stderr=f"Tool '{name}' ({info.command}) not found on PATH or WSL.",
            available=False,
        )

    # Determine command array (native vs WSL)
    cmd = [info.command] + args
    
    if platform.system() == "Windows" and shutil.which(info.command) is None:
        # Route through WSL. WSL automatically translates Windows paths 
        # in the working directory to /mnt/c/... for the Linux environment.
        cmd = ["wsl"] + cmd
    cmd_str = " ".join(cmd)
    _timeout = timeout or TOOL_TIMEOUT

    if VERBOSE:
        print(f"  [TOOL] {cmd_str}")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=_timeout,
            cwd=cwd,
            input=stdin_data,
        )
        stdout = proc.stdout.decode("utf-8", errors="replace")[:MAX_OUTPUT_SIZE]
        stderr = proc.stderr.decode("utf-8", errors="replace")[:MAX_OUTPUT_SIZE]
        return ToolResult(
            tool=name, command=cmd_str,
            returncode=proc.returncode,
            stdout=stdout, stderr=stderr,
        )
    except subprocess.TimeoutExpired:
        return ToolResult(
            tool=name, command=cmd_str,
            returncode=-1, stdout="", stderr="Timed out.",
            timed_out=True,
        )
    except Exception as exc:
        return ToolResult(
            tool=name, command=cmd_str,
            returncode=-1, stdout="", stderr=str(exc),
        )


def run_raw(
    command: list[str],
    *,
    cwd: Optional[Path] = None,
    timeout: Optional[int] = None,
    stdin_data: Optional[bytes] = None,
) -> ToolResult:
    """Execute an arbitrary command (not necessarily registered)."""
    cmd_str = " ".join(command)
    _timeout = timeout or TOOL_TIMEOUT

    if VERBOSE:
        print(f"  [RAW] {cmd_str}")

    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            timeout=_timeout,
            cwd=cwd,
            input=stdin_data,
            shell=(platform.system() == "Windows"),
        )
        stdout = proc.stdout.decode("utf-8", errors="replace")[:MAX_OUTPUT_SIZE]
        stderr = proc.stderr.decode("utf-8", errors="replace")[:MAX_OUTPUT_SIZE]
        return ToolResult(
            tool=command[0], command=cmd_str,
            returncode=proc.returncode,
            stdout=stdout, stderr=stderr,
        )
    except subprocess.TimeoutExpired:
        return ToolResult(
            tool=command[0], command=cmd_str,
            returncode=-1, stdout="", stderr="Timed out.",
            timed_out=True,
        )
    except Exception as exc:
        return ToolResult(
            tool=command[0], command=cmd_str,
            returncode=-1, stdout="", stderr=str(exc),
        )


# ── Register common CTF tools ─────────────────────────────────────────────
_TOOLS = [
    ("file",       "file",          ["--version"],    "file-type identification"),
    ("strings",    "strings",       ["--version"],    "printable string extraction"),
    ("binwalk",    "binwalk",       ["--help"],       "firmware / file analysis"),
    ("foremost",   "foremost",      ["-h"],           "file carving"),
    ("exiftool",   "exiftool",      ["-ver"],         "metadata extraction"),
    ("steghide",   "steghide",      ["--help"],       "steganography embed/extract"),
    ("zsteg",      "zsteg",         ["--help"],       "PNG/BMP LSB steganography"),
    ("tshark",     "tshark",        ["--version"],    "packet capture analysis"),
    ("nmap",       "nmap",          ["--version"],    "network scanner"),
    ("gobuster",   "gobuster",      ["--help"],       "directory brute-force"),
    ("ffuf",       "ffuf",          ["-V"],           "web fuzzer"),
    ("sqlmap",     "sqlmap",        ["--version"],    "SQL injection"),
    ("john",       "john",          ["--help"],       "password cracker"),
    ("hashcat",    "hashcat",       ["--version"],    "GPU password cracker"),
    ("gdb",        "gdb",           ["--version"],    "debugger"),
    ("objdump",    "objdump",       ["--version"],    "disassembler"),
    ("radare2",    "r2",            ["-v"],           "reverse engineering"),
    ("volatility", "vol.py",        ["--help"],       "memory forensics"),
    ("sox",        "sox",           ["--version"],    "audio processing"),
    ("ffmpeg",     "ffmpeg",        ["-version"],     "media processing"),
    ("python3",    "python",        ["--version"],    "Python interpreter"),
]

for _name, _cmd, _check, _desc in _TOOLS:
    register(_name, _cmd, _check, _desc)
