"""
Reverse Engineering Solver — static analysis, decompilation,
symbolic execution.

Strategies:
  1. strings_grep      — strings + flag grep
  2. file_info         — file type and architecture info
  3. ltrace_strace     — dynamic tracing (Linux only)
  4. objdump_disasm    — disassembly with objdump
  5. radare2_analysis  — r2 automated analysis
  6. angr_symbolic     — symbolic execution with angr
  7. python_decompile  — decompile .pyc files
  8. dotnet_decompile  — decompile .NET assemblies
  9. llm_reversing     — LLM code analysis
"""

from __future__ import annotations

import dis
import marshal
import struct
import sys
from pathlib import Path
from typing import Optional, Callable

from agent.solvers.base import BaseSolver, SolveResult
from agent.analyzer import ChallengeInfo
from agent.reporter import SolveReport
from agent.validator import find_flags
from agent.config import WORK_DIR
from agent import tools
from agent import llm as llm_engine


class ReversingSOlver(BaseSolver):

    @property
    def strategies(self) -> list[tuple[str, Callable]]:
        return [
            ("strings_grep",     self._strings_grep),
            ("file_info",        self._file_info),
            ("objdump_disasm",   self._objdump_disasm),
            ("radare2_analysis", self._radare2),
            ("python_decompile", self._python_decompile),
            ("angr_symbolic",    self._angr_symbolic),
            ("run_binary",       self._run_binary),
            ("llm_reversing",    self._llm_reversing),
        ]

    # ── Strategies ─────────────────────────────────────────────────────

    def _strings_grep(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        if not info.is_file:
            return None

        result = tools.run("strings", [str(info.path)])
        if not result.success:
            return None

        flags = find_flags(result.stdout)
        if flags:
            report.log("solve", "Flag found in strings")
            return SolveResult(flag=flags[0])

        # Look for interesting strings (hints)
        interesting = []
        for line in result.stdout.split("\n"):
            line = line.strip()
            if any(kw in line.lower() for kw in
                   ["password", "correct", "wrong", "flag", "secret",
                    "check", "compare", "success"]):
                interesting.append(line)

        if interesting:
            report.log("solve", "Interesting strings found",
                       detail="\n".join(interesting[:20]))

        return SolveResult(artifacts={"strings": result.stdout[:3000]})

    def _file_info(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        if not info.is_file:
            return None

        result = tools.run("file", [str(info.path)])
        if result.success:
            report.log("solve", f"File type: {result.stdout.strip()}")

        return None

    def _objdump_disasm(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        if not info.is_file:
            return None

        # Disassemble
        result = tools.run("objdump", ["-d", "-M", "intel", str(info.path)])
        if not result.success:
            return None

        # Look for comparison with flag characters
        flags = find_flags(result.stdout)
        if flags:
            report.log("solve", "Flag found in disassembly")
            return SolveResult(flag=flags[0])

        # Look for hardcoded strings in .rodata
        result2 = tools.run("objdump", ["-s", "-j", ".rodata", str(info.path)])
        if result2.success:
            flags = find_flags(result2.stdout)
            if flags:
                report.log("solve", "Flag found in .rodata section")
                return SolveResult(flag=flags[0])

        return SolveResult(artifacts={"disasm": result.stdout[:3000]})

    def _radare2(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        if not info.is_file:
            return None

        # Automated r2 analysis
        commands = [
            "aaa",           # analyze all
            "afl",           # list functions
            "iz",            # strings in data sections
            "pdf @main",     # disassemble main
        ]

        r2_script = ";".join(commands)
        result = tools.run_raw(
            ["r2", "-q", "-c", r2_script, str(info.path)],
            timeout=60,
        )

        if not result.success:
            return None

        flags = find_flags(result.stdout)
        if flags:
            report.log("solve", "Flag found via r2 analysis")
            return SolveResult(flag=flags[0])

        return SolveResult(artifacts={"r2": result.stdout[:3000]})

    def _python_decompile(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        if not info.is_file:
            return None

        ext = info.file_extension
        if ext not in (".pyc", ".pyo"):
            return None

        try:
            data = info.path.read_bytes()

            # Skip magic number and metadata (varies by Python version)
            # Try multiple offsets
            for offset in [16, 12, 8]:
                try:
                    code = marshal.loads(data[offset:])
                    source = dis.Bytecode(code)
                    text = "\n".join(str(instr) for instr in source)

                    flags = find_flags(text)
                    if flags:
                        report.log("solve", "Flag found in decompiled .pyc")
                        return SolveResult(flag=flags[0])

                    # Look through constants
                    if hasattr(code, 'co_consts'):
                        for const in code.co_consts:
                            if isinstance(const, str):
                                flags = find_flags(const)
                                if flags:
                                    report.log("solve",
                                               "Flag in .pyc constants")
                                    return SolveResult(flag=flags[0])
                    break
                except Exception:
                    continue

        except Exception as exc:
            report.log("solve", f"Python decompile failed: {exc}",
                       success=False)

        return None

    def _angr_symbolic(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        if not info.is_file:
            return None

        # Only try on ELF binaries
        if "ELF" not in info.file_type:
            return None

        try:
            import angr
            import claripy
        except ImportError:
            report.log("solve", "angr not installed", success=False)
            return None

        try:
            proj = angr.Project(str(info.path), auto_load_libs=False)

            # Find "correct" / "success" addresses and "wrong" / "fail" addresses
            good_addrs = []
            bad_addrs = []

            cfg = proj.analyses.CFGFast()

            for func in cfg.kb.functions.values():
                name = func.name.lower() if func.name else ""
                if any(w in name for w in ["win", "correct", "success"]):
                    good_addrs.append(func.addr)
                elif any(w in name for w in ["fail", "wrong", "lose"]):
                    bad_addrs.append(func.addr)

            if not good_addrs:
                # Try to find by string references
                for s in proj.loader.main_object.sections:
                    if s.name == ".rodata":
                        data = proj.loader.memory.load(s.vaddr, s.memsize)
                        text = data.decode("latin-1")
                        if "correct" in text.lower() or "flag" in text.lower():
                            report.log("solve", "Found target strings in binary")

            if not good_addrs:
                report.log("solve", "angr: couldn't find target addresses",
                           success=False)
                return None

            # Run symbolic execution
            state = proj.factory.entry_state()
            simgr = proj.factory.simulation_manager(state)

            simgr.explore(
                find=good_addrs,
                avoid=bad_addrs,
                timeout=60,
            )

            if simgr.found:
                found_state = simgr.found[0]
                output = found_state.posix.dumps(1).decode("latin-1")
                stdin = found_state.posix.dumps(0).decode("latin-1")

                check_text = output + "\n" + stdin
                flags = find_flags(check_text)
                if flags:
                    report.log("solve", "angr found the flag!")
                    return SolveResult(flag=flags[0])

                report.log("solve",
                           f"angr reached target. stdin={stdin!r} stdout={output!r}",
                           detail=check_text)

        except Exception as exc:
            report.log("solve", f"angr failed: {exc}", success=False)

        return None

    def _run_binary(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        """Try running the binary with various inputs."""
        if not info.is_file:
            return None

        if "ELF" not in info.file_type and "executable" not in info.file_type:
            return None

        # Try running with no input
        result = tools.run_raw(
            [str(info.path)],
            timeout=10,
            stdin_data=b"\n",
        )

        if result.success:
            flags = find_flags(result.output)
            if flags:
                report.log("solve", "Flag from running binary")
                return SolveResult(flag=flags[0])

        return None

    def _llm_reversing(
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
                "This is a reverse engineering CTF challenge. "
                "Analyze the available information and determine the flag.",
                context="\n".join(context_parts),
            )
            flags = find_flags(response)
            if flags:
                report.log("solve", "LLM found the flag")
                return SolveResult(flag=flags[0])
            report.log("solve", "LLM reversing analysis",
                       detail=response[:500], success=False)
        except Exception as exc:
            report.log("solve", f"LLM failed: {exc}", success=False)

        return None
