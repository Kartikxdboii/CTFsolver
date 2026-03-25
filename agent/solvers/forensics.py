"""
Forensics Solver — file carving, PCAP analysis, metadata extraction.

Strategies:
  1. strings_grep       — run `strings` and grep for flags
  2. file_metadata      — exiftool metadata extraction
  3. binwalk_extract    — binwalk firmware / embedded file extraction
  4. foremost_carve     — file carving with foremost
  5. pcap_analysis      — extract data from packet captures
  6. zip_crack          — brute-force password-protected ZIPs
  7. embedded_files     — look for files within files
  8. llm_forensics      — ask LLM for guidance
"""

from __future__ import annotations

import os
import zipfile
import shutil
from pathlib import Path
from typing import Optional, Callable

from agent.solvers.base import BaseSolver, SolveResult
from agent.analyzer import ChallengeInfo
from agent.reporter import SolveReport
from agent.validator import find_flags
from agent.config import WORK_DIR
from agent import tools
from agent import llm as llm_engine


class ForensicsSolver(BaseSolver):

    @property
    def strategies(self) -> list[tuple[str, Callable]]:
        return [
            ("strings_grep",    self._strings_grep),
            ("file_metadata",   self._file_metadata),
            ("binwalk_extract", self._binwalk_extract),
            ("foremost_carve",  self._foremost_carve),
            ("pcap_strings",    self._pcap_strings),
            ("pcap_tshark",     self._pcap_tshark),
            ("zip_inspect",     self._zip_inspect),
            ("hex_dump_scan",   self._hex_dump_scan),
            ("llm_forensics",   self._llm_forensics),
        ]

    def _work_dir(self, info: ChallengeInfo) -> Path:
        d = WORK_DIR / info.name
        d.mkdir(parents=True, exist_ok=True)
        return d

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
            report.log("solve", "Flag found in strings output",
                       detail=result.stdout[:500])
            return SolveResult(flag=flags[0], partial_flags=flags[1:])

        report.log("solve", "strings: no flag in output", success=False)
        return SolveResult(artifacts={"strings": result.stdout})

    def _file_metadata(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        if not info.is_file:
            return None

        result = tools.run("exiftool", [str(info.path)])
        if not result.success:
            return None

        flags = find_flags(result.stdout)
        if flags:
            report.log("solve", "Flag found in EXIF metadata",
                       detail=result.stdout[:500])
            return SolveResult(flag=flags[0])

        report.log("solve", "exiftool: no flag in metadata", success=False)
        return SolveResult(artifacts={"exiftool": result.stdout})

    def _binwalk_extract(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        if not info.is_file:
            return None

        workdir = self._work_dir(info)
        extract_dir = workdir / "binwalk_out"

        result = tools.run("binwalk", [
            "-e", "--directory", str(extract_dir), str(info.path)
        ])

        if not result.success:
            report.log("solve", "binwalk extraction failed", success=False)
            return None

        # Scan all extracted files for flags
        all_text = result.stdout + "\n"
        if extract_dir.exists():
            for root, dirs, files in os.walk(extract_dir):
                for fname in files:
                    fpath = Path(root) / fname
                    try:
                        content = fpath.read_text(errors="replace")
                        all_text += content + "\n"
                    except Exception:
                        pass

        flags = find_flags(all_text)
        if flags:
            report.log("solve", "Flag found in binwalk-extracted files",
                       detail=f"Files extracted to {extract_dir}")
            return SolveResult(flag=flags[0], partial_flags=flags[1:])

        return SolveResult(artifacts={"binwalk": all_text[:2000]})

    def _foremost_carve(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        if not info.is_file:
            return None

        workdir = self._work_dir(info)
        out_dir = workdir / "foremost_out"

        result = tools.run("foremost", [
            "-i", str(info.path), "-o", str(out_dir)
        ])

        if not result.success:
            return None

        # Scan carved files
        all_text = ""
        if out_dir.exists():
            for root, dirs, files in os.walk(out_dir):
                for fname in files:
                    fpath = Path(root) / fname
                    try:
                        content = fpath.read_text(errors="replace")
                        all_text += content + "\n"
                    except Exception:
                        pass

        flags = find_flags(all_text)
        if flags:
            report.log("solve", "Flag found in foremost-carved files")
            return SolveResult(flag=flags[0])

        return None

    def _pcap_strings(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        if not info.is_file:
            return None

        ext = info.file_extension
        if ext not in (".pcap", ".pcapng", ".cap"):
            return None

        result = tools.run("strings", [str(info.path)])
        if not result.success:
            return None

        flags = find_flags(result.stdout)
        if flags:
            report.log("solve", "Flag found in PCAP strings")
            return SolveResult(flag=flags[0])

        return SolveResult(artifacts={"pcap_strings": result.stdout[:3000]})

    def _pcap_tshark(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        if not info.is_file:
            return None

        ext = info.file_extension
        if ext not in (".pcap", ".pcapng", ".cap"):
            return None

        # Extract HTTP data
        for filter_expr in [
            "http.request.uri",
            "http.response.body",
            "tcp.payload",
            "data.text",
        ]:
            result = tools.run("tshark", [
                "-r", str(info.path),
                "-T", "fields",
                "-e", filter_expr,
            ])
            if result.success and result.stdout.strip():
                flags = find_flags(result.stdout)
                if flags:
                    report.log("solve", f"Flag found via tshark ({filter_expr})")
                    return SolveResult(flag=flags[0])

        # Follow TCP streams
        result = tools.run("tshark", [
            "-r", str(info.path),
            "-z", "follow,tcp,ascii,0",
            "-q",
        ])
        if result.success:
            flags = find_flags(result.stdout)
            if flags:
                report.log("solve", "Flag found in TCP stream")
                return SolveResult(flag=flags[0])

        return None

    def _zip_inspect(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        if not info.is_file:
            return None

        try:
            if not zipfile.is_zipfile(info.path):
                return None
        except Exception:
            return None

        workdir = self._work_dir(info)

        try:
            with zipfile.ZipFile(info.path) as zf:
                # Try extracting without password
                try:
                    zf.extractall(workdir / "zip_out")
                except RuntimeError:
                    # Password protected — try common passwords
                    passwords = [
                        b"", b"password", b"123456", b"admin",
                        b"flag", b"ctf", b"secret", b"test",
                    ]
                    for pwd in passwords:
                        try:
                            zf.extractall(workdir / "zip_out", pwd=pwd)
                            report.log("solve", f"ZIP cracked with password: {pwd}")
                            break
                        except RuntimeError:
                            continue
                    else:
                        report.log("solve", "ZIP is password-protected, "
                                   "common passwords failed", success=False)
                        return None

                # Scan extracted files
                extract_path = workdir / "zip_out"
                if extract_path.exists():
                    all_text = ""
                    for root, dirs, files in os.walk(extract_path):
                        for fname in files:
                            fpath = Path(root) / fname
                            try:
                                content = fpath.read_text(errors="replace")
                                all_text += content + "\n"
                            except Exception:
                                pass

                    flags = find_flags(all_text)
                    if flags:
                        report.log("solve", "Flag found in ZIP contents")
                        return SolveResult(flag=flags[0])

        except Exception as exc:
            report.log("solve", f"ZIP inspection failed: {exc}", success=False)

        return None

    def _hex_dump_scan(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        """Read file as raw bytes and search for flag patterns."""
        if not info.is_file:
            return None

        data = self._read_file(info.path)
        if not data:
            return None

        # Decode as latin-1 (preserves all bytes) and search
        text = data.decode("latin-1")
        flags = find_flags(text)
        if flags:
            report.log("solve", "Flag found in raw binary data")
            return SolveResult(flag=flags[0])

        return None

    def _llm_forensics(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        context_parts = [
            f"Challenge: {info.name}",
            f"File type: {info.file_type}",
            f"Extension: {info.file_extension}",
        ]
        if info.strings_sample:
            context_parts.append(f"Strings sample:\n{info.strings_sample[:2000]}")

        try:
            response = llm_engine.solve_puzzle(
                "This is a forensics CTF challenge. "
                "Analyze the information and suggest what the flag might be "
                "or what additional steps to take.",
                context="\n".join(context_parts),
            )
            flags = find_flags(response)
            if flags:
                report.log("solve", "LLM found the flag")
                return SolveResult(flag=flags[0])
            report.log("solve", "LLM analysis (no flag)",
                       detail=response[:500], success=False)
        except Exception as exc:
            report.log("solve", f"LLM failed: {exc}", success=False)

        return None
