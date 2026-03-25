"""
Steganography Solver — image/audio hidden data extraction.

Strategies:
  1. strings_grep       — basic strings search
  2. exif_metadata      — look for flags in EXIF data
  3. zsteg_lsb          — PNG/BMP LSB steganography
  4. steghide_extract   — JPEG/WAV steghide with common passwords
  5. lsb_manual         — manual LSB extraction via Pillow
  6. file_appended      — check for data appended after file end
  7. audio_spectrogram  — audio spectrogram analysis (sox/ffmpeg)
  8. llm_stego          — LLM analysis
"""

from __future__ import annotations

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


class StegoSolver(BaseSolver):

    @property
    def strategies(self) -> list[tuple[str, Callable]]:
        return [
            ("strings_grep",        self._strings_grep),
            ("exif_metadata",       self._exif_metadata),
            ("zsteg_lsb",           self._zsteg),
            ("steghide_extract",    self._steghide),
            ("lsb_manual",          self._lsb_manual),
            ("file_appended_data",  self._appended_data),
            ("png_chunks",          self._png_chunks),
            ("audio_spectrogram",   self._audio_spectrogram),
            ("llm_stego",           self._llm_stego),
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
            report.log("solve", "Flag found in strings", detail=flags[0])
            return SolveResult(flag=flags[0])

        return SolveResult(artifacts={"strings": result.stdout[:2000]})

    def _exif_metadata(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        if not info.is_file:
            return None

        result = tools.run("exiftool", [str(info.path)])
        if not result.success:
            return None

        flags = find_flags(result.stdout)
        if flags:
            report.log("solve", "Flag found in EXIF/metadata")
            return SolveResult(flag=flags[0])

        return SolveResult(artifacts={"exiftool": result.stdout})

    def _zsteg(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        if not info.is_file:
            return None

        ext = info.file_extension
        if ext not in (".png", ".bmp"):
            return None

        result = tools.run("zsteg", [str(info.path)])
        if not result.success:
            return None

        flags = find_flags(result.stdout)
        if flags:
            report.log("solve", "Flag found via zsteg LSB analysis")
            return SolveResult(flag=flags[0])

        # Also try specific channels
        for channel in ["b1,rgb,lsb,xy", "b1,r,lsb,xy", "b1,bgr,lsb,xy",
                        "b2,rgb,lsb,xy", "b1,rgba,lsb,xy"]:
            result = tools.run("zsteg", [str(info.path), channel])
            if result.success:
                flags = find_flags(result.stdout)
                if flags:
                    report.log("solve", f"Flag found via zsteg ({channel})")
                    return SolveResult(flag=flags[0])

        return None

    def _steghide(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        if not info.is_file:
            return None

        ext = info.file_extension
        if ext not in (".jpg", ".jpeg", ".bmp", ".wav", ".au"):
            return None

        workdir = self._work_dir(info)
        out_file = workdir / "steghide_out.txt"

        # Try empty password first, then common ones
        passwords = ["", "password", "123456", "secret", "flag", "ctf",
                      "admin", "stego", "hidden"]

        for pwd in passwords:
            result = tools.run("steghide", [
                "extract", "-sf", str(info.path),
                "-p", pwd,
                "-xf", str(out_file),
                "-f",
            ])

            if result.success and out_file.exists():
                content = out_file.read_text(errors="replace")
                flags = find_flags(content)
                if flags:
                    pwd_display = pwd if pwd else "(empty)"
                    report.log("solve",
                               f"steghide extracted flag (password='{pwd_display}')")
                    return SolveResult(flag=flags[0])

                # Also check if extracted file itself has flags
                flags = find_flags(result.stdout + result.stderr)
                if flags:
                    return SolveResult(flag=flags[0])

        return None

    def _lsb_manual(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        """Manually extract LSB data from image pixels using Pillow."""
        if not info.is_file:
            return None

        ext = info.file_extension
        if ext not in (".png", ".bmp", ".gif"):
            return None

        try:
            from PIL import Image
        except ImportError:
            report.log("solve", "Pillow not installed", success=False)
            return None

        try:
            img = Image.open(info.path)
            pixels = list(img.getdata())
        except Exception:
            return None

        # Extract LSB from each channel
        bits = []
        for pixel in pixels[:8192]:  # limit to prevent huge output
            if isinstance(pixel, (tuple, list)):
                for channel in pixel[:3]:  # RGB
                    bits.append(str(channel & 1))
            else:
                bits.append(str(pixel & 1))

        # Convert bits to bytes
        bit_string = "".join(bits)
        chars = []
        for i in range(0, len(bit_string) - 7, 8):
            byte = int(bit_string[i:i+8], 2)
            if 0x20 <= byte <= 0x7e or byte in (0x0a, 0x0d):
                chars.append(chr(byte))
            elif byte == 0x00:
                break

        text = "".join(chars)
        flags = find_flags(text)
        if flags:
            report.log("solve", "Flag found via manual LSB extraction")
            return SolveResult(flag=flags[0])

        return None

    def _appended_data(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        """Check for data appended after the official end of an image file."""
        if not info.is_file:
            return None

        data = self._read_file(info.path)
        if not data:
            return None

        extra = b""

        # PNG: ends with IEND chunk
        if info.file_extension == ".png":
            iend = data.find(b"IEND")
            if iend > 0:
                # IEND chunk = length(4) + "IEND"(4) + CRC(4)
                end_pos = iend + 8  # after "IEND" + CRC
                extra = data[end_pos:]

        # JPEG: ends with FFD9
        elif info.file_extension in (".jpg", ".jpeg"):
            ffd9 = data.rfind(b"\xff\xd9")
            if ffd9 > 0:
                extra = data[ffd9 + 2:]

        if extra and len(extra) > 2:
            text = extra.decode("latin-1")
            flags = find_flags(text)
            if flags:
                report.log("solve", "Flag found in appended data after image EOF")
                return SolveResult(flag=flags[0])

            # Also try interpreting as another file
            workdir = self._work_dir(info)
            hidden_path = workdir / "appended_data"
            hidden_path.write_bytes(extra)
            report.log("solve", f"Found {len(extra)} bytes appended after EOF",
                       detail=text[:200])

        return None

    def _png_chunks(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        """Inspect PNG chunks for hidden data (tEXt, zTXt, iTXt, etc)."""
        if not info.is_file or info.file_extension != ".png":
            return None

        data = self._read_file(info.path)
        if not data or not data.startswith(b"\x89PNG"):
            return None

        offset = 8  # skip PNG signature
        all_text = ""

        while offset < len(data) - 8:
            try:
                length = struct.unpack(">I", data[offset:offset+4])[0]
                chunk_type = data[offset+4:offset+8].decode("ascii", errors="replace")
                chunk_data = data[offset+8:offset+8+length]

                if chunk_type in ("tEXt", "zTXt", "iTXt"):
                    text = chunk_data.decode("latin-1")
                    all_text += text + "\n"

                offset += 12 + length  # length + type + data + CRC
            except Exception:
                break

        flags = find_flags(all_text)
        if flags:
            report.log("solve", "Flag found in PNG text chunks")
            return SolveResult(flag=flags[0])

        return None

    def _audio_spectrogram(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        """Generate spectrogram from audio — flag may be visual."""
        if not info.is_file:
            return None

        ext = info.file_extension
        if ext not in (".wav", ".mp3", ".flac", ".ogg"):
            return None

        workdir = self._work_dir(info)
        spectrogram_path = workdir / "spectrogram.png"

        # Try sox
        result = tools.run("sox", [
            str(info.path), "-n", "spectrogram",
            "-o", str(spectrogram_path),
        ])

        if result.success and spectrogram_path.exists():
            report.log("solve",
                       f"Spectrogram saved to {spectrogram_path}. "
                       "Visual inspection may be needed.",
                       success=False)

        # Also run strings on the audio file
        result = tools.run("strings", [str(info.path)])
        if result.success:
            flags = find_flags(result.stdout)
            if flags:
                report.log("solve", "Flag found in audio file strings")
                return SolveResult(flag=flags[0])

        return None

    def _llm_stego(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        context_parts = [
            f"Challenge: {info.name}",
            f"File type: {info.file_type}",
            f"Extension: {info.file_extension}",
        ]
        if info.strings_sample:
            context_parts.append(f"Strings:\n{info.strings_sample[:1500]}")

        try:
            response = llm_engine.solve_puzzle(
                "This is a steganography CTF challenge. Analyze and suggest "
                "what technique was used to hide data.",
                context="\n".join(context_parts),
            )
            flags = find_flags(response)
            if flags:
                report.log("solve", "LLM found the flag")
                return SolveResult(flag=flags[0])
            report.log("solve", "LLM stego analysis",
                       detail=response[:500], success=False)
        except Exception as exc:
            report.log("solve", f"LLM failed: {exc}", success=False)

        return None
