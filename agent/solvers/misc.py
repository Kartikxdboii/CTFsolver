"""
Misc / OSINT Solver — encoding chains, esoteric languages, QR codes.

Strategies:
  1. encoding_chains    — try all encoding combos
  2. qr_code_decode     — decode QR codes from images
  3. esoteric_langs     — brainfuck, whitespace, etc.
  4. morse_code         — morse code decode
  5. binary_to_text     — binary string → ASCII
  6. base_variants      — base58, base62, etc.
  7. llm_misc           — LLM general solve
"""

from __future__ import annotations

import base64
import re
from typing import Optional, Callable

from agent.solvers.base import BaseSolver, SolveResult
from agent.analyzer import ChallengeInfo
from agent.reporter import SolveReport
from agent.validator import find_flags
from agent import llm as llm_engine


class MiscSolver(BaseSolver):

    @property
    def strategies(self) -> list[tuple[str, Callable]]:
        return [
            ("encoding_chains",   self._encoding_chains),
            ("qr_code_decode",    self._qr_decode),
            ("morse_code",        self._morse_code),
            ("binary_to_text",    self._binary_to_text),
            ("esoteric_langs",    self._esoteric),
            ("number_to_chars",   self._number_to_chars),
            ("reverse_string",    self._reverse_string),
            ("llm_misc",          self._llm_misc),
        ]

    def _get_data(self, info: ChallengeInfo) -> str:
        if info.is_file:
            return self._read_text(info.path)
        return info.description

    # ── Strategies ─────────────────────────────────────────────────────

    def _encoding_chains(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        data = self._get_data(info).strip()
        if not data:
            return None

        decoders = {
            "base64": lambda d: base64.b64decode(d).decode("utf-8", errors="replace"),
            "base32": lambda d: base64.b32decode(d).decode("utf-8", errors="replace"),
            "base85": lambda d: base64.b85decode(d).decode("utf-8", errors="replace"),
            "hex":    lambda d: bytes.fromhex(d.replace(" ", "").replace("\n", "")).decode("utf-8", errors="replace"),
            "url":    lambda d: __import__("urllib.parse", fromlist=["unquote"]).unquote(d),
        }

        current = data
        for depth in range(8):
            decoded_any = False
            for name, decoder in decoders.items():
                try:
                    decoded = decoder(current.strip())
                    if decoded and decoded != current:
                        flags = find_flags(decoded)
                        if flags:
                            report.log("solve",
                                       f"Encoding chain (depth={depth+1}, {name})")
                            return SolveResult(flag=flags[0])
                        current = decoded
                        decoded_any = True
                        break
                except Exception:
                    continue

            if not decoded_any:
                break

        return None

    def _qr_decode(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        if not info.is_file:
            return None

        ext = info.file_extension
        if ext not in (".png", ".jpg", ".jpeg", ".bmp", ".gif"):
            return None

        try:
            from PIL import Image
            from pyzbar.pyzbar import decode
        except ImportError:
            report.log("solve", "pyzbar/Pillow not installed", success=False)
            return None

        try:
            img = Image.open(info.path)
            results = decode(img)

            for result in results:
                text = result.data.decode("utf-8", errors="replace")
                flags = find_flags(text)
                if flags:
                    report.log("solve", "Flag found in QR code")
                    return SolveResult(flag=flags[0])

                # The QR data itself might be the flag
                if text:
                    report.log("solve", f"QR data: {text}")
                    flags = find_flags(text)
                    if flags:
                        return SolveResult(flag=flags[0])

        except Exception as exc:
            report.log("solve", f"QR decode failed: {exc}", success=False)

        return None

    def _morse_code(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        data = self._get_data(info).strip()
        if not data:
            return None

        # Check if it looks like morse code
        if not re.match(r'^[\.\-\/ \n]+$', data):
            return None

        MORSE = {
            ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
            "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
            "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
            ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
            "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
            "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
            "...--": "3", "....-": "4", ".....": "5", "-....": "6",
            "--...": "7", "---..": "8", "----.": "9",
            ".-.-.-": ".", "--..--": ",", "..--..": "?",
            "-.-.--": "!", "---...": ":", "-.--.": "(", "-.--.-": ")",
            ".-..-.": '"', "-..-.": "/", ".--.-.": "@",
            "-...-": "=", ".-...": "&",
        }

        # Decode words separated by / or multiple spaces
        words = re.split(r'\s*/\s*|\s{3,}', data)
        result_text = ""
        for word in words:
            letters = word.strip().split()
            for letter in letters:
                result_text += MORSE.get(letter, "?")
            result_text += " "

        result_text = result_text.strip()
        flags = find_flags(result_text)
        if flags:
            report.log("solve", "Morse code decoded to flag")
            return SolveResult(flag=flags[0])

        if result_text:
            report.log("solve", f"Morse decoded: {result_text}")

        return None

    def _binary_to_text(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        data = self._get_data(info).strip()
        if not data:
            return None

        # Check if it's binary digits
        cleaned = data.replace(" ", "").replace("\n", "")
        if not re.match(r'^[01]+$', cleaned):
            return None

        if len(cleaned) % 8 != 0:
            return None

        text = ""
        for i in range(0, len(cleaned), 8):
            byte = int(cleaned[i:i+8], 2)
            text += chr(byte)

        flags = find_flags(text)
        if flags:
            report.log("solve", "Binary string decoded to flag")
            return SolveResult(flag=flags[0])

        return None

    def _esoteric(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        """Try interpreting as esoteric programming languages."""
        data = self._get_data(info).strip()
        if not data:
            return None

        # Brainfuck detection
        bf_chars = set("+-<>.,[]")
        if set(data) <= bf_chars | {" ", "\n", "\t"}:
            try:
                output = self._run_brainfuck(data)
                flags = find_flags(output)
                if flags:
                    report.log("solve", "Brainfuck program output contains flag")
                    return SolveResult(flag=flags[0])
                if output:
                    report.log("solve", f"Brainfuck output: {output[:200]}")
            except Exception:
                pass

        return None

    def _run_brainfuck(self, code: str) -> str:
        """Simple brainfuck interpreter."""
        code = "".join(c for c in code if c in "+-<>.,[]")
        tape = [0] * 30000
        ptr = 0
        ip = 0
        output = []
        max_steps = 1_000_000

        # Pre-compute bracket matching
        brackets = {}
        stack = []
        for i, ch in enumerate(code):
            if ch == "[":
                stack.append(i)
            elif ch == "]":
                if stack:
                    j = stack.pop()
                    brackets[j] = i
                    brackets[i] = j

        steps = 0
        while ip < len(code) and steps < max_steps:
            ch = code[ip]
            if ch == ">":
                ptr = (ptr + 1) % 30000
            elif ch == "<":
                ptr = (ptr - 1) % 30000
            elif ch == "+":
                tape[ptr] = (tape[ptr] + 1) % 256
            elif ch == "-":
                tape[ptr] = (tape[ptr] - 1) % 256
            elif ch == ".":
                output.append(chr(tape[ptr]))
            elif ch == "[" and tape[ptr] == 0:
                ip = brackets.get(ip, ip)
            elif ch == "]" and tape[ptr] != 0:
                ip = brackets.get(ip, ip)
            ip += 1
            steps += 1

        return "".join(output)

    def _number_to_chars(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        data = self._get_data(info).strip()
        if not data:
            return None

        # Try interpreting space/comma-separated numbers as ASCII
        numbers = re.findall(r'\d+', data)
        if len(numbers) < 3:
            return None

        try:
            text = "".join(chr(int(n)) for n in numbers if 0 < int(n) < 128)
            flags = find_flags(text)
            if flags:
                report.log("solve", "Numbers → ASCII conversion found flag")
                return SolveResult(flag=flags[0])
        except (ValueError, OverflowError):
            pass

        return None

    def _reverse_string(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        data = self._get_data(info).strip()
        if not data:
            return None

        reversed_data = data[::-1]
        flags = find_flags(reversed_data)
        if flags:
            report.log("solve", "Flag found in reversed text")
            return SolveResult(flag=flags[0])

        return None

    def _llm_misc(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        data = self._get_data(info)
        context_parts = [f"Challenge: {info.name}"]

        if data:
            context_parts.append(f"Data:\n{data[:3000]}")
        if info.description:
            context_parts.append(f"Description: {info.description}")

        try:
            response = llm_engine.solve_puzzle(
                "This is a miscellaneous CTF challenge. "
                "It could involve encoding, OSINT, trivia, or anything else. "
                "Analyze and solve it.",
                context="\n".join(context_parts),
            )
            flags = find_flags(response)
            if flags:
                report.log("solve", "LLM solved the challenge")
                return SolveResult(flag=flags[0])
            report.log("solve", "LLM misc analysis",
                       detail=response[:500], success=False)
        except Exception as exc:
            report.log("solve", f"LLM failed: {exc}", success=False)

        return None
