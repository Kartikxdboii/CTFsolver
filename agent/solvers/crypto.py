"""
Crypto Solver — handles encoding, classical ciphers, and RSA attacks.

Strategies (in order):
  1. base64_decode        — try Base64 / Base32 / Base85 / hex
  2. rot_bruteforce       — try all ROT-N (Caesar) shifts
  3. xor_single_byte      — brute-force single-byte XOR key
  4. xor_known_plaintext  — XOR with known flag prefix
  5. vigenere_crack       — frequency-based Vigenère key recovery
  6. rsa_small_e          — RSA with very small public exponent
  7. rsa_factor           — factor small N with sympy
  8. hash_lookup          — check if data is a known hash
  9. llm_crypto           — ask the LLM to solve it
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import itertools
import string
from typing import Optional, Callable

from agent.solvers.base import BaseSolver, SolveResult
from agent.analyzer import ChallengeInfo
from agent.reporter import SolveReport
from agent.validator import find_flags
from agent import llm as llm_engine


class CryptoSolver(BaseSolver):

    @property
    def strategies(self) -> list[tuple[str, Callable]]:
        return [
            ("base64_decode",       self._base64_decode),
            ("hex_decode",          self._hex_decode),
            ("rot_bruteforce",      self._rot_bruteforce),
            ("xor_single_byte",     self._xor_single_byte),
            ("xor_known_prefix",    self._xor_known_prefix),
            ("rsa_small_e",         self._rsa_small_e),
            ("rsa_factor_n",        self._rsa_factor_n),
            ("multi_decode_chain",  self._multi_decode_chain),
            ("llm_crypto",          self._llm_crypto),
        ]

    # ── Helpers ────────────────────────────────────────────────────────

    def _get_data(self, info: ChallengeInfo) -> str:
        """Get challenge data as text."""
        if info.is_file:
            return self._read_text(info.path)
        return info.description

    # ── Strategies ─────────────────────────────────────────────────────

    def _try_decode_candidates(
        self, data: str, report: SolveReport
    ) -> Optional[SolveResult]:
        """
        Extract likely encoded substrings from *data* (regex + tokens)
        and try to decode each one. Returns SolveResult on first flag.
        """
        import re

        # Build candidate list: whole text, regex-extracted b64, and tokens
        candidates = [data.strip()]

        # Extract base64-looking substrings (min 8 chars, valid charset)
        b64_pattern = r'[A-Za-z0-9+/]{8,}={0,2}'
        candidates.extend(re.findall(b64_pattern, data))

        # Also add every whitespace-delimited token
        candidates.extend(data.split())

        # Extract hex-looking substrings
        hex_pattern = r'(?:0x)?[0-9a-fA-F]{8,}'
        candidates.extend(re.findall(hex_pattern, data))

        # De-duplicate while preserving order
        seen = set()
        unique = []
        for c in candidates:
            c = c.strip()
            if c and c not in seen:
                seen.add(c)
                unique.append(c)

        decoders = [
            ("base64", lambda d: base64.b64decode(d).decode("utf-8", errors="replace")),
            ("base32", lambda d: base64.b32decode(d.upper()).decode("utf-8", errors="replace")),
            ("base85", lambda d: base64.b85decode(d).decode("utf-8", errors="replace")),
            ("hex",    lambda d: bytes.fromhex(d.replace("0x", "")).decode("utf-8", errors="replace")),
        ]

        for candidate in unique:
            for dec_name, decoder in decoders:
                try:
                    decoded = decoder(candidate)
                    if not decoded or len(decoded) < 3:
                        continue
                    flags = find_flags(decoded)
                    if flags:
                        report.log("solve",
                                   f"{dec_name} decode found flag",
                                   detail=decoded[:300])
                        return SolveResult(flag=flags[0])

                    # Try double-decode
                    for dec_name2, decoder2 in decoders:
                        try:
                            double = decoder2(decoded.strip())
                            if double and len(double) >= 3:
                                flags = find_flags(double)
                                if flags:
                                    report.log("solve",
                                               f"Double decode ({dec_name}→{dec_name2}) found flag",
                                               detail=double[:300])
                                    return SolveResult(flag=flags[0])
                        except Exception:
                            pass
                except Exception:
                    continue

        return None

    def _base64_decode(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        data = self._get_data(info).strip()
        if not data:
            return None
        return self._try_decode_candidates(data, report)

    def _hex_decode(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        data = self._get_data(info).strip()
        if not data:
            return None

        import re

        # Try whole text first (cleaned)
        cleaned = data.replace("0x", "").replace(" ", "").replace("\n", "")
        try:
            decoded = bytes.fromhex(cleaned).decode("utf-8", errors="replace")
            flags = find_flags(decoded)
            if flags:
                report.log("solve", "Hex decode found flag", detail=decoded)
                return SolveResult(flag=flags[0])
        except (ValueError, binascii.Error):
            pass

        # Try hex substrings
        for match in re.findall(r'(?:0x)?([0-9a-fA-F]{8,})', data):
            try:
                decoded = bytes.fromhex(match).decode("utf-8", errors="replace")
                flags = find_flags(decoded)
                if flags:
                    report.log("solve", "Hex substring decode found flag",
                               detail=decoded)
                    return SolveResult(flag=flags[0])
            except (ValueError, binascii.Error):
                pass

        return None

    def _rot_bruteforce(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        data = self._get_data(info).strip()
        if not data:
            return None

        for shift in range(1, 26):
            shifted = ""
            for ch in data:
                if ch.isalpha():
                    base = ord('A') if ch.isupper() else ord('a')
                    shifted += chr((ord(ch) - base + shift) % 26 + base)
                else:
                    shifted += ch

            flags = find_flags(shifted)
            if flags:
                report.log("solve", f"ROT-{shift} found flag", detail=shifted)
                return SolveResult(flag=flags[0])

        return None

    def _xor_single_byte(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        if not info.is_file:
            return None

        data = self._read_file(info.path)
        if not data or len(data) > 100_000:
            return None

        for key in range(256):
            decoded = bytes(b ^ key for b in data)
            try:
                text = decoded.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                continue

            flags = find_flags(text)
            if flags:
                report.log("solve", f"XOR key=0x{key:02x} found flag",
                           detail=text[:500])
                return SolveResult(flag=flags[0])

        return None

    def _xor_known_prefix(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        if not info.is_file:
            return None

        data = self._read_file(info.path)
        if not data:
            return None

        # Try known flag prefixes
        prefixes = [b"flag{", b"CTF{", b"FLAG{", b"picoCTF{", b"HTB{"]

        for prefix in prefixes:
            if len(data) < len(prefix):
                continue

            # Derive key from known prefix
            key = bytes(d ^ p for d, p in zip(data[:len(prefix)], prefix))
            if len(set(key)) == 1:
                # Single-byte key — already handled above
                continue

            # Try repeating key
            key_len = len(key)
            decoded = bytes(
                data[i] ^ key[i % key_len] for i in range(len(data))
            )
            try:
                text = decoded.decode("utf-8", errors="replace")
            except Exception:
                continue

            flags = find_flags(text)
            if flags:
                report.log("solve", f"XOR with derived key (prefix={prefix}) found flag",
                           detail=text[:500])
                return SolveResult(flag=flags[0])

        return None

    def _rsa_small_e(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        """RSA with small exponent: c = m^e mod n, take e-th root."""
        data = self._get_data(info)
        if not data:
            return None

        import re

        # Try to extract n, e, c from the text
        n_match = re.search(r'[nN]\s*[=:]\s*(\d+)', data)
        e_match = re.search(r'[eE]\s*[=:]\s*(\d+)', data)
        c_match = re.search(r'[cC]\s*[=:]\s*(\d+)', data)

        if not all([n_match, e_match, c_match]):
            return None

        n = int(n_match.group(1))
        e = int(e_match.group(1))
        c = int(c_match.group(1))

        report.log("solve", f"Found RSA params: e={e}, n has {len(str(n))} digits")

        if e <= 5:
            # Small e attack: take e-th root of c
            try:
                from sympy import integer_nthroot
                m, exact = integer_nthroot(c, e)
                if exact:
                    try:
                        plaintext = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()
                        flags = find_flags(plaintext)
                        if flags:
                            report.log("solve", f"RSA small-e attack (e={e}) found flag")
                            return SolveResult(flag=flags[0])
                    except Exception:
                        pass
            except ImportError:
                report.log("solve", "sympy not available for RSA", success=False)

        return None

    def _rsa_factor_n(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        """Factor small RSA modulus."""
        data = self._get_data(info)
        if not data:
            return None

        import re

        n_match = re.search(r'[nN]\s*[=:]\s*(\d+)', data)
        e_match = re.search(r'[eE]\s*[=:]\s*(\d+)', data)
        c_match = re.search(r'[cC]\s*[=:]\s*(\d+)', data)

        if not all([n_match, e_match, c_match]):
            return None

        n = int(n_match.group(1))
        e = int(e_match.group(1))
        c = int(c_match.group(1))

        # Only try factoring if n is small enough
        if n.bit_length() > 256:
            report.log("solve", f"N is too large to factor ({n.bit_length()} bits)",
                       success=False)
            return None

        try:
            from sympy import factorint
            factors = factorint(n)
            primes = list(factors.keys())

            if len(primes) == 2:
                p, q = primes
                phi = (p - 1) * (q - 1)
                d = pow(e, -1, phi)
                m = pow(c, d, n)

                try:
                    plaintext = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()
                    flags = find_flags(plaintext)
                    if flags:
                        report.log("solve", "RSA factored N, found flag")
                        return SolveResult(flag=flags[0])
                except Exception:
                    pass
        except ImportError:
            report.log("solve", "sympy not available", success=False)

        return None

    def _multi_decode_chain(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        """Try chained decodings: base64 → hex, hex → base64, etc."""
        data = self._get_data(info).strip()
        if not data:
            return None

        current = data
        for depth in range(5):  # max 5 rounds
            decoded = None

            # Try base64
            try:
                decoded = base64.b64decode(current).decode("utf-8", errors="replace")
            except Exception:
                pass

            if decoded is None:
                # Try hex
                try:
                    cleaned = current.replace(" ", "").replace("\n", "")
                    decoded = bytes.fromhex(cleaned).decode("utf-8", errors="replace")
                except Exception:
                    pass

            if decoded is None:
                break

            flags = find_flags(decoded)
            if flags:
                report.log("solve", f"Decode chain (depth={depth+1}) found flag",
                           detail=decoded[:300])
                return SolveResult(flag=flags[0])

            current = decoded.strip()

        return None

    def _llm_crypto(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        """Use the LLM to analyze and solve the crypto challenge."""
        data = self._get_data(info)
        if not data:
            return None

        try:
            context = f"Challenge file: {info.name}\nFile type: {info.file_type}\n\nData:\n{data[:3000]}"
            response = llm_engine.solve_puzzle(
                "This is a cryptography CTF challenge. Analyze and solve it.",
                context=context,
            )
            flags = find_flags(response)
            if flags:
                report.log("solve", "LLM solved the crypto challenge",
                           detail=response[:500])
                return SolveResult(flag=flags[0])
            else:
                report.log("solve", "LLM analysis (no flag found)",
                           detail=response[:500], success=False)
        except Exception as exc:
            report.log("solve", f"LLM failed: {exc}", success=False)

        return None
