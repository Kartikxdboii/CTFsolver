"""
Abstract base class for all CTF solvers.

Every solver implements a list of strategies. The orchestrator
calls `solve()`, which tries strategies in order until a flag is found.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Optional, Callable

from agent.analyzer import ChallengeInfo
from agent.reporter import SolveReport
from agent.validator import find_flags
from agent.config import MAX_STRATEGIES_PER_SOLVER, VERBOSE


@dataclass
class SolveResult:
    """Outcome of a solve attempt."""
    flag: Optional[str] = None
    partial_flags: list[str] = field(default_factory=list)
    artifacts: dict[str, str] = field(default_factory=dict)  # name → content

    @property
    def solved(self) -> bool:
        return self.flag is not None


class BaseSolver(abc.ABC):
    """
    Base class for category-specific solvers.

    Subclasses must define `strategies` — an ordered list of
    (name, method) tuples. Each method receives (info, report)
    and should return a SolveResult or None.
    """

    @property
    @abc.abstractmethod
    def strategies(self) -> list[tuple[str, Callable]]:
        """
        Return an ordered list of (strategy_name, callable).

        Each callable has signature:
            (self, info: ChallengeInfo, report: SolveReport) -> SolveResult | None
        """
        ...

    def solve(
        self,
        info: ChallengeInfo,
        report: SolveReport,
        *,
        flag_format: Optional[str] = None,
    ) -> SolveResult:
        """
        Try every strategy in order.  Stop at the first flag found.
        """
        for i, (name, method) in enumerate(self.strategies):
            if i >= MAX_STRATEGIES_PER_SOLVER:
                report.log("solve", "Max strategies reached, giving up.",
                           success=False)
                break

            if VERBOSE:
                print(f"  [STRATEGY] {self.__class__.__name__}::{name}")

            report.log("solve", f"Trying strategy: **{name}**")

            try:
                result = method(info, report)
            except Exception as exc:
                report.log("solve", f"Strategy '{name}' errored: {exc}",
                           success=False)
                continue

            if result is None:
                report.log("solve", f"Strategy '{name}' returned nothing.",
                           success=False)
                continue

            # Check for flags in any artifacts produced
            if not result.flag:
                for art_name, art_content in result.artifacts.items():
                    flags = find_flags(art_content, flag_format)
                    if flags:
                        result.flag = flags[0]
                        result.partial_flags.extend(flags[1:])
                        report.log("solve",
                                   f"Flag found in artifact '{art_name}': "
                                   f"`{result.flag}`")
                        break

            if result.solved:
                report.log("solve",
                           f"✅ Strategy **{name}** found the flag!",
                           detail=result.flag)
                return result

            # Even without a flag, log partial results
            if result.partial_flags:
                report.log("solve",
                           f"Partial flags from '{name}': "
                           f"{result.partial_flags}")

        # No strategy succeeded
        return SolveResult()

    # ── Helper utilities for subclasses ────────────────────────────────

    def _check_flags(
        self,
        text: str,
        flag_format: Optional[str] = None,
    ) -> SolveResult:
        """Scan text for flags and return a SolveResult."""
        flags = find_flags(text, flag_format)
        if flags:
            return SolveResult(flag=flags[0], partial_flags=flags[1:])
        return SolveResult()

    def _read_file(self, path) -> bytes:
        """Read a file as bytes, or return empty bytes."""
        try:
            from pathlib import Path as P
            return P(path).read_bytes()
        except Exception:
            return b""

    def _read_text(self, path) -> str:
        """Read a file as text, with fallback decoding."""
        data = self._read_file(path)
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.decode("latin-1")
