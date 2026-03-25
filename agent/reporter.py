"""
Logger / Reporter — records every agent step and generates
a Markdown solve report at the end.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from agent.config import REPORTS_DIR


@dataclass
class Step:
    """Single logged step."""
    timestamp: float
    phase: str          # "analyze", "solve", "validate", …
    action: str         # human-readable description
    detail: str = ""    # tool output / extra info
    success: bool = True


@dataclass
class SolveReport:
    """Accumulates steps and renders the final Markdown report."""
    challenge_name: str
    challenge_path: str = ""
    category: str = "unknown"
    flag: Optional[str] = None
    solved: bool = False
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    steps: list[Step] = field(default_factory=list)

    # ── Recording ──────────────────────────────────────────────────────

    def log(
        self,
        phase: str,
        action: str,
        detail: str = "",
        success: bool = True,
    ) -> None:
        self.steps.append(Step(
            timestamp=time.time(),
            phase=phase,
            action=action,
            detail=detail[:2000],      # cap stored detail
            success=success,
        ))

    def finish(self, flag: Optional[str] = None) -> None:
        self.end_time = time.time()
        if flag:
            self.flag = flag
            self.solved = True

    # ── Rendering ──────────────────────────────────────────────────────

    @property
    def elapsed(self) -> float:
        end = self.end_time or time.time()
        return end - self.start_time

    def to_markdown(self) -> str:
        lines = [
            f"# Solve Report: {self.challenge_name}",
            "",
            f"- **Category:** {self.category}",
            f"- **File:** `{self.challenge_path}`",
            f"- **Solved:** {'✅ Yes' if self.solved else '❌ No'}",
        ]

        if self.solved:
            lines.append(f"- **Flag:** `{self.flag}`")

        lines += [
            f"- **Time:** {self.elapsed:.1f}s",
            "",
            "---",
            "",
            "## Steps",
            "",
        ]

        for i, step in enumerate(self.steps, 1):
            icon = "✅" if step.success else "❌"
            elapsed = step.timestamp - self.start_time
            lines.append(
                f"{i}. {icon} **[{step.phase}]** {step.action} "
                f"*({elapsed:.1f}s)*"
            )
            if step.detail:
                # indent detail as a collapsible block
                lines.append(f"   <details><summary>detail</summary>\n")
                lines.append(f"   ```")
                for dl in step.detail.split("\n")[:30]:
                    lines.append(f"   {dl}")
                lines.append(f"   ```")
                lines.append(f"   </details>\n")

        return "\n".join(lines)

    def save(self, directory: Path | None = None) -> Path:
        """Write the Markdown report to disk and return the path."""
        out_dir = directory or REPORTS_DIR
        out_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = "".join(
            c if c.isalnum() or c in "-_" else "_"
            for c in self.challenge_name
        )
        path = out_dir / f"{ts}_{safe_name}.md"
        path.write_text(self.to_markdown(), encoding="utf-8")
        return path
