"""
Orchestrator — the main agent loop.

    analyze → route → solve → validate → report
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from agent.analyzer import analyze, ChallengeInfo
from agent.reporter import SolveReport
from agent.validator import find_flags
from agent.config import VERBOSE, MAX_STRATEGIES_PER_SOLVER
from agent.solvers import SOLVERS


def solve_challenge(
    path: Optional[str] = None,
    url: Optional[str] = None,
    description: str = "",
    flag_format: Optional[str] = None,
    category_override: Optional[str] = None,
) -> SolveReport:
    """
    End-to-end solve pipeline for a single CTF challenge.

    Parameters
    ----------
    path : file path to the challenge (file/archive)
    url  : target URL (for web challenges)
    description : challenge description text
    flag_format : custom flag regex  (e.g.  r"picoCTF\\{.*?\\}")
    category_override : skip classification and force a category

    Returns
    -------
    SolveReport with all steps logged and (hopefully) a flag.
    """
    # ── 1. Identify ────────────────────────────────────────────────────
    info: ChallengeInfo = analyze(path=path, url=url, description=description)
    report = SolveReport(
        challenge_name=info.name,
        challenge_path=str(info.path or info.url or ""),
    )

    if category_override and category_override in SOLVERS:
        info.category = category_override
        info.confidence = 1.0
        info.reasoning = "User override"

    report.category = info.category
    report.log("analyze", f"Classified as **{info.category}** "
               f"(confidence={info.confidence:.2f})",
               detail=info.reasoning)

    # ── 2. Route to solver ─────────────────────────────────────────────
    solver_cls = SOLVERS.get(info.category)
    if solver_cls is None:
        report.log("route", f"No solver for category '{info.category}'",
                   success=False)
        report.finish()
        return report

    solver = solver_cls()
    report.log("route", f"Using solver: {solver.__class__.__name__}")

    # ── 3. Solve ───────────────────────────────────────────────────────
    try:
        result = solver.solve(info, report, flag_format=flag_format)
    except Exception as exc:
        report.log("solve", f"Solver crashed: {exc}", success=False)
        result = None

    # ── 3b. Fallback: try other solvers if primary failed ──────────────
    if (not result or not result.flag) and info.confidence < 0.8:
        # Prioritised fallback order
        fallbacks = ["crypto", "misc", "forensics", "stego"]
        tried = {info.category}

        for fb_cat in fallbacks:
            if fb_cat in tried:
                continue
            tried.add(fb_cat)

            fb_cls = SOLVERS.get(fb_cat)
            if fb_cls is None:
                continue

            fb_solver = fb_cls()
            report.log("route",
                       f"Fallback: trying {fb_solver.__class__.__name__}")

            try:
                fb_result = fb_solver.solve(info, report, flag_format=flag_format)
            except Exception as exc:
                report.log("solve",
                           f"Fallback solver {fb_cat} crashed: {exc}",
                           success=False)
                continue

            if fb_result and fb_result.flag:
                result = fb_result
                report.category = fb_cat
                break

    # ── 4. Validate ────────────────────────────────────────────────────
    if result and result.flag:
        report.log("validate", f"Flag found: `{result.flag}`")
        report.finish(flag=result.flag)
    else:
        report.log("validate", "No flag found after all strategies.",
                   success=False)
        report.finish()

    # ── 5. Report ──────────────────────────────────────────────────────
    report_path = report.save()
    if VERBOSE:
        print(f"  [REPORT] Saved to {report_path}")

    return report


def solve_multi(
    paths: list[str],
    flag_format: Optional[str] = None,
) -> list[SolveReport]:
    """Solve multiple challenges sequentially."""
    reports = []
    for p in paths:
        print(f"\n{'='*60}")
        print(f"  Solving: {p}")
        print(f"{'='*60}")
        rpt = solve_challenge(path=p, flag_format=flag_format)
        reports.append(rpt)

        if rpt.solved:
            print(f"  ✅  Flag: {rpt.flag}")
        else:
            print(f"  ❌  No flag found.")

    # Summary
    solved = sum(1 for r in reports if r.solved)
    print(f"\n{'='*60}")
    print(f"  Results: {solved}/{len(reports)} solved")
    print(f"{'='*60}")
    return reports
