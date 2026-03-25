"""
CLI entry point for the CTF Agent.

Usage:
    python -m agent.main solve <challenge_path> [options]
    python -m agent.main scan                       # list available tools
"""

import argparse
import sys

from agent.orchestrator import solve_challenge, solve_multi
from agent import tools


def cmd_solve(args: argparse.Namespace) -> None:
    """Handle the 'solve' subcommand."""
    report = solve_challenge(
        path=args.file,
        url=args.url,
        description=args.description or "",
        flag_format=args.flag_format,
        category_override=args.category,
    )

    if report.solved:
        print(f"\n🏁  Flag: {report.flag}")
    else:
        print("\n😞  Could not find the flag.")
        sys.exit(1)


def cmd_batch(args: argparse.Namespace) -> None:
    """Handle the 'batch' subcommand."""
    import glob
    paths = []
    for pattern in args.files:
        paths.extend(glob.glob(pattern))
    if not paths:
        print("No files matched.")
        sys.exit(1)
    solve_multi(paths, flag_format=args.flag_format)


def cmd_scan(args: argparse.Namespace) -> None:
    """Handle the 'scan' subcommand — show available tools."""
    print("\n🔧  Tool Availability Scan")
    print("=" * 40)
    available = tools.list_tools()
    for name, ok in sorted(available.items()):
        icon = "✅" if ok else "❌"
        print(f"  {icon}  {name}")
    total = sum(available.values())
    print(f"\n  {total}/{len(available)} tools available.\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="ctf-agent",
        description="🤖 Autonomous CTF-Solving Agent",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="enable verbose output",
    )
    sub = parser.add_subparsers(dest="command")

    # ── solve ──────────────────────────────────────────────────────────
    p_solve = sub.add_parser("solve", help="Solve a single challenge")
    p_solve.add_argument("file", nargs="?", help="Path to challenge file")
    p_solve.add_argument("-u", "--url", help="Target URL (web challenges)")
    p_solve.add_argument("-d", "--description", help="Challenge description")
    p_solve.add_argument("-f", "--flag-format",
                         help="Custom flag regex (e.g. 'picoCTF\\{.*?\\}')")
    p_solve.add_argument("-c", "--category",
                         help="Force category (skip classification)")
    p_solve.set_defaults(func=cmd_solve)

    # ── batch ──────────────────────────────────────────────────────────
    p_batch = sub.add_parser("batch", help="Solve multiple challenges")
    p_batch.add_argument("files", nargs="+",
                         help="Glob patterns for challenge files")
    p_batch.add_argument("-f", "--flag-format",
                         help="Custom flag regex")
    p_batch.set_defaults(func=cmd_batch)

    # ── scan ───────────────────────────────────────────────────────────
    p_scan = sub.add_parser("scan", help="Show available external tools")
    p_scan.set_defaults(func=cmd_scan)

    args = parser.parse_args()

    if args.verbose:
        import agent.config
        agent.config.VERBOSE = True

    if not args.command:
        parser.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()
