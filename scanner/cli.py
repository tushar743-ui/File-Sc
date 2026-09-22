from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from .analyzers.base import SEVERITY_ORDER, meets_threshold
from .baseline import assign_fingerprints, build_baseline, dumps, filter_new, load_baseline
from .engine import DEFAULT_EXCLUDES, ScanConfig, scan
from .output import sarif as sarif_output
from .output import table as table_output
from .rules import RuleError, load_rules

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("target", type=Path, help="file or directory to analyze")
    parser.add_argument("--rules", type=Path, required=True, help="path to rules.yaml")
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="DIR",
        help="directory name to skip (repeatable)",
    )
    parser.add_argument("--jobs", type=int, default=0, help="worker processes (0 = auto)")
    parser.add_argument("--root", type=Path, default=None, help="project root for relative paths")
    parser.add_argument("--quiet", action="store_true", help="suppress progress on stderr")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scanner", description="Static taint analyzer for Python")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_parser = sub.add_parser("scan", help="analyze a codebase and report findings")
    _add_common(scan_parser)
    scan_parser.add_argument(
        "--format", choices=("table", "summary", "sarif"), default="table"
    )
    scan_parser.add_argument("--fail-on", choices=tuple(SEVERITY_ORDER), default=None)
    scan_parser.add_argument("--baseline", type=Path, default=None, help="report only new findings")
    scan_parser.add_argument("-o", "--output", type=Path, default=None)

    baseline_parser = sub.add_parser("baseline", help="write a baseline of current findings")
    _add_common(baseline_parser)
    baseline_parser.add_argument("-o", "--output", type=Path, default=None)

    bench_parser = sub.add_parser("bench", help="score findings against a labelled corpus")
    _add_common(bench_parser)
    bench_parser.add_argument("--labels", type=Path, required=True)
    bench_parser.add_argument("--format", choices=("table", "markdown"), default="table")
    bench_parser.add_argument("-o", "--output", type=Path, default=None)

    return parser


def _progress(started: float):
    def report(done: int, total: int) -> None:
        if done == 0:
            sys.stderr.write(f"scanner: {total} python file(s) to scan\n")
            return
        elapsed = time.monotonic() - started
        end = "\n" if done == total else "\r"
        sys.stderr.write(f"scanner: {done}/{total} files  {elapsed:.1f}s{end}")
        sys.stderr.flush()

    return report


def _run_scan(args) -> tuple[list, Path, list]:
    rules = load_rules(args.rules)
    excludes = DEFAULT_EXCLUDES + tuple(args.exclude)
    target = args.target.resolve()
    root = (args.root or (target if target.is_dir() else target.parent)).resolve()
    started = time.monotonic()
    findings = scan(
        ScanConfig(target=target, rules=rules, excludes=excludes, jobs=args.jobs, root=root),
        progress=None if args.quiet else _progress(started),
    )
    if not args.quiet:
        elapsed = time.monotonic() - started
        sys.stderr.write(f"scanner: {len(findings)} finding(s) in {elapsed:.1f}s\n")
    return findings, root, rules


def _write(text: str, destination: Path | None) -> None:
    if destination is None:
        sys.stdout.write(text)
    else:
        destination.write_text(text, encoding="utf-8")


def command_scan(args) -> int:
    findings, root, rules = _run_scan(args)
    if args.baseline is not None:
        scanned = {finding.file for finding in findings}
        findings = filter_new(findings, load_baseline(args.baseline), scanned)
    findings = assign_fingerprints(findings)

    if args.format == "sarif":
        _write(sarif_output.render(findings, rules, str(root)), args.output)
    elif args.format == "summary":
        _write(table_output.render_summary(findings, sys.stdout), args.output)
    else:
        _write(table_output.render(findings, sys.stdout), args.output)

    if args.fail_on and any(meets_threshold(f.severity, args.fail_on) for f in findings):
        return EXIT_FINDINGS
    return EXIT_OK


def command_baseline(args) -> int:
    findings, _, _ = _run_scan(args)
    _write(dumps(build_baseline(findings)), args.output)
    return EXIT_OK


def command_bench(args) -> int:
    from .bench import run_bench

    findings, root, rules = _run_scan(args)
    text = run_bench(findings, args.labels, root, rules, args.format)
    _write(text, args.output)
    return EXIT_OK


COMMANDS = {"scan": command_scan, "baseline": command_baseline, "bench": command_bench}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.target.exists():
        sys.stderr.write(f"scanner: target not found: {args.target}\n")
        return EXIT_ERROR
    try:
        return COMMANDS[args.command](args)
    except (RuleError, ValueError, OSError) as error:
        sys.stderr.write(f"scanner: {error}\n")
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
