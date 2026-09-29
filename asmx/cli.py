"""Command line of ASM X — the same analysis as the interface, without the interface.

Commands:

* ``check``    — analyzes and validates, showing the problems by line;
* ``run``      — runs the program in the virtual machine and shows the output;
* ``explain``  — explains one instruction of the catalog or one line of the file;
* ``report``   — generates the report (HTML, Markdown, JSON, DOT, SVG);
* ``analyze``  — analyzes several files and builds a comparative index;
* ``info``     — version, instruction catalog and configuration in effect;
* ``examples`` — lists, shows or writes the sample programs;
* ``version``  — only the version.

Exit codes (stable contract for CI)::

    0  everything is fine
    1  problems found in the code
    2  usage error (invalid argument)
    3  input error (missing file, format, configuration, label)
    4  time limit exceeded

The global options (``--config``, ``-v``, ``--log-json``...) come before the
command: ``asmx --config asmx.json check prog.asm``.

Example:
    >>> from asmx.cli import main
    >>> main(["version"])                     # doctest: +SKIP
    0
"""

from __future__ import annotations

import argparse
import json
import os
import platform as _platform
import sys
import webbrowser
from typing import Any, Callable, Dict, List, Optional, Sequence, TextIO, Tuple

from . import __version__
from .analyzer import Analysis, analyze
from .config import SandboxConfig
from .emulator import Machine, hexs
from .errors import (
    AnalysisTimeoutError,
    AsmxError,
    ConfigError,
    EmulationError,
    LineNotFoundError,
    ProjectError,
    SourceNotFoundError,
    SourceReadError,
    UnknownMnemonicError,
    UnsupportedSourceError,
)
from .examples import EXAMPLES, render
from .isa import CATEGORIES, ISA, LINUX_SYSCALLS, WIN_APIS
from concurrent import futures

from .linter import ALL_CHECKS, ERROR, INFO, WARNING, Problem, summary, validate
from .logging_setup import LoggingState, configure_logging, get_logger, log_event
from .source import SOURCE_SUFFIXES, SourceFile, read_source

__all__ = [
    "main",
    "build_parser",
    "build_payload",
    "describe_instruction",
    "load_config",
    "COMMANDS",
    "EXIT_OK",
    "EXIT_PROBLEMS",
    "EXIT_USAGE",
    "EXIT_INPUT",
    "EXIT_TIMEOUT",
]

logger = get_logger(__name__)

#: Everything is fine.
EXIT_OK = 0
#: Problems found in the analyzed code.
EXIT_PROBLEMS = 1
#: Usage error of the command line.
EXIT_USAGE = 2
#: Input error: file, format, configuration or label.
EXIT_INPUT = 3
#: The run went past the time limit.
EXIT_TIMEOUT = 4

#: Severities in the order they appear in the report.
SEVERITIES: Tuple[str, ...] = (ERROR, WARNING, INFO)

#: Names of the count keys in the JSON, in the same order as :data:`SEVERITIES`.
SUMMARY_KEYS: Tuple[str, ...] = ("errors", "warnings", "infos")

#: Report formats accepted by ``report`` and ``analyze``.
REPORT_FORMATS: Tuple[str, ...] = ("html", "md", "json", "dot", "svg", "mermaid")

#: Risk levels, from the calmest to the most severe.
RISK_LEVELS: Tuple[str, ...] = ("low", "medium", "high", "critical")

#: Rule severities accepted by ``--fail-on`` of the ``scan`` command.
RULE_SEVERITIES: Tuple[str, ...] = ("high", "medium", "low")

#: Extension of each report format.
FORMAT_SUFFIX = {
    "html": "html",
    "md": "md",
    "json": "json",
    "dot": "dot",
    "svg": "svg",
    "mermaid": "mmd",
}

#: ANSI colors used in the terminal output.
_COLORS = {
    "error": "\033[31m",
    "warning": "\033[33m",
    "info": "\033[34m",
    "title": "\033[1;36m",
    "good": "\033[32m",
    "dim": "\033[90m",
    "bold": "\033[1m",
}
_RESET = "\033[0m"


class Palette:
    """Paints text in the terminal when the destination accepts color.

    Attributes:
        enabled: Whether the ANSI sequences enter the output.
    """

    def __init__(self, enabled: bool = True) -> None:
        """Stores whether the color is on.

        Args:
            enabled: ``False`` returns the text untouched.
        """
        self.enabled = enabled

    def paint(self, text: str, color: str = "") -> str:
        """Wraps the text in the requested color.

        Args:
            text: Original text.
            color: Name in :data:`_COLORS`; empty paints nothing.

        Returns:
            Text with the ANSI sequences, or untouched when turned off.

        Example:
            >>> Palette(False).paint("error", "error")
            'error'
        """
        if not self.enabled or color not in _COLORS:
            return text
        return "%s%s%s" % (_COLORS[color], text, _RESET)

    def severity(self, severity: str, text: str) -> str:
        """Paints a text according to the severity of the problem.

        Args:
            severity: ``error``, ``warning`` or ``info``.
            text: Text to paint.

        Returns:
            Colored text.
        """
        return self.paint(text, severity)


# ------------------------------------------------------------------ parser --
def _add_global_options(parser: argparse.ArgumentParser, suppress: bool = False) -> None:
    """Registers the options that are valid for any command.

    The same group is registered in the main parser and in every subcommand,
    with ``default=SUPPRESS`` in the subcommands. That way ``asmx --no-color
    check x`` and ``asmx check x --no-color`` work the same, and the option
    given before the command is not overwritten by the subcommand default.

    Args:
        parser: Parser (or subcommand) that receives the options.
        suppress: When ``True``, the options only enter ``args`` if they are
            really used.
    """
    default: Any = argparse.SUPPRESS if suppress else False
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=default,
        help="shows the debug log (DEBUG)",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        default=default,
        help="silences the log; only the result is left",
    )
    parser.add_argument(
        "--log-json",
        action="store_true",
        default=default,
        help="emits the log as JSON (one line per event)",
    )
    parser.add_argument(
        "--log-file",
        metavar="PATH",
        default=argparse.SUPPRESS if suppress else None,
        help="also writes the log to this file",
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        default=argparse.SUPPRESS if suppress else None,
        help="configuration file (.json, .yaml or .yml)",
    )
    parser.add_argument(
        "--no-color", action="store_true", default=default, help="does not use color in the output"
    )


def build_parser() -> argparse.ArgumentParser:
    """Builds the argument parser of the command line.

    Returns:
        The :class:`argparse.ArgumentParser` with the commands and the global options.

    Example:
        >>> build_parser().parse_args(["check", "a.asm"]).command
        'check'
        >>> build_parser().parse_args(["check", "a.asm", "--no-color"]).no_color
        True
    """
    parser = argparse.ArgumentParser(
        prog="asmx",
        description="ASM X — study and debugging environment for x86-64 assembly.",
        epilog="with no argument it opens the graphical interface. The global "
        "options (--config, -v, --log-json) come before the command. "
        "Examples: asmx check prog.asm · asmx run prog.asm · "
        "asmx explain prog.asm --line 12",
    )
    parser.add_argument("--version", action="version", version="ASM X %s" % __version__)
    parser.add_argument(
        "--gui",
        action="store_true",
        help="opens the graphical interface (same as the command with no arguments)",
    )
    _add_global_options(parser)

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    check = sub.add_parser("check", help="analyzes and validates the code")
    check.add_argument("files", nargs="+", metavar="FILE", help="one or more .asm sources")
    check.add_argument("--json", action="store_true", help="output in JSON")
    check.add_argument(
        "--min-severity",
        choices=SEVERITIES,
        default=WARNING,
        help="minimum severity that makes the command fail (default: warning)",
    )
    check.add_argument(
        "--exit-zero", action="store_true", help="always returns 0, even with problems found"
    )
    check.add_argument(
        "--summary-only",
        action="store_true",
        help="shows only the summary, without the problem list",
    )
    _add_global_options(check, suppress=True)

    run = sub.add_parser("run", help="runs the program in the virtual machine")
    run.add_argument("file", metavar="FILE", help=".asm source")
    run.add_argument(
        "--entry",
        metavar="LABEL",
        default=None,
        help="starts the execution at this label (isolated function)",
    )
    run.add_argument(
        "--stdin", metavar="TEXT", default="", help="simulated input for the read syscall"
    )
    run.add_argument(
        "--limit",
        type=int,
        default=None,
        help="instruction limit (default: max_steps of the configuration)",
    )
    run.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="maximum time in seconds; when it is exceeded, exits with code 4",
    )
    run.add_argument("--json", action="store_true", help="output in JSON")
    run.add_argument("--trace", action="store_true", help="shows the execution history")
    run.add_argument(
        "--max-trace",
        type=int,
        default=40,
        help="how many lines of the history to show (default: 40)",
    )
    _add_global_options(run, suppress=True)

    explain = sub.add_parser("explain", help="explains one instruction or one line")
    explain.add_argument("file", metavar="FILE", help=".asm source")
    group = explain.add_mutually_exclusive_group(required=True)
    group.add_argument("--line", type=int, metavar="N", help="line number (1-based)")
    group.add_argument("--mnemonic", metavar="MNEMONIC", help="instruction to document")
    explain.add_argument("--json", action="store_true", help="output in JSON")
    _add_global_options(explain, suppress=True)

    report = sub.add_parser("report", help="generates the analysis report")
    report.add_argument("file", metavar="FILE", help=".asm source")
    report.add_argument(
        "--out",
        metavar="PATH",
        default=None,
        help="destination of the report (- for the standard output); without it, "
        "HTML goes to results/ and the other formats go to the screen",
    )
    report.add_argument(
        "--format",
        choices=REPORT_FORMATS,
        default=None,
        help="report format (default: by the extension, or html)",
    )
    report.add_argument(
        "--no-emulate",
        action="store_true",
        help="does not run the program; the report stays static only",
    )
    report.add_argument(
        "--limit", type=int, default=None, help="instruction limit of the simulated run"
    )
    report.add_argument(
        "--timeout", type=float, default=None, help="maximum time of the simulated run, in seconds"
    )
    report.add_argument(
        "--stdin", metavar="TEXT", default="", help="simulated input for the read syscall"
    )
    report.add_argument(
        "--entry", metavar="LABEL", default=None, help="starts the execution at this label"
    )
    report.add_argument(
        "--open", action="store_true", help="opens the report in the browser when it finishes"
    )
    report.add_argument(
        "--fail-on",
        choices=RISK_LEVELS,
        default=None,
        help="exits with code 1 if the risk is at this level or higher",
    )
    report.add_argument(
        "--json",
        action="store_true",
        help="analysis summary in JSON on the screen (writes no file; use --out to "
        "write and print the summary)",
    )
    _add_global_options(report, suppress=True)

    analyze_cmd = sub.add_parser("analyze", help="analyzes several files and builds an index")
    analyze_cmd.add_argument(
        "paths", nargs="+", metavar="PATH", help=".asm files or directories with sources"
    )
    analyze_cmd.add_argument(
        "--out",
        metavar="DIRECTORY",
        default=None,
        help="directory of the reports (default: output_dir of the configuration)",
    )
    analyze_cmd.add_argument(
        "--format",
        choices=REPORT_FORMATS,
        default="html",
        help="format of each report (default: html)",
    )
    analyze_cmd.add_argument(
        "--index",
        dest="index",
        action="store_true",
        default=True,
        help="writes index.html comparing the files (default)",
    )
    analyze_cmd.add_argument(
        "--no-index", dest="index", action="store_false", help="does not write the index"
    )
    analyze_cmd.add_argument(
        "--no-emulate",
        action="store_true",
        help="does not run the programs; static reports only",
    )
    analyze_cmd.add_argument(
        "--limit", type=int, default=None, help="instruction limit per simulated run"
    )
    analyze_cmd.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="maximum time per simulated run, in seconds",
    )
    analyze_cmd.add_argument(
        "--fail-on",
        choices=RISK_LEVELS,
        default=None,
        help="exits with code 1 if any file reaches this risk",
    )
    analyze_cmd.add_argument(
        "--jobs",
        type=int,
        default=1,
        help="analyses this many files in parallel processes (default: 1, sequential)",
    )
    analyze_cmd.add_argument(
        "--cluster",
        dest="cluster",
        action="store_true",
        help="also groups the files by similarity in the index",
    )
    analyze_cmd.add_argument(
        "--threshold",
        type=float,
        default=0.8,
        help="similarity threshold used by --cluster (default: 0.8)",
    )
    analyze_cmd.add_argument("--json", action="store_true", help="batch analysis summary as JSON")
    _add_global_options(analyze_cmd, suppress=True)

    scan = sub.add_parser("scan", help="matches signature rules against the sources")
    scan.add_argument("paths", nargs="+", metavar="PATH", help=".asm files or directories")
    scan.add_argument(
        "--rules",
        metavar="DIRECTORY",
        default=None,
        help="rule directory (default: the rule set shipped with the package)",
    )
    scan.add_argument(
        "--fail-on",
        choices=RULE_SEVERITIES,
        default=None,
        help="exits with code 1 when a rule of this severity matches",
    )
    scan.add_argument("--json", action="store_true", help="output in JSON")
    _add_global_options(scan, suppress=True)

    rules = sub.add_parser("rules", help="lists the signature rules in effect")
    rules.add_argument(
        "--rules",
        metavar="DIRECTORY",
        default=None,
        help="rule directory (default: the rule set shipped with the package)",
    )
    rules.add_argument("--json", action="store_true", help="output in JSON")
    _add_global_options(rules, suppress=True)

    cluster = sub.add_parser("cluster", help="groups sources by similarity")
    cluster.add_argument("paths", nargs="+", metavar="PATH", help=".asm files or directories")
    cluster.add_argument(
        "--threshold",
        type=float,
        default=0.8,
        help="minimum similarity for two files to share a group (default: 0.8)",
    )
    cluster.add_argument(
        "--linkage",
        choices=("single", "complete"),
        default="single",
        help="single joins by the closest pair, complete demands the whole group (default: single)",
    )
    cluster.add_argument(
        "--top",
        type=int,
        default=0,
        help="also lists the N files closest to the first one (default: 0)",
    )
    cluster.add_argument("--json", action="store_true", help="output in JSON")
    _add_global_options(cluster, suppress=True)

    dashboard = sub.add_parser("dashboard", help="serves a folder of reports on localhost")
    dashboard.add_argument(
        "directory",
        nargs="?",
        default=None,
        metavar="DIRECTORY",
        help="folder with the reports (default: output_dir of the configuration)",
    )
    dashboard.add_argument("--port", type=int, default=8765, help="TCP port (default: 8765)")
    dashboard.add_argument(
        "--host",
        default="127.0.0.1",
        help="interface to bind (default: 127.0.0.1, local connections only)",
    )
    dashboard.add_argument("--token", default=None, help="shared secret required by the page")
    dashboard.add_argument(
        "--open", dest="open_browser", action="store_true", help="opens the page in the browser"
    )
    _add_global_options(dashboard, suppress=True)

    info = sub.add_parser("info", help="version, catalog and configuration in effect")
    info.add_argument("--json", action="store_true", help="output in JSON")
    _add_global_options(info, suppress=True)

    examples = sub.add_parser("examples", help="lists, shows or writes the examples")
    examples.add_argument("--list", action="store_true", help="lists the names and titles")
    examples.add_argument("--show", metavar="NAME", default=None, help="prints the code")
    examples.add_argument(
        "--dump", metavar="DIRECTORY", default=None, help="writes all the examples as .asm"
    )
    examples.add_argument("--json", action="store_true", help="output in JSON")
    _add_global_options(examples, suppress=True)

    version = sub.add_parser("version", help="shows the version")
    version.add_argument("--json", action="store_true", help="output in JSON")
    _add_global_options(version, suppress=True)
    return parser


# -------------------------------------------------------------- utilities --
def _palette(args: argparse.Namespace) -> Palette:
    """Decides whether the output uses color, according to the options and the terminal.

    Returns:
        The palette turned on when the output is a terminal and nothing asked to
        turn it off.
    """
    if getattr(args, "no_color", False) or os.environ.get("NO_COLOR"):
        return Palette(False)
    return Palette(sys.stdout.isatty())


def _severity_rank(severity: str) -> int:
    """Converts the severity into a number, to compare with the accepted minimum.

    Returns:
        ``0`` for error, ``1`` for warning, ``2`` for information and ``3`` for
        an unknown severity.
    """
    return {ERROR: 0, WARNING: 1, INFO: 2}.get(severity, 3)


def _platform_dict(analysis: Analysis) -> Dict[str, Any]:
    """Summarizes the detected platform for the JSON.

    Returns:
        Dictionary with system, bits, confidence, ABI and the evidence found.
    """
    platform = analysis.platform
    return {
        "os": platform.os,
        "bits": platform.bits,
        "confidence": platform.confidence,
        "abi": platform.abi.get("name"),
        "evidence": {key: list(values) for key, values in platform.evidence.items()},
    }


def _emit_json(payload: Any, stream: Optional[TextIO] = None) -> None:
    """Prints a dictionary as indented JSON.

    Args:
        payload: Serializable structure.
        stream: Destination (default ``sys.stdout``).
    """
    destination = stream or sys.stdout
    destination.write(json.dumps(payload, ensure_ascii=False, indent=2, default=str) + "\n")


def _write(text: str, stream: Optional[TextIO] = None) -> None:
    """Writes one line to the destination, without ``print`` (easier to test)."""
    (stream or sys.stdout).write(text + "\n")


def describe_instruction(ins: Any) -> Dict[str, Any]:
    """Builds the record of an analyzed instruction.

    Args:
        ins: :class:`~asmx.parser.Line` object of an instruction.

    Returns:
        Dictionary with line, text, mnemonic, semantic label, explanation,
        category, catalog documentation and classified operands.

    Example:
        >>> from asmx.analyzer import analyze
        >>> describe_instruction(analyze("mov rax, 1").instrs[0])["mnemonic"]
        'mov'
    """
    doc = ISA.get(ins.mnemonic or "")
    return {
        "line": ins.n,
        "text": ins.text,
        "mnemonic": ins.mnemonic,
        "label": ins.sem.label if ins.sem else "",
        "detail": ins.sem.detail if ins.sem else "",
        "tag": ins.sem.tag if ins.sem else "",
        "category": doc["cat"] if doc else None,
        "documentation": doc if doc else None,
        "operands": [
            {
                "text": op.text,
                "type": op.type,
                "size": op.size,
                "reg": op.reg,
                "value": op.value,
                "symbol": op.symbol,
            }
            for op in (ins.operands or [])
        ],
    }


def load_config(args: argparse.Namespace) -> SandboxConfig:
    """Loads the configuration, combining file, environment and command line options.

    Args:
        args: Namespace already parsed by :func:`build_parser`.

    Returns:
        Validated configuration, already with the overrides of the command.

    Raises:
        ConfigError: Indicated file missing or invalid content.
    """
    config = SandboxConfig.load(getattr(args, "config", None))
    return config.merged(
        log_level="DEBUG" if getattr(args, "verbose", False) else None,
        log_file=getattr(args, "log_file", None),
        log_json=True if getattr(args, "log_json", False) else None,
        timeout=getattr(args, "timeout", None),
        max_steps=getattr(args, "limit", None),
    )


def build_payload(args: argparse.Namespace) -> Dict[str, Any]:
    """Describes the call in a dictionary (used in the log and in the tests).

    Args:
        args: Parsed namespace.

    Returns:
        Dictionary with the command and the relevant options.

    Example:
        >>> build_payload(build_parser().parse_args(["check", "a.asm"]))["command"]
        'check'
    """
    data: Dict[str, Any] = {"command": args.command}
    for field_name in (
        "file",
        "files",
        "paths",
        "entry",
        "line",
        "mnemonic",
        "show",
        "dump",
        "out",
        "format",
    ):
        value = getattr(args, field_name, None)
        if value not in (None, False, []):
            data[field_name] = value
    return data


# --------------------------------------------------------------- commands --
def cmd_check(args: argparse.Namespace, config: SandboxConfig, palette: Palette) -> int:
    """Runs the ``check`` command.

    Args:
        args: Namespace of the command.
        config: Configuration in effect.
        palette: Color palette of the output.

    Returns:
        :data:`EXIT_OK` when nothing reaches the minimum severity, otherwise
        :data:`EXIT_PROBLEMS` (or ``EXIT_OK`` with ``--exit-zero``).
    """
    limit = _severity_rank(args.min_severity)
    reports: List[Dict[str, Any]] = []
    all_problems: List[Problem] = []
    total = {name: 0 for name in SUMMARY_KEYS}
    code = EXIT_OK

    for path in args.files:
        source = read_source(path, suffixes=SOURCE_SUFFIXES)
        analysis = analyze(source.text)
        problems = validate(analysis)
        counts: Dict[str, Any] = {
            name: sum(1 for p in problems if p.severity == severity)
            for severity, name in zip(SEVERITIES, SUMMARY_KEYS)
        }
        for severity, name in zip(SEVERITIES, SUMMARY_KEYS):
            total[name] += counts[name]
        all_problems.extend(problems)
        if any(_severity_rank(p.severity) <= limit for p in problems):
            code = EXIT_PROBLEMS
        reports.append(
            {
                "source": source.to_dict(),
                "platform": _platform_dict(analysis),
                "stats": dict(analysis.stats),
                "problems": [p.to_dict() for p in problems],
                "summary": counts,
            }
        )
        log_event(
            logger,
            "check_finished",
            path=source.path,
            lines=source.lines,
            instructions=analysis.stats["instructions"],
            **counts,
        )
        if not args.json:
            _print_check_report(source, analysis, problems, palette, args.summary_only)

    if args.exit_zero:
        code = EXIT_OK
    if args.json:
        _emit_json(
            {
                "schema": "asmx-check/1",
                "command": "check",
                "files": reports,
                "summary": {"files": len(reports), **total},
                "exit_code": code,
            }
        )
    elif len(reports) > 1:
        _write(
            palette.paint(
                "%d file(s): %s" % (len(reports), summary(all_problems)),
                "error" if total["errors"] else "warning",
            )
        )
    return code


def _print_check_report(
    source: SourceFile,
    analysis: Analysis,
    problems: Sequence[Problem],
    palette: Palette,
    summary_only: bool,
) -> None:
    """Prints the readable report of one file in the ``check`` command.

    Args:
        source: File that was read.
        analysis: Result of the analysis.
        problems: Problems that were found.
        palette: Color palette.
        summary_only: When ``True``, omits the problem list.
    """
    platform = analysis.platform
    stats = analysis.stats
    _write(
        "%s %s"
        % (
            palette.paint(source.name, "bold"),
            palette.paint(
                "(%d bytes · %d lines · sha256 %s…)"
                % (source.size, source.lines, source.sha256[:12]),
                "dim",
            ),
        )
    )
    if source.encoding != "utf-8":
        _write(
            "  %s"
            % palette.paint("detected encoding: %s (UTF-8 is ideal)" % source.encoding, "warning")
        )
    _write(
        "  platform  %s · %d bits · %d%% confidence  (%s)"
        % (platform.os, platform.bits, platform.confidence, platform.abi.get("name"))
    )
    _write(
        "  %d instructions · %d blocks · %d syscall(s) · %d call(s) · %d label(s)"
        % (
            stats["instructions"],
            stats["blocks"],
            stats["syscalls"],
            stats["calls"],
            stats["labels"],
        )
    )
    if stats["unknown"]:
        _write(
            "  %s"
            % palette.paint("without documentation: " + ", ".join(stats["unknown"]), "warning")
        )
    if not problems:
        _write("  %s" % palette.paint("no problems found", "good"))
        return
    if not summary_only:
        for problem in problems:
            mark = {ERROR: "error  ", WARNING: "warning", INFO: "info   "}.get(
                problem.severity, "?      "
            )
            _write(
                "  %s L%-4d %-7s %s"
                % (
                    palette.severity(problem.severity, mark),
                    problem.line,
                    problem.code,
                    problem.message,
                )
            )
            if problem.hint:
                _write("         %s" % palette.paint("→ " + problem.hint, "dim"))
    _write(
        "  %s"
        % palette.paint(
            summary(list(problems)),
            "error" if any(p.severity == ERROR for p in problems) else "warning",
        )
    )


def cmd_run(args: argparse.Namespace, config: SandboxConfig, palette: Palette) -> int:
    """Runs the ``run`` command.

    Args:
        args: Namespace of the command.
        config: Configuration in effect (instruction and time limits).
        palette: Color palette of the output.

    Returns:
        :data:`EXIT_OK` when the run finishes clean, :data:`EXIT_PROBLEMS` when
        it reports a problem and :data:`EXIT_TIMEOUT` when the time is exceeded.

    Raises:
        EmulationError: When ``--entry`` points to a nonexistent label.
        SourceNotFoundError: When the file does not exist.
    """
    source = read_source(args.file, suffixes=SOURCE_SUFFIXES)
    analysis = analyze(source.text)
    if args.entry and args.entry not in analysis.label_at:
        raise EmulationError("label not found: %s" % args.entry)
    machine = Machine(analysis, stdin=args.stdin, entry=args.entry)
    steps = machine.run(
        limit=args.limit or config.max_steps,
        timeout=args.timeout,
        raise_on_timeout=args.timeout is not None,
    )
    problems = list(machine.issues)

    log_event(
        logger,
        "run_finished",
        path=source.path,
        steps=steps,
        exit_code=machine.exit_code,
        issues=len(problems),
        timed_out=machine.timed_out,
    )

    if args.json:
        payload: Dict[str, Any] = {
            "schema": "asmx-run/1",
            "command": "run",
            "source": source.to_dict(),
            "entry": args.entry or "program entry point",
            "exit_code": machine.exit_code,
            "output": machine.output,
            "steps": steps,
            "halted": machine.halted,
            "timed_out": machine.timed_out,
            "issues": problems,
            "registers": {key: hexs(value) for key, value in machine.regs.items() if value},
            "flags": dict(machine.flags),
        }
        if args.trace:
            payload["trace"] = [
                {"line": step.line, "text": step.text, "note": step.note}
                for step in machine.trace[-args.max_trace :]
            ]
        _emit_json(payload)
    else:
        _write(
            "%s %s"
            % (
                palette.paint(source.name, "bold"),
                palette.paint("· entry: %s" % (args.entry or "program entry point"), "dim"),
            )
        )
        if machine.output:
            _write("  output:")
            for line in machine.output.splitlines() or [""]:
                _write("    %s" % line)
        else:
            _write("  output: %s" % palette.paint("(empty)", "dim"))
        _write(
            "  %d instructions · exit code %s"
            % (steps, machine.exit_code if machine.exit_code is not None else "not set")
        )
        _write("  RAX=%s  RSP=%s" % (hexs(machine.regs["rax"]), hexs(machine.regs["rsp"])))
        for problem in problems:
            _write("  %s" % palette.paint("⚠ " + problem, "warning"))
        if not problems:
            _write("  %s" % palette.paint("run with no problems", "good"))
        if args.trace:
            _write("")
            _write("  history:")
            for step in machine.trace[-args.max_trace :]:
                _write("    L%-4d %-46s %s" % (step.line, step.text[:46], step.note))

    if machine.timed_out:
        return EXIT_TIMEOUT
    return EXIT_PROBLEMS if problems else EXIT_OK


def cmd_explain(args: argparse.Namespace, config: SandboxConfig, palette: Palette) -> int:
    """Runs the ``explain`` command.

    Args:
        args: Namespace of the command.
        config: Configuration in effect.
        palette: Color palette of the output.

    Returns:
        :data:`EXIT_OK` whenever the explanation is produced.

    Raises:
        UnknownMnemonicError: Mnemonic outside the catalog.
        LineNotFoundError: Line that does not exist in the file.
    """
    if args.mnemonic and args.line is None:
        return _explain_mnemonic(args.mnemonic, args.json, palette)

    source = read_source(args.file, suffixes=SOURCE_SUFFIXES)
    analysis = analyze(source.text)
    line = next((line for line in analysis.program.lines if line.n == args.line), None)
    if line is None:
        raise LineNotFoundError(int(args.line), source.lines)
    if line.kind == "instruction":
        record = describe_instruction(line)
        if args.json:
            _emit_json(
                {
                    "schema": "asmx-explain/1",
                    "command": "explain",
                    "source": source.to_dict(),
                    "kind": "instruction",
                    **record,
                }
            )
        else:
            _print_instruction(record, palette)
        return EXIT_OK

    detail = {
        "line": line.n,
        "kind": line.kind,
        "text": line.text,
        "label": line.label,
        "directive": line.directive,
        "args": list(line.args),
        "section": line.section,
        "func": line.func,
    }
    if args.json:
        _emit_json(
            {"schema": "asmx-explain/1", "command": "explain", "source": source.to_dict(), **detail}
        )
    else:
        _write(
            "%s %s"
            % (
                palette.paint("line %d" % line.n, "title"),
                palette.paint("(%s)" % line.kind, "dim"),
            )
        )
        _write("  %s" % line.text)
        if line.label:
            _write("  label %s%s" % (line.label, " (local)" if line.local_label else ""))
        if line.directive:
            _write(
                "  directive %s%s"
                % (
                    line.directive.upper(),
                    (
                        " · reserves %s byte(s)" % line.unit
                        if line.reserve
                        else " · %d byte(s) per item" % line.unit
                    ),
                )
            )
    return EXIT_OK


def _explain_mnemonic(mnemonic: str, as_json: bool, palette: Palette) -> int:
    """Shows the documentation of a mnemonic from the catalog.

    Args:
        mnemonic: Name of the instruction (``mov``, ``syscall``...).
        as_json: Whether the output should be JSON.
        palette: Color palette.

    Returns:
        :data:`EXIT_OK`.

    Raises:
        UnknownMnemonicError: When the catalog does not document the instruction.
    """
    key = mnemonic.strip().lower()
    doc = ISA.get(key)
    if doc is None:
        raise UnknownMnemonicError(mnemonic, len(ISA))
    if as_json:
        _emit_json(
            {
                "schema": "asmx-explain/1",
                "command": "explain",
                "kind": "mnemonic",
                "mnemonic": key,
                "documentation": doc,
            }
        )
        return EXIT_OK
    category = CATEGORIES.get(doc["cat"], {"label": doc["cat"]})
    _write(
        "%s  %s"
        % (
            palette.paint(key.upper(), "title"),
            palette.paint("· %s · %s" % (doc["name"], category["label"]), "dim"),
        )
    )
    _write("  syntax   %s" % doc["syntax"])
    _write("  %s" % doc["desc"])
    if doc.get("ex"):
        _write("  example")
        for example in doc["ex"]:
            _write("    %s" % example)
    _write("  flags    %s" % doc["flags"])
    if doc.get("note"):
        _write("  %s" % palette.paint(doc["note"], "dim"))
    return EXIT_OK


def _print_instruction(record: Dict[str, Any], palette: Palette) -> None:
    """Prints the record of an analyzed instruction.

    Args:
        record: Dictionary returned by :func:`describe_instruction`.
        palette: Color palette.
    """
    _write(
        "%s %s"
        % (
            palette.paint("line %d" % record["line"], "title"),
            palette.paint(str(record["mnemonic"]).upper(), "bold"),
        )
    )
    _write("  %s" % record["text"])
    _write("  %s — %s" % (palette.paint(record["label"], "good"), record["detail"]))
    doc = record.get("documentation")
    if doc:
        _write("  syntax   %s" % doc["syntax"])
        _write("  flags    %s" % doc["flags"])
        if doc.get("note"):
            _write("  %s" % palette.paint(doc["note"], "dim"))


def cmd_info(args: argparse.Namespace, config: SandboxConfig, palette: Palette) -> int:
    """Runs the ``info`` command.

    Args:
        args: Namespace of the command.
        config: Configuration in effect.
        palette: Color palette of the output.

    Returns:
        :data:`EXIT_OK`.
    """
    try:
        import tkinter  # noqa: F401

        has_tk = True
        tk_version: Optional[str] = str(tkinter.TkVersion)
    except ImportError:
        has_tk = False
        tk_version = None
    state: LoggingState = configure_logging()
    data = {
        "schema": "asmx-info/1",
        "command": "info",
        "version": __version__,
        "python": _platform.python_version(),
        "tkinter": {"available": has_tk, "version": tk_version},
        "platform": _platform.system().lower(),
        "isa": {
            "mnemonics": len(ISA),
            "categories": len(CATEGORIES),
            "linux_syscalls": len(LINUX_SYSCALLS),
            "windows_apis": len(WIN_APIS),
            "validation_rules": len(ALL_CHECKS),
            "examples": len(EXAMPLES),
        },
        "config": config.to_dict(),
        "logging": state.to_dict(),
    }
    if args.json:
        _emit_json(data)
        return EXIT_OK
    _write("%s %s" % (palette.paint("ASM X", "title"), __version__))
    _write(
        "  python %s · tkinter %s"
        % (
            data["python"],
            (
                tk_version
                if has_tk
                else palette.paint("unavailable (only the command line works)", "warning")
            ),
        )
    )
    _write(
        "  catalog: %d instructions · %d categories · %d Linux syscalls · %d Windows APIs"
        % (len(ISA), len(CATEGORIES), len(LINUX_SYSCALLS), len(WIN_APIS))
    )
    _write("  validation: %d rules · examples: %d" % (len(ALL_CHECKS), len(EXAMPLES)))
    _write("  configuration: %s" % config.describe())
    _write("  log: %s · json=%s" % (state.level, state.json_output))
    return EXIT_OK


def cmd_examples(args: argparse.Namespace, config: SandboxConfig, palette: Palette) -> int:
    """Runs the ``examples`` command.

    Args:
        args: Namespace of the command.
        config: Configuration in effect.
        palette: Color palette of the output.

    Returns:
        :data:`EXIT_OK`.

    Raises:
        EmulationError: Nonexistent example name.
    """
    names = sorted(EXAMPLES)
    if args.show:
        if args.show not in EXAMPLES:
            raise EmulationError(
                "unknown example: %s (available: %s)" % (args.show, ", ".join(names))
            )
        _write(EXAMPLES[args.show]["code"])
        return EXIT_OK
    if args.dump:
        os.makedirs(args.dump, exist_ok=True)
        paths = []
        for name in names:
            path = os.path.join(args.dump, "%s.asm" % name)
            with open(path, "w", encoding="utf-8") as file:
                file.write(render(name))
            paths.append(path)
        log_event(logger, "examples_dumped", directory=args.dump, count=len(names))
        if args.json:
            _emit_json(
                {
                    "schema": "asmx-examples/1",
                    "command": "examples",
                    "directory": args.dump,
                    "files": paths,
                }
            )
        else:
            _write(palette.paint("%d examples written to %s" % (len(names), args.dump), "good"))
        return EXIT_OK
    if args.json:
        _emit_json(
            {
                "schema": "asmx-examples/1",
                "command": "examples",
                "examples": [
                    {
                        "name": n,
                        "title": EXAMPLES[n]["title"],
                        "lines": EXAMPLES[n]["code"].count("\n") + 1,
                    }
                    for n in names
                ],
            }
        )
        return EXIT_OK
    for name in names:
        _write("%s %s" % (palette.paint("%-16s" % name, "bold"), EXAMPLES[name]["title"]))
    _write("")
    _write(
        palette.paint(
            "use --show NAME to see the code or --dump DIRECTORY " "to write them all", "dim"
        )
    )
    return EXIT_OK


def cmd_version(args: argparse.Namespace, config: SandboxConfig, palette: Palette) -> int:
    """Runs the ``version`` command.

    Args:
        args: Namespace of the command.
        config: Configuration in effect.
        palette: Color palette of the output.

    Returns:
        :data:`EXIT_OK`.
    """
    if getattr(args, "json", False):
        _emit_json(
            {
                "schema": "asmx-version/1",
                "command": "version",
                "version": __version__,
                "python": _platform.python_version(),
            }
        )
    else:
        _write("ASM X %s" % __version__)
    return EXIT_OK


def _risk_rank(level: str) -> int:
    """Converts the risk level into a number, to compare with ``--fail-on``.

    Args:
        level: ``low``, ``medium``, ``high`` or ``critical``.

    Returns:
        ``0`` to ``3``; an unknown level counts as the mildest one.
    """
    return RISK_LEVELS.index(level) if level in RISK_LEVELS else 0


def _expand_sources(paths: Sequence[str]) -> List[str]:
    """Expands directories into assembly files.

    Args:
        paths: Files and directories given on the command line.

    Returns:
        File paths, in alphabetical order inside each directory; files without a
        recognized extension also enter when they were named directly (the
        reader only complains if they do not exist).
    """
    found: List[str] = []
    for path in paths:
        if os.path.isdir(path):
            for folder, subfolders, names in os.walk(path):
                subfolders[:] = sorted(p for p in subfolders if not p.startswith("."))
                for name in sorted(names):
                    if os.path.splitext(name)[1].lower() in SOURCE_SUFFIXES:
                        found.append(os.path.join(folder, name))
        else:
            found.append(path)
    return found


def _report_summary(name: str, data: Any) -> str:
    """Summarizes a report in one terminal line.

    Args:
        name: Name of the analyzed file.
        data: :class:`~asmx.report.ReportData` already filled in.

    Returns:
        Line with risk, counts and highlights.
    """
    counts = data.counts
    highlights = ", ".join(b["label"] for b in data.behaviors[:3]) or "no relevant behavior"
    return "%-28s %-8s %3d/100  %4d instr  %2d behav  %3d IOC  %2d prob  %s" % (
        name[:28],
        str(data.risk.get("level", "?")).upper(),
        int(data.risk.get("score", 0)),
        counts["instructions"],
        counts["behaviors"],
        counts["iocs"],
        counts["problems"],
        highlights,
    )


def cmd_report(args: argparse.Namespace, config: SandboxConfig, palette: Palette) -> int:
    """Runs the ``report`` command.

    Args:
        args: Namespace of the command.
        config: Configuration in effect (output directory and limits).
        palette: Color palette of the output.

    Returns:
        :data:`EXIT_OK` when writing, :data:`EXIT_PROBLEMS` when ``--fail-on``
        is reached.
    """
    from .report import collect, write_report

    source = read_source(args.file, suffixes=SOURCE_SUFFIXES)
    data = collect(
        source.text,
        source=source,
        emulate=not args.no_emulate,
        limit=args.limit or config.max_steps,
        timeout=args.timeout,
        stdin=args.stdin,
        entry=args.entry,
        command="asmx report %s" % source.name,
    )

    # `--json` is script mode: it prints the summary and writes nothing without `--out`.
    summary_only = args.json and args.out is None
    destination = args.out
    if destination is None and not summary_only:
        if (args.format or "html") == "html":
            os.makedirs(config.output_dir, exist_ok=True)
            destination = os.path.join(
                config.output_dir, "%s.report.html" % os.path.splitext(source.name)[0]
            )
        else:
            destination = "-"
    written = "-" if summary_only else write_report(data, destination, fmt=args.format)

    if args.json:
        _emit_json(
            {
                "schema": "asmx-report/1",
                "command": "report",
                "file": source.name,
                "output": written,
                "risk": data.risk,
                "counts": data.counts,
                "behaviors": [b["category"] for b in data.behaviors],
                "techniques": [t["id"] for t in data.techniques],
                "exit_code": EXIT_PROBLEMS if _reached(args.fail_on, data) else EXIT_OK,
            }
        )
    elif written != "-":
        _write(
            "%s %s" % (palette.paint("report written to", "good"), palette.paint(written, "bold"))
        )
        _write("  %s" % _report_summary(source.name, data))
    if args.open and written != "-":
        webbrowser.open("file://" + os.path.abspath(written))
    return EXIT_PROBLEMS if _reached(args.fail_on, data) else EXIT_OK


def _reached(limit: Optional[str], data: Any) -> bool:
    """Tells whether the risk of the report reached the requested limit.

    Args:
        limit: Level passed in ``--fail-on`` (``None`` turns the check off).
        data: Filled report.

    Returns:
        ``True`` when the risk of the file is equal to or higher than the limit.
    """
    if not limit:
        return False
    return _risk_rank(str(data.risk.get("level", "low"))) >= _risk_rank(limit)


def cmd_analyze(args: argparse.Namespace, config: SandboxConfig, palette: Palette) -> int:
    """Runs the ``analyze`` command (several files and a comparative index).

    Args:
        args: Namespace of the command.
        config: Configuration in effect.
        palette: Color palette of the output.

    Returns:
        :data:`EXIT_OK`, or :data:`EXIT_PROBLEMS` when some file reaches the
        risk requested in ``--fail-on``.

    Raises:
        ProjectError: When no assembly file was found in the paths.
        SourceNotFoundError: When an indicated file does not exist.
    """
    from .report import render_index, write_report

    paths = _expand_sources(args.paths)
    if not paths:
        raise ProjectError("no assembly file found in: %s" % ", ".join(args.paths))
    folder = args.out or config.output_dir
    os.makedirs(folder, exist_ok=True)
    extension = FORMAT_SUFFIX.get(args.format, "html")
    reports: List[Any] = []
    analyses: List[Any] = []
    worst = EXIT_OK

    for name, data, analysis in _analysis_jobs(paths, args, config, folder, extension):
        destination = os.path.join(folder, str(data.source.get("report_file")))
        write_report(data, destination, fmt=args.format)
        reports.append(data)
        analyses.append(analysis)
        if _reached(args.fail_on, data):
            worst = EXIT_PROBLEMS
        if not args.json:
            _write("  %s" % _report_summary(name, data))

    # The manifest is what the dashboard reads and what another tool consumes,
    # so it is written in every format — `analyze --format md` stays useful.
    found: List[Dict[str, Any]] = []
    if getattr(args, "cluster", False):
        from .similarity import groups

        found = groups(
            [{"name": str(r.source.get("name")), "analysis": a} for r, a in zip(reports, analyses)],
            threshold=getattr(args, "threshold", 0.8),
        )
    manifest: Dict[str, Any] = {
        "schema": "asmx-analyze/1",
        "command": "analyze",
        "directory": folder,
        "format": args.format,
        "files": [
            {
                "name": r.source.get("name"),
                "risk": r.risk.get("level"),
                "score": r.risk.get("score"),
                "reason": (r.risk.get("reasons") or [""])[0],
                "instructions": r.counts.get("instructions", 0),
                "behaviors": r.counts.get("behaviors", 0),
                "indicators": r.counts.get("iocs", 0),
                "problems": r.counts.get("problems", 0),
                "platform": "%s · %d-bit" % (r.platform.get("os"), r.platform.get("bits", 64)),
                "report": r.source.get("report_file"),
            }
            for r in reports
        ],
        "groups": found,
        "exit_code": worst,
    }
    manifest_path = os.path.join(folder, "index.json")
    with open(manifest_path, "w", encoding="utf-8") as file:
        json.dump(manifest, file, ensure_ascii=False, indent=2, sort_keys=False)
    log_event(logger, "manifest_written", path=manifest_path, files=len(reports))

    index = ""
    if args.index and args.format == "html":
        index = os.path.join(folder, "index.html")
        with open(index, "w", encoding="utf-8") as file:
            file.write(render_index(reports, command="asmx analyze %s" % " ".join(args.paths)))
        log_event(logger, "index_written", path=index, files=len(reports))

    manifest["index"] = index
    if args.json:
        manifest["counts"] = {r.source.get("name"): r.counts for r in reports}
        _emit_json(manifest)
    else:
        _write("")
        _write(
            "%s %d file(s) · %d with high or critical risk%s"
            % (
                palette.paint("summary:", "bold"),
                len(reports),
                sum(1 for r in reports if _risk_rank(str(r.risk.get("level"))) >= 2),
                " · %d similar group(s)" % len(found) if found else "",
            )
        )
        _write(
            "  reports and manifest in %s%s"
            % (
                palette.paint(folder, "good"),
                " · index at %s" % palette.paint(index, "good") if index else "",
            )
        )
    return worst


def _analysis_jobs(
    paths: Sequence[str],
    args: argparse.Namespace,
    config: SandboxConfig,
    folder: str,
    extension: str,
) -> List[Tuple[str, Any, Any]]:
    """Analyses the files, in parallel processes when asked.

    Each worker opens its own file and returns ``(name, report, analysis)``; the
    reports are plain dictionaries, so they cross the process boundary without
    any pickling surprise. A worker that fails on one file does not take the
    batch down: the error is reported and the file is skipped.

    Args:
        paths: Files to analyse.
        args: Namespace of the ``analyze`` command.
        config: Configuration in effect.
        folder: Directory where the reports are written.
        extension: Suffix of each report file.

    Returns:
        List of ``(source name, ReportData, Analysis)`` in the order of
        ``paths``.
    """
    total = max(1, int(getattr(args, "jobs", 1) or 1))
    options = {
        "emulate": not args.no_emulate,
        "limit": args.limit or config.max_steps,
        "timeout": args.timeout,
        "command": "asmx analyze %s" % " ".join(args.paths),
        "extension": extension,
    }
    results: List[Tuple[str, Any, Any]] = []
    if total == 1 or len(paths) == 1:
        for path in paths:
            name, data, analysis, destination = _analyze_file(path, options)
            data.source["report_file"] = destination
            results.append((name, data, analysis))
        return results

    workers = min(total, len(paths))
    log_event(logger, "analyze_parallel", files=len(paths), workers=workers)
    with futures.ProcessPoolExecutor(max_workers=workers) as pool:
        pending = {pool.submit(_analyze_file, path, options): path for path in paths}
        for future in futures.as_completed(pending):
            path = pending[future]
            try:
                name, data, analysis, destination = future.result()
            except (AsmxError, OSError) as error:
                sys.stderr.write("skipping %s: %s\n" % (path, error))
                continue
            data.source["report_file"] = destination
            results.append((name, data, analysis))
    order = {os.path.basename(path): position for position, path in enumerate(paths)}
    results.sort(key=lambda pair: order.get(pair[0], len(order)))
    return results


def _analyze_file(path: str, options: Dict[str, Any]) -> Tuple[str, Any, Any, str]:
    """Analyzes one file; safe to call in another process.

    The function lives at module level and takes plain data, because a closure
    cannot be pickled — and a worker that cannot be pickled silently turns
    ``--jobs N`` into a crash.

    Args:
        path: File to analyse.
        options: ``emulate``, ``limit``, ``timeout``, ``command`` and
            ``extension``, all plain values.

    Returns:
        Tuple ``(source name, ReportData, Analysis, report file name)``.

    Raises:
        SourceNotFoundError: The file does not exist.
        SourceReadError: The file cannot be read.
    """
    from .report import collect

    source = read_source(path, suffixes=SOURCE_SUFFIXES)
    analysis = analyze(source.text)
    data = collect(
        source.text,
        source=source,
        analysis=analysis,
        emulate=bool(options.get("emulate", True)),
        limit=int(options.get("limit") or 200000),
        timeout=options.get("timeout"),
        command=str(options.get("command") or "asmx analyze"),
    )
    base_name = os.path.splitext(source.name)[0]
    return (
        source.name,
        data,
        analysis,
        "%s.report.%s" % (base_name, options.get("extension") or "html"),
    )


def cmd_scan(args: argparse.Namespace, config: SandboxConfig, palette: Palette) -> int:
    """Runs the ``scan`` command (signature rules over one or more sources).

    Args:
        args: Namespace of the command.
        config: Configuration in effect.
        palette: Color palette of the output.

    Returns:
        :data:`EXIT_OK`, or :data:`EXIT_PROBLEMS` when a match reaches the
        severity requested in ``--fail-on``.

    Raises:
        ProjectError: When no assembly file was found in the paths.
        ConfigError: When a rule file is invalid.
    """
    from .rules import load_rules, match_rules, severity_rank, summary as rules_summary

    paths = _expand_sources(args.paths)
    if not paths:
        raise ProjectError("no assembly file found in: %s" % ", ".join(args.paths))
    rules = load_rules(directory=getattr(args, "rules", None))
    exit_code = EXIT_OK
    payload: List[Dict[str, Any]] = []

    if not args.json:
        _write(
            "%s %d rule(s) from %s"
            % (
                palette.paint("rules:", "bold"),
                len(rules),
                os.path.dirname(rules[0].source) if rules and rules[0].source else "?",
            )
        )

    for path in paths:
        source = read_source(path, suffixes=SOURCE_SUFFIXES)
        analysis = analyze(source.text)
        problems = validate(analysis)
        matches = match_rules(rules, analysis, problems=problems, text=source.text)
        payload.append(
            {
                "name": source.name,
                "matches": [m.to_dict() for m in matches],
                "summary": rules_summary(matches),
            }
        )
        if args.fail_on and any(
            severity_rank(m.severity) <= severity_rank(args.fail_on) for m in matches
        ):
            exit_code = EXIT_PROBLEMS
        if not args.json:
            _write("")
            _write("  %s %s" % (palette.paint(source.name, "bold"), rules_summary(matches)))
            for match in matches:
                _write(
                    "    %-7s %-8s %s"
                    % (
                        palette.paint(match.rule_id, "bold"),
                        match.severity,
                        match.name,
                    )
                )
                for evidence in match.evidence:
                    _write("            %s" % evidence)

    if args.json:
        _emit_json(
            {
                "schema": "asmx-scan/1",
                "command": "scan",
                "rules": len(rules),
                "files": payload,
                "exit_code": exit_code,
            }
        )
    elif len(paths) > 1:
        total = sum(len(item["matches"]) for item in payload)
        _write("")
        _write(
            "%s %d file(s) · %d match(es)"
            % (palette.paint("summary:", "bold"), len(payload), total)
        )
    return exit_code


def cmd_rules(args: argparse.Namespace, config: SandboxConfig, palette: Palette) -> int:
    """Runs the ``rules`` command (lists the rule set in effect).

    Args:
        args: Namespace of the command.
        config: Configuration in effect.
        palette: Color palette of the output.

    Returns:
        :data:`EXIT_OK`.
    """
    from .rules import SEVERITIES as RULE_SEVERITIES
    from .rules import default_rules_dir, load_rules

    directory = getattr(args, "rules", None) or default_rules_dir()
    rules = load_rules(directory=getattr(args, "rules", None))
    if args.json:
        _emit_json(
            {
                "schema": "asmx-rules/1",
                "command": "rules",
                "directory": directory,
                "rules": [rule.to_dict() for rule in rules],
            }
        )
        return EXIT_OK
    _write(
        "%s %d rule(s) in %s"
        % (palette.paint("rules:", "bold"), len(rules), palette.paint(directory, "dim"))
    )
    for severity in RULE_SEVERITIES:
        group = [rule for rule in rules if rule.severity == severity]
        if not group:
            continue
        _write("")
        _write("  %s" % palette.paint("%s (%d)" % (severity, len(group)), "bold"))
        for rule in group:
            _write("    %-7s %s" % (rule.id, rule.name))
            if rule.tags:
                _write("            tags: %s" % ", ".join(rule.tags))
    return EXIT_OK


def cmd_cluster(args: argparse.Namespace, config: SandboxConfig, palette: Palette) -> int:
    """Runs the ``cluster`` command (groups sources by similarity).

    Args:
        args: Namespace of the command.
        config: Configuration in effect.
        palette: Color palette of the output.

    Returns:
        :data:`EXIT_OK`.

    Raises:
        ProjectError: When no assembly file was found in the paths.
    """
    from .similarity import feature_vector, groups, similar_to

    paths = _expand_sources(args.paths)
    if not paths:
        raise ProjectError("no assembly file found in: %s" % ", ".join(args.paths))
    samples: List[Dict[str, Any]] = []
    for path in paths:
        source = read_source(path, suffixes=SOURCE_SUFFIXES)
        samples.append({"name": source.name, "analysis": analyze(source.text)})
    found = groups(samples, threshold=args.threshold, linkage=args.linkage)

    if args.json:
        payload: Dict[str, Any] = {
            "schema": "asmx-cluster/1",
            "command": "cluster",
            "threshold": args.threshold,
            "linkage": args.linkage,
            "files": len(samples),
            "groups": found,
        }
        if args.top:
            vectors = [feature_vector(item["analysis"]) for item in samples]
            payload["closest_to_first"] = [
                {"name": samples[index]["name"], "similarity": round(score, 4)}
                for index, score in similar_to(vectors[0], vectors, top=args.top + 1)[1:]
            ]
        _emit_json(payload)
        return EXIT_OK

    _write(
        "%s %d file(s) · %d group(s) · threshold %.2f (%s linkage)"
        % (
            palette.paint("cluster:", "bold"),
            len(samples),
            len(found),
            args.threshold,
            args.linkage,
        )
    )
    for group in found:
        _write("")
        _write(
            "  %s %s"
            % (
                palette.paint("%d file(s)" % group["size"], "bold"),
                palette.paint("cohesion %.2f" % group["cohesion"], "dim"),
            )
        )
        if group["label"]:
            _write("      shared signal: %s" % group["label"])
        for member in group["members"]:
            _write("      %s" % member)
    if args.top:
        vectors = [feature_vector(item["analysis"]) for item in samples]
        _write("")
        _write("  %s" % palette.paint("closest to %s" % samples[0]["name"], "bold"))
        for index, score in similar_to(vectors[0], vectors, top=args.top + 1)[1:]:
            _write("      %.3f  %s" % (score, samples[index]["name"]))
    return EXIT_OK


def cmd_dashboard(args: argparse.Namespace, config: SandboxConfig, palette: Palette) -> int:
    """Runs the ``dashboard`` command (serves a folder of reports).

    Args:
        args: Namespace of the command.
        config: Configuration in effect.
        palette: Color palette of the output.

    Returns:
        :data:`EXIT_OK`, or :data:`EXIT_INPUT` when the served folder has no
        report at all.
    """
    from .dashboard import load_samples, serve

    folder = args.directory or config.output_dir
    samples = load_samples(folder)
    if not samples:
        sys.stderr.write(
            "no report found in %s\n" "  run: asmx analyze <files> --out %s\n" % (folder, folder)
        )
        return EXIT_INPUT
    server, url = serve(
        folder,
        host=args.host,
        port=args.port,
        title="ASM X — %s" % os.path.basename(os.path.abspath(folder)),
        token=args.token,
        open_browser=args.open_browser,
    )
    _write("%s %d sample(s) from %s" % (palette.paint("dashboard:", "bold"), len(samples), folder))
    _write("  %s" % palette.paint(url, "good"))
    _write("  read-only · press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        _write("")
        _write("  stopped")
    finally:
        server.server_close()
    return EXIT_OK


#: Available commands, bound to the functions that run them.
COMMANDS: Dict[str, Callable[[argparse.Namespace, SandboxConfig, Palette], int]] = {
    "check": cmd_check,
    "report": cmd_report,
    "analyze": cmd_analyze,
    "scan": cmd_scan,
    "rules": cmd_rules,
    "cluster": cmd_cluster,
    "dashboard": cmd_dashboard,
    "run": cmd_run,
    "explain": cmd_explain,
    "info": cmd_info,
    "examples": cmd_examples,
    "version": cmd_version,
}


def launch_gui() -> int:
    """Opens the graphical interface, if Tkinter and a display exist.

    Returns:
        :data:`EXIT_OK` when the window closes normally, :data:`EXIT_INPUT` when
        there is no Tkinter or display.
    """
    try:
        from .ui import main as ui_main
    except ImportError as error:
        sys.stderr.write(
            "the graphical interface needs Tkinter, which is not installed (%s).\n"
            "  Debian/Ubuntu:  sudo apt install python3-tk\n"
            "  Fedora:         sudo dnf install python3-tkinter\n"
            "  Windows/macOS:  reinstall Python with the 'tcl/tk' option checked\n"
            "the command line commands remain available: asmx --help\n" % error
        )
        return EXIT_INPUT
    try:
        ui_main()
    except Exception as error:  # pragma: no cover - depends on a real display
        sys.stderr.write("could not open the window: %s\n" % error)
        return EXIT_INPUT
    return EXIT_OK


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point of the command line.

    With no arguments (a real system call) it opens the graphical interface;
    with an explicit ``argv`` it requires a command — which keeps the tests
    predictable.

    Args:
        argv: Arguments without the program name; ``None`` uses ``sys.argv[1:]``.

    Returns:
        The exit code of the process (see the top of the module).
    """
    real_call = argv is None
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if getattr(args, "gui", False) or (real_call and not args.command):
        return launch_gui()
    if not args.command:
        parser.print_help()
        return EXIT_USAGE

    palette = _palette(args)
    try:
        config = load_config(args)
    except AsmxError as error:
        sys.stderr.write("%s\n" % palette.paint(str(error), "error"))
        return EXIT_INPUT
    # In the terminal the default is to say little: the output of the command is
    # the result. -v brings INFO/DEBUG, -q silences even the errors.
    config.apply_logging(force=True)
    configure_logging(
        "DEBUG" if args.verbose else ("ERROR" if args.quiet else "WARNING"),
        json_output=config.log_json,
        log_file=config.log_file,
        force=True,
    )

    log_event(logger, "command_started", level=10, **build_payload(args))
    try:
        code = COMMANDS[args.command](args, config, palette)
    except (
        SourceNotFoundError,
        SourceReadError,
        UnsupportedSourceError,
        ConfigError,
        UnknownMnemonicError,
        LineNotFoundError,
        EmulationError,
    ) as error:
        log_event(logger, "command_input_error", level=40, code=error.code, detail=error.message)
        sys.stderr.write("%s\n" % palette.paint(str(error), "error"))
        return EXIT_INPUT
    except AnalysisTimeoutError as error:
        log_event(logger, "command_timeout", level=40, timeout=error.timeout, steps=error.steps)
        sys.stderr.write("%s\n" % palette.paint(str(error), "error"))
        return EXIT_TIMEOUT
    except AsmxError as error:
        log_event(logger, "command_failed", level=40, code=error.code, detail=error.message)
        sys.stderr.write("%s\n" % palette.paint(str(error), "error"))
        return EXIT_INPUT
    except KeyboardInterrupt:  # pragma: no cover - user interaction
        sys.stderr.write("\ninterrupted\n")
        return 130
    log_event(logger, "command_finished", exit_code=code)
    return code
