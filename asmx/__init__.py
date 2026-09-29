"""ASM X — study and debugging environment for x86-64 assembly.

The idea is simple: read the assembly and explain what it does before any heavy
tool gets in the way. The package is split into layers that do not depend on one
another, from the bottom up:

    isa        instruction, register, flag and syscall catalog
    parser     source reading (NASM/Intel, MASM, GAS/AT&T)
    analyzer   platform, per-instruction semantics, blocks and flow
    emulator   step by step virtual machine
    linter     static validation (what can break before running)
    workspace  project, branches, notes and test scenarios
    config     configuration (file, environment, defaults)
    errors     exceptions with stable codes
    source     file reading with hash and encoding
    behavior   observed behaviors + MITRE ATT&CK
    iocs       strings, URLs, IPs, domains, paths and other indicators
    cfg        control flow and call graph (SVG, DOT, Mermaid)
    report     analysis report in HTML, Markdown, JSON and DOT
    cli        command line
    ui         graphical interface in Tkinter

Nothing here depends on an external library: only the Python standard library.

Example:
    >>> import asmx
    >>> analysis = asmx.analyze("mov rax, 1\\nsyscall")
    >>> analysis.stats["instructions"]
    2
    >>> asmx.summary(asmx.validate(analysis))
    '0 error(s), 2 warning(s), 0 info(s)'
"""

from __future__ import annotations

from typing import Tuple

__version__ = "1.0.0"

#: Version split into numbers, for comparison.
__version_info__: Tuple[int, int, int] = (1, 0, 0)

from .analyzer import Analysis, analyze, callers_of, functions  # noqa: E402
from .behavior import Behavior, classify, severity_rank  # noqa: E402
from .cfg import Graph, call_graph, control_flow_graph  # noqa: E402
from .config import SandboxConfig  # noqa: E402
from .emulator import Machine, Step  # noqa: E402
from .errors import ERROR_CODES, AsmxError  # noqa: E402
from .iocs import Ioc  # noqa: E402
from .iocs import extract as extract_iocs  # noqa: E402
from .iocs import group as group_iocs  # noqa: E402
from .linter import Problem, summary, validate  # noqa: E402
from .logging_setup import configure_logging, get_logger, log_event  # noqa: E402
from .parser import Line, Operand, Program, parse  # noqa: E402
from .dashboard import serve as serve_dashboard  # noqa: E402
from .report import ReportData, collect, render_html, write_report  # noqa: E402
from .rules import Rule, RuleMatch, load_rules, match_text  # noqa: E402
from .similarity import cluster, cosine, feature_vector, groups  # noqa: E402
from .source import SourceFile, read_source  # noqa: E402
from .workspace import (  # noqa: E402
    Branch,
    Project,
    Scenario,
    ScenarioResult,
    run_all_scenarios,
    run_scenario,
)

__all__ = [
    "__version__",
    "__version_info__",
    "Analysis",
    "Rule",
    "RuleMatch",
    "AsmxError",
    "Behavior",
    "Branch",
    "ERROR_CODES",
    "Graph",
    "Ioc",
    "Line",
    "Machine",
    "Operand",
    "Problem",
    "Program",
    "Project",
    "ReportData",
    "SandboxConfig",
    "Scenario",
    "ScenarioResult",
    "SourceFile",
    "Step",
    "analyze",
    "call_graph",
    "cluster",
    "cosine",
    "feature_vector",
    "groups",
    "load_rules",
    "match_text",
    "serve_dashboard",
    "callers_of",
    "classify",
    "collect",
    "configure_logging",
    "control_flow_graph",
    "extract_iocs",
    "functions",
    "get_logger",
    "group_iocs",
    "log_event",
    "parse",
    "read_source",
    "render_html",
    "run_all_scenarios",
    "run_scenario",
    "severity_rank",
    "summary",
    "validate",
    "write_report",
]
