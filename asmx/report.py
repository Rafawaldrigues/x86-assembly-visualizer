"""Report: turns the analysis into something one can look at, save and publish.

This module brings together everything the other layers produce — file metadata,
platform, explained instructions, validation, behaviors with MITRE ATT&CK,
indicators, control-flow and call graphs, and the execution on the virtual
machine — into a single object (:class:`ReportData`) and knows how to draw that
object in four formats:

* **HTML** — a single file, no network: CSS, JavaScript and the graphs as SVG are
  embedded, so the report opens offline in the browser, with no CDN and no
  server. It is the format to look at and share;
* **Markdown** — text to paste into an issue, pull request or blog, with the
  graph as Mermaid that GitHub draws by itself;
* **JSON** — the raw data, with the ``asmx-report/1`` schema, for automation;
* **DOT/Mermaid/SVG** — the graphs alone, for whoever wants to edit them in
  Graphviz.

Nothing here depends on an external library, and no format makes a network
request: the report belongs to the user, not to a service.

Example:
    >>> from asmx.report import collect, render_markdown
    >>> data = collect("global _start\\nsection .text\\n_start:\\n mov rax, 60\\n syscall")
    >>> data.risk["level"] in ("low", "medium", "high", "critical")
    True
    >>> "ASM X" in render_markdown(data)
    True
"""

from __future__ import annotations

import datetime
import html
import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import __version__
from .analyzer import Analysis, analyze
from .behavior import Behavior, classify, severity_rank, techniques, to_dicts as behaviors_to_dicts
from .cfg import call_graph, control_flow_graph, to_dot, to_mermaid, to_svg
from .emulator import Machine, hexs, to_signed
from .errors import ProjectError, SourceWriteError
from .iocs import extract as extract_iocs
from .iocs import from_memory as iocs_from_memory
from .iocs import to_dicts as iocs_to_dicts
from .isa import LINUX_SYSCALLS
from .linter import ERROR, INFO, WARNING, Problem, summary as problem_summary, validate
from .logging_setup import get_logger, log_event
from .source import SourceFile, fingerprint

logger = get_logger(__name__)

__all__ = [
    "REPORT_SCHEMA",
    "FORMATS",
    "ReportData",
    "collect",
    "risk_assessment",
    "executive_summary",
    "render_html",
    "render_markdown",
    "render_json",
    "render_dot",
    "render_svg",
    "render_index",
    "write_report",
    "guess_format",
]

#: JSON report schema, for whoever consumes the data.
REPORT_SCHEMA = "asmx-report/1"

#: Formats accepted by :func:`write_report`.
FORMATS: Tuple[str, ...] = ("html", "md", "json", "dot", "svg", "mermaid")

#: How many execution steps go into the report timeline.
TIMELINE_LIMIT = 400

#: Weights used in the risk calculation.
PROBLEM_WEIGHTS = {ERROR: 25, WARNING: 8, INFO: 2}
BEHAVIOR_WEIGHTS = {"high": 18, "medium": 9, "low": 3}

#: Color and emoji of each risk level.
RISK_STYLE = {
    "low": ("#5FD4A8", "🟢", "Nothing here points to dangerous behavior."),
    "medium": ("#E3A44B", "🟡", "There are signs that deserve a careful read before running."),
    "high": ("#F08A5D", "🟠", "The signals together call for caution: review before assembling."),
    "critical": ("#EF7D9D", "🔴", "Many strong signals at once: treat it as hostile."),
}


def _now() -> str:
    """Return the generation instant in local ISO-8601.

    Returns:
        Text such as ``2026-09-21T19:40:12``.
    """
    return datetime.datetime.now().replace(microsecond=0).isoformat()


def guess_format(path: str) -> str:
    """Find the report format from the file extension.

    Args:
        path: Output path.

    Returns:
        A name from :data:`FORMATS`; ``"html"`` when the extension is unknown.
    """
    extension = os.path.splitext(path)[1].lstrip(".").lower()
    return extension if extension in FORMATS else "html"


@dataclass
class ReportData:
    """Everything the report shows, already in simple types.

    Attributes:
        schema: Schema identifier (``asmx-report/1``).
        generated_at: Generation instant.
        version: Version of ASM X that generated the report.
        command: Command line used, when there is one.
        source: File metadata (name, hashes, size, encoding).
        platform: System, bits, detection confidence, ABI and evidence.
        dialect: Dialect detected by the parser (``intel``, ``masm``, ``att``).
        stats: Analyzer counts (instructions, blocks, syscalls...).
        risk: Risk level, color, emoji and description.
        summary: Text of the executive summary.
        problems: Validation problems, already as dictionaries.
        behaviors: Behavior detected.
        techniques: Aggregated MITRE ATT&CK techniques.
        iocs: Indicators grouped by kind.
        instructions: Instructions with the explanation of each one.
        blocks: Basic blocks with "comes from" and "goes to".
        cfg: Control-flow graph (graph, SVG, DOT and Mermaid).
        calls: Call graph (same structure).
        syscalls: Syscalls found, aggregated by name.
        apis: External APIs called.
        execution: Result of the execution on the virtual machine, when asked.
        timeline: Execution steps, in order.
    """

    schema: str = REPORT_SCHEMA
    generated_at: str = field(default_factory=_now)
    version: str = __version__
    command: str = ""
    source: Dict[str, Any] = field(default_factory=dict)
    platform: Dict[str, Any] = field(default_factory=dict)
    dialect: str = "intel"
    stats: Dict[str, Any] = field(default_factory=dict)
    risk: Dict[str, Any] = field(default_factory=dict)
    summary: str = ""
    problems: List[Dict[str, Any]] = field(default_factory=list)
    behaviors: List[Dict[str, Any]] = field(default_factory=list)
    techniques: List[Dict[str, Any]] = field(default_factory=list)
    iocs: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    instructions: List[Dict[str, Any]] = field(default_factory=list)
    blocks: List[Dict[str, Any]] = field(default_factory=list)
    cfg: Dict[str, Any] = field(default_factory=dict)
    calls: Dict[str, Any] = field(default_factory=dict)
    syscalls: List[Dict[str, Any]] = field(default_factory=list)
    apis: List[str] = field(default_factory=list)
    execution: Optional[Dict[str, Any]] = None
    timeline: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self, *, include_svg: bool = False) -> Dict[str, Any]:
        """Convert the report into a dictionary ready for JSON.

        Args:
            include_svg: When ``True``, keeps the graph SVG (useful to generate
                an HTML from the JSON; makes the file much larger).

        Returns:
            Dictionary with the schema, the metadata and every section.
        """
        data: Dict[str, Any] = {
            "schema": self.schema,
            "generated_at": self.generated_at,
            "version": self.version,
            "command": self.command,
            "source": self.source,
            "platform": self.platform,
            "dialect": self.dialect,
            "stats": self.stats,
            "risk": self.risk,
            "summary": self.summary,
            "problems": self.problems,
            "behaviors": self.behaviors,
            "techniques": self.techniques,
            "iocs": self.iocs,
            "instructions": self.instructions,
            "blocks": self.blocks,
            "cfg": {k: v for k, v in self.cfg.items() if include_svg or k != "svg"},
            "calls": {k: v for k, v in self.calls.items() if include_svg or k != "svg"},
            "syscalls": self.syscalls,
            "apis": self.apis,
            "execution": self.execution,
            "timeline": self.timeline,
        }
        return data

    @property
    def counts(self) -> Dict[str, int]:
        """Counts used in the cards at the top of the report.

        Returns:
            Dictionary with instructions, blocks, calls, syscalls, problems,
            behaviors, indicators and strings.
        """
        total_iocs = sum(len(values) for values in self.iocs.values())
        return {
            "instructions": int(self.stats.get("instructions", 0)),
            "blocks": int(self.stats.get("blocks", 0)),
            "calls": int(self.stats.get("calls", 0)),
            "syscalls": int(self.stats.get("syscalls", 0)),
            "problems": len(self.problems),
            "behaviors": len(self.behaviors),
            "iocs": total_iocs,
            "strings": len(self.iocs.get("string", [])),
        }


# ----------------------------------------------------------- collection ----
def risk_assessment(
    problems: Sequence[Problem],
    behaviors: Sequence[Behavior],
    stats: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Compute the risk level from the problems and the behaviors.

    The arithmetic is simple and explainable on purpose: each validation error
    weighs 25, each warning 8 and each information 2; each behavior of high
    severity weighs 18, medium 9 and low 3. The total is capped at 100.

    Args:
        problems: Problems returned by the validator.
        behaviors: Classified behaviors.
        stats: Analyzer statistics (used only to cite the size).

    Returns:
        Dictionary with ``score``, ``level``, ``color``, ``emoji``,
        ``description`` and ``reasons`` (what weighed the most).

    Example:
        >>> risk_assessment([], [])["level"]
        'low'
    """
    score = 0
    reasons: List[str] = []
    for problem in problems:
        score += PROBLEM_WEIGHTS.get(problem.severity, 0)
    if problems:
        errors = sum(1 for p in problems if p.severity == ERROR)
        warnings = sum(1 for p in problems if p.severity == WARNING)
        if errors:
            reasons.append("%d validation error(s)" % errors)
        if warnings:
            reasons.append("%d validation warning(s)" % warnings)
    for behavior in behaviors:
        score += BEHAVIOR_WEIGHTS.get(behavior.severity, 0)
    for severity in ("high", "medium", "low"):
        labels = [b.label for b in behaviors if b.severity == severity]
        if labels:
            reasons.append("%s: %s" % (severity, ", ".join(sorted(labels))))
    score = max(0, min(100, score))
    if score >= 70:
        level = "critical"
    elif score >= 40:
        level = "high"
    elif score >= 15:
        level = "medium"
    else:
        level = "low"
    color, emoji, description = RISK_STYLE[level]
    return {
        "score": score,
        "level": level,
        "color": color,
        "emoji": emoji,
        "description": description,
        "reasons": reasons,
        "instructions": int((stats or {}).get("instructions", 0)),
    }


def executive_summary(data: ReportData) -> str:
    """Write the executive summary paragraph of the report.

    Args:
        data: Report already filled in (except the summary itself).

    Returns:
        Two or three sentences saying what the program is, what it does and what
        deserves attention.
    """
    name = data.source.get("name", "program")
    platform = data.platform.get("os", "undefined")
    bits = data.platform.get("bits", 64)
    abi = data.platform.get("abi") or "undefined ABI"
    counts = data.counts
    parts = [
        "%s has %d instruction(s) in %d block(s), written for %s %d bits (%s)."
        % (name, counts["instructions"], counts["blocks"], platform, bits, abi)
    ]
    if counts["behaviors"]:
        labels = ", ".join(b["label"] for b in data.behaviors[:4])
        parts.append("Behaviors observed: %s." % labels)
    else:
        parts.append("No relevant behavior was identified.")
    if counts["problems"]:
        parts.append(
            "Validation reported %s."
            % problem_summary(
                [
                    Problem(p["line"], p["severity"], p["code"], p["message"], p.get("hint", ""))
                    for p in data.problems
                ]
            )
        )
    else:
        parts.append("Validation found no problem.")
    if counts["iocs"]:
        parts.append("There are %d indicator(s) in the program text." % counts["iocs"])
    if data.execution is not None:
        output = (data.execution.get("output") or "").strip()
        run_summary = "The simulated execution finished with exit code %s" % data.execution.get(
            "exit_code"
        )
        if output:
            run_summary += " and produced %d byte(s) of output" % len(
                data.execution.get("output") or ""
            )
        parts.append(run_summary + ".")
    return " ".join(parts)


def _syscall_table(instrs: Sequence[Any]) -> List[Dict[str, Any]]:
    """Aggregate the syscalls of the program by name.

    Args:
        instrs: Analyzed instructions.

    Returns:
        List of dictionaries with ``name``, ``number``, ``count`` and ``lines``.
    """
    aggregated: Dict[str, Dict[str, Any]] = {}
    for ins in instrs:
        if ins.mnemonic not in ("syscall", "int"):
            continue
        name = ins.sem.syscall_name if ins.sem and ins.sem.syscall_name else None
        if not name:
            name = "unknown syscall"
        record = aggregated.setdefault(
            name, {"name": name, "number": None, "count": 0, "lines": []}
        )
        record["count"] += 1
        record["lines"].append(ins.n)
        if record["number"] is None and ins.sem and ins.sem.detail:
            for number, entry in LINUX_SYSCALLS.items():
                if entry[0] == name:
                    record["number"] = number
                    break
    return sorted(aggregated.values(), key=lambda r: (-r["count"], r["name"]))


def _external_apis(instrs: Sequence[Any], label_at: Dict[str, int]) -> List[str]:
    """List the calls that point outside the file (APIs and libc).

    Args:
        instrs: Analyzed instructions.
        label_at: Index of the labels defined in the file.

    Returns:
        Unique names, in alphabetical order.
    """
    names = set()
    for ins in instrs:
        if ins.mnemonic == "call" and ins.operands:
            target = ins.operands[0].symbol or ins.operands[0].text
            if target and target not in label_at:
                names.add(str(target))
    return sorted(names)


def _blocks_table(analysis: Analysis) -> List[Dict[str, Any]]:
    """Summarize the basic blocks for the report.

    Args:
        analysis: Analysis of the program.

    Returns:
        List of dictionaries with name, function, lines, counts and neighbors.
    """
    rows: List[Dict[str, Any]] = []
    for block in analysis.blocks:
        if not block.instrs:
            continue
        rows.append(
            {
                "id": block.id,
                "name": block.name,
                "func": block.func,
                "lines": [block.instrs[0].n, block.instrs[-1].n],
                "instructions": len(block.instrs),
                "comes_from": [
                    analysis.blocks[e.target].name
                    for e in block.pred
                    if e.target < len(analysis.blocks)
                ],
                "goes_to": [
                    analysis.blocks[e.target].name
                    for e in block.succ
                    if e.target < len(analysis.blocks)
                ],
                "calls": list(block.calls),
                "exit": block.exit,
            }
        )
    return rows


def _execution_dict(machine: Machine) -> Dict[str, Any]:
    """Summarize the result of the execution on the virtual machine.

    Args:
        machine: Machine already executed.

    Returns:
        Dictionary with output, exit code, steps, flags, registers and problems
        detected during the execution.
    """
    return {
        "output": machine.output,
        "exit_code": machine.exit_code,
        "steps": machine.steps,
        "halted": machine.halted,
        "timed_out": machine.timed_out,
        "issues": list(machine.issues),
        "flags": dict(machine.flags),
        "registers": {key: hexs(value) for key, value in machine.regs.items() if value},
        "registers_decimal": {
            key: to_signed(value) for key, value in machine.regs.items() if value
        },
    }


#: Names that may appear at the start of a syscall annotation ("write: ...").
_SYSCALL_WORDS = frozenset(entry[0] for entry in LINUX_SYSCALLS.values()) | {"syscall"}


def _timeline(machine: Machine, limit: int = TIMELINE_LIMIT) -> List[Dict[str, Any]]:
    """Build the execution timeline from the machine history.

    Args:
        machine: Machine already executed.
        limit: Maximum number of steps included.

    Returns:
        List of dictionaries with ``step``, ``line``, ``text``, ``note`` and
        ``syscall`` (name of the syscall, when the step is one).
    """
    steps = machine.trace[-limit:] if limit else machine.trace
    timeline: List[Dict[str, Any]] = []
    for index, step in enumerate(steps):
        syscall = None
        if ":" in step.note:
            candidate = step.note.split(":", 1)[0].strip()
            if candidate in _SYSCALL_WORDS:
                syscall = candidate
        timeline.append(
            {
                "step": index,
                "line": step.line,
                "text": step.text,
                "note": step.note,
                "syscall": syscall,
                "issue": step.issue,
            }
        )
    return timeline


def _merge_iocs(
    base: Dict[str, List[Dict[str, Any]]], extra: Dict[str, List[Dict[str, Any]]]
) -> Dict[str, List[Dict[str, Any]]]:
    """Merge indicators from two origins without repeating a value.

    The memory of the virtual machine reveals strings that only exist at
    execution time (bytes assembled by ``times``/``dup``, for example); they come
    in together with the ones from the text, marked with line 0.

    Args:
        base: Indicators extracted from the source code.
        extra: Indicators extracted from memory during the execution.

    Returns:
        New dictionary ``kind -> list`` without repeated values.
    """
    result: Dict[str, List[Dict[str, Any]]] = {kind: list(items) for kind, items in base.items()}
    for kind, items in extra.items():
        destination = result.setdefault(kind, [])
        seen = {item["value"] for item in destination}
        for item in items:
            if item["value"] not in seen:
                destination.append(item)
                seen.add(item["value"])
    return result


def collect(
    text: str,
    *,
    source: Optional[SourceFile] = None,
    emulate: bool = True,
    limit: int = 200000,
    timeout: Optional[float] = None,
    stdin: str = "",
    entry: Optional[str] = None,
    command: str = "",
    analysis: Optional[Analysis] = None,
) -> ReportData:
    """Bring the complete analysis of a piece of code into a report.

    Args:
        text: Assembly source code.
        source: Metadata of the file read (name, hashes, size). Without it, the
            report uses a generic name and computes the fingerprint.
        emulate: Whether to run the program on the virtual machine and include
            the execution section with the timeline.
        limit: Instruction limit of the simulated execution.
        timeout: Maximum wall time of the execution, in seconds.
        stdin: Simulated input delivered to the ``read`` syscall.
        entry: Label where the execution starts (``None`` = entry point).
        command: Command line that generated the report, for the footer.
        analysis: Analysis to reuse instead of analysing the text again; the
            batch command already has one per file and passing it avoids doing
            the same work twice.

    Returns:
        The :class:`ReportData` ready to be rendered.

    Raises:
        ProjectError: If ``entry`` points to a label that does not exist.

    Example:
        >>> data = collect("nop")
        >>> data.counts["instructions"]
        1
    """
    analysis = analyze(text) if analysis is None else analysis
    problems = validate(analysis)
    behaviors = classify(analysis, problems)
    iocs = extract_iocs(text, include_comments=False)

    if entry and entry not in analysis.label_at:
        raise ProjectError("label not found to start the execution: %s" % entry)

    source_data: Dict[str, Any] = (
        source.to_dict()
        if source is not None
        else {
            "name": "program.asm",
            "path": "",
            "size": len(text.encode("utf-8")),
            "lines": text.count("\n") + (0 if text.endswith("\n") or not text else 1),
            "encoding": "utf-8",
            "sha256": "",
            "fingerprint": fingerprint(text),
        }
    )

    cfg_graph = control_flow_graph(analysis)
    calls_graph = call_graph(analysis)

    data = ReportData(
        command=command,
        source=source_data,
        platform={
            "os": analysis.platform.os,
            "bits": analysis.platform.bits,
            "confidence": analysis.platform.confidence,
            "abi": analysis.platform.abi.get("name"),
            "abi_notes": analysis.platform.abi.get("notes"),
            "arg_regs": list(analysis.platform.abi.get("args") or []),
            "preserved": list(analysis.platform.abi.get("preserved") or []),
            "evidence": {key: list(values) for key, values in analysis.platform.evidence.items()},
        },
        dialect=analysis.program.flavor,
        stats=dict(analysis.stats),
        problems=[p.to_dict() for p in problems],
        behaviors=behaviors_to_dicts(behaviors),
        techniques=techniques(behaviors),
        iocs=iocs_to_dicts(iocs),
        instructions=[
            {
                "line": ins.n,
                "text": ins.text,
                "mnemonic": ins.mnemonic,
                "label": ins.sem.label if ins.sem else "",
                "detail": ins.sem.detail if ins.sem else "",
                "tag": ins.sem.tag if ins.sem else "",
                "func": ins.func,
                "section": ins.section,
                "block": ins.block,
            }
            for ins in analysis.instrs
        ],
        blocks=_blocks_table(analysis),
        cfg={
            "graph": cfg_graph.to_dict(),
            "svg": to_svg(cfg_graph),
            "dot": to_dot(cfg_graph),
            "mermaid": to_mermaid(cfg_graph),
        },
        calls={
            "graph": calls_graph.to_dict(),
            "svg": to_svg(calls_graph),
            "dot": to_dot(calls_graph),
            "mermaid": to_mermaid(calls_graph),
        },
        syscalls=_syscall_table(analysis.instrs),
        apis=_external_apis(analysis.instrs, analysis.label_at),
    )
    data.risk = risk_assessment(problems, behaviors, analysis.stats)

    if emulate:
        machine = Machine(analysis, stdin=stdin, entry=entry)
        steps = machine.run(limit=limit, timeout=timeout)
        data.execution = _execution_dict(machine)
        data.execution["limit"] = limit
        data.execution["steps_returned"] = steps
        data.timeline = _timeline(machine)
        data.execution["timeline_truncated"] = len(machine.trace) > len(data.timeline)
        memory_iocs = iocs_from_memory(machine, min_length=6)
        if memory_iocs:
            data.iocs = _merge_iocs(data.iocs, iocs_to_dicts(memory_iocs))

    data.summary = executive_summary(data)
    log_event(
        logger,
        "report_collected",
        level=10,
        name=data.source.get("name"),
        instructions=data.counts["instructions"],
        behaviors=data.counts["behaviors"],
        iocs=data.counts["iocs"],
        risk=data.risk.get("level"),
        emulated=data.execution is not None,
    )
    return data


# ------------------------------------------------------------------ json ----
def render_json(data: ReportData, *, indent: int = 2, include_svg: bool = False) -> str:
    """Serialize the report as JSON.

    Args:
        data: Report to serialize.
        indent: JSON indentation.
        include_svg: Whether the graph SVG goes into the JSON.

    Returns:
        JSON text ending in a newline.
    """
    return (
        json.dumps(
            data.to_dict(include_svg=include_svg), ensure_ascii=False, indent=indent, default=str
        )
        + "\n"
    )


# -------------------------------------------------------------- markdown ----
def _md_table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    """Build a Markdown table.

    Args:
        headers: Column headers.
        rows: Rows already as text.

    Returns:
        Markdown table block; empty string when there are no rows.
    """
    if not rows:
        return ""
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        lines.append(
            "| " + " | ".join(str(c).replace("|", "\\|").replace("\n", " ") for c in row) + " |"
        )
    return "\n".join(lines)


def render_markdown(data: ReportData) -> str:
    """Draw the report as Markdown, ready for an issue, a PR or a blog.

    Args:
        data: Report to render.

    Returns:
        Markdown text; the graph comes in as a Mermaid block, which GitHub draws.
    """
    source = data.source
    counts = data.counts
    parts: List[str] = []
    parts.append("# ASM X — analysis of `%s`\n" % source.get("name", "program"))
    parts.append("> %s\n" % data.summary)
    parts.append(
        "**Risk:** %s %s (%d/100) — %s\n"
        % (
            data.risk.get("emoji", ""),
            str(data.risk.get("level", "")).upper(),
            int(data.risk.get("score", 0)),
            data.risk.get("description", ""),
        )
    )

    parts.append("## Metadata\n")
    parts.append(
        _md_table(
            ["field", "value"],
            [
                ["file", source.get("name", "")],
                ["size", "%s bytes" % source.get("size", 0)],
                ["lines", source.get("lines", 0)],
                ["encoding", source.get("encoding", "")],
                ["sha256", source.get("sha256", "") or "(not computed)"],
                ["fingerprint", source.get("fingerprint", "")],
                ["dialect", data.dialect],
                [
                    "platform",
                    "%s · %d bits · %d%% confidence"
                    % (
                        data.platform.get("os"),
                        data.platform.get("bits", 64),
                        data.platform.get("confidence", 0),
                    ),
                ],
                ["ABI", data.platform.get("abi") or "—"],
                ["generated at", data.generated_at],
                ["generated by", "ASM X %s" % data.version],
            ],
        )
        + "\n"
    )

    parts.append("## Numbers\n")
    parts.append(
        _md_table(
            [
                "instructions",
                "blocks",
                "calls",
                "syscalls",
                "behaviors",
                "indicators",
                "problems",
            ],
            [
                [
                    counts["instructions"],
                    counts["blocks"],
                    counts["calls"],
                    counts["syscalls"],
                    counts["behaviors"],
                    counts["iocs"],
                    counts["problems"],
                ]
            ],
        )
        + "\n"
    )

    if data.behaviors:
        parts.append("## Behaviors\n")
        parts.append(
            _md_table(
                ["behavior", "severity", "confidence", "evidence"],
                [
                    [
                        b["label"],
                        b["severity"],
                        "%d%%" % b["confidence"],
                        "; ".join(b["evidence"][:3]),
                    ]
                    for b in data.behaviors
                ],
            )
            + "\n"
        )
    if data.techniques:
        parts.append("## MITRE ATT&CK (indications)\n")
        parts.append(
            _md_table(
                ["technique", "tactic", "id", "linked to"],
                [
                    [t["name"], t["tactic"], t["id"], ", ".join(t.get("behaviors", []))]
                    for t in data.techniques
                ],
            )
            + "\n"
        )
    if data.cfg.get("mermaid"):
        parts.append("## Control flow\n")
        parts.append("```mermaid\n%s\n```\n" % data.cfg["mermaid"])
    if data.calls.get("mermaid") and not data.calls.get("graph", {}).get("empty", True):
        parts.append("## Calls\n")
        parts.append("```mermaid\n%s\n```\n" % data.calls["mermaid"])

    if data.iocs:
        parts.append("## Indicators and strings\n")
        for kind, items in sorted(data.iocs.items()):
            if not items:
                continue
            label = items[0].get("label", kind)
            parts.append("**%s** (%d)\n" % (label, len(items)))
            parts.append(
                _md_table(["value", "line"], [[i["value"], i["line"]] for i in items[:40]]) + "\n"
            )

    if data.problems:
        parts.append("## Validation\n")
        parts.append(
            _md_table(
                ["line", "severity", "code", "problem", "hint"],
                [
                    [p["line"], p["severity"], p["code"], p["message"], p.get("hint", "")]
                    for p in data.problems
                ],
            )
            + "\n"
        )
    else:
        parts.append("## Validation\n\nNo problem found.\n")

    if data.execution is not None:
        execution = data.execution
        parts.append("## Simulated execution\n")
        parts.append("```text\n%s\n```\n" % (execution.get("output") or "(no output)"))
        parts.append(
            _md_table(
                ["steps", "exit code", "timed out"],
                [
                    [
                        execution.get("steps", 0),
                        execution.get("exit_code"),
                        "yes" if execution.get("timed_out") else "no",
                    ]
                ],
            )
            + "\n"
        )
        if execution.get("issues"):
            parts.append("**Problems detected during the execution**\n")
            for problem in execution["issues"]:
                parts.append("- %s" % problem)
            parts.append("")

    parts.append("## Instructions\n")
    parts.append(
        _md_table(
            ["line", "instruction", "label", "explanation"],
            [[i["line"], "`%s`" % i["text"], i["label"], i["detail"]] for i in data.instructions],
        )
        + "\n"
    )
    parts.append("---\n\nGenerated by ASM X %s · schema %s\n" % (data.version, data.schema))
    return "\n".join(parts)


# ------------------------------------------------------------------- html ----
_CSS = """
:root {
  --bg: #0F1826; --panel: #16202E; --panel2: #1C2A3A; --line: #26394E;
  --fg: #DCE6F2; --dim: #8AA0B8; --white: #F2F7FF; --accent: #E3A44B;
  --cyan: #57C8D2; --green: #5FD4A8; --violet: #9C8CF0; --pink: #EF7D9D;
  --orange: #F08A5D; --blue: #79A6E8;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg);
  font: 15px/1.55 "Segoe UI", "DejaVu Sans", system-ui, sans-serif; }
a { color: var(--cyan); }
header { padding: 28px 32px 18px; border-bottom: 1px solid var(--line);
  background: linear-gradient(180deg, #121B28, #0F1826); }
h1 { margin: 0 0 6px; font-size: 26px; color: var(--white); }
h2 { margin: 0 0 14px; font-size: 19px; color: var(--white); }
h3 { margin: 22px 0 10px; font-size: 16px; color: var(--white); }
.sub { color: var(--dim); font-size: 14px; }
.wrap { max-width: 1180px; margin: 0 auto; padding: 0 32px 60px; }
.mono { font-family: "JetBrains Mono", "DejaVu Sans Mono", Consolas, monospace; }
.risk { display: flex; gap: 16px; align-items: center; margin: 18px 0 0;
  padding: 16px 20px; border-radius: 12px; border: 1px solid var(--line);
  background: var(--panel); }
.risk .score { font-size: 30px; font-weight: 700; }
.risk .level { font-size: 20px; font-weight: 700; letter-spacing: .5px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px; margin: 22px 0 8px; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
  padding: 12px 14px; }
.card b { display: block; font-size: 22px; color: var(--white); }
.card span { color: var(--dim); font-size: 13px; }
nav { display: flex; flex-wrap: wrap; gap: 6px; margin: 26px 0 18px;
  border-bottom: 1px solid var(--line); padding-bottom: 10px; }
nav button { background: var(--panel2); color: var(--fg); border: 1px solid var(--line);
  border-radius: 8px; padding: 7px 13px; cursor: pointer; font-size: 14px; }
nav button.active { background: var(--accent); color: #0F1826; font-weight: 700;
  border-color: var(--accent); }
section.tab { display: none; }
section.tab.active { display: block; }
table { width: 100%; border-collapse: collapse; margin: 8px 0 18px; font-size: 14px; }
th, td { text-align: left; padding: 7px 9px; border-bottom: 1px solid var(--line);
  vertical-align: top; }
th { color: var(--dim); font-weight: 600; font-size: 13px; text-transform: uppercase;
  letter-spacing: .4px; }
tr:hover td { background: #17253A; }
code, pre { font-family: "JetBrains Mono", "DejaVu Sans Mono", Consolas, monospace; }
pre { background: #0B1220; border: 1px solid var(--line); border-radius: 10px;
  padding: 12px 14px; overflow-x: auto; font-size: 13px; }
.chip { display: inline-block; padding: 2px 8px; border-radius: 20px; font-size: 12px;
  border: 1px solid var(--line); color: var(--dim); margin: 0 4px 4px 0; }
.sev-high, .sev-error { color: var(--pink); border-color: var(--pink); }
.sev-medium, .sev-warning { color: var(--accent); border-color: var(--accent); }
.sev-low, .sev-info { color: var(--blue); border-color: var(--blue); }
.behavior { background: var(--panel); border: 1px solid var(--line); border-left-width: 4px;
  border-radius: 10px; padding: 14px 16px; margin: 0 0 12px; }
.behavior.high { border-left-color: var(--pink); }
.behavior.medium { border-left-color: var(--accent); }
.behavior.low { border-left-color: var(--green); }
.behavior h3 { margin: 0 0 4px; }
.bar { height: 6px; border-radius: 4px; background: var(--panel2); margin: 8px 0 4px;
  overflow: hidden; }
.bar i { display: block; height: 100%; background: var(--cyan); }
.muted { color: var(--dim); }
.grid2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 18px; }
.svgbox { background: var(--panel); border: 1px solid var(--line); border-radius: 12px;
  padding: 10px; overflow: auto; }
.svgbox svg { max-width: 100%; height: auto; }
input.filter { width: 100%; padding: 9px 12px; border-radius: 8px; border: 1px solid var(--line);
  background: var(--panel2); color: var(--fg); margin: 6px 0 12px; font-size: 14px; }
footer { border-top: 1px solid var(--line); color: var(--dim); font-size: 13px;
  padding: 18px 32px 40px; text-align: center; }
.empty { color: var(--dim); font-style: italic; }
@media print {
  nav { display: none; }
  section.tab { display: block !important; page-break-inside: avoid; }
  body { background: #fff; color: #111; }
  .card, .behavior, pre, .svgbox { border-color: #ccc; background: #fafafa; }
  h1, h2, h3, .card b { color: #000; }
}
"""

_JS = """
function showTab(id, button) {
  document.querySelectorAll('section.tab').forEach(function (s) { s.classList.remove('active'); });
  document.querySelectorAll('nav button').forEach(function (b) { b.classList.remove('active'); });
  var target = document.getElementById(id);
  if (target) { target.classList.add('active'); }
  if (button) { button.classList.add('active'); }
}
function filterRows(inputId, tableId) {
  var term = (document.getElementById(inputId).value || '').toLowerCase();
  var rows = document.getElementById(tableId).getElementsByTagName('tr');
  for (var i = 1; i < rows.length; i++) {
    var text = (rows[i].innerText || '').toLowerCase();
    rows[i].style.display = (term === '' || text.indexOf(term) >= 0) ? '' : 'none';
  }
}
function copyText(id, button) {
  var target = document.getElementById(id);
  if (!target) { return; }
  navigator.clipboard.writeText(target.innerText).then(function () {
    var previous = button.innerText;
    button.innerText = 'copied';
    setTimeout(function () { button.innerText = previous; }, 1200);
  });
}
"""


class _Raw(str):
    """Text that already is HTML and must not be escaped again."""


def _esc(value: Any) -> str:
    """Escape a text for HTML.

    Args:
        value: Any value; it is converted to text before escaping.

    Returns:
        Text safe to go into the HTML.
    """
    return html.escape("" if value is None else str(value), quote=True)


def _md_to_html(text: str) -> str:
    """Escape a text and preserve the line breaks.

    Args:
        text: Plain text.

    Returns:
        HTML with ``<br>`` at the line breaks.
    """
    return _esc(text).replace("\n", "<br>")


def _table(
    headers: Sequence[str],
    rows: Sequence[Sequence[Any]],
    *,
    table_id: str = "",
    empty: str = "nothing here",
) -> str:
    """Build an HTML table.

    Args:
        headers: Column headers.
        rows: Rows, already in the final format (the text is escaped here).
        table_id: Identifier used by the JavaScript filter.
        empty: Text shown when there are no rows.

    Returns:
        HTML block of the table.
    """
    if not rows:
        return '<p class="empty">%s</p>' % _esc(empty)
    ident = ' id="%s"' % _esc(table_id) if table_id else ""
    parts = ["<table%s>" % ident, "<thead><tr>"]
    parts.extend("<th>%s</th>" % _esc(h) for h in headers)
    parts.append("</tr></thead><tbody>")
    for row in rows:
        parts.append("<tr>")
        for cell in row:
            parts.append("<td>%s</td>" % (cell if isinstance(cell, _Raw) else _esc(cell)))
        parts.append("</tr>")
    parts.append("</tbody></table>")
    return "".join(parts)


def _cards(counts: Dict[str, int]) -> str:
    """Build the number cards at the top.

    Args:
        counts: Counts returned by :attr:`ReportData.counts`.

    Returns:
        HTML of the card grid.
    """
    labels = [
        ("instructions", "instructions"),
        ("blocks", "blocks"),
        ("calls", "calls"),
        ("syscalls", "syscalls"),
        ("behaviors", "behaviors"),
        ("iocs", "indicators"),
        ("strings", "strings"),
        ("problems", "problems"),
    ]
    items = ["<div class='cards'>"]
    for key, label in labels:
        items.append(
            "<div class='card'><b>%d</b><span>%s</span></div>" % (counts.get(key, 0), _esc(label))
        )
    items.append("</div>")
    return "".join(items)


def _risk_banner(data: ReportData) -> str:
    """Draw the risk banner of the report.

    Args:
        data: Filled report.

    Returns:
        HTML of the banner, with the reason that weighed the most.
    """
    risk = data.risk
    color = _esc(risk.get("color", "#8AA0B8"))
    reasons = risk.get("reasons") or []
    detail = " · ".join(reasons[:3]) if reasons else "no relevant signal"
    return (
        "<div class='risk' style='border-color:%s'>"
        "<div class='score' style='color:%s'>%d<small>/100</small></div>"
        "<div><div class='level' style='color:%s'>%s risk %s</div>"
        "<div class='sub'>%s</div><div class='sub'>%s</div></div></div>"
        % (
            color,
            color,
            int(risk.get("score", 0)),
            color,
            _esc(risk.get("emoji", "")),
            _esc(str(risk.get("level", "")).upper()),
            _esc(risk.get("description", "")),
            _esc(detail),
        )
    )


def _meta_section(data: ReportData) -> str:
    """Build the section with the file and platform metadata.

    Args:
        data: Filled report.

    Returns:
        HTML of the summary section.
    """
    source = data.source
    platform = data.platform
    hints = []
    for origin, items in (platform.get("evidence") or {}).items():
        for hint in items:
            hints.append("<span class='chip'>%s: %s</span>" % (_esc(origin), _esc(hint)))
    rows = [
        ["file", _esc(source.get("name", ""))],
        ["path", _Raw('<span class="mono">%s</span>' % _esc(source.get("path", "") or "—"))],
        ["size", "%s bytes" % _esc(source.get("size", 0))],
        ["lines", _esc(source.get("lines", 0))],
        ["encoding", _esc(source.get("encoding", ""))],
        ["sha256", _Raw('<span class="mono">%s</span>' % _esc(source.get("sha256", "") or "—"))],
        [
            "fingerprint",
            _Raw('<span class="mono">%s</span>' % _esc(source.get("fingerprint", ""))),
        ],
        ["dialect", _esc(data.dialect)],
        [
            "platform",
            "%s · %d bits · %d%% confidence"
            % (
                _esc(platform.get("os")),
                platform.get("bits", 64),
                platform.get("confidence", 0),
            ),
        ],
        ["ABI", _esc(platform.get("abi") or "—")],
        ["generated at", _esc(data.generated_at)],
        ["generated by", "ASM X %s (schema %s)" % (_esc(data.version), _esc(data.schema))],
    ]
    body = [_table(["field", "value"], rows)]
    if platform.get("abi_notes"):
        body.append("<p class='sub'>%s</p>" % _esc(platform["abi_notes"]))
    if platform.get("arg_regs"):
        body.append(
            "<p><b>Arguments in</b> %s</p>"
            % " ".join("<span class='chip mono'>%s</span>" % _esc(r) for r in platform["arg_regs"])
        )
    if platform.get("preserved"):
        body.append(
            "<p><b>Preserved</b> %s</p>"
            % " ".join("<span class='chip mono'>%s</span>" % _esc(r) for r in platform["preserved"])
        )
    if hints:
        body.append("<h3>Evidence behind the conclusion</h3><p>%s</p>" % "".join(hints))
    body.append("<h2>Executive summary</h2><p>%s</p>" % _esc(data.summary))
    return "".join(body)


def _behaviors_section(data: ReportData) -> str:
    """Build the behaviors and MITRE ATT&CK section.

    Args:
        data: Filled report.

    Returns:
        HTML of the section.
    """
    if not data.behaviors:
        return "<p class='empty'>No relevant behavior was identified.</p>"
    parts = []
    for behavior in sorted(data.behaviors, key=lambda b: severity_rank(b["severity"])):
        evidence = "".join("<li>%s</li>" % _esc(e) for e in behavior["evidence"])
        chips = "".join(
            "<span class='chip mono'>%s</span>" % _esc(t) for t in behavior.get("mitre", [])
        )
        parts.append(
            "<div class='behavior %s'>"
            "<h3>%s <span class='chip sev-%s'>%s</span></h3>"
            "<p>%s</p>"
            "<div class='bar'><i style='width:%d%%'></i></div>"
            "<p class='sub'>confidence %d%% · lines %s</p>"
            "<ul>%s</ul>%s</div>"
            % (
                _esc(behavior["severity"]),
                _esc(behavior["label"]),
                _esc(behavior["severity"]),
                _esc(behavior["severity"]),
                _esc(behavior["description"]),
                int(behavior["confidence"]),
                int(behavior["confidence"]),
                _esc(", ".join(str(n) for n in behavior["lines"])),
                evidence,
                "<p>%s</p>" % chips if chips else "",
            )
        )
    if data.techniques:
        rows = [
            [
                _Raw(
                    '<a href="%s" target="_blank" rel="noopener">%s</a>'
                    % (_esc(t["url"]), _esc(t["id"]))
                ),
                _esc(t["name"]),
                _esc(t["tactic"]),
                _Raw(
                    " ".join(
                        "<span class='chip'>%s</span>" % _esc(b) for b in t.get("behaviors", [])
                    )
                ),
                _esc(t.get("description", "")),
            ]
            for t in data.techniques
        ]
        parts.append("<h2>MITRE ATT&CK — indications</h2>")
        parts.append(
            "<p class='sub'>Mapping derived from static patterns: an indication, "
            "not proof of malicious behavior.</p>"
        )
        parts.append(_table(["id", "technique", "tactic", "behaviors", "what it is"], rows))
    return "".join(parts)


def _iocs_section(data: ReportData) -> str:
    """Build the indicators and strings section.

    Args:
        data: Filled report.

    Returns:
        HTML of the section.
    """
    if not data.iocs:
        return "<p class='empty'>No string or indicator found.</p>"
    parts = []
    for kind, items in sorted(data.iocs.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        if not items:
            continue
        label = items[0].get("label", kind)
        rows = [
            [
                _Raw('<span class="mono">%s</span>' % _esc(i["value"])),
                _esc(i["line"]),
                _Raw('<span class="sub">%s</span>' % _esc(i.get("context", ""))),
            ]
            for i in items
        ]
        parts.append("<h3>%s <span class='chip'>%d</span></h3>" % (_esc(label), len(items)))
        parts.append(_table(["value", "line", "context"], rows, empty="nothing of this kind"))
    return "".join(parts)


def _instructions_section(data: ReportData) -> str:
    """Build the filterable instruction table.

    Args:
        data: Filled report.

    Returns:
        HTML of the section.
    """
    if not data.instructions:
        return "<p class='empty'>The file has no instructions.</p>"
    body = [
        '<input class="filter" id="instructions-filter" placeholder="filter by '
        'line, instruction, label or explanation…" '
        "oninput=\"filterRows('instructions-filter', 'instructions-table')\">"
    ]
    rows = [
        [
            i["line"],
            _Raw('<span class="mono">%s</span>' % _esc(i["text"])),
            _Raw('<span class="chip sev-info">%s</span>' % _esc(i["label"])),
            _esc(i["detail"]),
        ]
        for i in data.instructions
    ]
    body.append(
        _table(
            ["line", "instruction", "label", "what it does"], rows, table_id="instructions-table"
        )
    )
    return "".join(body)


def _problems_section(data: ReportData) -> str:
    """Build the validation section.

    Args:
        data: Filled report.

    Returns:
        HTML of the section.
    """
    if not data.problems:
        return "<p class='empty'>No problem found by the validator.</p>"
    parts = []
    for severity in (ERROR, WARNING, INFO):
        of_kind = [p for p in data.problems if p["severity"] == severity]
        if not of_kind:
            continue
        rows = [
            [
                p["line"],
                _Raw('<span class="chip mono">%s</span>' % _esc(p["code"])),
                _esc(p["message"]),
                _Raw('<span class="sub">%s</span>' % _esc(p.get("hint", ""))),
            ]
            for p in of_kind
        ]
        parts.append(
            "<h3>%s <span class='chip sev-%s'>%d</span></h3>"
            % (_esc(severity.capitalize()), _esc(severity), len(of_kind))
        )
        parts.append(_table(["line", "code", "problem", "how to fix"], rows))
    return "".join(parts)


def _execution_section(data: ReportData) -> str:
    """Build the simulated execution section.

    Args:
        data: Filled report.

    Returns:
        HTML of the section.
    """
    if data.execution is None:
        return (
            "<p class='empty'>The execution was not simulated in this report. "
            "Generate it again without <code>--no-emulate</code> to fill this tab.</p>"
        )
    execution = data.execution
    parts = [
        "<h2>Program output</h2>",
        "<pre>%s</pre>" % _esc(execution.get("output") or "(no output)"),
    ]
    parts.append(
        _table(
            ["steps", "exit code", "halted", "timeout"],
            [
                [
                    execution.get("steps", 0),
                    _esc(execution.get("exit_code")),
                    "yes" if execution.get("halted") else "no",
                    "yes" if execution.get("timed_out") else "no",
                ]
            ],
        )
    )
    issues = execution.get("issues") or []
    if issues:
        parts.append("<h3>Problems detected during the execution</h3><ul>")
        parts.extend("<li>%s</li>" % _esc(problem) for problem in issues)
        parts.append("</ul>")
    registers = execution.get("registers") or {}
    if registers:
        rows = [
            [
                _Raw('<span class="mono">%s</span>' % _esc(r)),
                _Raw('<span class="mono">%s</span>' % _esc(v)),
                (execution.get("registers_decimal") or {}).get(r, ""),
            ]
            for r, v in sorted(registers.items())
        ]
        parts.append("<h3>Registers at the end</h3>")
        parts.append(_table(["register", "hexadecimal", "decimal"], rows))
    flags = execution.get("flags") or {}
    if flags:
        parts.append(
            "<h3>Flags</h3><p>%s</p>"
            % "".join(
                "<span class='chip mono'>%s=%s</span>" % (_esc(f), _esc(v))
                for f, v in flags.items()
            )
        )
    if data.timeline:
        note = (
            " (showing the last %d steps)" % len(data.timeline)
            if execution.get("timeline_truncated")
            else ""
        )
        parts.append("<h3>Timeline%s</h3>" % _esc(note))
        rows = [
            [
                p["step"],
                p["line"],
                _Raw('<span class="mono">%s</span>' % _esc(p["text"])),
                _esc(p["note"]),
            ]
            for p in data.timeline
        ]
        parts.append(
            _table(["step", "line", "instruction", "effect"], rows, table_id="timeline-table")
        )
    return "".join(parts)


def _flow_section(data: ReportData) -> str:
    """Build the flow section: control graph, calls and exports.

    Args:
        data: Filled report.

    Returns:
        HTML of the section.
    """
    parts = [
        "<h2>Control-flow graph</h2>",
        "<p class='sub'>Each box is a basic block; the arrows are the branches, "
        "with the reason. Dark gray blocks are unreachable.</p>",
    ]
    if data.cfg.get("graph", {}).get("empty", True):
        parts.append("<p class='empty'>No code to draw.</p>")
    else:
        parts.append("<div class='svgbox'>%s</div>" % data.cfg.get("svg", ""))
    parts.append("<h2>Call graph</h2>")
    if data.calls.get("graph", {}).get("empty", True):
        parts.append("<p class='empty'>This program does not call anyone.</p>")
    else:
        parts.append("<div class='svgbox'>%s</div>" % data.calls.get("svg", ""))
    parts.append("<h2>Basic blocks</h2>")
    rows = [
        [
            b["name"],
            _esc(b["func"] or "—"),
            "L%d–L%d" % (b["lines"][0], b["lines"][1]),
            b["instructions"],
            _esc(", ".join(b["comes_from"]) or "—"),
            _esc(", ".join(b["goes_to"]) or (b["exit"] or "—")),
        ]
        for b in data.blocks
    ]
    parts.append(_table(["block", "function", "lines", "instr.", "comes from", "goes to"], rows))
    parts.append("<h2>Export the graph</h2>")
    for key, label in (("cfg", "control flow"), ("calls", "calls")):
        graph = data.cfg if key == "cfg" else data.calls
        if graph.get("graph", {}).get("empty", True):
            continue
        ident = "dot-%s" % key
        parts.append("<h3>%s — DOT (Graphviz)</h3>" % _esc(label.capitalize()))
        parts.append("<pre id='%s'>%s</pre>" % (ident, _esc(graph.get("dot", ""))))
        parts.append("<button onclick=\"copyText('%s', this)\">copy DOT</button>" % ident)
    return "".join(parts)


def _data_section(data: ReportData) -> str:
    """Build the raw data (JSON) tab and the offline note.

    Args:
        data: Filled report.

    Returns:
        HTML of the section.
    """
    raw = render_json(data, indent=2)
    ident = "raw-json"
    return (
        "<h2>Report JSON</h2>"
        "<p class='sub'>Same content as this page, in the <code>%s</code> schema. "
        "To save it without copying from the screen: "
        "<code>asmx report file.asm --format json</code>.</p>"
        "<pre id='%s'>%s</pre>"
        "<button onclick=\"copyText('%s', this)\">copy JSON</button>"
        % (_esc(data.schema), ident, _esc(raw), ident)
    )


def render_html(data: ReportData) -> str:
    """Draw the report as a self-contained HTML page.

    The generated file makes no network request: CSS, JavaScript and the graphs
    as SVG are embedded, so it opens offline in the browser (and can be attached
    to an e-mail or a commit without breaking).

    Args:
        data: Report to render.

    Returns:
        Complete HTML document, ready to be written to disk.
    """
    title = "ASM X — analysis of %s" % data.source.get("name", "program")
    tabs = [
        ("summary", "Summary"),
        ("flow", "Flow"),
        ("behaviors", "Behaviors"),
        ("iocs", "Indicators"),
        ("instructions", "Instructions"),
        ("validation", "Validation"),
        ("execution", "Execution"),
        ("data", "Data"),
    ]
    buttons = "".join(
        "<button class='%s' onclick=\"showTab('%s', this)\">%s</button>"
        % ("active" if index == 0 else "", key, _esc(label))
        for index, (key, label) in enumerate(tabs)
    )
    sections = "".join(
        "<section class='tab %s' id='%s'>%s</section>" % ("active" if index == 0 else "", key, body)
        for index, (key, body) in enumerate(
            [
                ("summary", _meta_section(data)),
                ("flow", _flow_section(data)),
                ("behaviors", _behaviors_section(data)),
                ("iocs", _iocs_section(data)),
                ("instructions", _instructions_section(data)),
                ("validation", _problems_section(data)),
                ("execution", _execution_section(data)),
                ("data", _data_section(data)),
            ]
        )
    )
    footer = (
        "Generated by ASM X %s on %s · schema %s · self-contained page, "
        "no network requests" % (_esc(data.version), _esc(data.generated_at), _esc(data.schema))
    )
    if data.command:
        footer += " · <span class='mono'>%s</span>" % _esc(data.command)
    return (
        "<!DOCTYPE html>\n<html lang='en'>\n<head>\n"
        "<meta charset='utf-8'>\n"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>\n"
        "<title>%s</title>\n<style>%s</style>\n</head>\n<body>\n"
        "<header><div class='wrap' style='padding-bottom:0'>"
        "<h1>%s</h1>"
        "<p class='sub'>%s</p>%s</div></header>\n"
        "<div class='wrap'>%s<nav>%s</nav>%s</div>\n"
        "<footer>%s</footer>\n<script>%s</script>\n</body>\n</html>\n"
        % (
            _esc(title),
            _CSS,
            _esc(title),
            _esc(
                "%d instructions · %s · generated at %s"
                % (data.counts["instructions"], data.platform.get("os", "?"), data.generated_at)
            ),
            _risk_banner(data),
            _cards(data.counts),
            buttons,
            sections,
            footer,
            _JS,
        )
    )


def render_index(
    reports: Sequence[ReportData], *, title: str = "ASM X — analysis index", command: str = ""
) -> str:
    """Draw an HTML index comparing several reports.

    It serves the batch analysis: one row per file, with risk, size, platform,
    behaviors and problems, plus the link to the individual report of each one.

    Args:
        reports: Collected reports, in the order they appear.
        title: Page title.
        command: Command line used, shown in the footer.

    Returns:
        Complete HTML document.
    """
    rows: List[List[Any]] = []
    for data in reports:
        name = data.source.get("name", "program")
        target = data.source.get("report_file") or ("%s.html" % name)
        rows.append(
            [
                _Raw('<a href="%s">%s</a>' % (_esc(target), _esc(name))),
                _Raw(
                    '<span class="chip sev-%s">%s</span>'
                    % (
                        _esc(data.risk.get("level", "low")),
                        _esc(str(data.risk.get("level", "")).upper()),
                    )
                ),
                int(data.risk.get("score", 0)),
                data.platform.get("os", "?"),
                data.counts["instructions"],
                data.counts["behaviors"],
                data.counts["iocs"],
                data.counts["problems"],
                _esc(", ".join(b["label"] for b in data.behaviors[:3]) or "—"),
            ]
        )
    total = len(reports)
    critical = sum(1 for r in reports if r.risk.get("level") in ("high", "critical"))
    summary = "%d file(s) analyzed · %d with high or critical risk · %d " "behavior(s) in total" % (
        total,
        critical,
        sum(r.counts["behaviors"] for r in reports),
    )
    body = _table(
        [
            "file",
            "risk",
            "score",
            "platform",
            "instr.",
            "behav.",
            "IOCs",
            "problems",
            "highlights",
        ],
        rows,
        table_id="index-table",
    )
    footer = "Generated by ASM X %s · schema %s" % (_esc(__version__), _esc(REPORT_SCHEMA))
    if command:
        footer += " · <span class='mono'>%s</span>" % _esc(command)
    return (
        "<!DOCTYPE html>\n<html lang='en'>\n<head>\n<meta charset='utf-8'>\n"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>\n"
        "<title>%s</title>\n<style>%s</style>\n</head>\n<body>\n"
        "<header><div class='wrap' style='padding-bottom:0'><h1>%s</h1>"
        "<p class='sub'>%s</p></div></header>\n"
        "<div class='wrap'>%s</div>\n<footer>%s</footer>\n</body>\n</html>\n"
        % (_esc(title), _CSS, _esc(title), _esc(summary), body, footer)
    )


# ------------------------------------------------------------------- files --
def render_dot(data: ReportData) -> str:
    """Return the control-flow graph as DOT (Graphviz).

    Args:
        data: Filled report.

    Returns:
        DOT text ending in a newline.
    """
    return data.cfg.get("dot", "") or 'digraph cfg { label="no code"; }\n'


def render_svg(data: ReportData) -> str:
    """Return the control-flow graph as SVG.

    Args:
        data: Filled report.

    Returns:
        Self-contained SVG document.
    """
    return data.cfg.get("svg", "")


def write_report(data: ReportData, path: str, *, fmt: Optional[str] = None) -> str:
    """Write the report in the requested format.

    Args:
        data: Report to write.
        path: Destination path (``-`` writes to ``stdout``). The directory is
            created when it does not exist yet.
        fmt: Explicit format; without it, the file extension decides.

    Returns:
        The path written (``"-"`` when it went to standard output).

    Raises:
        ProjectError: If the format does not exist.
        SourceWriteError: If the write failed.
    """
    format_name = (fmt or guess_format(path)).lower()
    if format_name not in FORMATS:
        raise ProjectError("unknown report format: %s (use %s)" % (format_name, ", ".join(FORMATS)))
    if format_name == "mermaid":
        content = data.cfg.get("mermaid", "flowchart TD\n") + "\n"
    elif format_name == "html":
        content = render_html(data)
    elif format_name == "md":
        content = render_markdown(data)
    elif format_name == "json":
        content = render_json(data, include_svg=False)
    elif format_name == "dot":
        content = render_dot(data)
    else:
        content = render_svg(data)
    if path == "-":
        print(content, end="")
        return "-"
    folder = os.path.dirname(os.path.abspath(path))
    try:
        os.makedirs(folder, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
    except OSError as error:
        raise SourceWriteError(path, str(error)) from error
    log_event(logger, "report_written", path=path, format=format_name, bytes=len(content))
    return path
