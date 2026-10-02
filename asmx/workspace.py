"""Project management: branches of the same assembly, notes and scenarios.

A project is a single ``.asmproj`` file (JSON) that keeps every variation of the
code, the notes of each line, the breakpoints and the test scenarios. None of
that lives inside the ``.asm``: the source stays clean, ready for the real
assembler, and the study history stays in the project.

Example:
    >>> from asmx.workspace import Project, Scenario
    >>> project = Project.new(code="mov rax, 1", name="test")
    >>> project.fork("experiment").parent
    'main'
    >>> project.set_note(1, "it starts here")
    >>> project.note(1)
    'it starts here'
"""

from __future__ import annotations

import copy
import datetime
import difflib
import json
import os
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from .analyzer import analyze
from .memory import MemoryFault
from .emulator import Machine
from .errors import (
    BranchExistsError,
    BranchNotFoundError,
    EmptyBranchNameError,
    LastBranchError,
    ProjectError,
    ProjectFormatError,
    ScenarioError,
    SourceNotFoundError,
    SourceReadError,
    SourceWriteError,
)
from .isa import REG_INFO
from .logging_setup import get_logger, log_event
from .parser import parse_number

logger = get_logger(__name__)

#: Mark written into the project file, to refuse a file from another program.
FORMAT = "asmx-project/1"


def _now() -> str:
    """Returns the current date and time in the format used by the project.

    Returns:
        Text such as ``2026-09-21 18:04:11``.
    """
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


@dataclass
class Scenario:
    """One test: initial state + expectation of the result.

    Attributes:
        name: Name of the scenario, unique inside the branch.
        entry: Label where the execution starts (``""`` = entry point).
        regs: Initial registers, as text (``{"rdi": "0x20"}``).
        stdin: Simulated input delivered to the ``read`` syscall.
        expect_output: Expected output; ``None`` does not check it.
        expect_exit: Expected exit code; ``None`` does not check it.
        expect_issue: When ``True``, the test passes if the run reports some
            problem (overflow, infinite loop, division by zero...).
        max_steps: Limit of executed instructions.
        timeout: Maximum wall clock time in seconds; ``None`` does not limit it.
    """

    name: str
    entry: str = ""  # label where to start ("" = entry point)
    regs: Dict[str, str] = field(default_factory=dict)
    stdin: str = ""
    expect_output: Optional[str] = None
    expect_exit: Optional[int] = None
    expect_issue: bool = False  # the test passes if the run reports a problem
    max_steps: int = 200000
    timeout: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """Converts the scenario into a dictionary ready for JSON.

        Returns:
            All fields of the scenario in simple types.
        """
        return asdict(self)

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Scenario":
        """Rebuilds the scenario from the dictionary stored in the project.

        Unknown fields (from future versions) are ignored, which allows opening
        a newer project without breaking.

        Args:
            d: Dictionary read from the ``.asmproj`` file.

        Returns:
            The corresponding :class:`Scenario`.
        """
        return Scenario(**{k: v for k, v in d.items() if k in Scenario.__annotations__})


@dataclass
class ScenarioResult:
    """Result of running one scenario.

    Attributes:
        scenario: Name of the scenario that ran.
        passed: Whether the result matched the expectation.
        output: Output produced by the program.
        exit_code: Exit code, when there was one.
        steps: How many instructions were executed.
        issues: Problems detected during the run.
        reason: Readable explanation, mainly when it failed.
    """

    scenario: str
    passed: bool
    output: str
    exit_code: Optional[int]
    steps: int
    issues: List[str]
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Converts the result into a dictionary ready for JSON.

        Returns:
            All fields of the result in simple types.
        """
        return asdict(self)


@dataclass
class Branch:
    """One variation of the program inside the project.

    Attributes:
        name: Name of the branch.
        code: Source code of this variation.
        parent: Name of the branch it came from (``None`` at the root).
        created: Creation date, as text.
        notes: Notes by line (``"12"`` -> text).
        breakpoints: Lines marked as breakpoints.
        scenarios: Test scenarios of this branch.
    """

    name: str
    code: str = ""
    parent: Optional[str] = None
    created: str = field(default_factory=_now)
    notes: Dict[str, str] = field(default_factory=dict)  # "12" -> text
    breakpoints: List[int] = field(default_factory=list)
    scenarios: List[Scenario] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Converts the branch (with the scenarios) into a dictionary.

        Returns:
            Dictionary with all fields of the branch.
        """
        d = asdict(self)
        d["scenarios"] = [s.to_dict() for s in self.scenarios]
        return d

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Branch":
        """Rebuilds the branch from the project dictionary.

        Args:
            d: Dictionary read from the ``.asmproj`` file.

        Returns:
            The corresponding :class:`Branch`, with normalized notes and breakpoints.
        """
        b = Branch(
            name=d.get("name", "main"),
            code=d.get("code", ""),
            parent=d.get("parent"),
            created=d.get("created", _now()),
            notes={str(k): v for k, v in (d.get("notes") or {}).items()},
            breakpoints=list(d.get("breakpoints") or []),
        )
        b.scenarios = [Scenario.from_dict(s) for s in (d.get("scenarios") or [])]
        return b


class Project:
    """Collection of branches of the same program.

    Attributes:
        name: Name of the project (taken from the file name when saving).
        path: Path of the ``.asmproj``; ``None`` while it was never saved.
        branches: Branches by name.
        active: Name of the branch being edited.
        dirty: Whether there is an unsaved change.
    """

    FORMAT = FORMAT

    def __init__(self, name: str = "project", path: Optional[str] = None) -> None:
        """Creates an empty project.

        Args:
            name: Name of the project.
            path: Path of the project file, when it is already known.
        """
        self.name = name
        self.path = path
        self.branches: Dict[str, Branch] = {}
        self.active: str = "main"
        self.dirty = False

    # -------------------------------------------------------------- basics --
    @classmethod
    def new(cls, code: str = "", name: str = "project") -> "Project":
        """Creates a project with one ``main`` branch.

        Args:
            code: Initial code.
            name: Name of the project.

        Returns:
            The project ready to use, with no pending changes.

        Example:
            >>> Project.new(code="mov rax, 1").code
            'mov rax, 1'
        """
        p = cls(name=name)
        p.branches["main"] = Branch(name="main", code=code)
        p.active = "main"
        return p

    @property
    def branch(self) -> Branch:
        """Branch being edited.

        Returns:
            The active :class:`Branch`; if the active name vanished, the first one.
        """
        if self.active not in self.branches:
            self.active = next(iter(self.branches))
        return self.branches[self.active]

    @property
    def code(self) -> str:
        """Code of the branch being edited.

        Returns:
            The source text of the active branch.
        """
        return self.branch.code

    def set_code(self, code: str) -> None:
        """Replaces the code of the active branch and marks the project as changed.

        Args:
            code: New source text.
        """
        if self.branch.code != code:
            self.branch.code = code
            self.dirty = True

    # ------------------------------------------------------------ branches --
    def fork(self, new_name: str, from_branch: Optional[str] = None) -> Branch:
        """Creates a branch by copying another one.

        Args:
            new_name: Name of the new branch.
            from_branch: Source branch (default: the active one).

        Returns:
            The newly created branch.

        Raises:
            BranchNotFoundError: When the source does not exist.
            EmptyBranchNameError: When the name is empty.
            BranchExistsError: When a branch with this name already exists.

        Example:
            >>> project = Project.new(code="mov rax, 1")
            >>> project.fork("alt").code
            'mov rax, 1'
        """
        src_name = from_branch or self.active
        if src_name not in self.branches:
            raise BranchNotFoundError(src_name)
        if not new_name.strip():
            raise EmptyBranchNameError()
        if new_name in self.branches:
            raise BranchExistsError(new_name)
        src = self.branches[src_name]
        b = Branch(
            name=new_name,
            code=src.code,
            parent=src_name,
            notes=dict(src.notes),
            breakpoints=list(src.breakpoints),
            scenarios=copy.deepcopy(src.scenarios),
        )
        self.branches[new_name] = b
        self.dirty = True
        log_event(
            logger,
            "branch_forked",
            branch=new_name,
            parent=src_name,
            lines=src.code.count("\n") + 1,
        )
        return b

    def switch(self, name: str) -> None:
        """Starts editing another branch.

        Args:
            name: Name of the destination branch.

        Raises:
            BranchNotFoundError: When the branch does not exist.
        """
        if name not in self.branches:
            raise BranchNotFoundError(name)
        self.active = name
        log_event(logger, "branch_switched", level=10, branch=name)

    def delete_branch(self, name: str) -> None:
        """Deletes a branch, leaving its children without a parent.

        Args:
            name: Name of the branch to delete.

        Raises:
            BranchNotFoundError: When the branch does not exist.
            LastBranchError: When it is the only branch of the project.
        """
        if name not in self.branches:
            raise BranchNotFoundError(name)
        if len(self.branches) == 1:
            raise LastBranchError()
        del self.branches[name]
        for b in self.branches.values():
            if b.parent == name:
                b.parent = None
        if self.active == name:
            self.active = next(iter(self.branches))
        self.dirty = True
        log_event(logger, "branch_deleted", branch=name, remaining=len(self.branches))

    def rename_branch(self, old: str, new: str) -> None:
        """Renames a branch and repoints its children.

        Args:
            old: Current name.
            new: New name.

        Raises:
            BranchNotFoundError: When ``old`` does not exist.
            BranchExistsError: When ``new`` is already in use.
        """
        if old not in self.branches:
            raise BranchNotFoundError(old)
        if new in self.branches:
            raise BranchExistsError(new)
        b = self.branches.pop(old)
        b.name = new
        self.branches[new] = b
        for other in self.branches.values():
            if other.parent == old:
                other.parent = new
        if self.active == old:
            self.active = new
        self.dirty = True
        log_event(logger, "branch_renamed", old=old, new=new)

    def diff(self, a: str, b: str) -> str:
        """Compares the code of two branches.

        Args:
            a: Name of the source branch.
            b: Name of the destination branch.

        Returns:
            The unified diff, like the one from ``diff -u``.

        Raises:
            BranchNotFoundError: When either branch does not exist.

        Example:
            >>> project = Project.new(code="mov rax, 1")
            >>> _ = project.fork("alt")
            >>> project.switch("alt")
            >>> project.set_code("mov rax, 2")
            >>> "+mov rax, 2" in project.diff("main", "alt")
            True
        """
        for name in (a, b):
            if name not in self.branches:
                raise BranchNotFoundError(name)
        ca = self.branches[a].code.splitlines()
        cb = self.branches[b].code.splitlines()
        return "\n".join(difflib.unified_diff(ca, cb, fromfile=a, tofile=b, lineterm=""))

    # --------------------------------------------------------------- notes --
    def set_note(self, line: int, text: str) -> None:
        """Writes (or deletes) the note of one line of the active branch.

        Args:
            line: Number of the annotated line.
            text: Text of the note; empty removes the note.
        """
        key = str(line)
        if text.strip():
            self.branch.notes[key] = text.strip()
        else:
            self.branch.notes.pop(key, None)
        self.dirty = True

    def note(self, line: int) -> str:
        """Returns the note of one line.

        Args:
            line: Number of the line.

        Returns:
            The annotated text, or an empty string.
        """
        return self.branch.notes.get(str(line), "")

    def toggle_breakpoint(self, line: int) -> bool:
        """Turns the breakpoint of one line on or off.

        Args:
            line: Number of the line.

        Returns:
            ``True`` if the breakpoint ended up on, ``False`` if it went off.
        """
        bps = self.branch.breakpoints
        if line in bps:
            bps.remove(line)
            active = False
        else:
            bps.append(line)
            bps.sort()
            active = True
        self.dirty = True
        return active

    # ----------------------------------------------------------- scenarios --
    def add_scenario(self, scenario: Scenario) -> None:
        """Adds (or replaces, by name) a scenario in the active branch.

        Args:
            scenario: Scenario to store.
        """
        names = [s.name for s in self.branch.scenarios]
        if scenario.name in names:
            self.branch.scenarios[names.index(scenario.name)] = scenario
        else:
            self.branch.scenarios.append(scenario)
        self.dirty = True
        log_event(logger, "scenario_saved", scenario=scenario.name, branch=self.active)

    def remove_scenario(self, name: str) -> None:
        """Removes a scenario from the active branch.

        Args:
            name: Name of the scenario.
        """
        self.branch.scenarios = [s for s in self.branch.scenarios if s.name != name]
        self.dirty = True

    def scenario(self, name: str) -> Scenario:
        """Searches for a scenario by name.

        Args:
            name: Name of the scenario.

        Returns:
            The scenario that was found.

        Raises:
            ScenarioError: When the active branch has no scenario with this name.
        """
        for s in self.branch.scenarios:
            if s.name == name:
                return s
        raise ScenarioError("scenario not found: %s" % name, scenario=name)

    # -------------------------------------------------------- persistence ---
    def to_dict(self) -> Dict[str, Any]:
        """Converts the whole project into a dictionary.

        Returns:
            Dictionary with format, name, active branch and all branches.
        """
        return {
            "format": self.FORMAT,
            "name": self.name,
            "active": self.active,
            "saved": _now(),
            "branches": {k: v.to_dict() for k, v in self.branches.items()},
        }

    def save(self, path: Optional[str] = None) -> str:
        """Writes the project to disk.

        Args:
            path: Destination; without it, uses the already known path.

        Returns:
            The path that was written.

        Raises:
            ProjectError: When no path was defined.
            SourceWriteError: When the write failed.
        """
        target = path or self.path
        if not target:
            raise ProjectError("no path defined to save")
        try:
            with open(target, "w", encoding="utf-8") as f:
                json.dump(self.to_dict(), f, ensure_ascii=False, indent=1)
        except OSError as error:
            raise SourceWriteError(target, str(error)) from error
        self.path = target
        self.name = os.path.splitext(os.path.basename(target))[0]
        self.dirty = False
        log_event(logger, "project_saved", path=target, branches=len(self.branches))
        return target

    @classmethod
    def load(cls, path: str) -> "Project":
        """Reads a saved project.

        Args:
            path: Path of the ``.asmproj`` file.

        Returns:
            The loaded project, with the active branch restored.

        Raises:
            SourceNotFoundError: When the file does not exist.
            SourceReadError: When it could not be read.
            ProjectFormatError: When the JSON is invalid or is not an ASM X
                project.
        """
        if not os.path.exists(path):
            raise SourceNotFoundError(path)
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except OSError as error:
            raise SourceReadError(path, str(error)) from error
        except json.JSONDecodeError as error:
            raise ProjectFormatError(
                path, "invalid JSON on line %d: %s" % (error.lineno, error.msg)
            ) from error
        if not isinstance(data, dict):
            raise ProjectFormatError(path, "the content needs to be a JSON object")
        mark = data.get("format")
        if mark and not str(mark).startswith("asmx-project/"):
            raise ProjectFormatError(path, "unknown format: %s" % mark)

        p = cls(name=data.get("name") or os.path.splitext(os.path.basename(path))[0], path=path)
        for key, bd in (data.get("branches") or {}).items():
            if not isinstance(bd, dict):
                raise ProjectFormatError(path, "branch %s is not an object" % key)
            bd.setdefault("name", key)
            p.branches[key] = Branch.from_dict(bd)
        if not p.branches:
            p.branches["main"] = Branch(name="main")
        p.active = data.get("active") or next(iter(p.branches))
        if p.active not in p.branches:
            p.active = next(iter(p.branches))
        p.dirty = False
        log_event(logger, "project_loaded", path=path, branches=len(p.branches), active=p.active)
        return p

    @classmethod
    def from_asm_file(cls, path: str) -> "Project":
        """Creates a project from a loose ``.asm`` file.

        Args:
            path: Path of the source.

        Returns:
            New project with one ``main`` branch holding the code.

        Raises:
            SourceNotFoundError: When the file does not exist.
            SourceReadError: When it could not be read.
        """
        with open(path, encoding="utf-8", errors="replace") as f:
            code = f.read()
        p = cls.new(code=code, name=os.path.splitext(os.path.basename(path))[0])
        log_event(logger, "project_imported", path=path, lines=code.count("\n") + 1)
        return p

    def export_asm(self, path: str) -> str:
        """Writes the code of the active branch as a common ``.asm``.

        Args:
            path: Destination.

        Returns:
            The path that was written.

        Raises:
            SourceWriteError: When the write failed.
        """
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.code)
        except OSError as error:
            raise SourceWriteError(path, str(error)) from error
        log_event(logger, "branch_exported", path=path, branch=self.active)
        return path


# --------------------------------------------------------- test execution -
def parse_reg_values(text: str) -> Dict[str, int]:
    """Reads register values written as text.

    Accepts ``rax=10, rbx=0x20``, separated by comma, semicolon or line break.
    Names that are not registers are ignored.

    Args:
        text: Text typed by the user.

    Returns:
        Dictionary ``name -> value`` with the recognized registers.

    Example:
        >>> parse_reg_values("rax=10, rbx=0x20")
        {'rax': 10, 'rbx': 32}
        >>> parse_reg_values("nonexistent=1")
        {}
    """
    out: Dict[str, int] = {}
    for part in re.split(r"[,;\n]", text or ""):
        m = re.match(r"^\s*(\w+)\s*=\s*(-?[\w]+)\s*$", part)
        if m and m.group(1).lower() in REG_INFO:
            out[m.group(1).lower()] = parse_number(m.group(2))
    return out


def run_scenario(code: str, scenario: Scenario, *, max_memory: int = 512) -> ScenarioResult:
    """Runs a scenario over a piece of code and compares it with the expectation.

    Args:
        code: Source code to run.
        scenario: Scenario with initial state and expectations.
        max_memory: Simulated allocation limit in MiB.

    Returns:
        The :class:`ScenarioResult` with what happened and why it failed.

    Raises:
        ScenarioError: When the scenario points to a label that does not exist.

    Example:
        >>> from asmx.examples import EXAMPLES
        >>> scenario = Scenario(name="hello", expect_output="Hello, world!\\n")
        >>> run_scenario(EXAMPLES["linux-hello"]["code"], scenario).passed
        True
    """
    analysis = analyze(code)
    if scenario.entry and scenario.entry not in analysis.label_at:
        raise ScenarioError(
            "scenario %s starts at %s, which does not exist in this code"
            % (scenario.name, scenario.entry),
            scenario=scenario.name,
        )
    machine = Machine(
        analysis, stdin=scenario.stdin, entry=scenario.entry or None, max_memory=max_memory
    )
    try:
        for reg, value in scenario.regs.items():
            machine.set_reg(reg.lower(), parse_number(value) if isinstance(value, str) else value)
    except MemoryFault as fault:
        machine._halt_memory_fault(fault, 0)
    machine.run(limit=scenario.max_steps, timeout=scenario.timeout)

    passed, reason = True, "state within expectations"
    if machine.timed_out:
        passed = False
        reason = "the run took longer than %gs (timeout)" % (scenario.timeout or 0.0)
    elif scenario.expect_output is not None and machine.output != scenario.expect_output:
        passed = False
        reason = "output differs: expected %r, got %r" % (
            scenario.expect_output,
            machine.output,
        )
    elif scenario.expect_exit is not None and machine.exit_code != scenario.expect_exit:
        passed = False
        reason = "exit code %s, expected %s" % (machine.exit_code, scenario.expect_exit)
    elif scenario.expect_issue and not machine.issues:
        passed = False
        reason = "expected a problem but none was found"
    elif not scenario.expect_issue and machine.issues:
        passed = False
        reason = "the run reported: " + "; ".join(machine.issues[:3])

    log_event(
        logger,
        "scenario_finished",
        level=10,
        scenario=scenario.name,
        passed=passed,
        steps=machine.steps,
        exit_code=machine.exit_code,
    )
    return ScenarioResult(
        scenario=scenario.name,
        passed=passed,
        output=machine.output,
        exit_code=machine.exit_code,
        steps=machine.steps,
        issues=list(machine.issues),
        reason=reason,
    )


def run_all_scenarios(
    code: str, scenarios: List[Scenario], *, max_memory: int = 512
) -> List[ScenarioResult]:
    """Runs a list of scenarios in order.

    Args:
        code: Source code to run.
        scenarios: Scenarios to run.
        max_memory: Simulated allocation limit in MiB.

    Returns:
        The list of results, in the same order as the scenarios.

    Example:
        >>> from asmx.examples import EXAMPLES
        >>> scenarios = [Scenario(name="ok", expect_exit=0)]
        >>> run_all_scenarios(EXAMPLES["linux-hello"]["code"], scenarios)[0].passed
        True
    """
    results = [run_scenario(code, s, max_memory=max_memory) for s in scenarios]
    log_event(
        logger,
        "scenarios_finished",
        scenarios=len(results),
        passed=sum(1 for r in results if r.passed),
    )
    return results
