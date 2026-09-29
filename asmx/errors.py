"""Errors of ASM X: every situation has its own exception and a stable code.

Why not use only ``ValueError``: whoever calls the library (the interface, the
command line, a CI script) needs to tell "the file does not exist" from "the
project is corrupted" without inspecting message text. Every class here carries
a fixed ``code`` — the same contract that shows up in the JSON of
``python -m asmx ... --json`` and in the tests.

All exceptions also inherit from the equivalent built-in error
(``FileNotFoundError``, ``ValueError``, ``KeyError``...). That way code that
already existed keeps working with ``except ValueError`` and gains, for free,
the error code and the context::

    try:
        project.load(path)
    except ProjectFormatError as error:
        print(error.code, error.context["path"])

Example:
    >>> from asmx.errors import BranchExistsError
    >>> error = BranchExistsError("test")
    >>> print(error)
    [ERR_BRANCH_EXISTS] already exists a branch named test
"""

from __future__ import annotations

from typing import Any, Dict, Optional

__all__ = [
    "AsmxError",
    "SourceNotFoundError",
    "SourceReadError",
    "SourceWriteError",
    "UnsupportedSourceError",
    "ParseError",
    "ProjectError",
    "ProjectFormatError",
    "BranchNotFoundError",
    "BranchExistsError",
    "EmptyBranchNameError",
    "LastBranchError",
    "ScenarioError",
    "ConfigError",
    "EmulationError",
    "AnalysisTimeoutError",
    "UnknownMnemonicError",
    "LineNotFoundError",
    "ERROR_CODES",
]


class AsmxError(Exception):
    """Base of every ASM X error.

    Attributes:
        code: Stable code in the ``ERR_SOMETHING`` format, used in reports and
            in the command line JSON.
        message: Readable message, in English, without the code prefix.
        context: Extra data of the error (path, line, received value) for
            whoever wants to build a structured report.
    """

    code: str = "ERR_ASMX"

    def __init__(self, message: str, code: Optional[str] = None, **context: Any) -> None:
        """Initializes the error.

        Args:
            message: Readable description of the problem.
            code: Code that overrides the class default (optional).
            **context: Key/value pairs stored in ``self.context``.
        """
        super().__init__(message)
        self.message = message
        if code:
            self.code = code
        self.context: Dict[str, Any] = dict(context)

    def __str__(self) -> str:
        """Returns ``[CODE] message``.

        Returns:
            The message formatted with the code in brackets.
        """
        return "[%s] %s" % (self.code, self.message)

    def __repr__(self) -> str:
        """Short representation, useful in logs.

        Returns:
            Text such as ``SourceNotFoundError(code='ERR_...', message='...')``.
        """
        return "%s(code=%r, message=%r)" % (type(self).__name__, self.code, self.message)

    def to_dict(self) -> Dict[str, Any]:
        """Converts the error into a dictionary ready for JSON.

        Returns:
            Dictionary with ``error`` (class name), ``code``, ``message`` and,
            when present, ``context``.
        """
        data: Dict[str, Any] = {
            "error": type(self).__name__,
            "code": self.code,
            "message": self.message,
        }
        if self.context:
            data["context"] = dict(self.context)
        return data


# -------------------------------------------------------------------- files --
class SourceNotFoundError(AsmxError, FileNotFoundError):
    """The source file pointed to does not exist."""

    code = "ERR_SOURCE_NOT_FOUND"

    def __init__(self, path: str) -> None:
        """Builds the error from the missing path.

        Args:
            path: Path that was searched for.
        """
        super().__init__("file not found: %s" % path, path=path)
        self.path = path


class SourceReadError(AsmxError, OSError):
    """The file exists, but could not be read (permission, directory, I/O)."""

    code = "ERR_SOURCE_READ"

    def __init__(self, path: str, detail: str = "") -> None:
        """Builds the error from the path and the reason.

        Args:
            path: Path that failed.
            detail: Original message from the operating system.
        """
        message = "could not read %s" % path
        if detail:
            message += ": %s" % detail
        super().__init__(message, path=path, detail=detail)
        self.path = path


class SourceWriteError(AsmxError, OSError):
    """It was not possible to write a file (permission, disk, directory)."""

    code = "ERR_SOURCE_WRITE"

    def __init__(self, path: str, detail: str = "") -> None:
        """Builds the error from the path and the reason.

        Args:
            path: Path that could not be written.
            detail: Original message from the operating system.
        """
        message = "could not write %s" % path
        if detail:
            message += ": %s" % detail
        super().__init__(message, path=path, detail=detail)
        self.path = path


class UnsupportedSourceError(AsmxError, ValueError):
    """The file extension is not one of the formats ASM X understands."""

    code = "ERR_UNSUPPORTED_SOURCE"

    def __init__(self, path: str, expected: str) -> None:
        """Builds the error with the list of accepted extensions.

        Args:
            path: Path that was refused.
            expected: Text describing the accepted extensions.
        """
        super().__init__(
            "unsupported format in %s (expected: %s)" % (path, expected),
            path=path,
            expected=expected,
        )
        self.path = path


class ParseError(AsmxError, ValueError):
    """The text could not be interpreted as assembly."""

    code = "ERR_PARSE"

    def __init__(self, message: str, line: Optional[int] = None) -> None:
        """Builds the error, optionally with the problematic line.

        Args:
            message: Description of the problem.
            line: Line number (1-based) where the problem was seen.
        """
        super().__init__(message, line=line)
        self.line = line


# ------------------------------------------------------------------ project --
class ProjectError(AsmxError, ValueError):
    """Generic error of project handling (branch, scenario, file)."""

    code = "ERR_PROJECT"


class ProjectFormatError(AsmxError, ValueError):
    """The ``.asmproj`` file exists but is not a valid ASM X project."""

    code = "ERR_PROJECT_FORMAT"

    def __init__(self, path: str, detail: str = "") -> None:
        """Builds the error from the path and the reason.

        Args:
            path: Project file that was read.
            detail: Short explanation of the inconsistency.
        """
        message = "invalid project at %s" % path
        if detail:
            message += ": %s" % detail
        super().__init__(message, path=path, detail=detail)
        self.path = path


class BranchNotFoundError(AsmxError, KeyError):
    """The requested branch does not exist in the project."""

    code = "ERR_BRANCH_NOT_FOUND"

    def __init__(self, name: str) -> None:
        """Builds the error from the branch name.

        Args:
            name: Name that was searched for.
        """
        super().__init__("branch not found: %s" % name, branch=name)
        self.name = name


class BranchExistsError(AsmxError, ValueError):
    """A branch with this name already exists."""

    code = "ERR_BRANCH_EXISTS"

    def __init__(self, name: str) -> None:
        """Builds the error from the repeated name.

        Args:
            name: Name that is already in use.
        """
        super().__init__("already exists a branch named %s" % name, branch=name)
        self.name = name


class EmptyBranchNameError(AsmxError, ValueError):
    """Someone tried to create a branch without a name."""

    code = "ERR_BRANCH_EMPTY_NAME"

    def __init__(self) -> None:
        """Builds the default empty name error."""
        super().__init__("the branch needs a name")


class LastBranchError(AsmxError, ValueError):
    """Someone tried to delete the only branch of the project."""

    code = "ERR_BRANCH_LAST"

    def __init__(self) -> None:
        """Builds the default last branch error."""
        super().__init__("the project needs at least one branch")


class ScenarioError(AsmxError, ValueError):
    """Invalid test scenario (nonexistent label, negative limit...)."""

    code = "ERR_SCENARIO"

    def __init__(self, message: str, scenario: Optional[str] = None) -> None:
        """Builds the error.

        Args:
            message: Description of the problem.
            scenario: Name of the scenario involved (optional).
        """
        super().__init__(message, scenario=scenario)
        self.scenario = scenario


# ------------------------------------------------------------- configuration --
class ConfigError(AsmxError, ValueError):
    """Configuration missing, unreadable or with a value out of range."""

    code = "ERR_CONFIG"

    def __init__(
        self, message: str, path: Optional[str] = None, field: Optional[str] = None
    ) -> None:
        """Builds the error.

        Args:
            message: Description of the problem.
            path: Configuration file involved (optional).
            field: Field that was rejected (optional).
        """
        super().__init__(message, path=path, field=field)
        self.path = path
        self.field = field


# --------------------------------------------------------------- execution --
class EmulationError(AsmxError, RuntimeError):
    """The virtual machine could not start or continue the execution."""

    code = "ERR_EMULATION"

    def __init__(self, message: str, line: Optional[int] = None) -> None:
        """Builds the error, optionally with the line.

        Args:
            message: Description of the problem.
            line: Line of the code where the execution stopped.
        """
        super().__init__(message, line=line)
        self.line = line


class AnalysisTimeoutError(AsmxError, TimeoutError):
    """The run went past the configured time limit."""

    code = "ERR_TIMEOUT"

    def __init__(self, timeout: float, steps: int = 0) -> None:
        """Builds the error with the limit that was exceeded.

        Args:
            timeout: Time limit in seconds.
            steps: How many instructions were executed before stopping.
        """
        super().__init__(
            "the run took longer than %g s (timeout)" % timeout, timeout=timeout, steps=steps
        )
        self.timeout = timeout
        self.steps = steps


# ------------------------------------------------------------------ lookup --
class UnknownMnemonicError(AsmxError, KeyError):
    """Someone asked for documentation of an instruction that is not in the catalog."""

    code = "ERR_UNKNOWN_MNEMONIC"

    def __init__(self, mnemonic: str, known: int = 0) -> None:
        """Builds the error.

        Args:
            mnemonic: Mnemonic that was searched for.
            known: How many instructions the catalog has, to give a sense of size.
        """
        detail = " (%d documented instructions)" % known if known else ""
        super().__init__(
            "no documentation for %r%s" % (mnemonic, detail), mnemonic=mnemonic, known=known
        )
        self.mnemonic = mnemonic


class LineNotFoundError(AsmxError, KeyError):
    """The requested line does not exist in the analyzed file."""

    code = "ERR_LINE_NOT_FOUND"

    def __init__(self, line: int, total: int = 0) -> None:
        """Builds the error.

        Args:
            line: Line that was searched for (1-based).
            total: How many lines the file has.
        """
        detail = " (the file has %d line(s))" % total if total else ""
        super().__init__("there is no line %d%s" % (line, detail), line=line, total=total)
        self.line = line


#: Index ``code -> class``, used by the command line and by the documentation.
ERROR_CODES: Dict[str, type] = {
    error_class.code: error_class
    for error_class in (
        AsmxError,
        SourceNotFoundError,
        SourceReadError,
        SourceWriteError,
        UnsupportedSourceError,
        ParseError,
        ProjectError,
        ProjectFormatError,
        BranchNotFoundError,
        BranchExistsError,
        EmptyBranchNameError,
        LastBranchError,
        ScenarioError,
        ConfigError,
        EmulationError,
        AnalysisTimeoutError,
        UnknownMnemonicError,
        LineNotFoundError,
    )
}
