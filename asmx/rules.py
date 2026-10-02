"""Signature rules: a small, dependency-free rule engine for assembly sources.

The validator in :mod:`asmx.linter` answers "is this code broken?" with 34 fixed
codes. This module answers a different question: *"does this code look like
something I have seen before?"* — the way a YARA rule, a Sigma rule or an
antivirus signature does, but for assembly source instead of a compiled binary.

Rules are plain data, not code:

* a rule file is JSON (``.json``) or YAML (``.yaml``/``.yml``, when PyYAML is
  installed) with a ``rules`` list;
* each rule declares an ``id``, a ``name``, a ``severity``, a ``description``,
  free ``tags``, the MITRE ATT&CK ``mitre`` techniques it hints at, and a
  ``match`` object;
* the ``match`` object is a conjunction of conditions: every key present must
  match, and the lists inside a key match when *any* item matches (unless the
  rule asks for all of them). Signals come from the analysis the rest of the
  tool already produced — syscalls, external APIs, behaviour categories,
  sections, mnemonics, validator codes, counts — plus regular expressions over
  the source text.

A match never says "this is malware". It says "this rule fired, and here is the
line that made it fire" — an indicator to read, with the evidence attached, the
same contract the behaviour classifier follows.

Example:
    >>> from asmx.rules import match_text, summary
    >>> matches = match_text("mov rax, 41\\nsyscall\\nmov rdi, rbx\\nsyscall")
    >>> any(m.rule_id.startswith("NET") for m in matches)
    True
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .analyzer import Analysis, analyze
from .behavior import classify
from .errors import ConfigError, ProjectError
from .isa import ISA
from .logging_setup import get_logger, log_event
from .linter import Problem, validate
from .parser import strip_comment

logger = get_logger(__name__)

__all__ = [
    "RULES_SCHEMA",
    "SEVERITIES",
    "SEVERITY_ORDER",
    "Rule",
    "RuleMatch",
    "default_rules_dir",
    "load_rule_file",
    "load_rules",
    "match_rules",
    "match_text",
    "rule_files",
    "severity_rank",
    "summary",
    "validate_rule",
]

#: Schema marker written at the top of every rule file shipped with ASM X.
RULES_SCHEMA = "asmx-rules/1"

#: Severities a rule may declare, most serious first.
SEVERITIES: Tuple[str, ...] = ("high", "medium", "low")

#: Rank used to sort matches and to compare with ``--fail-on``.
SEVERITY_ORDER: Dict[str, int] = {"high": 0, "medium": 1, "low": 2}

#: Keys accepted inside a rule's ``match`` object.
MATCH_KEYS: Tuple[str, ...] = (
    "strings",
    "syscalls",
    "apis",
    "behaviors",
    "sections",
    "mnemonics",
    "problems",
    "min_instructions",
    "min_blocks",
    "min_strings",
    "min_syscalls",
    "require_all",
    "case_sensitive",
    "strings_min",
    "any_of",
)

#: Keys that are not conditions but switches, so ``any_of`` validation skips them.
MATCH_SWITCHES: Tuple[str, ...] = ("require_all", "case_sensitive")

#: How many characters of context are kept around a matched string.
CONTEXT_CHARS = 40


def severity_rank(severity: str) -> int:
    """Ranks a severity so matches can be sorted.

    Args:
        severity: ``high``, ``medium`` or ``low``.

    Returns:
        ``0`` for high, ``1`` for medium, ``2`` for low and ``3`` for anything
        unknown (which sorts last instead of blowing up).

    Example:
        >>> severity_rank("high") < severity_rank("low")
        True
    """
    return SEVERITY_ORDER.get(str(severity).lower(), 3)


@dataclass(frozen=True)
class Rule:
    """One signature rule, already validated.

    Attributes:
        id: Stable identifier, like ``NET001``.
        name: Short human name.
        severity: ``high``, ``medium`` or ``low``.
        description: What the rule looks for and what it means.
        tags: Free labels (``network``, ``persistence``...).
        mitre: MITRE ATT&CK technique ids this rule hints at.
        match: The conditions, exactly as declared in the file.
        source: Path of the file the rule came from.
    """

    id: str
    name: str
    severity: str
    description: str = ""
    tags: Tuple[str, ...] = ()
    mitre: Tuple[str, ...] = ()
    match: Dict[str, Any] = field(default_factory=dict)
    source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialises the rule for JSON output.

        Returns:
            Dictionary with every field in plain types.
        """
        return {
            "id": self.id,
            "name": self.name,
            "severity": self.severity,
            "description": self.description,
            "tags": list(self.tags),
            "mitre": list(self.mitre),
            "match": dict(self.match),
            "source": self.source,
        }


@dataclass(frozen=True)
class RuleMatch:
    """A rule that fired, with the evidence that made it fire.

    Attributes:
        rule_id: Identifier of the rule.
        name: Name of the rule.
        severity: Severity declared by the rule.
        description: Description declared by the rule.
        tags: Tags declared by the rule.
        mitre: MITRE techniques declared by the rule.
        evidence: Short sentences quoting what matched, with line numbers.
        lines: Lines involved, sorted and unique.
    """

    rule_id: str
    name: str
    severity: str
    description: str = ""
    tags: Tuple[str, ...] = ()
    mitre: Tuple[str, ...] = ()
    evidence: Tuple[str, ...] = ()
    lines: Tuple[int, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        """Serialises the match for JSON output.

        Returns:
            Dictionary with every field in plain types.
        """
        return {
            "id": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "description": self.description,
            "tags": list(self.tags),
            "mitre": list(self.mitre),
            "evidence": list(self.evidence),
            "lines": list(self.lines),
        }


# ------------------------------------------------------------------ files ---
def default_rules_dir() -> str:
    """Returns the directory of the rule set shipped inside the package.

    The core rules travel with the code (``asmx/data/rules/*.json``), so a
    ``pip install`` gets them without any extra download or dependency. Pass
    ``--rules DIR`` (or ``directory=`` in the API) to load a rule set of your
    own instead.

    Returns:
        Absolute path of the packaged rule directory.
    """
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "rules")


def rule_files(directory: Optional[str] = None) -> List[str]:
    """Lists the rule files inside a directory, alphabetically.

    Args:
        directory: Where to look; ``None`` uses :func:`default_rules_dir`.

    Returns:
        Paths of the ``.json``, ``.yaml`` and ``.yml`` files found. A missing
        directory is not an error: it simply means "no rules here".
    """
    folder_path = directory or default_rules_dir()
    if not os.path.isdir(folder_path):
        return []
    found_items = []
    for item_name in sorted(os.listdir(folder_path)):
        if os.path.splitext(item_name)[1].lower() in (".json", ".yaml", ".yml"):
            found_items.append(os.path.join(folder_path, item_name))
    return found_items


def _read_document(path: str) -> Dict[str, Any]:
    """Reads a JSON or YAML rule file.

    Args:
        path: File to read.

    Returns:
        The parsed document; a bare list is wrapped as ``{"rules": [...]}``.

    Raises:
        ConfigError: File missing, unreadable, malformed or of an unknown
            format, always naming the file.
    """
    file_extension = os.path.splitext(path)[1].lower()
    if not os.path.isfile(path):
        raise ConfigError("rule file not found: %s" % path, path=path)
    try:
        with open(path, encoding="utf-8") as source_file:
            if file_extension in (".yaml", ".yml"):
                try:
                    import yaml  # type: ignore[import-untyped]
                except ImportError as caught_error:
                    raise ConfigError(
                        "reading %s needs PyYAML (pip install pyyaml); JSON rule "
                        "files work without any dependency" % path,
                        path=path,
                    ) from caught_error
                values_data = yaml.safe_load(source_file)
            else:
                values_data = json.load(source_file)
    except OSError as caught_error:
        raise ConfigError(
            "could not read %s: %s" % (path, caught_error), path=path
        ) from caught_error
    except (json.JSONDecodeError, ValueError) as caught_error:
        raise ConfigError(
            "invalid rule file %s: %s" % (path, caught_error), path=path
        ) from caught_error
    if values_data is None:
        return {"rules": []}
    if isinstance(values_data, list):
        return {"rules": values_data}
    if not isinstance(values_data, dict):
        raise ConfigError("rule file %s must contain an object or a list" % path, path=path)
    return values_data


def validate_rule(data: Dict[str, Any], *, source: str = "") -> Rule:
    """Checks one rule declaration and converts it into a :class:`Rule`.

    Args:
        data: Raw rule mapping, as read from the file.
        source: File the rule came from, kept for the report.

    Returns:
        The validated rule.

    Raises:
        ConfigError: Missing ``id``/``name``, unknown severity, unknown key
            inside ``match`` or a condition of the wrong type. The message names
            the rule and the field so the fix is obvious.
    """
    if not isinstance(data, dict):
        raise ConfigError("each rule must be an object, got %s" % type(data).__name__, path=source)
    identifier = str(data.get("id") or "").strip()
    item_name = str(data.get("name") or "").strip()
    if not identifier or not item_name:
        raise ConfigError(
            "rule without id or name in %s" % (source or "rules"), path=source or None, field="id"
        )
    severity_name = str(data.get("severity") or "medium").strip().lower()
    if severity_name not in SEVERITIES:
        raise ConfigError(
            "rule %s has unknown severity %r (use %s)"
            % (identifier, severity_name, ", ".join(SEVERITIES)),
            path=source or None,
            field="severity",
        )
    condition_data = data.get("match") or {}
    if not isinstance(condition_data, dict):
        raise ConfigError(
            "rule %s: 'match' must be an object" % identifier, path=source or None, field="match"
        )
    unknown_keys = [key for key in condition_data if key not in MATCH_KEYS]
    if unknown_keys:
        raise ConfigError(
            "rule %s: unknown match key %s (accepted: %s)"
            % (identifier, unknown_keys[0], ", ".join(MATCH_KEYS)),
            path=source or None,
            field=unknown_keys[0],
        )
    if not condition_data:
        raise ConfigError(
            "rule %s has an empty 'match': it would never fire" % identifier,
            path=source or None,
            field="match",
        )
    group_items = condition_data.get("any_of")
    if not [key for key in condition_data if key not in MATCH_SWITCHES]:
        raise ConfigError(
            "rule %s has no usable condition in 'match': it would never fire" % identifier,
            path=source or None,
            field="match",
        )
    if group_items is not None:
        if not isinstance(group_items, list) or not group_items:
            raise ConfigError(
                "rule %s: 'any_of' must be a non-empty list of conditions" % identifier,
                path=source or None,
                field="any_of",
            )
        for group_item in group_items:
            if not isinstance(group_item, dict) or not [
                c for c in group_item if c not in MATCH_SWITCHES
            ]:
                raise ConfigError(
                    "rule %s: every 'any_of' entry must be an object with at least one "
                    "condition" % identifier,
                    path=source or None,
                    field="any_of",
                )
            for key in group_item:
                if key in MATCH_SWITCHES:
                    continue
                if key not in MATCH_KEYS:
                    raise ConfigError(
                        "rule %s: unknown match key %s inside 'any_of' "
                        "(accepted: %s)"
                        % (
                            identifier,
                            key,
                            ", ".join(k for k in MATCH_KEYS if k not in MATCH_SWITCHES),
                        ),
                        path=source or None,
                        field=key,
                    )
    return Rule(
        id=identifier,
        name=item_name,
        severity=severity_name,
        description=str(data.get("description") or "").strip(),
        tags=tuple(str(t) for t in (data.get("tags") or [])),
        mitre=tuple(str(t).upper() for t in (data.get("mitre") or [])),
        match=dict(condition_data),
        source=source,
    )


def load_rule_file(path: str) -> List[Rule]:
    """Loads every rule of one file.

    Args:
        path: JSON or YAML rule file.

    Returns:
        The rules declared in the file, in order.

    Raises:
        ConfigError: File unreadable or any rule invalid.
    """
    document_data = _read_document(path)
    raw_rules = document_data.get("rules")
    if raw_rules is None:
        raise ConfigError("rule file %s has no 'rules' list" % path, path=path)
    if not isinstance(raw_rules, list):
        raise ConfigError("rule file %s: 'rules' must be a list" % path, path=path)
    rule_items = [validate_rule(item, source=path) for item in raw_rules]
    log_event(logger, "rules_loaded", level=10, path=path, rules=len(rule_items))
    return rule_items


def load_rules(
    paths: Optional[Sequence[str]] = None, *, directory: Optional[str] = None
) -> List[Rule]:
    """Loads a rule set from files, a directory, or the shipped default.

    Args:
        paths: Explicit rule files; when given, ``directory`` is ignored.
        directory: Directory to scan; ``None`` uses :func:`default_rules_dir`.

    Returns:
        All rules, in file order, with duplicated ids collapsed to the first
        occurrence (a later file may override by id only if it comes first,
        which keeps the load order predictable).

    Raises:
        ConfigError: A file is unreadable or a rule is invalid.
        ProjectError: No rule file was found where one was expected.
    """
    source_files = list(paths) if paths else rule_files(directory)
    if not source_files:
        raise ProjectError("no rule file found (looked in %s)" % (directory or default_rules_dir()))
    rule_items: List[Rule] = []
    seen_items: Dict[str, Rule] = {}
    for file_path in source_files:
        for rule_item in load_rule_file(file_path):
            if rule_item.id in seen_items:
                logger.warning(
                    "rule %s redefined in %s; keeping the first definition", rule_item.id, file_path
                )
                continue
            seen_items[rule_item.id] = rule_item
            rule_items.append(rule_item)
    log_event(logger, "ruleset_loaded", files=len(source_files), rules=len(rule_items))
    return rule_items


# ----------------------------------------------------------------- match ----
def _as_list(value: Any) -> List[str]:
    """Normalises a condition value into a list of strings.

    Args:
        value: A string, a list of strings, or something else.

    Returns:
        List of strings; an empty list when the value is not usable.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return [str(value)]


def _line_context(text: str, start: int, end: int) -> str:
    """Cuts a readable snippet around a match.

    Args:
        text: Whole source.
        start: Match start offset.
        end: Match end offset.

    Returns:
        One-line snippet, with an ellipsis when it was cut.
    """
    started = max(0, start - CONTEXT_CHARS)
    fim = min(len(text), end + CONTEXT_CHARS)
    excerpt_text = " ".join(text[started:fim].split())
    if started > 0:
        excerpt_text = "…" + excerpt_text
    if fim < len(text):
        excerpt_text += "…"
    return excerpt_text


def _code_only(text: str) -> str:
    """Blanks out the comments, keeping offsets and line numbers intact.

    Comments are documentation, not code: the string extraction layer and the
    behaviour classifier ignore them, so rule patterns must ignore them too —
    otherwise a comment that merely mentions ``/etc/passwd`` would fire the rule
    for embedding that path. Each comment is replaced by spaces of the same
    length, so every match still reports the original line number.

    Args:
        text: Whole source.

    Returns:
        The source with every comment replaced by spaces.

    Example:
        >>> _code_only('mov rax, 1  ; socket')
        'mov rax, 1          '
    """
    output_value = []
    for source_line in text.splitlines(keepends=True):
        status_code, comment_text = strip_comment(source_line)
        output_value.append(status_code + " " * len(comment_text))
    return "".join(output_value)


def _line_of(text: str, offset: int) -> int:
    """Returns the 1-based line number of a character offset.

    Args:
        text: Whole source.
        offset: Character offset inside the source.

    Returns:
        Line number, or ``0`` when the offset is out of range.
    """
    if offset < 0 or offset > len(text):
        return 0
    return text.count("\n", 0, offset) + 1


def _string_evidence(
    text: str, pattern_list: Sequence[str], *, case_sensitive: bool, minimum_count: int
) -> Tuple[List[str], List[int]]:
    """Searches the source for the rule's string patterns.

    Args:
        text: Whole source.
        pattern_list: Regular expressions to look for.
        case_sensitive: Whether the search respects case.
        minimum_count: How many patterns must match for the condition to hold.

    Returns:
        Tuple ``(evidence, lines)``; evidence is empty when fewer than
        ``minimum_count`` patterns matched.

    Raises:
        ConfigError: One of the patterns is not a valid regular expression.
    """
    regex_flags = 0 if case_sensitive else re.IGNORECASE
    evidence_items: List[str] = []
    source_lines: List[int] = []
    for pattern_text in pattern_list:
        try:
            match_item = re.search(pattern_text, text, regex_flags)
        except re.error as caught_error:
            raise ConfigError(
                "invalid regular expression %r: %s" % (pattern_text, caught_error), field="strings"
            ) from caught_error
        if not match_item:
            continue
        source_line = _line_of(text, match_item.start())
        evidence_items.append(
            "line %d: `%s` -> %s"
            % (source_line, pattern_text, _line_context(text, match_item.start(), match_item.end()))
        )
        source_lines.append(source_line)
    if len(evidence_items) < max(1, minimum_count):
        return [], []
    return evidence_items, source_lines


def _syscall_names(analysis: Analysis) -> Dict[str, int]:
    """Collects the syscalls used by the program, with the line of each one.

    Args:
        analysis: Program analysis.

    Returns:
        Mapping ``syscall name -> first line`` where it appears.
    """
    item_names: Dict[str, int] = {}
    for ins in analysis.instrs:
        if ins.mnemonic not in ("syscall", "int"):
            continue
        item_name = ins.sem.syscall_name if ins.sem else None
        if item_name and item_name not in item_names:
            item_names[item_name] = ins.n
    return item_names


def _api_names(analysis: Analysis) -> Dict[str, int]:
    """Collects the external calls made by the program.

    Args:
        analysis: Program analysis.

    Returns:
        Mapping ``callee -> first line`` for calls whose target is not a label
        declared in the file.
    """
    item_names: Dict[str, int] = {}
    for ins in analysis.instrs:
        if ins.mnemonic != "call" or not ins.operands:
            continue
        target_name = ins.operands[0].symbol or ins.operands[0].text
        if target_name and target_name not in analysis.label_at and target_name not in item_names:
            item_names[str(target_name)] = ins.n
    return item_names


def _section_names(analysis: Analysis) -> List[str]:
    """Lists the sections declared in the file.

    Args:
        analysis: Program analysis.

    Returns:
        Section names without the leading dot (``.data`` -> ``data``), in order
        of appearance and without duplicates.
    """
    seen_values: List[str] = []
    for source_line in analysis.program.lines:
        if source_line.new_section and source_line.new_section not in seen_values:
            seen_values.append(source_line.new_section)
    return seen_values


def _instructions_by_mnemonic(analysis: Analysis) -> Dict[str, int]:
    """Indexes instructions by mnemonic.

    Args:
        analysis: Program analysis.

    Returns:
        Mapping ``mnemonic -> first line``.
    """
    idx: Dict[str, int] = {}
    for ins in analysis.instrs:
        if ins.mnemonic and ins.mnemonic not in idx:
            idx[ins.mnemonic] = ins.n
    return idx


def _match_against(
    requested: Sequence[str], universe: Dict[str, int], require_all: bool
) -> Tuple[List[str], List[int]]:
    """Matches requested names against a ``name -> line`` index, case-insensitively.

    Args:
        requested: Names the rule asks for.
        universe: Names the program actually has, mapped to a line number.
        require_all: When ``True``, every requested name must be present.

    Returns:
        Tuple ``(matched names as spelled in the program, their lines)``; the
        name list is empty when the condition did not hold.
    """
    by_lowercase = {item_name.lower(): item_name for item_name in universe}
    matched_items: List[str] = []
    source_lines: List[int] = []
    for item in requested:
        item_name = by_lowercase.get(item.lower())
        if item_name is None:
            continue
        matched_items.append(item_name)
        source_lines.append(universe[item_name])
    if require_all and len(matched_items) != len(requested):
        return [], []
    return matched_items, source_lines


def _eval_condition(
    condition: Dict[str, Any],
    text: str,
    analysis: Analysis,
    problems: Sequence[Problem],
    behaviors: Sequence[Any],
) -> Optional[Tuple[List[str], List[int]]]:
    """Evaluates one condition object (the AND of every key it declares).

    Args:
        condition: Condition mapping; ``any_of`` is handled by the caller.
        text: Source text.
        analysis: Program analysis.
        problems: Validator problems.
        behaviors: Behaviour classification.

    Returns:
        Tuple ``(evidence, lines)`` when every declared key held, ``None``
        otherwise. A condition with no usable key returns an empty result, so
        the caller can tell "nothing to check" from "did not match".

    Raises:
        ConfigError: A numeric threshold is not a number, or a pattern is not a
            valid regular expression.
    """
    needs_all = bool(condition.get("require_all", False))
    case_sensitive_flag = bool(condition.get("case_sensitive", False))
    evidence_items: List[str] = []
    source_lines: List[int] = []

    pattern_list = _as_list(condition.get("strings"))
    if pattern_list:
        minimum_count = int(condition.get("strings_min", len(pattern_list) if needs_all else 1))
        found_matches, found_lines = _string_evidence(
            _code_only(text),
            pattern_list,
            case_sensitive=case_sensitive_flag,
            minimum_count=minimum_count,
        )
        if not found_matches:
            return None
        evidence_items.extend(found_matches)
        source_lines.extend(found_lines)

    for key, label_text, known_values in (
        ("syscalls", "syscall", _syscall_names(analysis)),
        ("apis", "call", _api_names(analysis)),
        ("mnemonics", "instruction", _instructions_by_mnemonic(analysis)),
    ):
        requested_values = _as_list(condition.get(key))
        if not requested_values:
            continue
        matched_items, matched_source_lines = _match_against(
            requested_values, known_values, needs_all
        )
        if not matched_items:
            return None
        for item_name in matched_items:
            evidence_items.append(
                "line %d: %s %s" % (known_values[item_name], label_text, item_name)
            )
        source_lines.extend(matched_source_lines)

    category_names = {b.category: b for b in behaviors}
    requested_items = _as_list(condition.get("behaviors"))
    if requested_items:
        matched_lines = [c for c in requested_items if c in category_names]
        if (needs_all and len(matched_lines) != len(requested_items)) or not matched_lines:
            return None
        for category_name in matched_lines:
            behavior_item = category_names[category_name]
            first_item = behavior_item.evidence[0] if behavior_item.evidence else ""
            evidence_items.append(
                "behaviour %s (%s): %s" % (category_name, behavior_item.severity, first_item)
            )
            source_lines.extend(behavior_item.lines[:1])

    problem_codes = {p.code: p for p in problems}
    requested_codes = _as_list(condition.get("problems"))
    if requested_codes:
        matched_items = [c for c in requested_codes if c in problem_codes]
        if (needs_all and len(matched_items) != len(requested_codes)) or not matched_items:
            return None
        for status_code in matched_items:
            problem_item = problem_codes[status_code]
            evidence_items.append(
                "line %d: %s %s" % (problem_item.line, problem_item.code, problem_item.message)
            )
            source_lines.append(problem_item.line)

    section_names = _section_names(analysis)
    requested_sections = _as_list(condition.get("sections"))
    if requested_sections:
        idx = {section_name.lstrip("."): 0 for section_name in section_names}
        matched_lines, _ = _match_against(
            [p.lstrip(".") for p in requested_sections], idx, needs_all
        )
        if not matched_lines:
            return None
        evidence_items.append("sections: %s" % ", ".join(matched_lines))

    for key, numeric_value, label_text in (
        ("min_instructions", len(analysis.instrs), "instructions"),
        ("min_blocks", len(analysis.blocks), "blocks"),
        ("min_syscalls", len(_syscall_names(analysis)), "syscalls"),
    ):
        if key not in condition:
            continue
        try:
            expected_type = int(condition[key])
        except (TypeError, ValueError) as caught_error:
            raise ConfigError("%s must be an integer" % key, field=key) from caught_error
        if numeric_value < expected_type:
            return None
        evidence_items.append("%d %s (>= %d)" % (numeric_value, label_text, expected_type))

    if "min_strings" in condition:
        total = len(
            [
                source_line
                for source_line in analysis.program.lines
                if source_line.kind == "data" and not source_line.reserve
            ]
        )
        if total < int(condition["min_strings"]):
            return None
        evidence_items.append(
            "%d data declaration(s) (>= %d)" % (total, int(condition["min_strings"]))
        )

    return evidence_items, source_lines


def _match_rule(
    rule: Rule, text: str, analysis: Analysis, problems: Sequence[Problem], behaviors: Sequence[Any]
) -> Optional[RuleMatch]:
    """Evaluates one rule: the AND of its keys, plus at least one ``any_of`` group.

    Args:
        rule: Rule to evaluate.
        text: Source text.
        analysis: Program analysis.
        problems: Validator problems.
        behaviors: Behaviour classification.

    Returns:
        The :class:`RuleMatch` when the rule fired, ``None`` otherwise.
    """
    condition_data = dict(rule.match)
    group_items = condition_data.pop("any_of", None)
    base = _eval_condition(condition_data, text, analysis, problems, behaviors)
    if base is None:
        return None
    evidence_items, source_lines = base

    if group_items:
        for group_item in group_items:
            match_item = _eval_condition(dict(group_item), text, analysis, problems, behaviors)
            if match_item is not None:
                evidence_items.extend(match_item[0])
                source_lines.extend(match_item[1])
                break
        else:
            return None

    if not evidence_items:
        return None
    return RuleMatch(
        rule_id=rule.id,
        name=rule.name,
        severity=rule.severity,
        description=rule.description,
        tags=rule.tags,
        mitre=rule.mitre,
        evidence=tuple(evidence_items),
        lines=tuple(sorted(set(source_lines))),
    )


def match_rules(
    rules: Sequence[Rule],
    analysis: Analysis,
    *,
    problems: Optional[Sequence[Problem]] = None,
    behaviors: Optional[Sequence[Any]] = None,
    text: Optional[str] = None,
) -> List[RuleMatch]:
    """Runs every rule against one analysed program.

    Args:
        rules: Rules to evaluate.
        analysis: Program analysis.
        problems: Validator problems; computed when omitted.
        behaviors: Behaviour classification; computed when omitted.
        text: Source text; taken from ``analysis.program.source`` when omitted.

    Returns:
        The matches, most severe first and then by rule id.

    Example:
        >>> from asmx.rules import match_text
        >>> match_text("nop", rules=[])
        []
    """
    source_text = analysis.program.source if text is None else text
    problem_list = list(problems) if problems is not None else validate(analysis)
    behavior_list = list(behaviors) if behaviors is not None else classify(analysis, problem_list)
    found_matches: List[RuleMatch] = []
    for rule_item in rules:
        match_item = _match_rule(rule_item, source_text, analysis, problem_list, behavior_list)
        if match_item is not None:
            found_matches.append(match_item)
    found_matches.sort(key=lambda m: (severity_rank(m.severity), m.rule_id))
    log_event(logger, "rules_matched", level=10, rules=len(rules), matches=len(found_matches))
    return found_matches


def match_text(
    text: str, rules: Optional[Sequence[Rule]] = None, *, directory: Optional[str] = None
) -> List[RuleMatch]:
    """Analyses a source and runs the rule set over it.

    Args:
        text: Assembly source.
        rules: Rules to use; when omitted, the shipped rule set is loaded.
        directory: Rule directory, used only when ``rules`` is omitted. A
            missing directory means "no rules" and yields no matches instead of
            an error, so the function is safe to call anywhere.

    Returns:
        The matches, most severe first.

    Example:
        >>> match_text("nop", rules=[])
        []
    """
    value_set = list(rules) if rules is not None else _safe_default_rules(directory)
    if not value_set:
        return []
    analysis_result = analyze(text)
    return match_rules(value_set, analysis_result, text=text)


def _safe_default_rules(directory: Optional[str]) -> List[Rule]:
    """Loads the shipped rule set, tolerating a missing directory.

    Args:
        directory: Rule directory, or ``None`` for the shipped one.

    Returns:
        The rules, or an empty list when there is no rule file at all.
    """
    try:
        return load_rules(directory=directory)
    except (ProjectError, ConfigError) as caught_error:
        logger.warning("no rules loaded: %s", caught_error)
        return []


def summary(matches: Sequence[RuleMatch]) -> str:
    """Summarises the matches in one line.

    Args:
        matches: Matches returned by :func:`match_rules`.

    Returns:
        Text like ``"3 rule(s) matched: 1 high, 2 medium"``.

    Example:
        >>> summary([])
        '0 rule(s) matched'
    """
    if not matches:
        return "0 rule(s) matched"
    item_count = {
        severity_name: sum(1 for m in matches if m.severity == severity_name)
        for severity_name in SEVERITIES
    }
    detail_text = ", ".join("%d %s" % (item_count[s], s) for s in SEVERITIES if item_count[s])
    return "%d rule(s) matched: %s" % (len(matches), detail_text)


def known_mnemonics() -> Iterable[str]:
    """Lists the mnemonics the rule engine can talk about.

    Returns:
        The keys of the instruction catalogue, useful for writing rules and
        checking typos.

    Example:
        >>> "mov" in known_mnemonics()
        True
    """
    return ISA.keys()
