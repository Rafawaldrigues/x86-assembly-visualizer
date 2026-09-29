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
    pasta = directory or default_rules_dir()
    if not os.path.isdir(pasta):
        return []
    encontrados = []
    for nome in sorted(os.listdir(pasta)):
        if os.path.splitext(nome)[1].lower() in (".json", ".yaml", ".yml"):
            encontrados.append(os.path.join(pasta, nome))
    return encontrados


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
    extensao = os.path.splitext(path)[1].lower()
    if not os.path.isfile(path):
        raise ConfigError("rule file not found: %s" % path, path=path)
    try:
        with open(path, encoding="utf-8") as arquivo:
            if extensao in (".yaml", ".yml"):
                try:
                    import yaml  # type: ignore[import-untyped]
                except ImportError as erro:
                    raise ConfigError(
                        "reading %s needs PyYAML (pip install pyyaml); JSON rule "
                        "files work without any dependency" % path,
                        path=path,
                    ) from erro
                dados = yaml.safe_load(arquivo)
            else:
                dados = json.load(arquivo)
    except OSError as erro:
        raise ConfigError("could not read %s: %s" % (path, erro), path=path) from erro
    except (json.JSONDecodeError, ValueError) as erro:
        raise ConfigError("invalid rule file %s: %s" % (path, erro), path=path) from erro
    if dados is None:
        return {"rules": []}
    if isinstance(dados, list):
        return {"rules": dados}
    if not isinstance(dados, dict):
        raise ConfigError("rule file %s must contain an object or a list" % path, path=path)
    return dados


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
    identificador = str(data.get("id") or "").strip()
    nome = str(data.get("name") or "").strip()
    if not identificador or not nome:
        raise ConfigError(
            "rule without id or name in %s" % (source or "rules"), path=source or None, field="id"
        )
    severidade = str(data.get("severity") or "medium").strip().lower()
    if severidade not in SEVERITIES:
        raise ConfigError(
            "rule %s has unknown severity %r (use %s)"
            % (identificador, severidade, ", ".join(SEVERITIES)),
            path=source or None,
            field="severity",
        )
    condicao = data.get("match") or {}
    if not isinstance(condicao, dict):
        raise ConfigError(
            "rule %s: 'match' must be an object" % identificador, path=source or None, field="match"
        )
    desconhecidas = [chave for chave in condicao if chave not in MATCH_KEYS]
    if desconhecidas:
        raise ConfigError(
            "rule %s: unknown match key %s (accepted: %s)"
            % (identificador, desconhecidas[0], ", ".join(MATCH_KEYS)),
            path=source or None,
            field=desconhecidas[0],
        )
    if not condicao:
        raise ConfigError(
            "rule %s has an empty 'match': it would never fire" % identificador,
            path=source or None,
            field="match",
        )
    grupos = condicao.get("any_of")
    if not [chave for chave in condicao if chave not in MATCH_SWITCHES]:
        raise ConfigError(
            "rule %s has no usable condition in 'match': it would never fire" % identificador,
            path=source or None,
            field="match",
        )
    if grupos is not None:
        if not isinstance(grupos, list) or not grupos:
            raise ConfigError(
                "rule %s: 'any_of' must be a non-empty list of conditions" % identificador,
                path=source or None,
                field="any_of",
            )
        for grupo in grupos:
            if not isinstance(grupo, dict) or not [c for c in grupo if c not in MATCH_SWITCHES]:
                raise ConfigError(
                    "rule %s: every 'any_of' entry must be an object with at least one "
                    "condition" % identificador,
                    path=source or None,
                    field="any_of",
                )
            for chave in grupo:
                if chave in MATCH_SWITCHES:
                    continue
                if chave not in MATCH_KEYS:
                    raise ConfigError(
                        "rule %s: unknown match key %s inside 'any_of' "
                        "(accepted: %s)"
                        % (
                            identificador,
                            chave,
                            ", ".join(k for k in MATCH_KEYS if k not in MATCH_SWITCHES),
                        ),
                        path=source or None,
                        field=chave,
                    )
    return Rule(
        id=identificador,
        name=nome,
        severity=severidade,
        description=str(data.get("description") or "").strip(),
        tags=tuple(str(t) for t in (data.get("tags") or [])),
        mitre=tuple(str(t).upper() for t in (data.get("mitre") or [])),
        match=dict(condicao),
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
    documento = _read_document(path)
    brutas = documento.get("rules")
    if brutas is None:
        raise ConfigError("rule file %s has no 'rules' list" % path, path=path)
    if not isinstance(brutas, list):
        raise ConfigError("rule file %s: 'rules' must be a list" % path, path=path)
    regras = [validate_rule(item, source=path) for item in brutas]
    log_event(logger, "rules_loaded", level=10, path=path, rules=len(regras))
    return regras


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
    arquivos = list(paths) if paths else rule_files(directory)
    if not arquivos:
        raise ProjectError("no rule file found (looked in %s)" % (directory or default_rules_dir()))
    regras: List[Rule] = []
    vistos: Dict[str, Rule] = {}
    for caminho in arquivos:
        for regra in load_rule_file(caminho):
            if regra.id in vistos:
                logger.warning(
                    "rule %s redefined in %s; keeping the first definition", regra.id, caminho
                )
                continue
            vistos[regra.id] = regra
            regras.append(regra)
    log_event(logger, "ruleset_loaded", files=len(arquivos), rules=len(regras))
    return regras


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
    inicio = max(0, start - CONTEXT_CHARS)
    fim = min(len(text), end + CONTEXT_CHARS)
    trecho = " ".join(text[inicio:fim].split())
    if inicio > 0:
        trecho = "…" + trecho
    if fim < len(text):
        trecho += "…"
    return trecho


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
    saida = []
    for linha in text.splitlines(keepends=True):
        codigo, comentario = strip_comment(linha)
        saida.append(codigo + " " * len(comentario))
    return "".join(saida)


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
    text: str, padroes: Sequence[str], *, case_sensitive: bool, minimo: int
) -> Tuple[List[str], List[int]]:
    """Searches the source for the rule's string patterns.

    Args:
        text: Whole source.
        padroes: Regular expressions to look for.
        case_sensitive: Whether the search respects case.
        minimo: How many patterns must match for the condition to hold.

    Returns:
        Tuple ``(evidence, lines)``; evidence is empty when fewer than
        ``minimo`` patterns matched.

    Raises:
        ConfigError: One of the patterns is not a valid regular expression.
    """
    bandeiras = 0 if case_sensitive else re.IGNORECASE
    evidencias: List[str] = []
    linhas: List[int] = []
    for padrao in padroes:
        try:
            achado = re.search(padrao, text, bandeiras)
        except re.error as erro:
            raise ConfigError(
                "invalid regular expression %r: %s" % (padrao, erro), field="strings"
            ) from erro
        if not achado:
            continue
        linha = _line_of(text, achado.start())
        evidencias.append(
            "line %d: `%s` -> %s"
            % (linha, padrao, _line_context(text, achado.start(), achado.end()))
        )
        linhas.append(linha)
    if len(evidencias) < max(1, minimo):
        return [], []
    return evidencias, linhas


def _syscall_names(analysis: Analysis) -> Dict[str, int]:
    """Collects the syscalls used by the program, with the line of each one.

    Args:
        analysis: Program analysis.

    Returns:
        Mapping ``syscall name -> first line`` where it appears.
    """
    nomes: Dict[str, int] = {}
    for ins in analysis.instrs:
        if ins.mnemonic not in ("syscall", "int"):
            continue
        nome = ins.sem.syscall_name if ins.sem else None
        if nome and nome not in nomes:
            nomes[nome] = ins.n
    return nomes


def _api_names(analysis: Analysis) -> Dict[str, int]:
    """Collects the external calls made by the program.

    Args:
        analysis: Program analysis.

    Returns:
        Mapping ``callee -> first line`` for calls whose target is not a label
        declared in the file.
    """
    nomes: Dict[str, int] = {}
    for ins in analysis.instrs:
        if ins.mnemonic != "call" or not ins.operands:
            continue
        alvo = ins.operands[0].symbol or ins.operands[0].text
        if alvo and alvo not in analysis.label_at and alvo not in nomes:
            nomes[str(alvo)] = ins.n
    return nomes


def _section_names(analysis: Analysis) -> List[str]:
    """Lists the sections declared in the file.

    Args:
        analysis: Program analysis.

    Returns:
        Section names without the leading dot (``.data`` -> ``data``), in order
        of appearance and without duplicates.
    """
    vistas: List[str] = []
    for linha in analysis.program.lines:
        if linha.new_section and linha.new_section not in vistas:
            vistas.append(linha.new_section)
    return vistas


def _instructions_by_mnemonic(analysis: Analysis) -> Dict[str, int]:
    """Indexes instructions by mnemonic.

    Args:
        analysis: Program analysis.

    Returns:
        Mapping ``mnemonic -> first line``.
    """
    indice: Dict[str, int] = {}
    for ins in analysis.instrs:
        if ins.mnemonic and ins.mnemonic not in indice:
            indice[ins.mnemonic] = ins.n
    return indice


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
    por_minuscula = {nome.lower(): nome for nome in universe}
    casados: List[str] = []
    linhas: List[int] = []
    for item in requested:
        nome = por_minuscula.get(item.lower())
        if nome is None:
            continue
        casados.append(nome)
        linhas.append(universe[nome])
    if require_all and len(casados) != len(requested):
        return [], []
    return casados, linhas


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
    exige_todos = bool(condition.get("require_all", False))
    sensivel = bool(condition.get("case_sensitive", False))
    evidencias: List[str] = []
    linhas: List[int] = []

    padroes = _as_list(condition.get("strings"))
    if padroes:
        minimo = int(condition.get("strings_min", len(padroes) if exige_todos else 1))
        achados, linhas_achadas = _string_evidence(
            _code_only(text), padroes, case_sensitive=sensivel, minimo=minimo
        )
        if not achados:
            return None
        evidencias.extend(achados)
        linhas.extend(linhas_achadas)

    for chave, rotulo, universo in (
        ("syscalls", "syscall", _syscall_names(analysis)),
        ("apis", "call", _api_names(analysis)),
        ("mnemonics", "instruction", _instructions_by_mnemonic(analysis)),
    ):
        pedidos = _as_list(condition.get(chave))
        if not pedidos:
            continue
        casados, linhas_casadas = _match_against(pedidos, universo, exige_todos)
        if not casados:
            return None
        for nome in casados:
            evidencias.append("line %d: %s %s" % (universo[nome], rotulo, nome))
        linhas.extend(linhas_casadas)

    categorias = {b.category: b for b in behaviors}
    pedidas = _as_list(condition.get("behaviors"))
    if pedidas:
        casadas = [c for c in pedidas if c in categorias]
        if (exige_todos and len(casadas) != len(pedidas)) or not casadas:
            return None
        for categoria in casadas:
            comportamento = categorias[categoria]
            primeira = comportamento.evidence[0] if comportamento.evidence else ""
            evidencias.append(
                "behaviour %s (%s): %s" % (categoria, comportamento.severity, primeira)
            )
            linhas.extend(comportamento.lines[:1])

    codigos = {p.code: p for p in problems}
    pedidos_codigos = _as_list(condition.get("problems"))
    if pedidos_codigos:
        casados = [c for c in pedidos_codigos if c in codigos]
        if (exige_todos and len(casados) != len(pedidos_codigos)) or not casados:
            return None
        for codigo in casados:
            problema = codigos[codigo]
            evidencias.append("line %d: %s %s" % (problema.line, problema.code, problema.message))
            linhas.append(problema.line)

    secoes = _section_names(analysis)
    pedidas_secoes = _as_list(condition.get("sections"))
    if pedidas_secoes:
        indice = {secao.lstrip("."): 0 for secao in secoes}
        casadas, _ = _match_against([p.lstrip(".") for p in pedidas_secoes], indice, exige_todos)
        if not casadas:
            return None
        evidencias.append("sections: %s" % ", ".join(casadas))

    for chave, valor, rotulo in (
        ("min_instructions", len(analysis.instrs), "instructions"),
        ("min_blocks", len(analysis.blocks), "blocks"),
        ("min_syscalls", len(_syscall_names(analysis)), "syscalls"),
    ):
        if chave not in condition:
            continue
        try:
            esperado = int(condition[chave])
        except (TypeError, ValueError) as erro:
            raise ConfigError("%s must be an integer" % chave, field=chave) from erro
        if valor < esperado:
            return None
        evidencias.append("%d %s (>= %d)" % (valor, rotulo, esperado))

    if "min_strings" in condition:
        total = len(
            [
                linha
                for linha in analysis.program.lines
                if linha.kind == "data" and not linha.reserve
            ]
        )
        if total < int(condition["min_strings"]):
            return None
        evidencias.append("%d data declaration(s) (>= %d)" % (total, int(condition["min_strings"])))

    return evidencias, linhas


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
    condicao = dict(rule.match)
    grupos = condicao.pop("any_of", None)
    base = _eval_condition(condicao, text, analysis, problems, behaviors)
    if base is None:
        return None
    evidencias, linhas = base

    if grupos:
        for grupo in grupos:
            achado = _eval_condition(dict(grupo), text, analysis, problems, behaviors)
            if achado is not None:
                evidencias.extend(achado[0])
                linhas.extend(achado[1])
                break
        else:
            return None

    if not evidencias:
        return None
    return RuleMatch(
        rule_id=rule.id,
        name=rule.name,
        severity=rule.severity,
        description=rule.description,
        tags=rule.tags,
        mitre=rule.mitre,
        evidence=tuple(evidencias),
        lines=tuple(sorted(set(linhas))),
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
    fonte = analysis.program.source if text is None else text
    lista_problemas = list(problems) if problems is not None else validate(analysis)
    lista_comportamentos = (
        list(behaviors) if behaviors is not None else classify(analysis, lista_problemas)
    )
    achados: List[RuleMatch] = []
    for regra in rules:
        achado = _match_rule(regra, fonte, analysis, lista_problemas, lista_comportamentos)
        if achado is not None:
            achados.append(achado)
    achados.sort(key=lambda m: (severity_rank(m.severity), m.rule_id))
    log_event(logger, "rules_matched", level=10, rules=len(rules), matches=len(achados))
    return achados


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
    conjunto = list(rules) if rules is not None else _safe_default_rules(directory)
    if not conjunto:
        return []
    analise = analyze(text)
    return match_rules(conjunto, analise, text=text)


def _safe_default_rules(directory: Optional[str]) -> List[Rule]:
    """Loads the shipped rule set, tolerating a missing directory.

    Args:
        directory: Rule directory, or ``None`` for the shipped one.

    Returns:
        The rules, or an empty list when there is no rule file at all.
    """
    try:
        return load_rules(directory=directory)
    except (ProjectError, ConfigError) as erro:
        logger.warning("no rules loaded: %s", erro)
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
    contagem = {
        severidade: sum(1 for m in matches if m.severity == severidade) for severidade in SEVERITIES
    }
    detalhe = ", ".join("%d %s" % (contagem[s], s) for s in SEVERITIES if contagem[s])
    return "%d rule(s) matched: %s" % (len(matches), detalhe)


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
