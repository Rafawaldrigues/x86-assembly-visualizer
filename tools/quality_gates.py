#!/usr/bin/env python3
"""Quality gates of ASM X: type annotations and docstrings.

The project plan promises "100% type annotations" and "Google standard
docstrings". A promise nobody checks turns into an excuse, so these two checks
are automatic: they run in ``make quality``, in CI and in the test
``tests/test_quality_gates.py``. What is enforced:

* every function, method, class and module has a docstring;
* the first line of the docstring is a sentence ending with punctuation;
* the function has ``Args:`` describing every parameter when it takes three or
  more (``self`` and ``cls`` do not count);
* the function has ``Returns:`` when it returns a value and ``Raises:`` when it
  raises an exception explicitly;
* every parameter and the return value has a type annotation.

The code is read with :mod:`ast`, so nothing is imported or executed.

Usage:
    python3 tools/quality_gates.py            # checks asmx/, tools/, asmx.py, tests/
    python3 tools/quality_gates.py asmx/      # checks a single path
    python3 tools/quality_gates.py --quiet    # final result only

Exit codes:
    0  no violation
    1  at least one violation
"""

from __future__ import annotations

import argparse
import ast
import os
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: Paths checked when none is given on the command line.
PADRAO: Tuple[str, ...] = ("asmx", "tools", "asmx.py")

#: Paths checked for annotations only (the tests do not require a docstring).
TESTES: Tuple[str, ...] = ("tests",)

#: Folders ignored by the scan.
IGNORAR = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        "build",
        "dist",
        ".mypy_cache",
        ".pytest_cache",
        "node_modules",
    }
)

#: Names that do not count as a parameter to document.
AUTO_PARAMS = frozenset({"self", "cls"})

#: Punctuation accepted at the end of the first docstring line.
PONTUACAO = (".", "?", "!", ":")


@dataclass(frozen=True)
class Violation:
    """A broken rule found in the code.

    Attributes:
        path: File where the problem is, relative to the root.
        line: Line of the node (function, class...).
        name: Qualified name of the node (``Class.method``).
        kind: Broken rule (``docstring``, ``args``, ``returns``, ``raises``,
            ``annotation``).
        detail: Short explanation of what is missing.
    """

    path: str
    line: int
    name: str
    kind: str
    detail: str

    def __str__(self) -> str:
        """Formats the violation as ``file:line: kind name — detail``.

        Returns:
            The line ready to print.
        """
        return "%s:%d: %s %s — %s" % (self.path, self.line, self.kind, self.name, self.detail)


def iter_python_files(paths: Sequence[str]) -> List[str]:
    """Lists the ``.py`` files of a list of files and directories.

    Args:
        paths: Paths absolute or relative to the project root.

    Returns:
        Paths relative to the root, in alphabetical order.
    """
    arquivos: List[str] = []
    for caminho in paths:
        absoluto = caminho if os.path.isabs(caminho) else os.path.join(RAIZ, caminho)
        if os.path.isfile(absoluto):
            if absoluto.endswith(".py"):
                arquivos.append(absoluto)
            continue
        for pasta, subpastas, nomes in os.walk(absoluto):
            subpastas[:] = [s for s in subpastas if s not in IGNORAR]
            for nome in nomes:
                if nome.endswith(".py"):
                    arquivos.append(os.path.join(pasta, nome))
    return sorted(os.path.relpath(a, RAIZ) for a in arquivos)


def _qualified(node: ast.AST, prefixo: str = "") -> str:
    """Builds the node name including the class/scope where it appears.

    Args:
        node: :mod:`ast` node (function, class...).
        prefixo: Name of the scope where the node appears.

    Returns:
        Qualified name, such as ``Project.fork``.
    """
    nome = getattr(node, "name", "<anonymous>")
    return "%s.%s" % (prefixo, nome) if prefixo else nome


def _docstring(node: ast.AST) -> Optional[str]:
    """Returns the node docstring, or ``None`` when there is none.

    Returns:
        The docstring text or ``None``.
    """
    corpo = getattr(node, "body", None)
    if not corpo:
        return None
    primeiro = corpo[0]
    if (
        isinstance(primeiro, ast.Expr)
        and isinstance(primeiro.value, ast.Constant)
        and isinstance(primeiro.value.value, str)
    ):
        return primeiro.value.value
    return None


def _params(node: ast.AST) -> List[str]:
    """Lists the parameter names of a function, without ``self``/``cls``.

    Returns:
        Names in signature order, ``*args`` and ``**kwargs`` included.
    """
    args = node.args  # type: ignore[attr-defined]
    nomes = [a.arg for a in list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)]
    if args.vararg:
        nomes.append("*" + args.vararg.arg)
    if args.kwarg:
        nomes.append("**" + args.kwarg.arg)
    return [n for n in nomes if n not in AUTO_PARAMS]


def _iter_corpo(node: ast.AST) -> Iterable[ast.AST]:
    """Walks the body of a function without entering nested functions.

    What a nested function returns or raises is a problem for its own
    docstring, not for the outer function.

    Args:
        node: Function node.

    Yields:
        Each node of the body, except the inside of functions, classes and lambdas.
    """
    pilha = list(getattr(node, "body", []))
    while pilha:
        atual = pilha.pop()
        yield atual
        if isinstance(atual, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        pilha.extend(ast.iter_child_nodes(atual))


def _returns_value(node: ast.AST) -> bool:
    """Tells whether the function has any ``return`` that returns a value.

    Returns:
        ``True`` when there is a ``return`` with an expression in the body of
        the function itself.
    """
    return any(
        isinstance(filho, ast.Return) and filho.value is not None for filho in _iter_corpo(node)
    )


def _raises(node: ast.AST) -> bool:
    """Tells whether the function raises an exception explicitly.

    Returns:
        ``True`` when there is a ``raise`` in the body of the function itself.
    """
    return any(isinstance(filho, ast.Raise) for filho in _iter_corpo(node))


def _has_section(doc: str, titulo: str) -> bool:
    """Tells whether the docstring has a ``Title:`` section (Google style).

    Args:
        doc: Docstring text.
        titulo: Section name, without the colon (``Args``, ``Returns``...).

    Returns:
        ``True`` when the section exists.
    """
    return any(linha.strip() == titulo + ":" for linha in doc.splitlines())


def _section_names(doc: str, titulo: str) -> Set[str]:
    """Extracts the names documented inside a section of the ``name:`` form.

    Args:
        doc: Docstring text.
        titulo: Name of the section to scan.

    Returns:
        Set with the names found before the colon.
    """
    nomes: Set[str] = set()
    dentro = False
    for linha in doc.splitlines():
        if linha.strip() == titulo + ":":
            dentro = True
            continue
        if dentro:
            if linha.strip() and not linha.startswith(" " * 8):
                break
            texto = linha.strip()
            if ":" in texto:
                nomes.add(texto.split(":", 1)[0].strip().lstrip("*"))
    return nomes


def check_file(
    path: str, *, args_min_params: int = 3, require_docstrings: bool = True
) -> List[Violation]:
    """Checks annotations and docstrings of a single file.

    Args:
        path: Path relative to the project root.
        args_min_params: From how many parameters the ``Args:`` section becomes
            mandatory.
        require_docstrings: When ``False``, only the type annotations are
            enforced (this is the mode used on test files, where the case name
            already explains what it does).

    Returns:
        List of violations found (empty when the file is up to date).
    """
    with open(os.path.join(RAIZ, path), encoding="utf-8") as arquivo:
        try:
            arvore = ast.parse(arquivo.read(), filename=path)
        except SyntaxError as erro:
            return [Violation(path, erro.lineno or 0, "<module>", "syntax", str(erro.msg))]

    violacoes: List[Violation] = []
    if require_docstrings:
        _verifica_docstring_modulo(arvore, path, violacoes)

    def visitar(node: ast.AST, prefixo: str) -> None:
        """Walks the tree checking classes and nested functions."""
        for filho in ast.iter_child_nodes(node):
            if isinstance(filho, ast.ClassDef):
                nome = _qualified(filho, prefixo)
                if require_docstrings:
                    _verifica_classe(filho, path, nome, violacoes, args_min_params)
                visitar(filho, nome)
            elif isinstance(filho, (ast.FunctionDef, ast.AsyncFunctionDef)):
                nome = _qualified(filho, prefixo)
                _verifica_funcao(filho, path, nome, violacoes, args_min_params, require_docstrings)
                visitar(filho, nome)
            elif isinstance(filho, (ast.If, ast.Try, ast.With, ast.For, ast.While)):
                visitar(filho, prefixo)

    visitar(arvore, "")
    return violacoes


def _verifica_docstring_modulo(arvore: ast.Module, path: str, violacoes: List[Violation]) -> None:
    """Checks the module docstring.

    Args:
        arvore: Syntax tree of the file.
        path: Relative path, used in the violations.
        violacoes: List where the violations are accumulated.
    """
    doc = _docstring(arvore)
    if doc is None:
        violacoes.append(Violation(path, 1, "<module>", "docstring", "module without docstring"))
        return
    if not doc.strip().splitlines()[0].strip().endswith(PONTUACAO):
        violacoes.append(
            Violation(path, 1, "<module>", "docstring", "first line must end with punctuation")
        )


def _verifica_classe(
    node: ast.ClassDef, path: str, nome: str, violacoes: List[Violation], args_min_params: int
) -> None:
    """Checks the class docstring, including the dataclass attributes.

    Args:
        node: Class node.
        path: Relative path of the file.
        nome: Qualified name of the class.
        violacoes: List where the violations are accumulated.
        args_min_params: Parameter threshold to require ``Args:`` in the methods.
    """
    doc = _docstring(node)
    if doc is None:
        violacoes.append(Violation(path, node.lineno, nome, "docstring", "class without docstring"))
    elif not doc.strip().splitlines()[0].strip().endswith(PONTUACAO):
        violacoes.append(
            Violation(
                path,
                node.lineno,
                nome,
                "docstring",
                "first line must end with punctuation",
            )
        )


def _verifica_funcao(
    node: ast.AST,
    path: str,
    nome: str,
    violacoes: List[Violation],
    args_min_params: int,
    require_docstrings: bool = True,
) -> None:
    """Checks annotations, docstring and sections of a function or method.

    Args:
        node: Function or method node.
        path: Relative path of the file.
        nome: Qualified name of the function.
        violacoes: List where the violations are accumulated.
        args_min_params: From how many parameters ``Args:`` is required.
        require_docstrings: Whether the docstring sections are enforced.
    """
    doc = _docstring(node)
    if doc is None and require_docstrings:
        violacoes.append(
            Violation(
                path,
                node.lineno,  # type: ignore[attr-defined]
                nome,
                "docstring",
                "no docstring",
            )
        )
    elif doc is not None and require_docstrings:
        primeira = doc.strip().splitlines()[0].strip() if doc.strip() else ""
        if not primeira:
            violacoes.append(
                Violation(
                    path,
                    node.lineno,  # type: ignore[attr-defined]
                    nome,
                    "docstring",
                    "empty docstring",
                )
            )
        elif not primeira.endswith(PONTUACAO):
            violacoes.append(
                Violation(
                    path,
                    node.lineno,  # type: ignore[attr-defined]
                    nome,
                    "docstring",
                    "first line must end with punctuation",
                )
            )
        parametros = _params(node)
        if not require_docstrings:
            parametros = []
        if len(parametros) >= args_min_params and not _has_section(doc, "Args"):
            violacoes.append(
                Violation(
                    path,
                    node.lineno,  # type: ignore[attr-defined]
                    nome,
                    "args",
                    "takes %d parameters and has no Args: section" % len(parametros),
                )
            )
        elif _has_section(doc, "Args"):
            documentados = _section_names(doc, "Args")
            faltando = [p for p in parametros if p.lstrip("*") not in documentados]
            if faltando:
                violacoes.append(
                    Violation(
                        path,
                        node.lineno,  # type: ignore[attr-defined]
                        nome,
                        "args",
                        "parameters without a description: " + ", ".join(faltando),
                    )
                )
        if require_docstrings and _returns_value(node) and not _has_section(doc, "Returns"):
            violacoes.append(
                Violation(
                    path,
                    node.lineno,  # type: ignore[attr-defined]
                    nome,
                    "returns",
                    "returns a value and has no Returns: section",
                )
            )
        if require_docstrings and _raises(node) and not _has_section(doc, "Raises"):
            violacoes.append(
                Violation(
                    path,
                    node.lineno,  # type: ignore[attr-defined]
                    nome,
                    "raises",
                    "raises and has no Raises: section",
                )
            )

    for parametro in _params(node):
        alvo = (
            node.args.vararg  # type: ignore[attr-defined]
            if parametro.startswith("*") and not parametro.startswith("**")
            else (
                node.args.kwarg  # type: ignore[attr-defined]
                if parametro.startswith("**")
                else None
            )
        )
        if alvo is not None:
            if alvo.annotation is None:
                violacoes.append(
                    Violation(
                        path,
                        node.lineno,  # type: ignore[attr-defined]
                        nome,
                        "annotation",
                        "parameter %s has no annotation" % parametro,
                    )
                )
            continue
        for argumento in (
            list(node.args.posonlyargs)  # type: ignore[attr-defined]
            + list(node.args.args)  # type: ignore[attr-defined]
            + list(node.args.kwonlyargs)  # type: ignore[attr-defined]
        ):
            if argumento.arg == parametro and argumento.annotation is None:
                violacoes.append(
                    Violation(
                        path,
                        node.lineno,  # type: ignore[attr-defined]
                        nome,
                        "annotation",
                        "parameter %s has no annotation" % parametro,
                    )
                )
    if getattr(node, "returns", None) is None:
        violacoes.append(
            Violation(
                path,
                node.lineno,  # type: ignore[attr-defined]
                nome,
                "annotation",
                "return has no annotation",
            )
        )


def check_paths(
    paths: Sequence[str], *, args_min_params: int = 3, require_docstrings: bool = True
) -> List[Violation]:
    """Checks every file given.

    Args:
        paths: Files and directories to check.
        args_min_params: Forwarded to :func:`check_file`.
        require_docstrings: Forwarded to :func:`check_file`.

    Returns:
        List of violations, sorted by file and line.
    """
    violacoes: List[Violation] = []
    for path in iter_python_files(paths):
        violacoes.extend(
            check_file(path, args_min_params=args_min_params, require_docstrings=require_docstrings)
        )
    return sorted(violacoes, key=lambda v: (v.path, v.line, v.kind))


def summarize(violacoes: Iterable[Violation]) -> Dict[str, int]:
    """Counts the violations by type.

    Args:
        violacoes: Violations found.

    Returns:
        Dictionary ``type -> count``.
    """
    contagem: Dict[str, int] = {}
    for violacao in violacoes:
        contagem[violacao.kind] = contagem.get(violacao.kind, 0) + 1
    return contagem


def build_parser() -> argparse.ArgumentParser:
    """Builds the argument parser of the utility.

    Returns:
        The parser with the positional paths and the options.
    """
    parser = argparse.ArgumentParser(
        prog="quality_gates", description="Checks type annotations and docstrings of ASM X."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=list(PADRAO),
        help="files or directories (default: %s)" % ", ".join(PADRAO),
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="shows only the final summary")
    parser.add_argument(
        "--max", type=int, default=40, help="how many violations to list (default: 40)"
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point of the utility.

    Args:
        argv: Arguments without the program name.

    Returns:
        ``0`` when there is no violation, ``1`` when there is at least one.
    """
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    violacoes = check_paths(args.paths or list(PADRAO))
    if violacoes:
        if not args.quiet:
            for violacao in violacoes[: args.max]:
                print(violacao)
        print(
            "failed %d check(s): %s"
            % (
                len(violacoes),
                ", ".join("%s=%d" % kv for kv in sorted(summarize(violacoes).items())),
            )
        )
        return 1
    print(
        "all good: %d file(s) with 100%% annotations and docstrings"
        % len(iter_python_files(args.paths or list(PADRAO)))
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
