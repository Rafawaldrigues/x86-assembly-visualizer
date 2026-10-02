#!/usr/bin/env python3
"""Check function annotations and docstring sections.

Run ``python3 tools/quality_gates.py`` to check the package. These checks verify
presence and structure; they do not assess documentation accuracy or completeness.
"""

from __future__ import annotations

import argparse
import ast
import os
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: Paths checked when none is given on the command line.
DEFAULT_PATHS: Tuple[str, ...] = ("asmx", "tools", "asmx.py")

#: Paths checked for annotations only (the tests do not require a docstring).
TEST_PATHS: Tuple[str, ...] = ("tests",)

#: Folders ignored by the scan.
IGNORED = frozenset(
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
PUNCTUATION = (".", "?", "!", ":")


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
    source_files: List[str] = []
    for file_path in paths:
        absolute_path = file_path if os.path.isabs(file_path) else os.path.join(ROOT, file_path)
        if os.path.isfile(absolute_path):
            if absolute_path.endswith(".py"):
                source_files.append(absolute_path)
            continue
        for folder_path, subfolders, item_names in os.walk(absolute_path):
            subfolders[:] = [s for s in subfolders if s not in IGNORED]
            for item_name in item_names:
                if item_name.endswith(".py"):
                    source_files.append(os.path.join(folder_path, item_name))
    return sorted(os.path.relpath(a, ROOT) for a in source_files)


def _qualified(node: ast.AST, prefix_text: str = "") -> str:
    """Builds the node name including the class/scope where it appears.

    Args:
        node: :mod:`ast` node (function, class...).
        prefix_text: Name of the scope where the node appears.

    Returns:
        Qualified name, such as ``Project.fork``.
    """
    item_name = getattr(node, "name", "<anonymous>")
    return "%s.%s" % (prefix_text, item_name) if prefix_text else item_name


def _docstring(node: ast.AST) -> Optional[str]:
    """Returns the node docstring, or ``None`` when there is none.

    Returns:
        The docstring text or ``None``.
    """
    body = getattr(node, "body", None)
    if not body:
        return None
    first_item = body[0]
    if (
        isinstance(first_item, ast.Expr)
        and isinstance(first_item.value, ast.Constant)
        and isinstance(first_item.value.value, str)
    ):
        return first_item.value.value
    return None


def _params(node: ast.AST) -> List[str]:
    """Lists the parameter names of a function, without ``self``/``cls``.

    Returns:
        Names in signature order, ``*args`` and ``**kwargs`` included.
    """
    args = node.args  # type: ignore[attr-defined]
    item_names = [a.arg for a in list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)]
    if args.vararg:
        item_names.append("*" + args.vararg.arg)
    if args.kwarg:
        item_names.append("**" + args.kwarg.arg)
    return [n for n in item_names if n not in AUTO_PARAMS]


def _iter_body(node: ast.AST) -> Iterable[ast.AST]:
    """Walks the body of a function without entering nested functions.

    What a nested function returns or raises is a problem for its own
    docstring, not for the outer function.

    Args:
        node: Function node.

    Yields:
        Each node of the body, except the inside of functions, classes and lambdas.
    """
    node_stack = list(getattr(node, "body", []))
    while node_stack:
        current_value = node_stack.pop()
        yield current_value
        if isinstance(
            current_value, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
        ):
            continue
        node_stack.extend(ast.iter_child_nodes(current_value))


def _returns_value(node: ast.AST) -> bool:
    """Tells whether the function has any ``return`` that returns a value.

    Returns:
        ``True`` when there is a ``return`` with an expression in the body of
        the function itself.
    """
    return any(
        isinstance(child_node, ast.Return) and child_node.value is not None
        for child_node in _iter_body(node)
    )


def _raises(node: ast.AST) -> bool:
    """Tells whether the function raises an exception explicitly.

    Returns:
        ``True`` when there is a ``raise`` in the body of the function itself.
    """
    return any(isinstance(child_node, ast.Raise) for child_node in _iter_body(node))


def _has_section(doc: str, title: str) -> bool:
    """Tells whether the docstring has a ``Title:`` section (Google style).

    Args:
        doc: Docstring text.
        title: Section name, without the colon (``Args``, ``Returns``...).

    Returns:
        ``True`` when the section exists.
    """
    return any(source_line.strip() == title + ":" for source_line in doc.splitlines())


def _section_names(doc: str, title: str) -> Set[str]:
    """Extracts the names documented inside a section of the ``name:`` form.

    Args:
        doc: Docstring text.
        title: Name of the section to scan.

    Returns:
        Set with the names found before the colon.
    """
    item_names: Set[str] = set()
    inside = False
    for source_line in doc.splitlines():
        if source_line.strip() == title + ":":
            inside = True
            continue
        if inside:
            if source_line.strip() and not source_line.startswith(" " * 8):
                break
            source_text = source_line.strip()
            if ":" in source_text:
                item_names.add(source_text.split(":", 1)[0].strip().lstrip("*"))
    return item_names


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
    with open(os.path.join(ROOT, path), encoding="utf-8") as source_file:
        try:
            syntax_tree = ast.parse(source_file.read(), filename=path)
        except SyntaxError as caught_error:
            return [
                Violation(
                    path, caught_error.lineno or 0, "<module>", "syntax", str(caught_error.msg)
                )
            ]

    violation_list: List[Violation] = []
    if require_docstrings:
        _check_module_docstring(syntax_tree, path, violation_list)

    def visit_node(node: ast.AST, prefix_text: str) -> None:
        """Walks the tree checking classes and nested functions."""
        for child_node in ast.iter_child_nodes(node):
            if isinstance(child_node, ast.ClassDef):
                item_name = _qualified(child_node, prefix_text)
                if require_docstrings:
                    _check_class(child_node, path, item_name, violation_list, args_min_params)
                visit_node(child_node, item_name)
            elif isinstance(child_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                item_name = _qualified(child_node, prefix_text)
                _check_function(
                    child_node, path, item_name, violation_list, args_min_params, require_docstrings
                )
                visit_node(child_node, item_name)
            elif isinstance(child_node, (ast.If, ast.Try, ast.With, ast.For, ast.While)):
                visit_node(child_node, prefix_text)

    visit_node(syntax_tree, "")
    return violation_list


def _check_module_docstring(
    syntax_tree: ast.Module, path: str, violation_list: List[Violation]
) -> None:
    """Checks the module docstring.

    Args:
        syntax_tree: Syntax tree of the file.
        path: Relative path, used in the violations.
        violation_list: List where the violations are accumulated.
    """
    doc = _docstring(syntax_tree)
    if doc is None:
        violation_list.append(
            Violation(path, 1, "<module>", "docstring", "module without docstring")
        )
        return
    if not doc.strip().splitlines()[0].strip().endswith(PUNCTUATION):
        violation_list.append(
            Violation(path, 1, "<module>", "docstring", "first line must end with punctuation")
        )


def _check_class(
    node: ast.ClassDef,
    path: str,
    item_name: str,
    violation_list: List[Violation],
    args_min_params: int,
) -> None:
    """Checks the class docstring, including the dataclass attributes.

    Args:
        node: Class node.
        path: Relative path of the file.
        item_name: Qualified name of the class.
        violation_list: List where the violations are accumulated.
        args_min_params: Parameter threshold to require ``Args:`` in the methods.
    """
    doc = _docstring(node)
    if doc is None:
        violation_list.append(
            Violation(path, node.lineno, item_name, "docstring", "class without docstring")
        )
    elif not doc.strip().splitlines()[0].strip().endswith(PUNCTUATION):
        violation_list.append(
            Violation(
                path,
                node.lineno,
                item_name,
                "docstring",
                "first line must end with punctuation",
            )
        )


def _check_function(
    node: ast.AST,
    path: str,
    item_name: str,
    violation_list: List[Violation],
    args_min_params: int,
    require_docstrings: bool = True,
) -> None:
    """Checks annotations, docstring and sections of a function or method.

    Args:
        node: Function or method node.
        path: Relative path of the file.
        item_name: Qualified name of the function.
        violation_list: List where the violations are accumulated.
        args_min_params: From how many parameters ``Args:`` is required.
        require_docstrings: Whether the docstring sections are enforced.
    """
    doc = _docstring(node)
    if doc is None and require_docstrings:
        violation_list.append(
            Violation(
                path,
                node.lineno,  # type: ignore[attr-defined]
                item_name,
                "docstring",
                "no docstring",
            )
        )
    elif doc is not None and require_docstrings:
        first_item = doc.strip().splitlines()[0].strip() if doc.strip() else ""
        if not first_item:
            violation_list.append(
                Violation(
                    path,
                    node.lineno,  # type: ignore[attr-defined]
                    item_name,
                    "docstring",
                    "empty docstring",
                )
            )
        elif not first_item.endswith(PUNCTUATION):
            violation_list.append(
                Violation(
                    path,
                    node.lineno,  # type: ignore[attr-defined]
                    item_name,
                    "docstring",
                    "first line must end with punctuation",
                )
            )
        parameters = _params(node)
        if not require_docstrings:
            parameters = []
        if len(parameters) >= args_min_params and not _has_section(doc, "Args"):
            violation_list.append(
                Violation(
                    path,
                    node.lineno,  # type: ignore[attr-defined]
                    item_name,
                    "args",
                    "takes %d parameters and has no Args: section" % len(parameters),
                )
            )
        elif _has_section(doc, "Args"):
            documented = _section_names(doc, "Args")
            missing_names = [p for p in parameters if p.lstrip("*") not in documented]
            if missing_names:
                violation_list.append(
                    Violation(
                        path,
                        node.lineno,  # type: ignore[attr-defined]
                        item_name,
                        "args",
                        "parameters without a description: " + ", ".join(missing_names),
                    )
                )
        if require_docstrings and _returns_value(node) and not _has_section(doc, "Returns"):
            violation_list.append(
                Violation(
                    path,
                    node.lineno,  # type: ignore[attr-defined]
                    item_name,
                    "returns",
                    "returns a value and has no Returns: section",
                )
            )
        if require_docstrings and _raises(node) and not _has_section(doc, "Raises"):
            violation_list.append(
                Violation(
                    path,
                    node.lineno,  # type: ignore[attr-defined]
                    item_name,
                    "raises",
                    "raises and has no Raises: section",
                )
            )

    for parameter in _params(node):
        target_name = (
            node.args.vararg  # type: ignore[attr-defined]
            if parameter.startswith("*") and not parameter.startswith("**")
            else (
                node.args.kwarg  # type: ignore[attr-defined]
                if parameter.startswith("**")
                else None
            )
        )
        if target_name is not None:
            if target_name.annotation is None:
                violation_list.append(
                    Violation(
                        path,
                        node.lineno,  # type: ignore[attr-defined]
                        item_name,
                        "annotation",
                        "parameter %s has no annotation" % parameter,
                    )
                )
            continue
        for argument_node in (
            list(node.args.posonlyargs)  # type: ignore[attr-defined]
            + list(node.args.args)  # type: ignore[attr-defined]
            + list(node.args.kwonlyargs)  # type: ignore[attr-defined]
        ):
            if argument_node.arg == parameter and argument_node.annotation is None:
                violation_list.append(
                    Violation(
                        path,
                        node.lineno,  # type: ignore[attr-defined]
                        item_name,
                        "annotation",
                        "parameter %s has no annotation" % parameter,
                    )
                )
    if getattr(node, "returns", None) is None:
        violation_list.append(
            Violation(
                path,
                node.lineno,  # type: ignore[attr-defined]
                item_name,
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
    violation_list: List[Violation] = []
    for path in iter_python_files(paths):
        violation_list.extend(
            check_file(path, args_min_params=args_min_params, require_docstrings=require_docstrings)
        )
    return sorted(violation_list, key=lambda v: (v.path, v.line, v.kind))


def summarize(violation_list: Iterable[Violation]) -> Dict[str, int]:
    """Counts the violations by type.

    Args:
        violation_list: Violations found.

    Returns:
        Dictionary ``type -> count``.
    """
    item_count: Dict[str, int] = {}
    for violation in violation_list:
        item_count[violation.kind] = item_count.get(violation.kind, 0) + 1
    return item_count


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
        default=list(DEFAULT_PATHS),
        help="files or directories (default: %s)" % ", ".join(DEFAULT_PATHS),
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
    violation_list = check_paths(args.paths or list(DEFAULT_PATHS))
    if violation_list:
        if not args.quiet:
            for violation in violation_list[: args.max]:
                print(violation)
        print(
            "failed %d check(s): %s"
            % (
                len(violation_list),
                ", ".join("%s=%d" % kv for kv in sorted(summarize(violation_list).items())),
            )
        )
        return 1
    print(
        "checked annotations and docstrings in %d file(s)"
        % len(iter_python_files(args.paths or list(DEFAULT_PATHS)))
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
