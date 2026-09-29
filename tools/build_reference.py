#!/usr/bin/env python3
"""Regenerates ``docs/REFERENCIA.md`` from the instruction catalogue.

The catalogue in ``asmx/data/isa.json`` drives the Docs tab, ``asmx explain``,
the report and the F1 help. The Markdown reference is a second copy of the same
text, and two copies drift apart. This tool renders the Markdown straight from
the JSON, so the reference can never fall behind the data:

* one ``## Category: <label>`` section per category, in catalogue order;
* one ``### MNEMONIC — <name>`` block per mnemonic, with syntax, description,
  examples, flags and the extra note when the record has one; the heading keeps
  the descriptive part of the name, since the first part repeats the mnemonic;
* the register, flag, system call and Windows API tables at the end.

Usage:
    python3 tools/build_reference.py            # writes docs/REFERENCIA.md
    python3 tools/build_reference.py --check    # compares, writes nothing

Exit codes:
    0  file written, or already identical in ``--check`` mode
    1  ``--check`` found a difference (run the tool without ``--check``)
"""

from __future__ import annotations

import difflib
import json
import os
import re
import sys
from typing import Any, Dict, List, Sequence

#: Project root, used to resolve the catalogue and the output file.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: Catalogue loaded by :mod:`asmx.isa` at import time.
CATALOGUE = os.path.join(ROOT, "asmx", "data", "isa.json")

#: Markdown file this tool owns.
REFERENCE = os.path.join(ROOT, "docs", "REFERENCIA.md")

#: First line of the generated document.
TITLE = "# x86-64 instruction reference"

#: Characters GitHub drops from a heading anchor (letters, digits, space, - and _ stay).
_ANCHOR_DROP = re.compile(r"[^a-z0-9 \-_]")


def load_catalogue(path: str = CATALOGUE) -> Dict[str, Any]:
    """Loads the JSON catalogue that feeds every documentation surface.

    Args:
        path: Path to ``isa.json``.

    Returns:
        The parsed catalogue, with the section order of the file preserved.
    """
    with open(path, encoding="utf-8") as handle:
        catalogue: Dict[str, Any] = json.load(handle)
    return catalogue


def slugify(title: str) -> str:
    """Builds the anchor GitHub generates for a heading.

    Args:
        title: Heading text, without the leading ``#`` characters.

    Returns:
        Lowercase anchor with the punctuation removed and spaces turned into
        hyphens (``Category: Call / return`` -> ``category-call--return``).
    """
    anchor = _ANCHOR_DROP.sub("", title.lower())
    return anchor.replace(" ", "-")


def _cell(text: str) -> str:
    """Escapes the pipe that would break a Markdown table cell.

    Args:
        text: Raw cell text.

    Returns:
        Text safe to place between two table pipes.
    """
    return text.replace("|", "\\|")


def render_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> List[str]:
    """Renders a GitHub-flavoured Markdown table.

    Args:
        headers: Column titles, in order.
        rows: One sequence of cells per line, already escaped by :func:`_cell`.

    Returns:
        Lines of the table, without a trailing blank line.
    """
    lines = ["| " + " | ".join(headers) + " |"]
    lines.append("| " + " | ".join("---" for _ in headers) + " |")
    for row in rows:
        cells = [cell if cell else "—" for cell in row]
        lines.append("| " + " | ".join(cells) + " |")
    return lines


def heading_title(record: Dict[str, Any]) -> str:
    """Picks the text that follows the mnemonic in a section heading.

    Catalogue names look like ``Move — copies a value``: the part before the
    dash repeats the mnemonic, so the heading uses only the descriptive tail
    (``MOV — copies a value``). Names without a dash are used as they are.

    Args:
        record: Instruction record with the ``name`` field.

    Returns:
        Heading text, without the mnemonic and without the separator.
    """
    name: str = record["name"]
    if " — " in name:
        return name.split(" — ", 1)[1]
    return name


def render_instruction(mnemonic: str, record: Dict[str, Any]) -> List[str]:
    """Renders the block of a single mnemonic.

    Args:
        mnemonic: Catalogue key, in lowercase (``mov``).
        record: Instruction record with ``name``, ``syntax``, ``desc``, ``ex``,
            ``flags`` and, sometimes, ``note``.

    Returns:
        Lines of the mnemonic section, without a trailing blank line.
    """
    lines = ["### %s — %s" % (mnemonic.upper(), heading_title(record)), ""]
    lines.append("**Syntax:** `%s`" % record["syntax"])
    lines.append("")
    lines.append(record["desc"])
    lines.append("")
    lines.append("```asm")
    lines.extend(record["ex"])
    lines.append("```")
    lines.append("")
    lines.append("**Flags:** %s" % record["flags"])
    if record.get("note"):
        lines.append("")
        lines.append("> **Note:** %s" % record["note"])
    return lines


def render_categories(catalogue: Dict[str, Any]) -> List[str]:
    """Renders one section per category, in the order of the catalogue.

    Args:
        catalogue: Parsed ``isa.json``.

    Returns:
        Lines of every category section, separated by horizontal rules.
    """
    instructions: Dict[str, Dict[str, Any]] = catalogue["ISA"]
    lines: List[str] = []
    for key, category in catalogue["CATEGORIES"].items():
        members = [(m, r) for m, r in instructions.items() if r["cat"] == key]
        lines.extend(["---", "", "## Category: %s" % category["label"], ""])
        lines.append(category["hint"])
        lines.append("")
        for index, (mnemonic, record) in enumerate(members):
            if index:
                lines.append("")
            lines.extend(render_instruction(mnemonic, record))
    return lines


def render_tables(catalogue: Dict[str, Any]) -> List[str]:
    """Renders the register, flag, system call and API tables.

    Args:
        catalogue: Parsed ``isa.json``.

    Returns:
        Lines of the closing sections, separated by horizontal rules.
    """
    lines: List[str] = ["---", "", "## Registers", ""]
    lines.extend(
        render_table(
            ["Register", "Description"],
            [["`%s`" % name, _cell(text)] for name, text in catalogue["REG_DOC"].items()],
        )
    )

    lines.extend(["", "---", "", "## Flags (RFLAGS)", ""])
    lines.extend(
        render_table(
            ["Flag", "Description"],
            [["`%s`" % name, _cell(text)] for name, text in catalogue["FLAG_DOC"].items()],
        )
    )

    lines.extend(["", "---", "", "## Linux x86-64 system calls", ""])
    lines.extend(
        render_table(
            ["Number", "Name", "Description", "Arguments"],
            [
                [number, "`%s`" % entry[0], _cell(entry[1]), _cell(entry[2])]
                for number, entry in catalogue["LINUX_SYSCALLS"].items()
            ],
        )
    )

    lines.extend(["", "---", "", "## Windows APIs used by the examples", ""])
    lines.extend(
        render_table(
            ["Function", "Description", "Parameters"],
            [
                ["`%s`" % entry[0], _cell(entry[1]), _cell(entry[2])]
                for entry in catalogue["WIN_APIS"].values()
            ],
        )
    )
    return lines


def render(catalogue: Dict[str, Any]) -> str:
    """Renders the complete reference document.

    Args:
        catalogue: Parsed ``isa.json``.

    Returns:
        Markdown text, ending with a single newline.
    """
    total = len(catalogue["ISA"])
    lines = [
        TITLE,
        "",
        "Generated by `tools/build_reference.py` from `asmx/data/isa.json`, the same",
        "catalogue the **Docs** tab reads, so this file cannot drift from the data.",
        "All %d mnemonics are listed below, grouped by category." % total,
        "",
        "Operand order follows the Intel/NASM convention: destination first, then",
        "source. GAS/AT&T reverses the order and prefixes registers with `%`.",
        "",
        "## Contents",
        "",
    ]
    for key, category in catalogue["CATEGORIES"].items():
        heading = "Category: %s" % category["label"]
        lines.append("- [%s](#%s)" % (category["label"], slugify(heading)))
    lines.append("")
    lines.extend(render_categories(catalogue))
    lines.extend([""])
    lines.extend(render_tables(catalogue))
    return "\n".join(lines) + "\n"


def check(path: str, expected: str, limit: int = 40) -> List[str]:
    """Compares the file on disk with the freshly generated content.

    Args:
        path: Markdown file to compare.
        expected: Content the file should have.
        limit: Maximum number of diff lines to report.

    Returns:
        Report lines (empty when the file is already up to date).
    """
    if not os.path.exists(path):
        return ["missing file: %s" % path]
    with open(path, encoding="utf-8") as handle:
        current = handle.read()
    if current == expected:
        return []
    diff = list(
        difflib.unified_diff(
            current.splitlines(),
            expected.splitlines(),
            fromfile=path,
            tofile="generated",
            lineterm="",
        )
    )
    report = ["%s is out of date (%d diff lines):" % (path, len(diff))]
    report.extend(diff[:limit])
    if len(diff) > limit:
        report.append("... %d more lines" % (len(diff) - limit))
    report.append("run: python3 tools/build_reference.py")
    return report


def main(argv: List[str]) -> int:
    """Entry point of the generator.

    Args:
        argv: Command line arguments, without the program name.

    Returns:
        Exit code described at the top of the module.
    """
    catalogue = load_catalogue()
    expected = render(catalogue)
    if "--check" in argv:
        report = check(REFERENCE, expected)
        for line in report:
            print(line)
        if report:
            return 1
        print("%s is up to date (%d bytes)" % (REFERENCE, len(expected)))
        return 0
    with open(REFERENCE, "w", encoding="utf-8") as handle:
        handle.write(expected)
    print("wrote %s (%d bytes, %d mnemonics)" % (REFERENCE, len(expected), len(catalogue["ISA"])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
