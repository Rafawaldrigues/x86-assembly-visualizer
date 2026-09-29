"""Tests for the instruction catalogue: lookups, registers and tables."""

import importlib.util
import json
import os
import subprocess
import sys
import unittest
from types import ModuleType

from asmx import isa
from asmx.isa import (
    ARG_REGS_SYSCALL,
    ARG_REGS_SYSV,
    ARG_REGS_WIN,
    CALLEE_SAVED_SYSV,
    CALLEE_SAVED_WIN,
    CATEGORIES,
    CONDITIONS,
    CONTROL_DIRECTIVES,
    DATA_DIRECTIVES,
    FLAG_DOC,
    ISA,
    LINUX_SYSCALLS,
    REG_DOC,
    REG_INFO,
    REGS64,
    SIZE_KEYWORDS,
    WIN_APIS,
    category_of,
    doc_for,
    is_cond_jump,
)

#: Project root, used to run the reference generator as a real command.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: Generator that owns docs/REFERENCIA.md.
BUILD_REFERENCE = os.path.join(ROOT, "tools", "build_reference.py")

#: Markdown reference generated from asmx/data/isa.json.
REFERENCE = os.path.join(ROOT, "docs", "REFERENCIA.md")


def load_build_reference() -> ModuleType:
    """Imports tools/build_reference.py, which is not part of a package.

    Returns:
        The loaded module, with ``render`` and ``check`` available.
    """
    spec = importlib.util.spec_from_file_location("build_reference", BUILD_REFERENCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestCatalogue(unittest.TestCase):
    """The catalogue must be complete and consistent."""

    def test_counts(self) -> None:
        self.assertEqual(len(ISA), 148)
        self.assertEqual(len(LINUX_SYSCALLS), 43)
        self.assertEqual(len(CATEGORIES), 11)
        self.assertGreaterEqual(len(WIN_APIS), 18)

    def test_every_instruction_has_required_fields(self) -> None:
        for mnemonic, record in ISA.items():
            with self.subTest(mnemonic=mnemonic):
                for field in ("name", "cat", "syntax", "desc", "ex", "flags"):
                    self.assertIn(field, record)
                self.assertIn(record["cat"], CATEGORIES)

    def test_category_keys_are_lowercase(self) -> None:
        for key in CATEGORIES:
            self.assertEqual(key, key.lower())

    def test_json_file_matches_loaded_catalogue(self) -> None:
        path = os.path.join(os.path.dirname(isa.__file__), "data", "isa.json")
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        self.assertEqual(len(data["ISA"]), len(ISA))

    def test_registers_and_flags_are_documented(self) -> None:
        self.assertIn("rax", REG_DOC)
        self.assertIn("ZF", FLAG_DOC)

    def test_conditions_and_flags_have_full_tables(self) -> None:
        self.assertEqual(len(CONDITIONS), 20)
        self.assertEqual(len(REG_DOC), 17)
        self.assertEqual(len(FLAG_DOC), 6)

    def test_known_syscalls(self) -> None:
        self.assertEqual(LINUX_SYSCALLS[1][0], "write")
        self.assertEqual(LINUX_SYSCALLS[60][0], "exit")
        self.assertEqual(LINUX_SYSCALLS[0][0], "read")

    def test_syscall_keys_are_integers(self) -> None:
        for number in LINUX_SYSCALLS:
            self.assertIsInstance(number, int)


class TestDocFor(unittest.TestCase):
    """Documentation lookup."""

    def test_known_instruction(self) -> None:
        self.assertEqual(doc_for("mov")["cat"], "data")

    def test_uppercase_and_lowercase(self) -> None:
        self.assertEqual(doc_for("MOV"), doc_for("mov"))

    def test_unknown_instruction(self) -> None:
        self.assertIsNone(doc_for("xyzzy"))

    def test_empty_input(self) -> None:
        self.assertIsNone(doc_for(""))
        self.assertIsNone(doc_for(None))

    def test_category_of(self) -> None:
        self.assertEqual(category_of("syscall"), "sys")
        self.assertEqual(category_of("jne"), "branch")
        self.assertEqual(category_of("unknown"), "misc")


class TestConditionalBranches(unittest.TestCase):
    """Telling a conditional branch from an unconditional one is used everywhere."""

    def test_conditional_jumps(self) -> None:
        for mnemonic in ("je", "jne", "jl", "jge", "ja", "jb", "jrcxz", "jecxz"):
            with self.subTest(mnemonic=mnemonic):
                self.assertTrue(is_cond_jump(mnemonic))

    def test_jmp_is_not_conditional(self) -> None:
        self.assertFalse(is_cond_jump("jmp"))

    def test_other_instructions_are_not_conditional(self) -> None:
        for mnemonic in ("mov", "call", "ret", "j", "jx"):
            with self.subTest(mnemonic=mnemonic):
                self.assertFalse(is_cond_jump(mnemonic))

    def test_conditions_have_name_and_explanation(self) -> None:
        for suffix, text in CONDITIONS.items():
            with self.subTest(suffix=suffix):
                self.assertEqual(len(text), 2)
                self.assertTrue(text[0] and text[1])


class TestRegisters(unittest.TestCase):
    """The register map covers partial names and the SIMD registers."""

    def test_64_bit_registers(self) -> None:
        for name in REGS64:
            self.assertEqual(REG_INFO[name]["size"], 8)
            self.assertEqual(REG_INFO[name]["base"], name)

    def test_partial_names(self) -> None:
        self.assertEqual(REG_INFO["eax"]["base"], "rax")
        self.assertEqual(REG_INFO["eax"]["size"], 4)
        self.assertEqual(REG_INFO["ax"]["size"], 2)
        self.assertEqual(REG_INFO["al"]["size"], 1)

    def test_high_byte(self) -> None:
        self.assertTrue(REG_INFO["ah"]["high"])
        self.assertEqual(REG_INFO["ah"]["base"], "rax")
        self.assertFalse(REG_INFO["al"]["high"])

    def test_r8_to_r15(self) -> None:
        self.assertEqual(REG_INFO["r8d"]["base"], "r8")
        self.assertEqual(REG_INFO["r15b"]["size"], 1)

    def test_simd(self) -> None:
        self.assertTrue(REG_INFO["xmm0"]["simd"])
        self.assertEqual(REG_INFO["xmm0"]["size"], 16)
        self.assertEqual(REG_INFO["ymm15"]["size"], 32)

    def test_rip(self) -> None:
        self.assertEqual(REG_INFO["rip"]["size"], 8)


class TestTables(unittest.TestCase):
    """Size keywords, directives and ABIs."""

    def test_size_keywords(self) -> None:
        self.assertEqual(SIZE_KEYWORDS["byte"], 1)
        self.assertEqual(SIZE_KEYWORDS["qword"], 8)
        self.assertEqual(SIZE_KEYWORDS["xmmword"], 16)

    def test_data_directives(self) -> None:
        self.assertEqual(DATA_DIRECTIVES["db"], 1)
        self.assertEqual(DATA_DIRECTIVES["dq"], 8)
        self.assertEqual(DATA_DIRECTIVES["resb"], 1)

    def test_control_directives(self) -> None:
        for directive in ("section", "global", "extern", "proc", ".cfi_startproc"):
            self.assertIn(directive, CONTROL_DIRECTIVES)

    def test_argument_order(self) -> None:
        self.assertEqual(ARG_REGS_SYSV[:3], ["rdi", "rsi", "rdx"])
        self.assertEqual(ARG_REGS_SYSCALL[3], "r10")
        self.assertEqual(ARG_REGS_WIN, ["rcx", "rdx", "r8", "r9"])

    def test_callee_saved_registers(self) -> None:
        self.assertIn("rbx", CALLEE_SAVED_SYSV)
        self.assertIn("rdi", CALLEE_SAVED_WIN)
        self.assertNotIn("rdi", CALLEE_SAVED_SYSV)


class TestBuildReference(unittest.TestCase):
    """docs/REFERENCIA.md is generated, so it must never drift from the JSON.

    The reference file only exists in a checkout (it is not installed with the
    package), so these tests skip — instead of failing — when they are run from
    an installed copy without the documentation around.
    """

    @classmethod
    def setUpClass(cls) -> None:
        """Skips the whole class when the generated reference is not there."""
        if not os.path.isfile(REFERENCE):
            raise unittest.SkipTest("docs/REFERENCIA.md is not in this checkout")

    def test_check_passes_on_generated_file(self) -> None:
        result = subprocess.run(
            [sys.executable, BUILD_REFERENCE, "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_generated_file_mentions_known_mnemonics(self) -> None:
        with open(REFERENCE, encoding="utf-8") as handle:
            text = handle.read()
        for mnemonic in ("mov", "jne", "syscall", "ret"):
            self.assertIn("### %s — " % mnemonic.upper(), text)

    def test_generated_file_lists_every_mnemonic(self) -> None:
        with open(REFERENCE, encoding="utf-8") as handle:
            text = handle.read()
        for mnemonic in ISA:
            self.assertIn("### %s — " % mnemonic.upper(), text)

    def test_check_reports_out_of_date_content(self) -> None:
        module = load_build_reference()
        report = module.check(REFERENCE, "content that is not the reference\n")
        self.assertTrue(report)
        self.assertTrue(any("out of date" in line for line in report))

    def test_check_is_quiet_when_content_matches(self) -> None:
        module = load_build_reference()
        with open(REFERENCE, encoding="utf-8") as handle:
            text = handle.read()
        self.assertEqual(module.check(REFERENCE, text), [])


if __name__ == "__main__":
    unittest.main()
