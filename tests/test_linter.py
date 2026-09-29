"""Tests of the static validation: the rules that run over the whole source."""

import unittest
from typing import List, Set

from asmx.analyzer import analyze
from asmx.examples import EXAMPLES
from asmx.linter import ERROR, Problem, summary, validate


def codes(src: str) -> Set[str]:
    """Set of issue codes for a source."""
    return {p.code for p in validate(analyze(src))}


def problems(src: str, code: str) -> List[Problem]:
    """Issues with one specific code."""
    return [p for p in validate(analyze(src)) if p.code == code]


CLEAN = EXAMPLES["linux-hello"]["code"]


class TestStrings(unittest.TestCase):
    """STR001, STR002, STR003, STR004 and STR005."""

    def test_non_ascii_character_in_the_string(self) -> None:
        src = 'section .data\n  msg db "caf\xe9 invalido", 10\n  size equ $ - msg\n'
        found = problems(src, "STR001")
        self.assertTrue(found)
        self.assertIn("ASCII", found[0].message)

    def test_ascii_string_does_not_complain(self) -> None:
        src = 'section .data\n  msg db "Acao valida", 10\n'
        self.assertNotIn("STR001", codes(src))

    def test_unterminated_quotes(self) -> None:
        src = 'section .data\n  msg db "missing the close, 10\n'
        self.assertIn("STR002", codes(src))

    def test_string_without_terminator_for_c_function(self) -> None:
        src = (
            'extern printf\nsection .data\n  text db "rafael"\n'
            "section .text\nmain:\n  mov rdi, text\n  call printf\n  ret\n"
        )
        self.assertIn("STR003", codes(src))

    def test_string_with_terminator_passes(self) -> None:
        src = (
            'extern printf\nsection .data\n  text db "rafael", 0\n'
            "section .text\nmain:\n  mov rdi, text\n  call printf\n  ret\n"
        )
        self.assertNotIn("STR003", codes(src))


class TestDivision(unittest.TestCase):
    """DIV001, DIV002 and DIV003."""

    def test_div_without_preparing_rdx(self) -> None:
        src = "f:\n mov rax, 100\n mov rbx, 7\n div rbx\n ret"
        found = problems(src, "DIV001")
        self.assertTrue(found)
        self.assertEqual(found[0].severity, ERROR)
        self.assertIn("XOR RDX, RDX", found[0].hint)

    def test_div_prepared_does_not_complain(self) -> None:
        src = "f:\n xor rdx, rdx\n mov rax, 100\n mov rbx, 7\n div rbx\n ret"
        self.assertNotIn("DIV001", codes(src))

    def test_idiv_accepts_cqo(self) -> None:
        src = "f:\n mov rax, -100\n cqo\n mov rbx, 7\n idiv rbx\n ret"
        self.assertNotIn("DIV001", codes(src))

    def test_division_by_immediate(self) -> None:
        src = "f:\n xor rdx, rdx\n mov rax, 10\n div 0\n ret"
        found = codes(src)
        self.assertIn("DIV002", found)


class TestStackAndAbi(unittest.TestCase):
    """STK001..STK003, ABI001 and ABI002."""

    def test_push_without_pop_is_reported(self) -> None:
        src = "f:\n push rbx\n mov rax, 1\n ret"
        found = problems(src, "STK001")
        self.assertTrue(found)

    def test_push_with_pop_passes(self) -> None:
        src = "f:\n push rbx\n mov rax, 1\n pop rbx\n ret"
        self.assertNotIn("STK001", codes(src))

    def test_pop_without_push(self) -> None:
        src = "f:\n pop rbx\n ret"
        self.assertIn("STK002", codes(src))

    def test_called_function_without_ret(self) -> None:
        src = "_start:\n call f\nf:\n mov rax, 1"
        self.assertIn("STK003", codes(src))

    def test_callee_saved_without_saving(self) -> None:
        src = "f:\n mov rbx, 10\n ret"
        self.assertIn("ABI002", codes(src))

    def test_shadow_space_on_windows(self) -> None:
        src = (
            "extern ExitProcess\nsection .text\nglobal main\nmain:\n"
            "  xor rcx, rcx\n  call ExitProcess\n  ret\n"
        )
        self.assertIn("ABI001", codes(src))

    def test_shadow_space_present_passes(self) -> None:
        src = (
            "extern ExitProcess\nsection .text\nglobal main\nmain:\n"
            "  sub rsp, 40\n  xor rcx, rcx\n  call ExitProcess\n  ret\n"
        )
        self.assertNotIn("ABI001", codes(src))


class TestOperands(unittest.TestCase):
    """IMM001, IMM002, MEM001, MEM002, SHF001 and UNK001."""

    def test_value_too_large(self) -> None:
        found = problems("f:\n mov al, 300\n ret", "IMM001")
        self.assertTrue(found)
        self.assertIn("8 bits", found[0].message)

    def test_value_that_fits_passes(self) -> None:
        self.assertNotIn("IMM001", codes("f:\n mov al, 200\n ret"))

    def test_huge_value_in_a_large_register(self) -> None:
        self.assertIn("IMM001", codes("f:\n mov eax, 0x1FFFFFFFFF\n ret"))

    def test_ambiguous_size_in_memory(self) -> None:
        self.assertIn(
            "MEM001", codes("section .bss\nx resb 8\nsection .text\nf:\n mov [x], 1\n ret")
        )

    def test_explicit_size_passes(self) -> None:
        self.assertNotIn(
            "MEM001", codes("section .bss\nx resb 8\nsection .text\nf:\n mov qword [x], 1\n ret")
        )

    def test_memory_on_both_sides(self) -> None:
        self.assertIn("MEM002", codes("f:\n mov [rax], [rbx]\n ret"))

    def test_shift_larger_than_the_register(self) -> None:
        self.assertIn("SHF001", codes("f:\n mov al, 1\n shl al, 12\n ret"))

    def test_unknown_mnemonic(self) -> None:
        self.assertIn("UNK001", codes("f:\n movq2dq xmm0, mm0\n ret"))


class TestSymbolsAndFlow(unittest.TestCase):
    """SYM001..SYM003, ENT002, FLOW001, FLOW002 and EXIT001."""

    def test_jump_to_a_nonexistent_label(self) -> None:
        found = problems("_start:\n jmp missing", "SYM001")
        self.assertTrue(found)
        self.assertIn("missing", found[0].message)

    def test_extern_does_not_complain(self) -> None:
        self.assertNotIn("SYM001", codes("extern printf\n_start:\n call printf"))

    def test_label_never_used(self) -> None:
        self.assertIn("SYM002", codes("_start:\n mov rax, 1\nforgotten:\n mov rbx, 2"))

    def test_entry_point_without_global(self) -> None:
        self.assertIn("ENT002", codes("section .text\n_start:\n mov rax, 60\n syscall"))

    def test_entry_point_with_global_passes(self) -> None:
        src = "section .text\nglobal _start\n_start:\n mov rax, 60\n xor rdi, rdi\n syscall"
        self.assertNotIn("ENT002", codes(src))

    def test_infinite_loop_without_change(self) -> None:
        src = "global _start\nsection .text\n_start:\n.stuck:\n jmp .stuck"
        self.assertIn("FLOW002", codes(src))

    def test_unreachable_block(self) -> None:
        src = (
            "global _start\nsection .text\n_start:\n mov rax, 60\n xor rdi, rdi\n syscall\n"
            "orphan:\n mov rbx, 1\n jmp orphan\n"
        )
        self.assertIn("FLOW001", codes(src))

    def test_without_explicit_exit(self) -> None:
        self.assertIn("EXIT001", codes("global _start\nsection .text\n_start:\n mov rax, 1"))


class TestSyscallsAndSections(unittest.TestCase):
    """SYS001, SYS002, SEC002 and REG001."""

    def test_syscall_without_rax(self) -> None:
        src = "global _start\nsection .text\n_start:\n mov rdi, 1\n syscall\n"
        self.assertIn("SYS001", codes(src))

    def test_rcx_after_syscall(self) -> None:
        src = (
            "global _start\nsection .text\n_start:\n mov rax, 1\n syscall\n"
            " mov rbx, rcx\n mov rax, 60\n syscall\n"
        )
        self.assertIn("SYS002", codes(src))

    def test_write_to_rodata(self) -> None:
        src = (
            "section .rodata\n  fixed dq 1\nsection .text\nglobal _start\n_start:\n"
            "  mov [fixed], rax\n  mov rax, 60\n  xor rdi, rdi\n  syscall\n"
        )
        self.assertIn("SEC002", codes(src))

    def test_uninitialized_register(self) -> None:
        self.assertIn("REG001", codes("f:\n add rax, r12\n ret"))


class TestWholeSource(unittest.TestCase):
    """The rules together, over the examples the tool ships."""

    def test_clean_example_has_no_errors(self) -> None:
        found = validate(analyze(CLEAN))
        errors = [p for p in found if p.severity == ERROR]
        self.assertEqual(errors, [], "the good example should have no errors: %s" % errors)

    def test_good_examples_have_no_errors(self) -> None:
        for name in ("linux-loop", "linux-function", "bubble", "windows-hello"):
            with self.subTest(example=name):
                errors = [
                    p for p in validate(analyze(EXAMPLES[name]["code"])) if p.severity == ERROR
                ]
                self.assertEqual(errors, [], "%s: %s" % (name, errors))

    def test_broken_example_reports_several_problems(self) -> None:
        found = codes(EXAMPLES["broken"]["code"])
        for expected in ("STR006", "DIV001", "IMM001", "MEM001", "REG001", "STK001", "FLOW002"):
            self.assertIn(expected, found, "failed to detect %s" % expected)
        self.assertIn("SYM003", found)

    def test_summary(self) -> None:
        text = summary(validate(analyze(EXAMPLES["broken"]["code"])))
        self.assertIn("error", text)

    def test_validation_does_not_break_on_garbage(self) -> None:
        for src in ("", "   ", ";;;;", "mov\n\n\n", "section", '"', "[[[", "f:"):
            with self.subTest(src=src):
                validate(analyze(src))


if __name__ == "__main__":
    unittest.main()
