"""Tests of the validation rules: every issue code has its own case."""

import unittest

from asmx.analyzer import analyze
from asmx.linter import ALL_CHECKS, ERROR, INFO, WARNING, Problem, summary, validate


def codes(src: str) -> set:
    """Set of issue codes for a source."""
    return {p.code for p in validate(analyze(src))}


def problems(src: str, code: str) -> list:
    """Issues with one specific code."""
    return [p for p in validate(analyze(src)) if p.code == code]


class TestStringsAndWarnings(unittest.TestCase):
    """Rules that look at the text and at the strings."""

    def test_open_quotes(self) -> None:
        self.assertIn("STR002", codes('section .data\nmsg db "missing, 10\n'))

    def test_non_ascii_character(self) -> None:
        self.assertIn("STR001", codes('section .data\nmsg db "caf\xe9", 10\nsize equ $ - msg\n'))

    def test_literal_control_character(self) -> None:
        self.assertIn("STR004", codes('section .data\nmsg db "a\x01b", 10\n'))

    def test_backslash_without_escape(self) -> None:
        self.assertIn("STR005", codes('section .data\nmsg db "a\\b", 10\n'))

    def test_known_escape_does_not_complain(self) -> None:
        self.assertNotIn("STR005", codes('section .data\nmsg db "a\\nb", 10\n'))

    def test_string_without_terminator(self) -> None:
        self.assertIn("STR006", codes('section .data\ntext db "rafael"\n'))

    def test_string_with_terminator_passes(self) -> None:
        self.assertNotIn("STR006", codes('section .data\ntext db "rafael", 0\n'))

    def test_string_for_printf_without_zero(self) -> None:
        src = (
            'extern printf\nsection .data\ntext db "rafael"\n'
            "section .text\nmain:\n mov rdi, text\n call printf\n ret\n"
        )
        self.assertIn("STR003", codes(src))

    def test_semicolon_inside_the_string_is_not_open_quotes(self) -> None:
        """The comment is split off respecting the quotes; cutting at ";" by
        hand gave a false positive on a User-Agent such as
        "Mozilla/5.0 (compatible; X)"."""
        src = 'section .data\nua db "Mozilla/5.0 (compatible; ASMX/1.0)", 0\n'
        self.assertNotIn("STR002", codes(src))

    def test_unbalanced_quotes_outside_a_string_are_still_caught(self) -> None:
        self.assertIn("STR002", codes('section .data\nmsg db "missing, 10\n'))

    def test_string_with_computed_size_passes(self) -> None:
        self.assertNotIn("STR006", codes('section .data\nmsg db "abc"\nsize equ $ - msg\n'))


class TestDivision(unittest.TestCase):
    """Division requires RDX to be prepared."""

    def test_div_without_preparation(self) -> None:
        self.assertIn("DIV001", codes("f:\n mov rax, 100\n mov rbx, 7\n div rbx\n ret"))

    def test_div_prepared_with_xor(self) -> None:
        self.assertNotIn(
            "DIV001", codes("f:\n xor rdx, rdx\n mov rax, 10\n mov rbx, 2\n" " div rbx\n ret")
        )

    def test_div_prepared_with_mov_zero(self) -> None:
        self.assertNotIn(
            "DIV001", codes("f:\n mov rdx, 0\n mov rax, 10\n mov rbx, 2\n" " div rbx\n ret")
        )

    def test_literal_division_by_zero(self) -> None:
        self.assertIn("DIV002", codes("f:\n xor rdx, rdx\n mov rax, 10\n div 0\n ret"))

    def test_immediate_divisor(self) -> None:
        self.assertIn("DIV003", codes("f:\n xor rdx, rdx\n mov rax, 10\n div 3\n ret"))

    def test_two_divisions_require_two_preparations(self) -> None:
        src = (
            "f:\n xor rdx, rdx\n mov rax, 10\n mov rbx, 2\n div rbx\n"
            " mov rax, 20\n div rbx\n ret"
        )
        self.assertIn("DIV001", codes(src))


class TestStack(unittest.TestCase):
    """Stack balance and return."""

    def test_push_without_pop(self) -> None:
        self.assertIn("STK001", codes("f:\n push rbx\n mov rax, 1\n ret"))

    def test_pop_without_push(self) -> None:
        self.assertIn("STK002", codes("f:\n pop rbx\n ret"))

    def test_leave_balances(self) -> None:
        self.assertNotIn("STK002", codes("f:\n push rbp\n mov rbp, rsp\n pop rbx\n" " leave\n ret"))

    def test_called_function_without_ret(self) -> None:
        self.assertIn("STK003", codes("_start:\n call f\nf:\n mov rax, 1"))

    def test_function_with_jmp_as_exit_passes(self) -> None:
        self.assertNotIn("STK003", codes("_start:\n call f\nf:\n jmp _start"))


class TestAbi(unittest.TestCase):
    """Calling conventions of both systems."""

    def test_preserved_register_changed(self) -> None:
        self.assertIn("ABI002", codes("f:\n mov rbx, 10\n ret"))

    def test_register_saved_with_push_passes(self) -> None:
        self.assertNotIn("ABI002", codes("f:\n push rbx\n mov rbx, 10\n pop rbx\n ret"))

    def test_windows_without_shadow_space(self) -> None:
        src = (
            "extern ExitProcess\nsection .text\nglobal main\nmain:\n xor rcx, rcx\n"
            " call ExitProcess\n ret\n"
        )
        self.assertIn("ABI001", codes(src))

    def test_windows_with_shadow_space_passes(self) -> None:
        src = (
            "extern ExitProcess\nsection .text\nglobal main\nmain:\n sub rsp, 40\n"
            " xor rcx, rcx\n call ExitProcess\n ret\n"
        )
        self.assertNotIn("ABI001", codes(src))

    def test_linux_does_not_require_shadow_space(self) -> None:
        src = "f:\n call g\n ret\ng:\n ret"
        self.assertNotIn("ABI001", codes(src))


class TestOperands(unittest.TestCase):
    """Size, immediates and shifts."""

    def test_immediate_too_large(self) -> None:
        self.assertIn("IMM001", codes("f:\n mov al, 300\n ret"))

    def test_64_bit_immediate_outside_mov(self) -> None:
        self.assertIn("IMM002", codes("f:\n mov rax, 0x1FFFFFFFF\n add rax, 0x1FFFFFFFF\n ret"))

    def test_mov_accepts_64_bits(self) -> None:
        self.assertNotIn("IMM002", codes("f:\n mov rax, 0x1FFFFFFFF\n ret"))

    def test_memory_without_size(self) -> None:
        self.assertIn(
            "MEM001", codes("section .bss\nx resb 8\nsection .text\nf:\n" " mov [x], 1\n ret")
        )

    def test_memory_with_size(self) -> None:
        self.assertNotIn(
            "MEM001", codes("section .bss\nx resb 8\nsection .text\nf:\n" " mov byte [x], 1\n ret")
        )

    def test_memory_on_both_sides(self) -> None:
        self.assertIn("MEM002", codes("f:\n mov [rax], [rbx]\n ret"))

    def test_shift_larger_than_the_register(self) -> None:
        self.assertIn("SHF001", codes("f:\n mov al, 1\n shl al, 12\n ret"))

    def test_unknown_mnemonic(self) -> None:
        self.assertIn("UNK001", codes("f:\n xyzzy rax\n ret"))


class TestSymbolsAndEntry(unittest.TestCase):
    """Symbols, entry point and exit."""

    def test_jump_to_a_nonexistent_label(self) -> None:
        self.assertIn("SYM001", codes("_start:\n jmp missing"))

    def test_nonexistent_variable(self) -> None:
        self.assertIn("SYM003", codes("f:\n mov rax, [missing]\n ret"))

    def test_extern_is_not_an_error(self) -> None:
        self.assertNotIn("SYM001", codes("extern printf\n_start:\n call printf"))

    def test_label_without_use(self) -> None:
        self.assertIn("SYM002", codes("_start:\n mov rax, 1\nforgotten:\n mov rbx, 2"))

    def test_without_entry_point(self) -> None:
        self.assertIn("ENT001", codes("f:\n mov rax, 1\n ret"))

    def test_entry_point_without_global(self) -> None:
        self.assertIn("ENT002", codes("section .text\n_start:\n mov rax, 60\n syscall"))

    def test_entry_point_with_global(self) -> None:
        self.assertNotIn(
            "ENT002", codes("section .text\nglobal _start\n_start:\n" " mov rax, 60\n syscall")
        )

    def test_without_explicit_exit(self) -> None:
        self.assertIn("EXIT001", codes("global _start\nsection .text\n_start:\n mov rax, 1"))

    def test_with_exit_passes(self) -> None:
        self.assertNotIn(
            "EXIT001", codes("global _start\nsection .text\n_start:\n" " mov rax, 60\n syscall")
        )

    def test_exit_through_exitprocess(self) -> None:
        self.assertNotIn(
            "EXIT001",
            codes("extern ExitProcess\nglobal main\nmain:\n" " xor rcx, rcx\n call ExitProcess"),
        )

    def test_exit_through_ret_in_main(self) -> None:
        self.assertNotIn("EXIT001", codes("global main\nmain:\n mov rax, 0\n ret"))


class TestFlow(unittest.TestCase):
    """Unreachable blocks and loops that do not end."""

    def test_unreachable_block(self) -> None:
        src = (
            "global _start\nsection .text\n_start:\n mov rax, 60\n xor rdi, rdi\n"
            " syscall\norphan:\n mov rbx, 1\n jmp orphan\n"
        )
        self.assertIn("FLOW001", codes(src))

    def test_loop_without_change(self) -> None:
        self.assertIn(
            "FLOW002", codes("global _start\nsection .text\n_start:\n" ".stuck:\n jmp .stuck")
        )

    def test_loop_with_counter_passes(self) -> None:
        src = (
            "global _start\nsection .text\n_start:\n mov rcx, 5\n.loop:\n dec rcx\n"
            " jnz .loop\n mov rax, 60\n syscall\n"
        )
        self.assertNotIn("FLOW002", codes(src))


class TestSyscallsAndSections(unittest.TestCase):
    """System calls and sections."""

    def test_syscall_without_rax(self) -> None:
        self.assertIn(
            "SYS001", codes("global _start\nsection .text\n_start:\n" " mov rdi, 1\n syscall\n")
        )

    def test_rcx_read_after_syscall(self) -> None:
        src = (
            "global _start\nsection .text\n_start:\n mov rax, 1\n syscall\n"
            " mov rbx, rcx\n mov rax, 60\n syscall\n"
        )
        self.assertIn("SYS002", codes(src))

    def test_instructions_outside_the_code_section(self) -> None:
        self.assertIn(
            "SEC001", codes("section .data\nx db 1\nsection .rodata\ny db 2\n" "mov rax, 1")
        )

    def test_write_to_rodata(self) -> None:
        src = (
            "section .rodata\nfixed dq 1\nsection .text\nglobal _start\n_start:\n"
            " mov [fixed], rax\n mov rax, 60\n syscall\n"
        )
        self.assertIn("SEC002", codes(src))


class TestRegisters(unittest.TestCase):
    """Reads of a register that has no value yet."""

    def test_uninitialized_register(self) -> None:
        self.assertIn("REG001", codes("f:\n add rax, r12\n ret"))

    def test_initialized_register_passes(self) -> None:
        self.assertNotIn("REG001", codes("f:\n mov r12, 1\n add r12, 5\n ret"))

    def test_rax_read_before_receiving_a_value(self) -> None:
        """RAX is the scratch register: reading it before writing is suspicious."""
        self.assertIn("REG001", codes("f:\n add rax, r12\n ret"))

    def test_argument_is_not_counted_as_uninitialized(self) -> None:
        self.assertNotIn("REG001", codes("f:\n mov rax, rdi\n ret"))


class TestRegression(unittest.TestCase):
    """Fixed defects must not come back."""

    def test_att_does_not_report_ambiguous_size(self) -> None:
        """`movl $0, -4(%rbp)` writes 4 bytes: the AT&T suffix is the size."""
        from asmx.examples import EXAMPLES

        self.assertEqual(validate(analyze(EXAMPLES["gcc-att"]["code"])), [])

    def test_semicolon_in_a_string_is_not_open_quotes(self) -> None:
        src = 'section .data\nua db "Mozilla/5.0 (compatible; ASMX/1.0)", 0\n'
        self.assertNotIn("STR002", codes(src))


class TestInfrastructure(unittest.TestCase):
    """What surrounds the rules: list, summary, ordering and internal failure."""

    def test_rule_list(self) -> None:
        self.assertEqual(len(ALL_CHECKS), 15)
        for rule in ALL_CHECKS:
            with self.subTest(rule=rule.__name__):
                self.assertEqual(rule(analyze("")), [])

    def test_problem_str(self) -> None:
        problem = Problem(3, ERROR, "XXX001", "something", "tip")
        self.assertEqual(str(problem), "L3 [error] XXX001: something")

    def test_problem_to_dict(self) -> None:
        problem = Problem(3, WARNING, "XXX002", "something", "tip")
        self.assertEqual(
            problem.to_dict(),
            {
                "line": 3,
                "severity": WARNING,
                "code": "XXX002",
                "message": "something",
                "hint": "tip",
            },
        )

    def test_summary(self) -> None:
        found = [
            Problem(1, ERROR, "A", "a"),
            Problem(2, WARNING, "B", "b"),
            Problem(3, INFO, "C", "c"),
        ]
        self.assertEqual(summary(found), "1 error(s), 1 warning(s), 1 info(s)")

    def test_ordering_by_severity_and_line(self) -> None:
        found = validate(analyze("f:\n mov al, 300\n jmp missing\n ret"))
        self.assertEqual(found[0].severity, ERROR)
        lines = [p.line for p in found if p.severity == ERROR]
        self.assertEqual(lines, sorted(lines))

    def test_internal_failure_becomes_info(self) -> None:
        from asmx import linter

        def broken_rule(analysis: object) -> list:
            raise RuntimeError("blew up on purpose")

        original = linter.ALL_CHECKS
        linter.ALL_CHECKS = [broken_rule]
        try:
            found = linter.validate(analyze("nop"))
        finally:
            linter.ALL_CHECKS = original
        self.assertEqual(found[0].code, "INT001")
        self.assertIn("blew up on purpose", found[0].message)

    def test_empty_code_has_no_problem(self) -> None:
        self.assertEqual(validate(analyze("")), [])


if __name__ == "__main__":
    unittest.main()
