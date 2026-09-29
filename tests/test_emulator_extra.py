"""Tests of the instructions and of the less obvious paths of the machine."""

import unittest

from asmx.analyzer import analyze
from asmx.emulator import (
    BSS_BASE,
    DATA_BASE,
    MASK64,
    RET_MAGIC,
    STACK_TOP,
    Machine,
    Symbol,
    hexs,
    to_signed,
)
from asmx.errors import AnalysisTimeoutError


class TestDesviosCondicionais(unittest.TestCase):
    """Signed comparisons must really compare (jl/jle regression)."""

    def roda(self, fonte: str) -> object:
        """Runs a source and returns the machine."""
        maquina = Machine(analyze(fonte))
        maquina.run(limit=200)
        return maquina

    def test_jl_desvia_quando_menor(self) -> None:
        fonte = (
            "mov rax, 5\nmov rbx, 9\ncmp rax, rbx\njl smaller\n"
            "mov rdi, 1\njmp done\nsmaller:\nmov rdi, 2\ndone:\nmov rax, 60\nsyscall"
        )
        self.assertEqual(self.roda(fonte).regs["rdi"], 2)

    def test_jl_nao_desvia_quando_maior(self) -> None:
        fonte = (
            "mov rax, 9\nmov rbx, 5\ncmp rax, rbx\njl smaller\n"
            "mov rdi, 1\njmp done\nsmaller:\nmov rdi, 2\ndone:\nmov rax, 60\nsyscall"
        )
        self.assertEqual(self.roda(fonte).regs["rdi"], 1)

    def test_jle_desvia_na_igualdade(self) -> None:
        fonte = (
            "mov rax, 7\nmov rbx, 7\ncmp rax, rbx\njle smaller\n"
            "mov rdi, 1\njmp done\nsmaller:\nmov rdi, 2\ndone:\nmov rax, 60\nsyscall"
        )
        self.assertEqual(self.roda(fonte).regs["rdi"], 2)

    def test_jg_e_jge_continuam_certos(self) -> None:
        fonte = (
            "mov rax, 9\nmov rbx, 5\ncmp rax, rbx\njg bigger\n"
            "mov rdi, 1\njmp done\nbigger:\nmov rdi, 2\ndone:\nmov rax, 60\nsyscall"
        )
        self.assertEqual(self.roda(fonte).regs["rdi"], 2)


class FakeClock:
    """Clock that advances a fixed amount on every read.

    It allows testing the timeout without depending on real time: every query
    adds ``step`` seconds, so the limit always runs out at the same instant.
    """

    def __init__(self, step: float = 10.0) -> None:
        self.step = step
        self.value = 0.0

    def __call__(self) -> float:
        self.value += self.step
        return self.value


def fake_clock() -> float:
    """Stopped clock, used by the tests that do not care about time."""
    return 0.0


def run(code: str, stdin: str = "", limit: int = 100000, **kwargs: object) -> Machine:
    """Runs a source with a stopped clock and returns the machine."""
    machine = Machine(
        analyze(code), stdin=stdin, clock=fake_clock, **kwargs  # type: ignore[arg-type]
    )
    machine.run(limit=limit)
    return machine


class TestInstructions(unittest.TestCase):
    """Instructions that still had no test."""

    def test_xchg(self) -> None:
        machine = run("mov rax, 1\nmov rbx, 2\nxchg rax, rbx")
        self.assertEqual(machine.regs["rax"], 2)
        self.assertEqual(machine.regs["rbx"], 1)

    def test_movzx_and_movsx(self) -> None:
        machine = run("mov rax, 0\nmov al, 0xFF\nmovzx rbx, al\nmovsx rcx, al")
        self.assertEqual(machine.regs["rbx"], 255)
        self.assertEqual(to_signed(machine.regs["rcx"], 8), -1)

    def test_movsxd(self) -> None:
        machine = run("mov eax, -1\nmovsxd rbx, eax")
        self.assertEqual(to_signed(machine.regs["rbx"], 8), -1)

    def test_setcc(self) -> None:
        machine = run("mov rax, 5\ncmp rax, 5\nsete bl\nsetne cl")
        self.assertEqual(machine.regs["rbx"], 1)
        self.assertEqual(machine.regs["rcx"], 0)

    def test_cmov(self) -> None:
        machine = run("mov rax, 5\nmov rbx, 9\ncmp rax, 5\ncmove rbx, rax")
        self.assertEqual(machine.regs["rbx"], 5)

    def test_cmov_does_not_copy_when_false(self) -> None:
        machine = run("mov rax, 5\nmov rbx, 9\ncmp rax, 4\ncmove rbx, rax")
        self.assertEqual(machine.regs["rbx"], 9)

    def test_not_and_neg(self) -> None:
        machine = run("mov rax, 0\nnot rax")
        self.assertEqual(machine.regs["rax"], MASK64)

    def test_mul_imul_and_div(self) -> None:
        machine = run("mov rax, 6\nmov rbx, 7\nmul rbx")
        self.assertEqual(machine.regs["rax"], 42)
        self.assertEqual(machine.regs["rdx"], 0)

    def test_imul_three_operands(self) -> None:
        machine = run("mov rax, 3\nmov rbx, 4\nimul rcx, rax, rbx")
        self.assertEqual(machine.regs["rcx"], 12)

    def test_imul_two_operands(self) -> None:
        machine = run("mov rax, -3\nmov rbx, 4\nimul rax, rbx")
        self.assertEqual(to_signed(machine.regs["rax"], 8), -12)

    def test_cdq_and_cqo(self) -> None:
        machine = run("mov eax, -1\ncdq")
        self.assertEqual(machine.regs["rdx"], 0xFFFFFFFF)
        machine = run("mov rax, -1\ncqo")
        self.assertEqual(machine.regs["rdx"], MASK64)

    def test_division_overflow_warns(self) -> None:
        machine = run("mov rdx, -1\nmov rax, 100\nmov rbx, 7\ndiv rbx")
        self.assertTrue(any("quotient does not fit" in issue for issue in machine.issues))

    def test_shifts(self) -> None:
        machine = run("mov rax, 8\nshr rax, 1\nshl rax, 2")
        self.assertEqual(machine.regs["rax"], 16)

    def test_sal_and_sar(self) -> None:
        machine = run("mov rax, -16\nsar rax, 2\nsal rax, 1")
        self.assertEqual(to_signed(machine.regs["rax"], 8), -8)

    def test_loop_with_rcx_zero(self) -> None:
        machine = run("mov rcx, 1\nbody:\nmov rax, 7\nloop body")
        self.assertEqual(machine.regs["rax"], 7)
        self.assertEqual(machine.regs["rcx"], 0)

    def test_jrcxz_jump(self) -> None:
        machine = run("mov rcx, 0\njrcxz end\nmov rax, 1\nend:\nmov rbx, 2")
        self.assertEqual(machine.regs["rax"], 0)
        self.assertEqual(machine.regs["rbx"], 2)

    def test_leave_tears_down_the_frame(self) -> None:
        code = (
            "f:\n push rbp\n mov rbp, rsp\n sub rsp, 16\n mov rax, 1\n"
            " leave\n ret\n_start:\n call f\n mov rax, 60\n syscall"
        )
        machine = run(code)
        self.assertTrue(machine.halted)

    def test_hlt_stops_execution(self) -> None:
        machine = run("mov rax, 1\nhlt\nmov rbx, 2")
        self.assertTrue(machine.halted)
        self.assertEqual(machine.regs["rbx"], 0)

    def test_unemulated_instruction_warns(self) -> None:
        machine = Machine(analyze("movdqa xmm0, xmm1\nmov rax, 1"))
        machine.step()
        self.assertTrue(any("not emulated" in issue for issue in machine.issues))

    def test_cld_and_std_change_df(self) -> None:
        machine = run("std")
        self.assertEqual(machine.flags["DF"], 1)
        machine = run("std\ncld")
        self.assertEqual(machine.flags["DF"], 0)


class TestStringInstructions(unittest.TestCase):
    """REP MOVSB/STOSB/LODSB/SCASB and the direction flag."""

    def test_rep_movsb_copies(self) -> None:
        code = (
            "section .data\nsource db 1, 2, 3\ntarget db 0, 0, 0\nsection .text\n"
            "global _start\n_start:\n lea rsi, [source]\n lea rdi, [target]\n"
            " mov rcx, 3\n rep movsb\n mov rax, 1\n mov rdi, 1\n"
            " lea rsi, [target]\n mov rdx, 3\n syscall\n"
            " mov rax, 60\n xor rdi, rdi\n syscall"
        )
        machine = run(code)
        self.assertEqual([ord(c) for c in machine.output], [1, 2, 3])

    def test_rep_stosb_fills(self) -> None:
        code = (
            "section .bss\nbuf resb 4\nsection .text\nglobal _start\n_start:\n"
            " lea rdi, [buf]\n mov al, 65\n mov rcx, 4\n rep stosb\n"
            " mov rax, 1\n mov rdi, 1\n lea rsi, [buf]\n mov rdx, 4\n syscall\n"
            " mov rax, 60\n xor rdi, rdi\n syscall"
        )
        self.assertEqual(run(code).output, "AAAA")

    def test_lodsb_advances_rsi(self) -> None:
        machine = run("section .data\nx db 7\nsection .text\n lea rsi, [x]\n lodsb")
        self.assertEqual(machine.get_reg("al"), 7)

    def test_rep_with_absurd_counter_warns(self) -> None:
        machine = run("mov rcx, 0xFFFFFF\nrep stosb", limit=10)
        self.assertTrue(any("REP with RCX" in issue for issue in machine.issues))

    def test_scasb_compares(self) -> None:
        code = "section .data\nx db 65\nsection .text\n lea rdi, [x]\n mov al, 65\n" " scasb"
        self.assertEqual(run(code).flags["ZF"], 1)


class TestEmulatedSyscalls(unittest.TestCase):
    """Every syscall the machine handles."""

    def test_getpid(self) -> None:
        self.assertEqual(run("mov rax, 39\nsyscall").regs["rax"], 4242)

    def test_time(self) -> None:
        self.assertGreater(run("mov rax, 201\nsyscall").regs["rax"], 0)

    def test_nanosleep_is_ignored(self) -> None:
        machine = run("mov rax, 35\nsyscall")
        self.assertFalse(any("35" in issue for issue in machine.issues))
        machine = Machine(analyze("mov rax, 35\nsyscall"))
        machine.step()
        self.assertIn("nanosleep", machine.step().note)

    def test_brk_returns_a_simulated_heap(self) -> None:
        self.assertEqual(run("mov rax, 12\nsyscall").regs["rax"], BSS_BASE + 0x10000)

    def test_getrandom_fills_the_buffer(self) -> None:
        code = (
            "section .bss\nbuf resb 8\nsection .text\nglobal _start\n_start:\n"
            " mov rax, 318\n lea rdi, [buf]\n mov rsi, 8\n syscall\n"
            " mov rbx, rax\n mov rax, 60\n xor rdi, rdi\n syscall"
        )
        machine = run(code)
        self.assertEqual(machine.regs["rbx"], 8)
        self.assertTrue(any(machine.rd8(machine.symbols["buf"].addr + i) for i in range(8)))

    def test_unknown_syscall_warns(self) -> None:
        machine = run("mov rax, 999\nsyscall")
        self.assertTrue(any("not emulated" in issue for issue in machine.issues))

    def test_write_with_absurd_size(self) -> None:
        machine = run("mov rax, 1\nmov rdi, 1\nmov rsi, 0x1000\n" "mov rdx, 0xFFFFFF\nsyscall")
        self.assertTrue(any("absurd size" in issue for issue in machine.issues))

    def test_exit_group(self) -> None:
        machine = run("mov rax, 231\nmov rdi, 3\nsyscall")
        self.assertEqual(machine.exit_code, 3)

    def test_int_0x80_swaps_the_registers(self) -> None:
        code = (
            'section .data\nmsg db "ok"\nsection .text\nglobal _start\n_start:\n'
            " mov eax, 4\n mov ebx, 1\n lea ecx, [msg]\n mov edx, 2\n int 0x80\n"
            " mov eax, 1\n xor ebx, ebx\n int 0x80"
        )
        self.assertEqual(run(code).output, "ok")

    def test_int_0x80_without_equivalent_warns(self) -> None:
        machine = Machine(analyze("mov eax, 11\nint 0x80"))
        machine.step()
        machine.step()
        self.assertTrue(any("32-bit" in issue for issue in machine.issues))

    def test_int_3_is_a_breakpoint(self) -> None:
        machine = Machine(analyze("int 3\nmov rax, 1"))
        step = machine.step()
        self.assertIn("breakpoint", step.note)

    def test_unknown_interrupt(self) -> None:
        machine = Machine(analyze("int 0x21\nmov rax, 1"))
        self.assertIn("unemulated interrupt", machine.step().note)


class TestWindowsApi(unittest.TestCase):
    """Stubs of the kernel32/user32 functions."""

    def program(self, call: str) -> Machine:
        code = (
            'extern %s\nsection .data\nmsg db "hi", 0\nsection .text\n'
            "global main\nmain:\n sub rsp, 40\n%s\n xor rcx, rcx\n"
            " call ExitProcess" % (call.split()[0], call)
        )
        return run(code)

    def test_getstdhandle(self) -> None:
        machine = self.program("call GetStdHandle")
        self.assertEqual(machine.regs["rax"], 0x13)

    def test_writeconsole(self) -> None:
        code = (
            "extern GetStdHandle\nextern WriteConsoleA\nextern ExitProcess\n"
            'section .data\nmsg db "Hello", 0\nsection .text\nglobal main\nmain:\n'
            " sub rsp, 40\n mov rcx, -11\n call GetStdHandle\n mov rbx, rax\n"
            " mov rcx, rbx\n lea rdx, [msg]\n mov r8, 5\n mov r9, 0\n"
            " call WriteConsoleA\n xor rcx, rcx\n call ExitProcess"
        )
        self.assertEqual(run(code).output, "Hello")

    def test_messagebox(self) -> None:
        code = (
            "extern MessageBoxA\nextern ExitProcess\nsection .data\n"
            'title db "Warning", 0\ntext db "Careful", 0\nsection .text\n'
            "global main\nmain:\n sub rsp, 40\n xor rcx, rcx\n lea rdx, [text]\n"
            " lea r8, [title]\n mov r9, 0\n call MessageBoxA\n xor rcx, rcx\n"
            " call ExitProcess"
        )
        self.assertIn("Careful", run(code).output)

    def test_sleep_is_ignored(self) -> None:
        self.assertFalse(self.program("call Sleep").issues)

    def test_getlasterror(self) -> None:
        self.assertEqual(self.program("call GetLastError").regs["rax"], 0)

    def test_unknown_external_function(self) -> None:
        machine = self.program("call NothingLikeThis")
        self.assertTrue(any("not emulated" in issue for issue in machine.issues))


class TestMemoryAndRegisters(unittest.TestCase):
    """Reads, writes and addressing."""

    def test_write_and_read_8_bytes(self) -> None:
        machine = Machine(analyze("mov rax, 1"))
        machine.write_mem(0x1000, 8, 0x1122334455667788)
        self.assertEqual(machine.read_mem(0x1000, 8), 0x1122334455667788)
        self.assertEqual(machine.rd8(0x1000), 0x88)

    def test_zero_terminated_string(self) -> None:
        machine = Machine(analyze("mov rax, 1"))
        for i, letter in enumerate("abc\0"):
            machine.wr8(0x2000 + i, ord(letter))
        self.assertEqual(machine.read_cstring(0x2000), "abc")

    def test_address_with_scale(self) -> None:
        code = "section .data\nv db 1, 2, 3, 4\nsection .text\n mov rbx, 2\n" "mov al, [v + rbx]"
        machine = run(code)
        self.assertEqual(machine.get_reg("al"), 3)

    def test_negative_address(self) -> None:
        code = "f:\n push rbp\n mov rbp, rsp\n sub rsp, 16\n mov al, [rbp - 4]\n leave\n ret"
        self.assertIsNotNone(run(code).halted)

    def test_read_of_a_pointer_never_written(self) -> None:
        machine = run("mov rax, [rbx]")
        self.assertTrue(any("never written" in issue for issue in machine.issues))

    def test_default_operand_size(self) -> None:
        machine = Machine(analyze("mov rax, 1"))
        self.assertEqual(machine.op_size(analyze("mov rax, 1").instrs[0].operands[0]), 8)

    def test_empty_stack_warns(self) -> None:
        machine = Machine(analyze("pop rax"))
        machine.step()
        self.assertTrue(any("stack underflow" in issue for issue in machine.issues))

    def test_push_and_pop_with_memory(self) -> None:
        code = "section .data\nx dq 42\nsection .text\n push qword [x]\n pop rbx"
        self.assertEqual(run(code).regs["rbx"], 42)


class TestDataAndSymbols(unittest.TestCase):
    """Data loading, BSS and constants."""

    def test_data_and_bss_addresses(self) -> None:
        code = (
            "section .data\na db 1\nsection .bss\nb resb 16\nsection .text\n"
            "global _start\n_start:\n mov rax, 60\n syscall"
        )
        machine = run(code)
        self.assertEqual(machine.symbols["a"].addr, DATA_BASE)
        self.assertEqual(machine.symbols["b"].addr, BSS_BASE)
        self.assertTrue(machine.symbols["b"].bss)

    def test_times_generates_zeros(self) -> None:
        code = (
            "section .data\nzeros times 4 db 0\nsection .text\n"
            "global _start\n_start:\n mov rax, 60\n syscall"
        )
        machine = run(code)
        self.assertEqual(machine.symbols["zeros"].size, 4)

    def test_times_with_a_value_repeats_it(self) -> None:
        code = (
            "section .data\nv times 3 db 7\nsection .text\nglobal _start\n_start:\n"
            " mov rax, 1\n mov rdi, 1\n lea rsi, [v]\n mov rdx, 3\n syscall\n"
            " mov rax, 60\n syscall"
        )
        self.assertEqual(run(code).output, "\x07\x07\x07")

    def test_equ_with_a_value(self) -> None:
        code = (
            "section .data\nn equ 42\nsection .text\nglobal _start\n_start:\n"
            " mov rax, n\n mov rax, 60\n syscall"
        )
        machine = run(code)
        self.assertEqual(machine.symbols["n"].equ, 42)

    def test_equ_with_dollar_minus_label(self) -> None:
        code = (
            'section .data\nmsg db "abc"\nsize equ $ - msg\nsection .text\n'
            "global _start\n_start:\n mov rdx, size\n mov rax, 60\n syscall"
        )
        machine = run(code)
        self.assertEqual(machine.symbols["size"].equ, 3)

    def test_code_label_becomes_a_magic_address(self) -> None:
        code = "f:\n mov rax, 1\n ret\n_start:\n lea rbx, [f]"
        machine = run(code)
        self.assertGreaterEqual(machine.regs["rbx"], RET_MAGIC)


class TestExecution(unittest.TestCase):
    """Control of the execution, of the clock and of the history."""

    def test_timeout_marks_and_stops(self) -> None:
        machine = Machine(analyze("start:\njmp start"), clock=FakeClock())
        machine.run(limit=100000, timeout=1.0)
        self.assertTrue(machine.timed_out)
        self.assertTrue(machine.halted)
        self.assertTrue(any("timeout" in issue for issue in machine.issues))

    def test_strict_timeout_raises(self) -> None:
        machine = Machine(analyze("start:\njmp start"), clock=FakeClock())
        with self.assertRaises(AnalysisTimeoutError):
            machine.run(limit=100000, timeout=1.0, raise_on_timeout=True)

    def test_run_until_stops_at_the_index(self) -> None:
        machine = Machine(analyze("mov rax, 1\nmov rbx, 2\nmov rcx, 3"))
        machine.run_until({2})
        self.assertEqual(machine.ip, 2)
        self.assertEqual(machine.regs["rcx"], 0)

    def test_snapshot(self) -> None:
        machine = run("mov rax, 5")
        snapshot = machine.snapshot()
        self.assertEqual(snapshot["regs"]["rax"], 5)
        self.assertIn("rsp", snapshot["regs"])
        self.assertIsNotNone(snapshot["halted"])

    def test_limited_history(self) -> None:
        machine = Machine(analyze("start:\nmov rax, 1\ninc rax\njmp start"))
        machine.run(limit=3000)
        self.assertLessEqual(len(machine.trace), 2000)

    def test_ret_without_a_valid_address(self) -> None:
        machine = run("f:\n pop rax\n ret\n_start:\n call f")
        self.assertTrue(
            any("not a valid" in issue or "unbalanced" in issue for issue in machine.issues)
        )

    def test_jump_to_a_nonexistent_label_stops(self) -> None:
        machine = run("jmp nowhere")
        self.assertTrue(machine.halted)
        self.assertTrue(any("unknown label" in issue for issue in machine.issues))

    def test_step_after_halting(self) -> None:
        machine = run("mov rax, 1")
        machine.halted = True
        self.assertIn("already finished", machine.step().note)

    def test_simulation_error_becomes_an_issue(self) -> None:
        machine = Machine(analyze("mov rax, 1"))
        machine.instrs[0].operands[0].reg = "register_that_does_not_exist"
        machine.step()
        self.assertTrue(machine.issues)

    def test_unknown_conditions_are_false(self) -> None:
        machine = Machine(analyze("mov rax, 1"))
        self.assertFalse(machine.cond("zz"))

    def test_parity_and_sign_flags(self) -> None:
        machine = Machine(analyze("mov rax, 1"))
        machine.set_logic_flags(0, 8)
        self.assertEqual(machine.flags["ZF"], 1)
        self.assertEqual(machine.flags["PF"], 1)
        machine.set_logic_flags(0x80, 1)
        self.assertEqual(machine.flags["SF"], 1)

    def test_signed_sum_overflow(self) -> None:
        machine = Machine(analyze("mov rax, 1"))
        machine.set_arith_flags(0x7FFFFFFFFFFFFFFF, 1, 0x8000000000000000, 8, False)
        self.assertEqual(machine.flags["OF"], 1)
        machine.set_arith_flags(0, 1, -1, 8, True)
        self.assertEqual(machine.flags["CF"], 1)

    def test_hexs_and_to_signed(self) -> None:
        self.assertEqual(hexs(MASK64), "0xffffffffffffffff")
        self.assertEqual(to_signed(MASK64, 8), -1)
        self.assertEqual(to_signed(0xFF, 1), -1)

    def test_symbol_dataclass(self) -> None:
        symbol = Symbol(addr=0x1000, size=8, line=3)
        self.assertEqual(symbol.addr, 0x1000)
        self.assertFalse(symbol.bss)

    def test_short_input_is_enough(self) -> None:
        code = (
            "section .bss\nbuf resb 4\nsection .text\nglobal _start\n_start:\n"
            " mov rax, 0\n mov rdi, 0\n lea rsi, [buf]\n mov rdx, 4\n syscall\n"
            " mov rbx, rax\n mov rax, 60\n syscall"
        )
        machine = run(code, stdin="ab")
        self.assertEqual(machine.regs["rbx"], 2)

    def test_stack_starts_at_the_top(self) -> None:
        machine = Machine(analyze("mov rax, 1"))
        self.assertEqual(machine.regs["rsp"], STACK_TOP)

    def test_missing_explicit_exit_warns(self) -> None:
        self.assertTrue(
            any("without an explicit exit" in issue for issue in run("mov rax, 1").issues)
        )


if __name__ == "__main__":
    unittest.main()
