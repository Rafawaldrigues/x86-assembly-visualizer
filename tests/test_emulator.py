"""Tests of the didactic virtual machine: instructions, programs and issues."""

import unittest

from asmx.analyzer import analyze
from asmx.emulator import Machine, to_signed
from asmx.examples import EXAMPLES


def run(code: str, **kw: object) -> Machine:
    """Runs a source to the end and returns the machine."""
    machine = Machine(analyze(code), **kw)
    machine.run(limit=100000)
    return machine


class TestBasicEmulation(unittest.TestCase):
    """One instruction at a time: arithmetic, flags, stack and flow."""

    def test_mov_and_arithmetic(self) -> None:
        machine = run("mov rax, 10\nadd rax, 5\nsub rax, 3\nimul rax, 2")
        self.assertEqual(machine.regs["rax"], 24)

    def test_partial_registers(self) -> None:
        machine = run("mov rax, 0x1122334455667788\nmov al, 0xff")
        self.assertEqual(machine.regs["rax"], 0x11223344556677FF)
        machine = run("mov rax, 0x1122334455667788\nmov eax, 1")
        self.assertEqual(machine.regs["rax"], 1, "writing to EAX zeroes the high part")

    def test_comparison_flags(self) -> None:
        machine = run("mov rax, 5\ncmp rax, 5")
        self.assertEqual(machine.flags["ZF"], 1)
        machine = run("mov rax, 2\ncmp rax, 5")
        self.assertEqual(machine.flags["ZF"], 0)
        self.assertEqual(machine.flags["CF"], 1)

    def test_conditional_jump(self) -> None:
        code = "mov rax, 3\ncmp rax, 3\njne end\nmov rbx, 1\nend:\nmov rcx, 9"
        machine = run(code)
        self.assertEqual(machine.regs["rbx"], 1)
        self.assertEqual(machine.regs["rcx"], 9)

    def test_stack_push_pop(self) -> None:
        machine = run("mov rax, 7\npush rax\nmov rax, 0\npop rbx")
        self.assertEqual(machine.regs["rbx"], 7)

    def test_call_ret(self) -> None:
        code = (
            "jmp start\nadd_pair:\n add rdi, rsi\n mov rax, rdi\n ret\n"
            "start:\n mov rdi, 20\n mov rsi, 22\n call add_pair"
        )
        machine = run(code)
        self.assertEqual(machine.regs["rax"], 42)

    def test_division_with_remainder(self) -> None:
        machine = run("xor rdx, rdx\nmov rax, 100\nmov rbx, 7\ndiv rbx")
        self.assertEqual(machine.regs["rax"], 14)
        self.assertEqual(machine.regs["rdx"], 2)

    def test_division_by_zero_is_fatal(self) -> None:
        machine = run("xor rdx, rdx\nmov rax, 1\nxor rbx, rbx\ndiv rbx")
        self.assertTrue(machine.halted)
        self.assertTrue(any("division by zero" in issue for issue in machine.issues))

    def test_idiv_with_negative_number(self) -> None:
        machine = run("mov rax, -100\ncqo\nmov rbx, 7\nidiv rbx")
        self.assertEqual(to_signed(machine.regs["rax"]), -14)
        self.assertEqual(to_signed(machine.regs["rdx"]), -2)

    def test_shifts(self) -> None:
        machine = run("mov rax, 1\nshl rax, 10")
        self.assertEqual(machine.regs["rax"], 1024)
        machine = run("mov rax, -8\nsar rax, 1")
        self.assertEqual(to_signed(machine.regs["rax"]), -4)

    def test_lea_does_not_read_memory(self) -> None:
        machine = run("section .data\nx dq 99\nsection .text\nlea rax, [x]\nmov rbx, [x]")
        self.assertNotEqual(machine.regs["rax"], 99)
        self.assertEqual(machine.regs["rbx"], 99)

    def test_loop_counts_down_to_zero(self) -> None:
        machine = run("mov rcx, 5\nmov rax, 0\nbody:\ninc rax\nloop body")
        self.assertEqual(machine.regs["rax"], 5)


class TestPrograms(unittest.TestCase):
    """Whole examples, from the first instruction to the exit call."""

    def test_hello_linux(self) -> None:
        machine = run(EXAMPLES["linux-hello"]["code"])
        self.assertEqual(machine.output, "Hello, world!\n")
        self.assertEqual(machine.exit_code, 0)
        self.assertTrue(machine.halted)

    def test_loop_prints_five_times(self) -> None:
        machine = run(EXAMPLES["linux-loop"]["code"])
        self.assertEqual(machine.output.count("loop iteration"), 5)

    def test_function_converts_number(self) -> None:
        machine = run(EXAMPLES["linux-function"]["code"])
        self.assertEqual(machine.output, "42\n")

    def test_bubble_sorts(self) -> None:
        machine = run(EXAMPLES["bubble"]["code"])
        self.assertEqual(machine.output.strip(), "12345789")

    def test_windows_writes_to_the_console(self) -> None:
        machine = run(EXAMPLES["windows-hello"]["code"])
        self.assertIn("Hello from Windows!", machine.output)
        self.assertEqual(machine.exit_code, 0)

    def test_gcc_att_sample(self) -> None:
        machine = run(EXAMPLES["gcc-att"]["code"])
        self.assertEqual(machine.exit_code, 10)

    def test_simulated_input(self) -> None:
        code = (
            "section .bss\nbuf resb 16\nsection .text\nglobal _start\n_start:\n"
            "mov rax, 0\nmov rdi, 0\nmov rsi, buf\nmov rdx, 5\nsyscall\n"
            "mov rax, 1\nmov rdi, 1\nmov rsi, buf\nmov rdx, 5\nsyscall\n"
            "mov rax, 60\nxor rdi, rdi\nsyscall"
        )
        machine = run(code, stdin="abcde")
        self.assertEqual(machine.output, "abcde")

    def test_step_by_step(self) -> None:
        machine = Machine(analyze("mov rax, 1\nmov rbx, 2\nmov rcx, 3"))
        machine.step()
        self.assertEqual(machine.regs["rax"], 1)
        self.assertEqual(machine.regs["rbx"], 0)
        machine.step()
        self.assertEqual(machine.regs["rbx"], 2)
        self.assertEqual(len(machine.trace), 2)

    def test_alternative_entry_point(self) -> None:
        code = "f:\n mov rax, 123\n ret\n_start:\n mov rax, 1\n"
        machine = Machine(analyze(code), entry="f")
        machine.run()
        self.assertEqual(machine.regs["rax"], 123)


class TestProblemDetection(unittest.TestCase):
    """The machine must warn instead of lying about the result."""

    def test_infinite_loop_stops_at_the_limit(self) -> None:
        machine = Machine(analyze("start:\njmp start"))
        machine.run(limit=500)
        self.assertTrue(machine.halted)
        self.assertTrue(any("infinite loop" in issue for issue in machine.issues))

    def test_large_value_truncated(self) -> None:
        machine = run("mov al, 300")
        self.assertTrue(any("does not fit" in issue for issue in machine.issues))

    def test_sum_overflow(self) -> None:
        machine = run("mov rax, -1\nadd rax, 2")
        self.assertTrue(any("overflowed" in issue for issue in machine.issues))

    def test_read_of_memory_never_written(self) -> None:
        machine = run("mov rax, [0x500000]")
        self.assertTrue(any("never written" in issue for issue in machine.issues))

    def test_unbalanced_stack_on_ret(self) -> None:
        code = "jmp i\nf:\n push rax\n ret\ni:\n call f"
        machine = run(code)
        self.assertTrue(
            any("unbalanced" in issue or "not a valid" in issue for issue in machine.issues)
        )

    def test_without_explicit_exit(self) -> None:
        machine = run("mov rax, 1\nmov rbx, 2")
        self.assertTrue(any("without an explicit exit" in issue for issue in machine.issues))

    def test_snapshot(self) -> None:
        machine = run("mov rax, 5")
        snapshot = machine.snapshot()
        self.assertEqual(snapshot["regs"]["rax"], 5)
        self.assertIn("flags", snapshot)


if __name__ == "__main__":
    unittest.main()
