"""Regression tests for allocation limits and checked simulated memory."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from asmx.analyzer import analyze
from asmx.cli import main
from asmx.emulator import DATA_BASE, MASK64, STACK_SIZE, STACK_TOP, Machine
from asmx.memory import ADDRESS_LIMIT, PAGE_SIZE, Memory, MemoryFault
from asmx.report import collect, render_html, render_markdown
from asmx.workspace import Scenario, run_scenario


class TestMemoryRegions(unittest.TestCase):
    """Allocation accounting, permissions, page storage and released ranges."""

    def test_invalid_budget(self) -> None:
        with self.assertRaises(ValueError):
            Memory(0)

    def test_exact_budget_and_no_partial_allocation(self) -> None:
        memory = Memory(8)
        memory.allocate(0x1000, 8, "data")
        with self.assertRaises(MemoryFault) as caught:
            memory.allocate(0x2000, 1, "extra")
        self.assertEqual(caught.exception.code, "MEM_LIMIT")
        self.assertEqual(memory.allocated, 8)
        self.assertEqual(len(memory.regions), 1)

    def test_negative_size_and_address_wrap(self) -> None:
        memory = Memory(16)
        for address, size in ((0, -1), (-1, 1), (ADDRESS_LIMIT - 1, 2)):
            with self.subTest(address=address, size=size):
                with self.assertRaises(MemoryFault):
                    memory.allocate(address, size, "bad")

    def test_overlapping_allocations(self) -> None:
        memory = Memory(32)
        memory.allocate(10, 8, "first")
        with self.assertRaises(MemoryFault):
            memory.allocate(17, 2, "second")
        memory.allocate(18, 8, "adjacent")
        with self.assertRaises(MemoryFault):
            memory.check(17, 2)

    def test_protected_region(self) -> None:
        memory = Memory(16)
        memory.allocate(10, 8, "constant", writable=False)
        memory.check(10, 8)
        with self.assertRaises(MemoryFault) as caught:
            memory.check(10, 1, write=True)
        self.assertEqual(caught.exception.code, "MEM_READONLY")

    def test_invalid_access_sizes(self) -> None:
        memory = Memory(8)
        for address, size in ((0, -1), (-1, 1), (ADDRESS_LIMIT - 1, 2), (10, 1)):
            with self.assertRaises(MemoryFault):
                memory.check(address, size)

    def test_pages_and_partial_initialization(self) -> None:
        memory = Memory(2 * PAGE_SIZE)
        memory.allocate(0, 2 * PAGE_SIZE, "heap", initialized=False)
        memory.store(PAGE_SIZE - 1, b"ab")
        self.assertEqual(memory.peek(PAGE_SIZE - 1), ord("a"))
        self.assertEqual(memory.peek(PAGE_SIZE), ord("b"))
        self.assertTrue(memory.initialized(PAGE_SIZE - 1, 2))
        self.assertFalse(memory.initialized(PAGE_SIZE - 1, 3))
        self.assertEqual(memory.snapshot()["committed_bytes"], 2 * PAGE_SIZE)

    def test_large_zero_initializer_is_sparse(self) -> None:
        memory = Memory(1 << 30)
        memory.allocate(0, 1 << 30, "zeros")
        memory.fill(0, b"\0", 1 << 30)
        self.assertEqual(memory.pages, {})
        self.assertTrue(memory.initialized(0, 1 << 30))

    def test_repeated_pattern_crosses_pages(self) -> None:
        memory = Memory(20000)
        memory.allocate(0, 15000, "pattern")
        memory.fill(0, b"abc", 5000)
        self.assertEqual(bytes(memory.peek(i) for i in range(15000)), b"abc" * 5000)
        memory.fill(0, b"", 2)
        memory.fill(0, b"x", 0)

    def test_shrink_discards_bytes_and_initialization(self) -> None:
        memory = Memory(PAGE_SIZE * 4)
        region = memory.allocate(0, PAGE_SIZE * 3, "heap", initialized=False)
        memory.store(0, b"a" * (PAGE_SIZE * 3))
        memory.resize(region, 2, PAGE_SIZE)
        self.assertEqual(memory.peek(0), 0)
        self.assertEqual(memory.peek(2), ord("a"))
        self.assertEqual(memory.peek(PAGE_SIZE + 2), 0)
        self.assertNotIn(2, memory.pages)
        memory.resize(region, 0, PAGE_SIZE * 3)
        self.assertFalse(memory.initialized(0, 1))
        self.assertTrue(memory.initialized(2, 1))
        self.assertFalse(memory.initialized(PAGE_SIZE + 2, 1))
        self.assertEqual(memory.peak, PAGE_SIZE * 3)

    def test_resize_failure_keeps_original_mapping(self) -> None:
        memory = Memory(16)
        region = memory.allocate(100, 4, "heap")
        memory.allocate(108, 4, "data")
        for start, size in ((100, 13), (100, -1), (100, 9), (-1, 4), (ADDRESS_LIMIT, 1)):
            with self.subTest(start=start, size=size):
                with self.assertRaises(MemoryFault):
                    memory.resize(region, start, size)
                self.assertEqual((region.start, region.size), (100, 4))
                self.assertEqual(memory.allocated, 8)


class TestMachineMemory(unittest.TestCase):
    """Memory faults through instructions and syscalls, rather than private helpers."""

    def run_code(self, code: str, **kwargs: object) -> Machine:
        """Execute a small program and return its machine state."""
        machine = Machine(analyze(code), **kwargs)
        machine.run(limit=10000)
        return machine

    def assert_fault(self, machine: Machine, code: str) -> None:
        """Check a terminal fault without requiring a particular message."""
        self.assertTrue(machine.halted)
        self.assertEqual(machine.memory_fault["code"], code)
        self.assertTrue(any(code in issue for issue in machine.issues))

    def test_oversized_declarations_stop_before_execution(self) -> None:
        for declaration in (
            "buffer resb 1048577",
            "buffer times 1048577 db 1",
            "buffer dq 1048577 dup (7)",
            "buffer times 1048576 dq 0",
            "buffer times 400000 db 'abc'",
        ):
            with self.subTest(declaration=declaration):
                machine = self.run_code(declaration + "\nmov rax, 7", max_memory=1)
                self.assert_fault(machine, "MEM_LIMIT")
                self.assertTrue(machine.out_of_memory)
                self.assertEqual(machine.steps, 0)
                self.assertEqual(machine.regs["rax"], 0)
                self.assertEqual(machine.memory.pages, {})
                self.assertEqual(machine.memory_fault["line"], 1)

    def test_negative_and_unsupported_declarations(self) -> None:
        for declaration in ("x resb -1", "x times -1 db 0", "x dw -2 dup (0)", "x times 3 nop"):
            with self.subTest(declaration=declaration):
                self.assert_fault(self.run_code(declaration), "MEM_SIZE")

    def test_total_budget_counts_multiple_regions(self) -> None:
        machine = self.run_code("a resb 524288\nb resb 524289", max_memory=1)
        self.assert_fault(machine, "MEM_LIMIT")
        self.assertEqual(machine.memory.allocated, 524288)

    def test_initialized_data_and_bss(self) -> None:
        machine = self.run_code(
            "section .data\na times 2 dw 0x1234\nb dq 2 dup (7)\n"
            "section .bss\nz resb 1048500\nsection .text\nmov rax, [z]\nhlt",
            max_memory=1,
        )
        self.assertFalse(machine.issues)
        self.assertEqual(machine.regs["rax"], 0)
        self.assertEqual(machine.read_mem(machine.symbols["a"].addr, 4), 0x12341234)
        self.assertEqual(machine.read_mem(machine.symbols["b"].addr, 8), 7)
        self.assertLessEqual(machine.memory.snapshot()["committed_bytes"], PAGE_SIZE)

    def test_large_data_does_not_overlap_bss(self) -> None:
        machine = self.run_code(
            "section .data\na times 3145728 db 0\n"
            "section .bss\nb resb 8\nsection .text\nmov qword [b], 7\nhlt"
        )
        self.assertFalse(machine.issues)
        self.assertGreaterEqual(machine.symbols["b"].addr, DATA_BASE + 3145728)

    def test_null_and_unmapped_accesses_stop_at_fault(self) -> None:
        for instruction in ("mov rax, [0]", "mov byte [0x1234], 7"):
            machine = self.run_code(instruction + "\nmov rbx, 99")
            self.assert_fault(machine, "MEM_ACCESS")
            self.assertFalse(machine.out_of_memory)
            self.assertEqual(machine.ip, 0)
            self.assertEqual(machine.trace[-1].issue, "fatal")
            self.assertEqual(machine.regs["rbx"], 0)

    def test_crossing_boundary_does_not_partially_write(self) -> None:
        machine = self.run_code(
            "section .data\nbuf db 1, 2, 3, 4\n" "section .text\nmov qword [buf], -1"
        )
        self.assert_fault(machine, "MEM_ACCESS")
        self.assertEqual(machine.read_mem(machine.symbols["buf"].addr, 4), 0x04030201)

    def test_read_crossing_boundary_is_fatal(self) -> None:
        self.assert_fault(self.run_code("buf db 1\nmov eax, [buf]"), "MEM_ACCESS")

    def test_readonly_scalar_and_string_writes(self) -> None:
        for code in ("mov byte [x], 2", "lea rdi, [x]\nmov al, 2\nstosb"):
            machine = self.run_code("section .rodata\nx db 1\nsection .text\n" + code)
            self.assert_fault(machine, "MEM_READONLY")
            self.assertEqual(machine.peek8(machine.symbols["x"].addr), 1)

    def test_address_wrap_is_not_silently_masked(self) -> None:
        machine = self.run_code("mov rbx, -1\nmov rax, [rbx]")
        self.assert_fault(machine, "MEM_ACCESS")
        self.assertEqual(machine.memory_fault["address"], MASK64)

    def test_lea_does_not_access_memory(self) -> None:
        machine = self.run_code("lea rax, [0]\nhlt")
        self.assertFalse(machine.issues)

    def test_partial_initialization_warns(self) -> None:
        machine = self.run_code("sub rsp, 8\nmov byte [rsp], 7\nmov rax, [rsp]\nhlt")
        self.assertIsNone(machine.memory_fault)
        self.assertTrue(any("MEM_UNINITIALIZED" in issue for issue in machine.issues))
        self.assertEqual(machine.regs["rax"], 7)

    def test_full_initialization_has_no_warning(self) -> None:
        machine = self.run_code("sub rsp, 8\nmov qword [rsp], 7\nmov rax, [rsp]\nhlt")
        self.assertFalse(machine.issues)

    def test_stack_boundaries(self) -> None:
        machine = self.run_code("sub rsp, %d\npush rax" % STACK_SIZE)
        self.assert_fault(machine, "MEM_STACK")
        self.assertEqual(machine.regs["rsp"], STACK_TOP - STACK_SIZE)
        self.assert_fault(self.run_code("pop rax\nmov rbx, 7"), "MEM_STACK")
        self.assert_fault(self.run_code("sub rsp, %d" % (STACK_SIZE + 1)), "MEM_STACK")

    def test_stack_growth_counts_toward_budget(self) -> None:
        machine = self.run_code("buf resb 1048570\npush rax", max_memory=1)
        self.assert_fault(machine, "MEM_LIMIT")
        self.assertEqual(machine.regs["rsp"], STACK_TOP)

    def test_push_pop_does_not_leak_allocation(self) -> None:
        machine = self.run_code("mov rcx, 20\nagain:\npush rax\npop rbx\nloop again\nhlt")
        self.assertFalse(machine.issues)
        self.assertEqual(machine.memory.allocated, 8)

    def test_red_zone_and_low_stack_register(self) -> None:
        machine = self.run_code("mov qword [rsp - 128], 7\nmov rax, [rsp - 128]\nhlt")
        self.assertEqual(machine.regs["rax"], 7)
        self.assertFalse(machine.issues)
        self.assert_fault(self.run_code("mov byte [rsp - 129], 7"), "MEM_STACK")
        machine = self.run_code("sub rsp, 8\nmov spl, 0xf0\nhlt")
        self.assertFalse(machine.issues)
        self.assertEqual(machine.regs["rsp"], STACK_TOP - 16)

    def test_brk_growth_shrink_and_reallocation(self) -> None:
        machine = Machine(analyze("hlt"), max_memory=1)
        base = machine.heap_base
        for end in (base + 8, base, base + 8):
            machine.regs.update(rax=12, rdi=end)
            machine.do_syscall()
            self.assertEqual(machine.regs["rax"], end)
            self.assertEqual(machine.memory.allocated, end - base)
            if end == base:
                with self.assertRaises(MemoryFault):
                    machine.read_mem(base, 1)
            else:
                self.assertEqual(machine.peek8(base), 0)
                machine.write_mem(base, 8, 7)

    def test_brk_out_of_memory(self) -> None:
        machine = self.run_code(
            "mov rax, 12\nxor rdi, rdi\nsyscall\n" "lea rdi, [rax + 1048577]\nmov rax, 12\nsyscall",
            max_memory=1,
        )
        self.assert_fault(machine, "MEM_LIMIT")

    def test_syscall_and_api_buffer_bounds(self) -> None:
        calls = (
            "mov rax, 1\nlea rsi, [buf]\nmov rdx, 9\nsyscall",
            "mov rax, 0\nlea rsi, [buf]\nmov rdx, 9\nsyscall",
            "mov rax, 318\nlea rdi, [buf]\nmov rsi, 9\nsyscall",
            "lea rdx, [buf]\nmov r8, 9\ncall WriteConsoleA",
        )
        for call in calls:
            with self.subTest(call=call):
                machine = self.run_code("buf resb 8\n" + call, stdin="123456789")
                self.assert_fault(machine, "MEM_ACCESS")
                self.assertEqual(machine.output, "")
                self.assertEqual(machine.peek8(machine.symbols["buf"].addr), 0)

    def test_zero_length_io_needs_no_pointer(self) -> None:
        machine = self.run_code("mov rax, 1\nxor rsi, rsi\nxor rdx, rdx\nsyscall\nhlt")
        self.assertFalse(machine.issues)

    def test_random_syscall_reports_actual_short_count(self) -> None:
        machine = self.run_code(
            "buf resb 8192\nmov rax, 318\nlea rdi, [buf]\n" "mov rsi, 8192\nsyscall\nhlt"
        )
        self.assertEqual(machine.regs["rax"], 4096)
        self.assertFalse(machine.issues)

    def test_rep_faults_at_buffer_end(self) -> None:
        machine = self.run_code("buf resb 4\nlea rdi, [buf]\nmov al, 65\nmov rcx, 5\nrep stosb")
        self.assert_fault(machine, "MEM_ACCESS")
        self.assertEqual(machine.read_mem(machine.symbols["buf"].addr, 4), 0x41414141)

    def test_host_memory_error_is_terminal(self) -> None:
        machine = Machine(analyze("buf resb 8\nmov qword [buf], 1"))
        with patch.object(machine.memory, "store", side_effect=MemoryError):
            machine.step()
        self.assert_fault(machine, "MEM_HOST")
        self.assertTrue(machine.out_of_memory)
        with patch.object(
            Memory, "allocate", side_effect=[Memory(1).allocate(0, 0, "stack"), MemoryError()]
        ):
            machine = Machine(analyze("buf db 1"))
        self.assert_fault(machine, "MEM_HOST")

    def test_reset_clears_runtime_fault_and_usage(self) -> None:
        machine = self.run_code("push rax\nmov byte [0], 1")
        self.assert_fault(machine, "MEM_ACCESS")
        machine.reset()
        self.assertFalse(machine.halted)
        self.assertFalse(machine.issues)
        self.assertIsNone(machine.memory_fault)
        self.assertEqual(machine.memory.allocated, 0)

    def test_output_limit(self) -> None:
        machine = Machine(analyze("buf db 65\nmov rax, 1\nlea rsi, [buf]\n" "mov rdx, 1\nsyscall"))
        machine.output = "a" * (1 << 20)
        machine.run()
        self.assert_fault(machine, "MEM_OUTPUT")
        self.assertEqual(len(machine.output), 1 << 20)


class TestMemoryIntegration(unittest.TestCase):
    """Limits and diagnostics reach CLI, reports and scenarios."""

    def test_cli_limit_and_json_diagnostic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "large.asm"
            source.write_text("buffer resb 16777217\nmov rax, 7", encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(["run", str(source), "--max-memory", "16", "--json"])
            payload = json.loads(output.getvalue())
            self.assertEqual(status, 1)
            self.assertTrue(payload["out_of_memory"])
            self.assertEqual(payload["memory_fault"]["line"], 1)
            self.assertEqual(payload["memory"]["limit_bytes"], 16 << 20)
            self.assertEqual(payload["steps"], 0)

    def test_report_carries_load_failure(self) -> None:
        data = collect("buffer resb 1048577\nhlt", max_memory=1)
        self.assertTrue(data.execution["out_of_memory"])
        self.assertEqual(data.execution["memory_fault"]["code"], "MEM_LIMIT")
        self.assertEqual(data.execution["steps"], 0)
        self.assertIn("MEM_LIMIT", render_html(data))
        self.assertIn("MEM_LIMIT", render_markdown(data))
        self.assertIn("1048576", render_markdown(data))

    def test_report_inspection_does_not_create_execution_issues(self) -> None:
        data = collect("buf resb 8\nhlt")
        self.assertEqual(data.execution["issues"], [])

    def test_scenario_limit_and_invalid_initial_stack(self) -> None:
        expected = Scenario(name="allocation failure", expect_issue=True)
        result = run_scenario("x resb 1048577\nhlt", expected, max_memory=1)
        self.assertTrue(result.passed)
        self.assertEqual(result.steps, 0)
        invalid = Scenario(name="bad stack", regs={"rsp": 0}, expect_issue=True)
        result = run_scenario("hlt", invalid)
        self.assertTrue(result.passed)
        self.assertTrue(any("MEM_STACK" in issue for issue in result.issues))


if __name__ == "__main__":
    unittest.main()
