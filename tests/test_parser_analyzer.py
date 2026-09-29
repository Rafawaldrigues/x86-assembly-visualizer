"""Tests of the parser and the analyzer: reading, semantics, platform and flow."""

import unittest

from asmx.analyzer import analyze, callers_of
from asmx.examples import EXAMPLES
from asmx.parser import classify_operand, parse, parse_number, strip_comment


class TestParser(unittest.TestCase):
    """Number, operand, label and data declaration reading."""

    def test_strip_comment_keeps_the_semicolon_inside_a_string(self) -> None:
        """A `;` inside quotes belongs to the string, it does not open a comment."""
        body, comment = strip_comment('    db "a;b", 10   ; this is a comment')
        self.assertIn('"a;b"', body)
        self.assertTrue(comment.startswith("; this"))

    def test_numbers_in_several_bases(self) -> None:
        """Decimal, hexadecimal (0x and h) and binary literals are all understood."""
        self.assertEqual(parse_number("10"), 10)
        self.assertEqual(parse_number("0x10"), 16)
        self.assertEqual(parse_number("10h"), 16)
        self.assertEqual(parse_number("1010b"), 10)
        self.assertEqual(parse_number("-5"), -5)

    def test_operand_classification(self) -> None:
        """Register, immediate, symbol and memory operands get the right type."""
        self.assertEqual(classify_operand("rax").type, "reg")
        self.assertEqual(classify_operand("42").type, "imm")
        self.assertEqual(classify_operand("msg").type, "sym")
        mem = classify_operand("qword [rbx + rcx*4 + 8]")
        self.assertEqual(mem.type, "mem")
        self.assertEqual(mem.size, 8)
        self.assertIn("rbx", mem.regs)
        self.assertIn("rcx", mem.regs)

    def test_label_and_instruction_on_the_same_line(self) -> None:
        """`label: mov ...` becomes two lines: one label and one instruction."""
        p = parse("entry: mov rax, 1")
        kinds = [line.kind for line in p.lines if line.kind != "empty"]
        self.assertEqual(kinds, ["label", "instruction"])

    def test_local_label_does_not_change_the_function(self) -> None:
        """A `.loop`-style local label stays inside the function that owns it."""
        p = parse("func:\n  mov rax, 1\n.loop:\n  dec rax\n  jnz .loop\n  ret")
        self.assertTrue(all(line.func == "func" for line in p.instructions))

    def test_data_declaration(self) -> None:
        """`db` counts units and `resb` reserves space without initializing it."""
        p = parse('section .data\nmsg db "hi", 10\nbuf resb 64')
        data = [line for line in p.lines if line.kind == "data"]
        self.assertEqual(data[0].label, "msg")
        self.assertEqual(data[0].unit, 1)
        self.assertTrue(data[1].reserve)
        self.assertEqual(p.symbols["msg"]["type"], "data")

    def test_att_is_normalized_to_intel(self) -> None:
        """AT&T source comes out with Intel order, without the `%` and `$` sigils."""
        p = parse("movq %rsp, %rbp\naddl $10, -4(%rbp)")
        self.assertEqual(p.flavor, "att")
        instrs = p.instructions
        self.assertEqual(instrs[0].mnemonic, "mov")
        self.assertEqual(instrs[0].operands[0].reg, "rbp")  # destination first
        self.assertEqual(instrs[0].operands[1].reg, "rsp")
        self.assertEqual(instrs[1].mnemonic, "add")
        self.assertEqual(instrs[1].operands[0].type, "mem")

    def test_masm_proc(self) -> None:
        """`PROC`/`ENDP` mark the function and its extent in MASM syntax."""
        p = parse("main PROC\n  mov rax, 1\n  ret\nmain ENDP")
        self.assertEqual(p.flavor, "masm")
        self.assertIn("main", p.symbols)
        self.assertEqual(p.instructions[0].func, "main")


class TestAnalyzer(unittest.TestCase):
    """Platform detection, semantic labels, blocks, callers and statistics."""

    def test_platform_linux(self) -> None:
        """The Linux example is detected as System V AMD64 with Linux evidence."""
        a = analyze(EXAMPLES["linux-hello"]["code"])
        self.assertEqual(a.platform.os, "linux")
        self.assertGreater(a.platform.confidence, 60)
        self.assertTrue(a.platform.evidence["linux"])
        self.assertEqual(a.platform.abi["name"], "System V AMD64")

    def test_platform_windows(self) -> None:
        """The Windows example follows the Microsoft ABI: 1st argument in RCX."""
        a = analyze(EXAMPLES["windows-hello"]["code"])
        self.assertEqual(a.platform.os, "windows")
        self.assertEqual(a.platform.abi["args"][0], "rcx")

    def test_platform_unknown_when_nothing_points_to_an_os(self) -> None:
        """Code with no syscall and no entry point is `unknown` with zero confidence."""
        a = analyze("mov rax, 1\nadd rax, 2\nret")
        self.assertEqual(a.platform.os, "unknown")
        self.assertEqual(a.platform.confidence, 0)

    def test_semantics_recognize_write_and_read(self) -> None:
        """`mov [x], rax` is a store, `mov rbx, [x]` a load and `lea` an address."""
        a = analyze(
            "section .data\nx dq 0\nsection .text\n" "mov [x], rax\nmov rbx, [x]\nlea rsi, [x]"
        )
        tags = [i.sem.tag for i in a.instrs]
        self.assertEqual(tags, ["store", "load", "addr"])
        self.assertIn("x = rax", a.instrs[0].sem.detail)

    def test_syscall_semantics_resolves_the_name(self) -> None:
        """The number in RAX before a SYSCALL becomes the syscall name."""
        a = analyze("mov rax, 1\nmov rdi, 1\nsyscall")
        self.assertEqual(a.instrs[-1].sem.syscall_name, "write")
        self.assertIn("write", a.instrs[-1].sem.detail)

    def test_prologue_is_detected(self) -> None:
        """`push rbp` plus `mov rbp, rsp` is the prologue and `pop rbp` the epilogue."""
        a = analyze("f:\n push rbp\n mov rbp, rsp\n pop rbp\n ret")
        self.assertEqual(a.instrs[0].sem.label, "Function prologue")
        self.assertEqual(a.instrs[2].sem.label, "Function epilogue")

    def test_arguments_do_not_leak_between_functions(self) -> None:
        """Argument setup annotated for `add_pair` does not stick to another function."""
        a = analyze(EXAMPLES["linux-function"]["code"])
        itoa = [i for i in a.instrs if i.func == "itoa"]
        start = [i for i in a.instrs if i.func == "_start"]
        self.assertTrue(itoa)
        self.assertTrue(any("argument 1 of the call to add_pair" in i.sem.detail for i in start))
        self.assertFalse(any("of the call to add_pair" in i.sem.detail for i in itoa))

    def test_blocks_and_flow(self) -> None:
        """`.loop` is a block with a predecessor and a taken exit back to itself."""
        a = analyze(EXAMPLES["linux-loop"]["code"])
        names = [b.name for b in a.blocks]
        self.assertIn(".loop", names)
        self.assertIn("continuation of .loop", names)
        loop = next(b for b in a.blocks if b.name == ".loop")
        self.assertTrue(loop.pred, "the loop block must have predecessors")
        self.assertTrue(any(e.kind == "taken" for e in loop.succ))

    def test_block_exit_describes_how_the_block_ends(self) -> None:
        """A block that calls exit ends the process and one that returns goes back."""
        loop = analyze(EXAMPLES["linux-loop"]["code"])
        done = next(b for b in loop.blocks if b.name == ".done")
        self.assertEqual(done.exit, "terminates the process")
        func = analyze("f:\n  ret")
        self.assertEqual(func.blocks[0].exit, "returns to the caller")

    def test_callers_of_lists_the_callers(self) -> None:
        """Every CALL to `add_pair` shows up as `function (line N)`."""
        a = analyze(EXAMPLES["linux-function"]["code"])
        callers = callers_of(a, "add_pair")
        self.assertTrue(callers)
        self.assertTrue(all(c.startswith("_start (line ") for c in callers))

    def test_callers_of_reports_a_jump_with_its_line(self) -> None:
        """A jump target is reported as `jump from line N`, without a function name."""
        a = analyze("f:\n  jmp .done\n.done:\n  ret")
        self.assertEqual(callers_of(a, ".done"), ["jump from line 2"])

    def test_statistics(self) -> None:
        """The counters agree with the instructions and no mnemonic is unknown."""
        a = analyze(EXAMPLES["bubble"]["code"])
        self.assertEqual(a.stats["instructions"], len(a.instrs))
        self.assertEqual(a.stats["unknown"], [])
        self.assertGreater(a.stats["blocks"], 3)

    def test_empty_code_does_not_break(self) -> None:
        """An empty source yields an empty analysis instead of an exception."""
        a = analyze("")
        self.assertEqual(a.instrs, [])
        self.assertEqual(a.blocks, [])


if __name__ == "__main__":
    unittest.main()
