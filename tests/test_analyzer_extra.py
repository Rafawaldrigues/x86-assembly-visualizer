"""Edge tests of the analysis: platform, semantics, blocks and flow."""

import unittest

from asmx.analyzer import (
    Analysis,
    Block,
    Edge,
    Platform,
    Semantic,
    analyze,
    build_blocks,
    callers_of,
    detect_platform,
    functions,
    semantics_of,
)
from asmx.examples import EXAMPLES
from asmx.parser import parse

HELLO = EXAMPLES["linux-hello"]["code"]
FUNCTION_SAMPLE = EXAMPLES["linux-function"]["code"]


class TestPlatform(unittest.TestCase):
    """System, bits and ABI detection."""

    def test_linux_with_several_clues(self) -> None:
        platform = detect_platform(parse(HELLO))
        self.assertEqual(platform.os, "linux")
        self.assertGreater(platform.confidence, 80)
        self.assertIn("System V", platform.abi["name"])
        self.assertIn("RDI", platform.abi["notes"])

    def test_windows_by_the_api(self) -> None:
        platform = detect_platform(parse(EXAMPLES["windows-hello"]["code"]))
        self.assertEqual(platform.os, "windows")
        self.assertEqual(platform.abi["args"], ["rcx", "rdx", "r8", "r9"])
        self.assertIn("shadow space", platform.abi["notes"])

    def test_unknown(self) -> None:
        platform = detect_platform(parse("mov rax, 1\nadd rax, 2"))
        self.assertEqual(platform.os, "unknown")
        self.assertEqual(platform.confidence, 0)
        self.assertEqual(platform.evidence["linux"], [])

    def test_ambiguous(self) -> None:
        code = "call printf\nsub rsp, 40\n"
        platform = detect_platform(parse(code))
        self.assertEqual(platform.os, "ambiguous")
        self.assertEqual(platform.confidence, 35)

    def test_windows_clues(self) -> None:
        platform = detect_platform(parse("extern __imp_CreateFileA\nincludelib kernel32"))
        self.assertEqual(platform.os, "windows")
        self.assertTrue(platform.evidence["windows"])

    def test_bits_16(self) -> None:
        self.assertEqual(detect_platform(parse("bits 16\nmov ax, 1")).bits, 16)

    def test_bits_32(self) -> None:
        self.assertEqual(detect_platform(parse("bits 32\nmov eax, 1")).bits, 32)

    def test_use32_also_marks_32(self) -> None:
        self.assertEqual(detect_platform(parse("use32\nmov eax, 1")).bits, 32)

    def test_default_64(self) -> None:
        self.assertEqual(detect_platform(parse("mov rax, 1")).bits, 64)

    def test_dataclasses(self) -> None:
        platform = Platform(os="linux", confidence=50, bits=64, evidence={}, abi={})
        self.assertEqual(platform.bits, 64)
        self.assertEqual(Edge(1, "taken", "just because").kind, "taken")


class TestSemantics(unittest.TestCase):
    """Every instruction family gets an explanation."""

    def sem(self, code: str, index: int = -1) -> Semantic:
        """Semantics of the requested instruction (by index, from the end)."""
        return analyze(code).instrs[index].sem

    def sem_of(self, code: str, mnemonic: str) -> Semantic:
        """Semantics of the first instruction with this mnemonic."""
        for instruction in analyze(code).instrs:
            if instruction.mnemonic == mnemonic:
                return instruction.sem
        raise AssertionError("did not find %s in %r" % (mnemonic, code))

    def test_write_to_local_variable(self) -> None:
        code = "f:\n push rbp\n mov rbp, rsp\n mov [rbp - 8], rax"
        self.assertEqual(self.sem(code, 0).tag, "frame")
        self.assertIn("local variable", self.sem(code).detail)

    def test_read_of_parameter(self) -> None:
        self.assertIn("parameter", self.sem("f:\n mov rax, [rbp + 16]").detail)

    def test_memory_by_symbol(self) -> None:
        self.assertIn(
            "variable", self.sem("section .data\nx dq 0\nsection .text\n" "mov rax, [x]").detail
        )

    def test_memory_by_pointer(self) -> None:
        self.assertIn("address pointed to", self.sem("f:\n mov rax, [rbx]").detail)

    def test_copy_between_registers(self) -> None:
        sem = self.sem("mov rax, rbx")
        self.assertEqual(sem.tag, "copy")
        self.assertIn("copy", sem.detail)

    def test_address_of_symbol(self) -> None:
        sem = self.sem("section .data\nx dq 0\nsection .text\nmov rax, x")
        self.assertEqual(sem.label, "Sets address/symbol")

    def test_lea_computes_address(self) -> None:
        sem = self.sem("section .data\nx dq 0\nsection .text\nlea rax, [x]")
        self.assertEqual(sem.label, "Computes address")
        self.assertIn("&", sem.detail)

    def test_push_and_pop(self) -> None:
        self.assertEqual(self.sem("push rax").tag, "push")
        self.assertEqual(self.sem("pop rax").tag, "pop")

    def test_call_to_windows_api(self) -> None:
        sem = self.sem("extern ExitProcess\ncall ExitProcess")
        self.assertIn("Windows API", sem.detail)

    def test_call_to_external_function(self) -> None:
        self.assertIn("External", self.sem("extern printf\ncall printf").detail)

    def test_ret(self) -> None:
        self.assertIn("RAX", self.sem("ret").detail)

    def test_jmp(self) -> None:
        self.assertIn("Goes straight", self.sem("end:\njmp end").detail)

    def test_conditional_jump_cites_the_comparison(self) -> None:
        sem = self.sem_of("mov rax, 1\ncmp rax, 1\nje end\nend:\nret", "je")
        self.assertEqual(sem.label, "Jumps if equal")
        self.assertIn("cmp", sem.detail)

    def test_cmp_and_test(self) -> None:
        self.assertIn("only to update the flags", self.sem("cmp rax, rbx").detail)
        self.assertIn("is zero?", self.sem("test rax, rax").detail)

    def test_syscall_with_known_number(self) -> None:
        sem = self.sem("mov rax, 1\nsyscall")
        self.assertEqual(sem.syscall_name, "write")
        self.assertIn("RDI", sem.detail)

    def test_syscall_without_number(self) -> None:
        self.assertIn("service number is in RAX", self.sem("syscall").detail)

    def test_int_is_treated_as_syscall(self) -> None:
        self.assertEqual(self.sem("int 0x80").tag, "syscall")

    def test_simple_arithmetic(self) -> None:
        self.assertIn("rax = rax + 1", self.sem("inc rax").detail)
        self.assertIn("flips the sign", self.sem("neg rax").detail)
        self.assertIn("RDX:RAX", self.sem("mul rbx").detail)
        self.assertIn("quotient in RAX", self.sem("div rbx").detail)

    def test_multiplication_with_two_operands(self) -> None:
        self.assertIn("rax = rax * rbx", self.sem("imul rax, rbx").detail)

    def test_bits(self) -> None:
        self.assertIn("shortest way to zero it", self.sem("xor rax, rax").detail)
        self.assertIn("* 2^", self.sem("shl rax, 2").detail)
        self.assertIn("/ 2^", self.sem("shr rax, 2").detail)
        self.assertIn("flipped", self.sem("not rax").detail)
        self.assertIn("bit by bit", self.sem("or rax, rbx").detail)

    def test_setcc(self) -> None:
        self.assertEqual(self.sem("sete al").label, "Boolean of the condition")

    def test_leave_and_nop(self) -> None:
        self.assertIn("Restores RSP", self.sem("leave").detail)
        self.assertEqual(self.sem("nop").label, "Nothing")

    def test_known_instruction_without_specific_rule(self) -> None:
        self.assertTrue(self.sem("cpuid").detail)

    def test_unknown_instruction(self) -> None:
        self.assertEqual(self.sem("xyzzy rax").tag, "unknown")

    def test_prologue_and_epilogue(self) -> None:
        analysis = analyze("f:\n push rbp\n mov rbp, rsp\n pop rbp\n ret")
        self.assertEqual(analysis.instrs[0].sem.label, "Function prologue")
        self.assertEqual(analysis.instrs[1].sem.label, "Function prologue")
        self.assertEqual(analysis.instrs[2].sem.label, "Function epilogue")

    def test_numbered_arguments(self) -> None:
        analysis = analyze("f:\n ret\n_start:\n mov rdi, 1\n mov rsi, 2\n call f")
        call = [i for i in analysis.instrs if i.mnemonic == "call"][0]
        self.assertIn("argument 1", analysis.instrs[1].sem.detail)
        self.assertIn("argument 2", analysis.instrs[2].sem.detail)
        self.assertEqual(call.sem.tag, "call")

    def test_windows_arguments(self) -> None:
        analysis = analyze(
            "extern ExitProcess\nsection .text\nmain:\n mov rcx, 0\n" " call ExitProcess"
        )
        self.assertIn("argument 1", analysis.instrs[0].sem.detail)

    def test_semantics_of_line_without_operands(self) -> None:
        analysis = analyze("syscall")
        self.assertEqual(
            semantics_of(
                analysis.instrs[0],
                {
                    "platform": analysis.platform,
                    "symbols": {},
                    "pending_syscall": None,
                    "last_compare": None,
                    "syscall_ahead": False,
                },
            ).tag,
            "syscall",
        )


class TestBlocks(unittest.TestCase):
    """Basic blocks, edges and exit reasons."""

    def test_single_block(self) -> None:
        blocks, label_at = build_blocks(parse("mov rax, 1\nmov rbx, 2"))
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0].name, "start")
        self.assertEqual(blocks[0].exit, "end of code")
        self.assertEqual(label_at, {})

    def test_ret_ends_the_block(self) -> None:
        blocks, _ = build_blocks(parse("f:\n mov rax, 1\n ret"))
        self.assertEqual(blocks[-1].exit, "returns to the caller")

    def test_exit_syscall_ends_the_block(self) -> None:
        self.assertTrue(any(b.exit == "terminates the process" for b in analyze(HELLO).blocks))

    def test_missing_semantics_falls_back_to_end_of_code(self) -> None:
        blocks, _ = build_blocks(parse("mov rax, 60\nsyscall"))
        self.assertIsNone(blocks[0].instrs[-1].sem)
        self.assertEqual(blocks[0].exit, "end of code")

    def test_call_to_exitprocess_ends_the_block(self) -> None:
        blocks, _ = build_blocks(parse("extern ExitProcess\nmain:\n call ExitProcess"))
        self.assertEqual(blocks[-1].exit, "terminates the process")

    def test_jump_outside_the_code(self) -> None:
        blocks, _ = build_blocks(parse("jmp nowhere"))
        self.assertIn("outside the loaded code", blocks[0].exit)

    def test_branch_edges(self) -> None:
        blocks, label_at = build_blocks(
            parse("f:\n cmp rax, 1\n je end\n mov rbx, 1\n" "end:\n ret")
        )
        self.assertIn("end", label_at)
        kinds = {e.kind for b in blocks for e in b.succ}
        self.assertIn("taken", kinds)
        self.assertIn("fallthrough", kinds)

    def test_unconditional_edge(self) -> None:
        blocks, _ = build_blocks(parse("a:\n jmp b\nb:\n ret"))
        self.assertTrue(any(e.kind == "jmp" for e in blocks[0].succ))

    def test_continuation_block_has_a_name(self) -> None:
        blocks, _ = build_blocks(parse("f:\n cmp rax, 1\n je f\n mov rbx, 1\n mov rcx, 2"))
        self.assertTrue(any(b.name.startswith("continuation") for b in blocks))

    def test_block_calls(self) -> None:
        blocks, _ = build_blocks(parse("f:\n ret\n_start:\n call f"))
        self.assertIn("f", blocks[-1].calls)

    def test_predecessors(self) -> None:
        blocks, _ = build_blocks(parse("a:\n cmp rax, 1\n je a\n ret"))
        self.assertTrue(blocks[0].pred)
        self.assertEqual(blocks[0].pred[0].kind, "taken")

    def test_block_dataclass(self) -> None:
        block = Block(id=0, start=0, end=1, name="x", func=None)
        self.assertEqual(block.instrs, [])
        self.assertIsNone(block.exit)


class TestQueries(unittest.TestCase):
    """Support functions used by the interface."""

    def test_callers_of_with_call(self) -> None:
        analysis = analyze(FUNCTION_SAMPLE)
        call = [i for i in analysis.instrs if i.mnemonic == "call"][0]
        name = call.operands[0].symbol or call.operands[0].text
        callers = callers_of(analysis, name)
        self.assertTrue(callers)
        self.assertTrue(all("(line " in caller for caller in callers))

    def test_callers_of_with_jump(self) -> None:
        analysis = analyze("_start:\n jmp target\ntarget:\n ret")
        self.assertTrue(any("jump from" in c for c in callers_of(analysis, "target")))

    def test_callers_of_without_callers(self) -> None:
        self.assertEqual(callers_of(analyze("f:\n ret"), "f"), [])

    def test_functions(self) -> None:
        self.assertIn("add_pair", functions(analyze(FUNCTION_SAMPLE)))
        self.assertEqual(functions(analyze("mov rax, 1")), [])

    def test_stats(self) -> None:
        analysis = analyze(
            "section .data\nx dq 0\nsection .text\nf:\n mov rax, [x]\n"
            " xyzzy rax\n syscall\n call f\n ret"
        )
        self.assertEqual(analysis.stats["instructions"], 5)
        self.assertEqual(analysis.stats["syscalls"], 1)
        self.assertEqual(analysis.stats["calls"], 1)
        self.assertEqual(analysis.stats["unknown"], ["xyzzy"])
        self.assertEqual(analysis.stats["labels"], 1)

    def test_symbols_of_the_analysis(self) -> None:
        analysis = analyze("section .data\nx dq 1")
        self.assertIn("x", analysis.symbols)

    def test_label_index(self) -> None:
        analysis = analyze("a:\n mov rax, 1\nb:\n mov rbx, 2")
        self.assertEqual(analysis.label_at, {"a": 0, "b": 1})

    def test_instructions_get_index_and_block(self) -> None:
        analysis = analyze("mov rax, 1\nmov rbx, 2")
        self.assertEqual(analysis.instrs[0].idx, 0)
        self.assertEqual(analysis.instrs[0].block, 0)

    def test_analysis_dataclass(self) -> None:
        analysis = analyze("nop")
        self.assertIsInstance(analysis, Analysis)
        self.assertIsInstance(analysis.blocks[0], Block)

    def test_empty_program(self) -> None:
        analysis = analyze("")
        self.assertEqual(analysis.stats["instructions"], 0)
        self.assertEqual(analysis.blocks, [])


if __name__ == "__main__":
    unittest.main()
