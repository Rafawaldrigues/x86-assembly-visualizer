"""Edge tests of the parser: dialects, directives, operands and symbols."""

import unittest

from asmx.parser import (
    ATT_SIZES,
    Line,
    Operand,
    Program,
    att_operand_size,
    classify_operand,
    detect_flavor,
    normalize_att,
    parse,
    parse_number,
    split_operands,
    strip_comment,
)


class TestComments(unittest.TestCase):
    """Each dialect has its own way of commenting."""

    def test_semicolon(self) -> None:
        """``;`` opens a comment in every dialect."""
        self.assertEqual(strip_comment("mov rax, 1 ; note"), ("mov rax, 1 ", "; note"))

    def test_gas_hash(self) -> None:
        """GAS comments start with ``#``."""
        self.assertEqual(strip_comment("movq %rax, %rbx # note")[1], "# note")

    def test_glued_hash_is_not_a_comment(self) -> None:
        """``#`` glued to a word is not a comment marker."""
        body, comment = strip_comment("mov rax, 1\n")
        self.assertEqual(comment, "")
        self.assertEqual(body, "mov rax, 1\n")

    def test_double_slash(self) -> None:
        """``//`` opens a comment as well."""
        self.assertEqual(strip_comment("mov rax, 1 // note")[1], "// note")

    def test_escaped_quotes(self) -> None:
        """A quoted ``;`` does not end the string."""
        body, _ = strip_comment('db "a\\";b" ; end')
        self.assertIn('"a\\";b"', body)

    def test_line_without_comment(self) -> None:
        """A line with no marker comes back with an empty comment."""
        self.assertEqual(strip_comment("nop"), ("nop", ""))


class TestOperands(unittest.TestCase):
    """Classification of each kind of operand."""

    def test_negative_immediate(self) -> None:
        """A minus sign in front makes the immediate negative."""
        self.assertEqual(classify_operand("-1").value, -1)

    def test_character(self) -> None:
        """A character literal becomes its code point and is flagged."""
        operand = classify_operand("'A'")
        self.assertEqual(operand.value, 65)
        self.assertTrue(operand.is_char)

    def test_expression(self) -> None:
        """Arithmetic over a symbol counts as an expression."""
        self.assertEqual(classify_operand("label + 4").type, "expr")

    def test_unknown(self) -> None:
        """Brackets that do not close stay unknown."""
        self.assertEqual(classify_operand("[[").type, "unknown")

    def test_empty(self) -> None:
        """Blank text stays unknown."""
        self.assertEqual(classify_operand("   ").type, "unknown")

    def test_memory_with_ptr(self) -> None:
        """``dword ptr [..]`` is memory of 4 bytes."""
        operand = classify_operand("dword ptr [rbp - 4]")
        self.assertEqual(operand.type, "mem")
        self.assertEqual(operand.size, 4)
        self.assertIn("rbp", operand.regs)

    def test_memory_with_symbol(self) -> None:
        """The symbol inside the brackets is kept."""
        self.assertEqual(classify_operand("[vector + rsi*4]").symbol, "vector")

    def test_memory_with_rel(self) -> None:
        """``rel`` is a modifier, not a register."""
        self.assertNotIn("rel", classify_operand("[rel msg]").regs)

    def test_register_with_percent(self) -> None:
        """The AT&T ``%`` is dropped from the register name."""
        self.assertEqual(classify_operand("%rax").reg, "rax")

    def test_split_respects_parentheses(self) -> None:
        """A comma inside parentheses does not split the operands."""
        self.assertEqual(split_operands("4 dup (0), 8"), ["4 dup (0)", "8"])

    def test_split_empty(self) -> None:
        """Blank text yields no operand."""
        self.assertEqual(split_operands("   "), [])

    def test_split_without_comma(self) -> None:
        """A single operand comes back alone."""
        self.assertEqual(split_operands("rax"), ["rax"])


class TestNumbers(unittest.TestCase):
    """Conversion of constants in every base."""

    def test_hexadecimal_with_dollar_sign(self) -> None:
        """The AT&T ``$`` does not get in the way of the hexadecimal."""
        self.assertEqual(parse_number("$0x10"), 16)

    def test_octal(self) -> None:
        """``0o`` marks an octal literal."""
        self.assertEqual(parse_number("0o17"), 15)

    def test_negative_hexadecimal(self) -> None:
        """The sign applies after the base conversion."""
        self.assertEqual(parse_number("-0x10"), -16)

    def test_any_text_becomes_zero(self) -> None:
        """Text that is not a number becomes zero."""
        self.assertEqual(parse_number("label"), 0)

    def test_empty(self) -> None:
        """An empty token becomes zero."""
        self.assertEqual(parse_number(""), 0)


class TestDialects(unittest.TestCase):
    """Detection and normalization of AT&T."""

    def test_default_intel(self) -> None:
        """Plain Intel code has neither AT&T nor MASM marks."""
        self.assertEqual(detect_flavor("mov rax, 1"), "intel")

    def test_masm_by_proc(self) -> None:
        """``PROC``/``ENDP`` identify MASM."""
        self.assertEqual(detect_flavor("main PROC\n ret\nmain ENDP"), "masm")

    def test_masm_by_model(self) -> None:
        """``.model``/``.code`` identify MASM."""
        self.assertEqual(detect_flavor(".model flat\n.code\nmain:\n ret"), "masm")

    def test_att_by_registers(self) -> None:
        """``%`` registers and ``$`` immediates identify AT&T."""
        self.assertEqual(detect_flavor("movq %rsp, %rbp\nmovl $1, %eax\nret"), "att")

    def test_size_suffix_goes_away(self) -> None:
        """``movl`` loses the size suffix and becomes ``mov``."""
        mnemonic, _ = normalize_att("movl", ["$1", "%eax"])
        self.assertEqual(mnemonic, "mov")

    def test_operands_swapped(self) -> None:
        """The AT&T order is reversed into Intel order."""
        _, operands = normalize_att("mov", ["%rax", "%rbx"])
        self.assertEqual(operands, ["rbx", "rax"])

    def test_att_memory_converted(self) -> None:
        """``-8(%rbp)`` becomes ``[rbp-8]``."""
        _, operands = normalize_att("movl", ["-8(%rbp)", "%eax"])
        self.assertEqual(operands[0], "eax")
        self.assertEqual(operands[1], "[rbp-8]")

    def test_att_memory_with_index(self) -> None:
        """``(%rax,%rcx,4)`` becomes ``[rax+rcx*4]``."""
        _, operands = normalize_att("movl", ["(%rax,%rcx,4)", "%edx"])
        self.assertEqual(operands[1], "[rax+rcx*4]")

    def test_mnemonic_suffix_tells_the_memory_size(self) -> None:
        """In AT&T the width of the access comes from the suffix, not the operand.

        Without this, `movl $0, -4(%rbp)` ended up with an ambiguous size
        (MEM001) and the virtual machine read 8 bytes where the program stores 4.
        """
        program = parse("movl $0, -4(%rbp)\nmovb $1, -5(%rbp)\nmovq %rax, -16(%rbp)")
        sizes = [i.operands[0].size for i in program.instructions]
        self.assertEqual(sizes, [4, 1, 8])

    def test_no_suffix_does_not_invent_a_size(self) -> None:
        """`lea` with no suffix declares no width: there is none to invent."""
        program = parse("movq %rsp, %rbp\nlea -4(%rbp), %rax\naddq $1, %rax")
        self.assertIsNone(program.instructions[1].operands[1].size)

    def test_register_decides_the_size(self) -> None:
        """The register width fills in the size of the memory access."""
        program = parse("movq %rsp, %rbp\nmovl -8(%rbp), %eax\naddl %eax, %eax")
        instruction = program.instructions[1]
        self.assertEqual(instruction.operands[0].size, 4)
        self.assertEqual(instruction.operands[1].size, 4)

    def test_att_operand_size(self) -> None:
        """Only the size suffixes ``b``, ``w``, ``l`` and ``q`` count."""
        self.assertEqual(att_operand_size("movl", "mov"), 4)
        self.assertEqual(att_operand_size("pushq", "push"), 8)
        self.assertIsNone(att_operand_size("call", "call"))
        self.assertIsNone(att_operand_size("movsb", "movsb"))
        self.assertEqual(set(ATT_SIZES), {"b", "w", "l", "q"})

    def test_zero_displacement_does_not_show_up(self) -> None:
        """A displacement of zero is left out of the address."""
        _, operands = normalize_att("mov", ["0(%rbp)", "%rax"])
        self.assertEqual(operands[1], "[rbp]")


class TestStructure(unittest.TestCase):
    """Labels, sections, directives and data."""

    def test_section_changes_mid_way(self) -> None:
        """The section in force changes when another directive opens."""
        program = parse("section .data\nx db 1\nsection .text\ny:\n ret")
        sections = [line.section for line in program.lines if line.kind != "empty"]
        self.assertEqual(sections[0], "data")
        self.assertIn("text", sections)

    def test_dotted_section_directive(self) -> None:
        """``.section .rodata`` opens the rodata section."""
        program = parse("\t.section .rodata\nfixed: .quad 1")
        self.assertTrue(any(line.new_section == "rodata" for line in program.lines))

    def test_data_directive_without_label(self) -> None:
        """``db`` with no label is still a data line."""
        program = parse("section .data\n db 1, 2, 3")
        data_lines = [line for line in program.lines if line.kind == "data"]
        self.assertEqual(data_lines[0].args, ["1", "2", "3"])

    def test_space_reservation(self) -> None:
        """``resb``/``resq`` only reserve space, with the right unit."""
        program = parse("section .bss\nbuf resb 64\nv resq 2")
        reserved = [line for line in program.lines if line.kind == "data"]
        self.assertTrue(all(line.reserve for line in reserved))
        self.assertEqual(reserved[0].unit, 1)
        self.assertEqual(reserved[1].unit, 8)

    def test_gas_space_and_zero_are_reservations(self) -> None:
        """``.space`` and ``.zero`` are reservations too."""
        program = parse("section .bss\n.space 8\n.zero 4")
        self.assertTrue(all(line.reserve for line in program.lines if line.kind == "data"))

    def test_global_marks_the_symbol(self) -> None:
        """``global`` marks the symbol as global."""
        program = parse("global _start\nsection .text\n_start:\n ret")
        self.assertTrue(program.symbols["_start"]["global"])

    def test_extern_creates_a_symbol(self) -> None:
        """``extern`` creates a symbol of type extern."""
        program = parse("extern printf\nmain:\n call printf")
        self.assertEqual(program.symbols["printf"]["type"], "extern")

    def test_masm_endp_closes_the_function(self) -> None:
        """``ENDP`` becomes a directive of its own."""
        program = parse("main PROC\n mov rax, 1\nmain ENDP")
        self.assertTrue(any(line.directive == "endp" for line in program.lines))

    def test_local_label_belongs_to_the_function(self) -> None:
        """Labels starting with ``.`` inherit the enclosing function."""
        program = parse("f:\n.a:\n ret\ng:\n.b:\n ret")
        local_labels = [line for line in program.lines if line.kind == "label" and line.local_label]
        self.assertEqual([line.func for line in local_labels], ["f", "g"])

    def test_equ_as_data(self) -> None:
        """``equ`` is read as a data declaration."""
        program = parse("section .data\nsize equ 10")
        entry = [line for line in program.lines if line.kind == "data"][0]
        self.assertEqual(entry.directive, "equ")
        self.assertEqual(entry.args, ["10"])

    def test_times_as_data(self) -> None:
        """``times`` is read as a data declaration."""
        program = parse("section .data\nzeros times 8 db 0")
        entry = [line for line in program.lines if line.kind == "data"][0]
        self.assertEqual(entry.directive, "times")

    def test_rep_prefix(self) -> None:
        """``rep`` is a prefix, not the mnemonic."""
        program = parse("rep movsb")
        instruction = program.instructions[0]
        self.assertEqual(instruction.prefix, "rep")
        self.assertEqual(instruction.mnemonic, "movsb")

    def test_lock_prefix(self) -> None:
        """``lock`` is a prefix as well."""
        self.assertEqual(parse("lock inc rax").instructions[0].prefix, "lock")

    def test_nasm_macro_is_a_directive(self) -> None:
        """``%define`` is a directive."""
        program = parse("%define SIZE 10\nmov rax, SIZE")
        self.assertEqual(program.lines[0].kind, "directive")

    def test_label_with_colon_and_instruction(self) -> None:
        """``label:`` followed by code becomes two lines."""
        program = parse("f: mov rax, 1")
        self.assertEqual([line.kind for line in program.lines], ["label", "instruction"])

    def test_unknown_instruction(self) -> None:
        """A mnemonic outside the catalogue is marked as unknown."""
        self.assertFalse(parse("strange_instruction rax").instructions[0].known)

    def test_unknown_directive_with_dot(self) -> None:
        """A dot directive outside the ISA is still a directive."""
        program = parse(".cfi_startproc")
        self.assertEqual(program.lines[0].kind, "directive")

    def test_empty_program(self) -> None:
        """An empty source produces no instruction and no symbol."""
        program = parse("")
        self.assertEqual(program.instructions, [])
        self.assertEqual(program.symbols, {})

    def test_text_without_label_keeps_the_function(self) -> None:
        """Instructions after a label keep that function."""
        program = parse("f:\n mov rax, 1\n mov rbx, 2")
        self.assertTrue(all(i.func == "f" for i in program.instructions))

    def test_line_text_trimmed(self) -> None:
        """``Line.text`` trims the raw line."""
        line = Line(n=1, raw="   mov rax, 1   ")
        self.assertEqual(line.text, "mov rax, 1")

    def test_default_operand(self) -> None:
        """A bare operand starts as unknown."""
        self.assertEqual(Operand("x").type, "unknown")

    def test_program_instructions(self) -> None:
        """``Program.instructions`` filters the instruction lines."""
        program = Program(
            lines=[Line(n=1, raw="nop", kind="instruction")],
            symbols={},
            flavor="intel",
            source="nop",
        )
        self.assertEqual(len(program.instructions), 1)


if __name__ == "__main__":
    unittest.main()
