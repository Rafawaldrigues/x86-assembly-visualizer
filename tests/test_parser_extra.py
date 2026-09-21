"""Testes de canto do parser: dialetos, diretivas, operandos e símbolos."""

import unittest

from asmx.parser import (
    Line,
    Operand,
    Program,
    classify_operand,
    detect_flavor,
    normalize_att,
    parse,
    parse_number,
    split_operands,
    strip_comment,
)


class TestComentarios(unittest.TestCase):
    """Cada dialeto comenta de um jeito."""

    def test_ponto_e_virgula(self) -> None:
        self.assertEqual(strip_comment("mov rax, 1 ; nota"), ("mov rax, 1 ", "; nota"))

    def test_cerquilha_do_gas(self) -> None:
        self.assertEqual(strip_comment("movq %rax, %rbx # nota")[1], "# nota")

    def test_cerquilha_colada_nao_e_comentario(self) -> None:
        corpo, comentario = strip_comment("mov rax, 1\n")
        self.assertEqual(comentario, "")
        self.assertEqual(corpo, "mov rax, 1\n")

    def test_barra_barra(self) -> None:
        self.assertEqual(strip_comment("mov rax, 1 // nota")[1], "// nota")

    def test_aspas_escapadas(self) -> None:
        corpo, _ = strip_comment('db "a\\";b" ; fim')
        self.assertIn('"a\\";b"', corpo)

    def test_linha_sem_comentario(self) -> None:
        self.assertEqual(strip_comment("nop"), ("nop", ""))


class TestOperandos(unittest.TestCase):
    """Classificação de cada tipo de operando."""

    def test_imediato_negativo(self) -> None:
        self.assertEqual(classify_operand("-1").value, -1)

    def test_caractere(self) -> None:
        operando = classify_operand("'A'")
        self.assertEqual(operando.value, 65)
        self.assertTrue(operando.is_char)

    def test_expressao(self) -> None:
        self.assertEqual(classify_operand("rotulo + 4").type, "expr")

    def test_desconhecido(self) -> None:
        self.assertEqual(classify_operand("[[").type, "unknown")

    def test_vazio(self) -> None:
        self.assertEqual(classify_operand("   ").type, "unknown")

    def test_memoria_com_ptr(self) -> None:
        operando = classify_operand("dword ptr [rbp - 4]")
        self.assertEqual(operando.type, "mem")
        self.assertEqual(operando.size, 4)
        self.assertIn("rbp", operando.regs)

    def test_memoria_com_simbolo(self) -> None:
        self.assertEqual(classify_operand("[vetor + rsi*4]").symbol, "vetor")

    def test_memoria_com_rel(self) -> None:
        self.assertNotIn("rel", classify_operand("[rel msg]").regs)

    def test_registrador_com_porcento(self) -> None:
        self.assertEqual(classify_operand("%rax").reg, "rax")

    def test_split_respeita_parenteses(self) -> None:
        self.assertEqual(split_operands("4 dup (0), 8"), ["4 dup (0)", "8"])

    def test_split_vazio(self) -> None:
        self.assertEqual(split_operands("   "), [])

    def test_split_sem_virgula(self) -> None:
        self.assertEqual(split_operands("rax"), ["rax"])


class TestNumeros(unittest.TestCase):
    """Conversão de constantes em todas as bases."""

    def test_hexadecimal_com_cifrao(self) -> None:
        self.assertEqual(parse_number("$0x10"), 16)

    def test_octal(self) -> None:
        self.assertEqual(parse_number("0o17"), 15)

    def test_negativo_hexadecimal(self) -> None:
        self.assertEqual(parse_number("-0x10"), -16)

    def test_texto_qualquer_vira_zero(self) -> None:
        self.assertEqual(parse_number("rotulo"), 0)

    def test_vazio(self) -> None:
        self.assertEqual(parse_number(""), 0)


class TestDialetos(unittest.TestCase):
    """Detecção e normalização de AT&T."""

    def test_intel_padrao(self) -> None:
        self.assertEqual(detect_flavor("mov rax, 1"), "intel")

    def test_masm_pelo_proc(self) -> None:
        self.assertEqual(detect_flavor("main PROC\n ret\nmain ENDP"), "masm")

    def test_masm_pelo_model(self) -> None:
        self.assertEqual(detect_flavor(".model flat\n.code\nmain:\n ret"), "masm")

    def test_att_pelos_registradores(self) -> None:
        self.assertEqual(detect_flavor("movq %rsp, %rbp\nmovl $1, %eax\nret"), "att")

    def test_sufixo_de_tamanho_sai(self) -> None:
        mnemonic, _ = normalize_att("movl", ["$1", "%eax"])
        self.assertEqual(mnemonic, "mov")

    def test_operandos_invertidos(self) -> None:
        _, operands = normalize_att("mov", ["%rax", "%rbx"])
        self.assertEqual(operands, ["rbx", "rax"])

    def test_memoria_att_convertida(self) -> None:
        _, operands = normalize_att("movl", ["-8(%rbp)", "%eax"])
        self.assertEqual(operands[0], "eax")
        self.assertEqual(operands[1], "[rbp-8]")

    def test_memoria_att_com_indice(self) -> None:
        _, operands = normalize_att("movl", ["(%rax,%rcx,4)", "%edx"])
        self.assertEqual(operands[1], "[rax+rcx*4]")

    def test_deslocamento_zero_nao_aparece(self) -> None:
        _, operands = normalize_att("mov", ["0(%rbp)", "%rax"])
        self.assertEqual(operands[1], "[rbp]")


class TestEstrutura(unittest.TestCase):
    """Rótulos, seções, diretivas e dados."""

    def test_secao_muda_no_meio(self) -> None:
        programa = parse("section .data\nx db 1\nsection .text\ny:\n ret")
        secoes = [linha.section for linha in programa.lines if linha.kind != "empty"]
        self.assertEqual(secoes[0], "data")
        self.assertIn("text", secoes)

    def test_diretiva_section_com_ponto(self) -> None:
        programa = parse("\t.section .rodata\nfixo: .quad 1")
        self.assertTrue(any(linha.new_section == "rodata" for linha in programa.lines))

    def test_diretiva_data_sem_rotulo(self) -> None:
        programa = parse("section .data\n db 1, 2, 3")
        dados = [linha for linha in programa.lines if linha.kind == "data"]
        self.assertEqual(dados[0].args, ["1", "2", "3"])

    def test_reserva_de_espaco(self) -> None:
        programa = parse("section .bss\nbuf resb 64\nv resq 2")
        reservas = [linha for linha in programa.lines if linha.kind == "data"]
        self.assertTrue(all(linha.reserve for linha in reservas))
        self.assertEqual(reservas[0].unit, 1)
        self.assertEqual(reservas[1].unit, 8)

    def test_espaco_e_zero_do_gas_sao_reserva(self) -> None:
        programa = parse("section .bss\n.space 8\n.zero 4")
        self.assertTrue(all(linha.reserve for linha in programa.lines if linha.kind == "data"))

    def test_global_marca_simbolo(self) -> None:
        programa = parse("global _start\nsection .text\n_start:\n ret")
        self.assertTrue(programa.symbols["_start"]["global"])

    def test_extern_cria_simbolo(self) -> None:
        programa = parse("extern printf\nmain:\n call printf")
        self.assertEqual(programa.symbols["printf"]["type"], "extern")

    def test_masm_endp_fecha_funcao(self) -> None:
        programa = parse("main PROC\n mov rax, 1\nmain ENDP")
        self.assertTrue(any(linha.directive == "endp" for linha in programa.lines))

    def test_rotulo_local_pertence_a_funcao(self) -> None:
        programa = parse("f:\n.a:\n ret\ng:\n.b:\n ret")
        locais = [linha for linha in programa.lines if linha.kind == "label" and linha.local_label]
        self.assertEqual([linha.func for linha in locais], ["f", "g"])

    def test_equ_como_dado(self) -> None:
        programa = parse("section .data\ntam equ 10")
        dado = [linha for linha in programa.lines if linha.kind == "data"][0]
        self.assertEqual(dado.directive, "equ")
        self.assertEqual(dado.args, ["10"])

    def test_times_como_dado(self) -> None:
        programa = parse("section .data\nzeros times 8 db 0")
        dado = [linha for linha in programa.lines if linha.kind == "data"][0]
        self.assertEqual(dado.directive, "times")

    def test_prefixo_rep(self) -> None:
        programa = parse("rep movsb")
        instrucao = programa.instructions[0]
        self.assertEqual(instrucao.prefix, "rep")
        self.assertEqual(instrucao.mnemonic, "movsb")

    def test_prefixo_lock(self) -> None:
        self.assertEqual(parse("lock inc rax").instructions[0].prefix, "lock")

    def test_macro_do_nasm_e_diretiva(self) -> None:
        programa = parse("%define TAM 10\nmov rax, TAM")
        self.assertEqual(programa.lines[0].kind, "directive")

    def test_rotulo_com_dois_pontos_e_instrucao(self) -> None:
        programa = parse("f: mov rax, 1")
        self.assertEqual([linha.kind for linha in programa.lines], ["label", "instruction"])

    def test_instrucao_desconhecida(self) -> None:
        self.assertFalse(parse("instrucao_estranha rax").instructions[0].known)

    def test_diretiva_desconhecida_com_ponto(self) -> None:
        programa = parse(".cfi_startproc")
        self.assertEqual(programa.lines[0].kind, "directive")

    def test_programa_vazio(self) -> None:
        programa = parse("")
        self.assertEqual(programa.instructions, [])
        self.assertEqual(programa.symbols, {})

    def test_texto_sem_rotulo_mantem_funcao(self) -> None:
        programa = parse("f:\n mov rax, 1\n mov rbx, 2")
        self.assertTrue(all(i.func == "f" for i in programa.instructions))

    def test_linha_text_apareada(self) -> None:
        linha = Line(n=1, raw="   mov rax, 1   ")
        self.assertEqual(linha.text, "mov rax, 1")

    def test_operand_padrao(self) -> None:
        self.assertEqual(Operand("x").type, "unknown")

    def test_instrucoes_do_programa(self) -> None:
        programa = Program(
            lines=[Line(n=1, raw="nop", kind="instruction")],
            symbols={},
            flavor="intel",
            source="nop",
        )
        self.assertEqual(len(programa.instructions), 1)


if __name__ == "__main__":
    unittest.main()
