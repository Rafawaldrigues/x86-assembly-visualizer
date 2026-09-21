import unittest

from asmx.analyzer import analyze, callers_of
from asmx.examples import EXAMPLES
from asmx.parser import classify_operand, parse, parse_number, strip_comment


class TestParser(unittest.TestCase):

    def test_strip_comment_respeita_string(self) -> None:
        body, comment = strip_comment('    db "a;b", 10   ; isto é comentário')
        self.assertIn('"a;b"', body)
        self.assertTrue(comment.startswith("; isto"))

    def test_numeros_em_varias_bases(self) -> None:
        self.assertEqual(parse_number("10"), 10)
        self.assertEqual(parse_number("0x10"), 16)
        self.assertEqual(parse_number("10h"), 16)
        self.assertEqual(parse_number("1010b"), 10)
        self.assertEqual(parse_number("-5"), -5)

    def test_classificacao_de_operandos(self) -> None:
        self.assertEqual(classify_operand("rax").type, "reg")
        self.assertEqual(classify_operand("42").type, "imm")
        self.assertEqual(classify_operand("msg").type, "sym")
        mem = classify_operand("qword [rbx + rcx*4 + 8]")
        self.assertEqual(mem.type, "mem")
        self.assertEqual(mem.size, 8)
        self.assertIn("rbx", mem.regs)
        self.assertIn("rcx", mem.regs)

    def test_rotulo_com_instrucao_na_mesma_linha(self) -> None:
        p = parse("inicio: mov rax, 1")
        kinds = [linha.kind for linha in p.lines if linha.kind != "empty"]
        self.assertEqual(kinds, ["label", "instruction"])

    def test_rotulo_local_nao_troca_a_funcao(self) -> None:
        p = parse("func:\n  mov rax, 1\n.loop:\n  dec rax\n  jnz .loop\n  ret")
        self.assertTrue(all(linha.func == "func" for linha in p.instructions))

    def test_declaracao_de_dados(self) -> None:
        p = parse('section .data\nmsg db "oi", 10\nbuf resb 64')
        data = [linha for linha in p.lines if linha.kind == "data"]
        self.assertEqual(data[0].label, "msg")
        self.assertEqual(data[0].unit, 1)
        self.assertTrue(data[1].reserve)
        self.assertEqual(p.symbols["msg"]["type"], "data")

    def test_att_normalizado_para_intel(self) -> None:
        p = parse("movq %rsp, %rbp\naddl $10, -4(%rbp)")
        self.assertEqual(p.flavor, "att")
        i = p.instructions
        self.assertEqual(i[0].mnemonic, "mov")
        self.assertEqual(i[0].operands[0].reg, "rbp")  # destino primeiro
        self.assertEqual(i[0].operands[1].reg, "rsp")
        self.assertEqual(i[1].mnemonic, "add")
        self.assertEqual(i[1].operands[0].type, "mem")

    def test_masm_proc(self) -> None:
        p = parse("main PROC\n  mov rax, 1\n  ret\nmain ENDP")
        self.assertEqual(p.flavor, "masm")
        self.assertIn("main", p.symbols)
        self.assertEqual(p.instructions[0].func, "main")


class TestAnalyzer(unittest.TestCase):

    def test_plataforma_linux(self) -> None:
        a = analyze(EXAMPLES["linux-hello"]["code"])
        self.assertEqual(a.platform.os, "linux")
        self.assertGreater(a.platform.confidence, 60)
        self.assertTrue(a.platform.evidence["linux"])
        self.assertEqual(a.platform.abi["name"], "System V AMD64")

    def test_plataforma_windows(self) -> None:
        a = analyze(EXAMPLES["windows-hello"]["code"])
        self.assertEqual(a.platform.os, "windows")
        self.assertEqual(a.platform.abi["args"][0], "rcx")

    def test_plataforma_indefinida(self) -> None:
        a = analyze("mov rax, 1\nadd rax, 2\nret")
        self.assertEqual(a.platform.os, "indefinido")
        self.assertEqual(a.platform.confidence, 0)

    def test_semantica_reconhece_escrita_e_leitura(self) -> None:
        a = analyze(
            "section .data\nx dq 0\nsection .text\n" "mov [x], rax\nmov rbx, [x]\nlea rsi, [x]"
        )
        tags = [i.sem.tag for i in a.instrs]
        self.assertEqual(tags, ["store", "load", "addr"])
        self.assertIn("x = rax", a.instrs[0].sem.detail)

    def test_semantica_de_syscall_resolve_nome(self) -> None:
        a = analyze("mov rax, 1\nmov rdi, 1\nsyscall")
        self.assertEqual(a.instrs[-1].sem.syscall_name, "write")
        self.assertIn("write", a.instrs[-1].sem.detail)

    def test_prologo_detectado(self) -> None:
        a = analyze("f:\n push rbp\n mov rbp, rsp\n pop rbp\n ret")
        self.assertEqual(a.instrs[0].sem.label, "Prólogo da função")
        self.assertEqual(a.instrs[2].sem.label, "Epílogo da função")

    def test_argumentos_nao_vazam_entre_funcoes(self) -> None:
        a = analyze(EXAMPLES["linux-funcao"]["code"])
        itoa = [i for i in a.instrs if i.func == "itoa"]
        self.assertTrue(itoa)
        self.assertFalse(any("argumento da chamada a soma" in i.sem.detail for i in itoa))

    def test_blocos_e_fluxo(self) -> None:
        a = analyze(EXAMPLES["linux-loop"]["code"])
        nomes = [b.name for b in a.blocks]
        self.assertIn(".loop", nomes)
        loop = next(b for b in a.blocks if b.name == ".loop")
        self.assertTrue(loop.pred, "o bloco do laço precisa ter predecessores")
        self.assertTrue(any(e.kind == "taken" for e in loop.succ))

    def test_callers_of(self) -> None:
        a = analyze(EXAMPLES["linux-funcao"]["code"])
        self.assertTrue(callers_of(a, "soma"))

    def test_estatisticas(self) -> None:
        a = analyze(EXAMPLES["bubble"]["code"])
        self.assertEqual(a.stats["instructions"], len(a.instrs))
        self.assertEqual(a.stats["unknown"], [])
        self.assertGreater(a.stats["blocks"], 3)

    def test_codigo_vazio_nao_quebra(self) -> None:
        a = analyze("")
        self.assertEqual(a.instrs, [])
        self.assertEqual(a.blocks, [])


if __name__ == "__main__":
    unittest.main()
