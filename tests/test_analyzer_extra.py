"""Testes de canto da análise: plataforma, semântica, blocos e fluxo."""

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
FUNCAO = EXAMPLES["linux-funcao"]["code"]


class TestPlataforma(unittest.TestCase):
    """Detecção de sistema, bits e ABI."""

    def test_linux_com_varias_pistas(self) -> None:
        plataforma = detect_platform(parse(HELLO))
        self.assertEqual(plataforma.os, "linux")
        self.assertGreater(plataforma.confidence, 80)
        self.assertIn("System V", plataforma.abi["name"])
        self.assertIn("RDI", plataforma.abi["notes"])

    def test_windows_pela_api(self) -> None:
        plataforma = detect_platform(parse(EXAMPLES["windows-hello"]["code"]))
        self.assertEqual(plataforma.os, "windows")
        self.assertEqual(plataforma.abi["args"], ["rcx", "rdx", "r8", "r9"])
        self.assertIn("shadow space", plataforma.abi["notes"])

    def test_indefinido(self) -> None:
        plataforma = detect_platform(parse("mov rax, 1\nadd rax, 2"))
        self.assertEqual(plataforma.os, "indefinido")
        self.assertEqual(plataforma.confidence, 0)
        self.assertEqual(plataforma.evidence["linux"], [])

    def test_ambiguo(self) -> None:
        codigo = "call printf\nsub rsp, 40\n"
        plataforma = detect_platform(parse(codigo))
        self.assertEqual(plataforma.os, "ambíguo")
        self.assertEqual(plataforma.confidence, 35)

    def test_pistas_de_windows(self) -> None:
        plataforma = detect_platform(parse("extern __imp_CreateFileA\nincludelib kernel32"))
        self.assertEqual(plataforma.os, "windows")
        self.assertTrue(plataforma.evidence["windows"])

    def test_bits_16(self) -> None:
        self.assertEqual(detect_platform(parse("bits 16\nmov ax, 1")).bits, 16)

    def test_bits_32(self) -> None:
        self.assertEqual(detect_platform(parse("bits 32\nmov eax, 1")).bits, 32)

    def test_use32_tambem_marca_32(self) -> None:
        self.assertEqual(detect_platform(parse("use32\nmov eax, 1")).bits, 32)

    def test_padrao_64(self) -> None:
        self.assertEqual(detect_platform(parse("mov rax, 1")).bits, 64)

    def test_dataclasses(self) -> None:
        plataforma = Platform(os="linux", confidence=50, bits=64, evidence={}, abi={})
        self.assertEqual(plataforma.bits, 64)
        self.assertEqual(Edge(1, "taken", "porque sim").kind, "taken")


class TestSemantica(unittest.TestCase):
    """Cada família de instruções ganha uma explicação em português."""

    def sem(self, codigo: str, indice: int = -1) -> Semantic:
        """Semântica da instrução pedida (por índice, do fim por padrão)."""
        return analyze(codigo).instrs[indice].sem

    def sem_de(self, codigo: str, mnemonic: str) -> Semantic:
        """Semântica da primeira instrução com esse mnemônico."""
        for instrucao in analyze(codigo).instrs:
            if instrucao.mnemonic == mnemonic:
                return instrucao.sem
        raise AssertionError("não achei %s em %r" % (mnemonic, codigo))

    def test_escrita_em_local(self) -> None:
        codigo = "f:\n push rbp\n mov rbp, rsp\n mov [rbp - 8], rax"
        self.assertEqual(self.sem(codigo, 0).tag, "frame")
        self.assertIn("variável local", self.sem(codigo).detail)

    def test_leitura_de_parametro(self) -> None:
        self.assertIn("parâmetro", self.sem("f:\n mov rax, [rbp + 16]").detail)

    def test_memoria_por_simbolo(self) -> None:
        self.assertIn(
            "variável", self.sem("section .data\nx dq 0\nsection .text\n" "mov rax, [x]").detail
        )

    def test_memoria_por_ponteiro(self) -> None:
        self.assertIn("endereço apontado", self.sem("f:\n mov rax, [rbx]").detail)

    def test_copia_entre_registradores(self) -> None:
        sem = self.sem("mov rax, rbx")
        self.assertEqual(sem.tag, "copy")
        self.assertIn("cópia", sem.detail)

    def test_endereco_de_simbolo(self) -> None:
        sem = self.sem("section .data\nx dq 0\nsection .text\nmov rax, x")
        self.assertEqual(sem.label, "Define endereço/símbolo")

    def test_lea_calcula_endereco(self) -> None:
        sem = self.sem("section .data\nx dq 0\nsection .text\nlea rax, [x]")
        self.assertEqual(sem.label, "Calcula endereço")
        self.assertIn("&", sem.detail)

    def test_push_e_pop(self) -> None:
        self.assertEqual(self.sem("push rax").tag, "push")
        self.assertEqual(self.sem("pop rax").tag, "pop")

    def test_call_de_api_do_windows(self) -> None:
        sem = self.sem("extern ExitProcess\ncall ExitProcess")
        self.assertIn("API do Windows", sem.detail)

    def test_call_de_funcao_externa(self) -> None:
        self.assertIn("externa", self.sem("extern printf\ncall printf").detail)

    def test_ret(self) -> None:
        self.assertIn("RAX", self.sem("ret").detail)

    def test_jmp(self) -> None:
        self.assertIn("Segue direto", self.sem("fim:\njmp fim").detail)

    def test_desvio_condicional_cita_a_comparacao(self) -> None:
        sem = self.sem_de("mov rax, 1\ncmp rax, 1\nje fim\nfim:\nret", "je")
        self.assertEqual(sem.label, "Desvia se igual")
        self.assertIn("cmp", sem.detail)

    def test_cmp_e_test(self) -> None:
        self.assertIn("só para atualizar as flags", self.sem("cmp rax, rbx").detail)
        self.assertIn("é zero?", self.sem("test rax, rax").detail)

    def test_syscall_com_numero_conhecido(self) -> None:
        sem = self.sem("mov rax, 1\nsyscall")
        self.assertEqual(sem.syscall_name, "write")
        self.assertIn("RDI", sem.detail)

    def test_syscall_sem_numero(self) -> None:
        self.assertIn("número do serviço está em RAX", self.sem("syscall").detail)

    def test_int_e_tratado_como_syscall(self) -> None:
        self.assertEqual(self.sem("int 0x80").tag, "syscall")

    def test_aritmetica_simples(self) -> None:
        self.assertIn("rax = rax + 1", self.sem("inc rax").detail)
        self.assertIn("troca o sinal", self.sem("neg rax").detail)
        self.assertIn("RDX:RAX", self.sem("mul rbx").detail)
        self.assertIn("quociente em RAX", self.sem("div rbx").detail)

    def test_multiplicacao_por_dois_operandos(self) -> None:
        self.assertIn("rax = rax * rbx", self.sem("imul rax, rbx").detail)

    def test_bits(self) -> None:
        self.assertIn("mais curto de zerar", self.sem("xor rax, rax").detail)
        self.assertIn("* 2^", self.sem("shl rax, 2").detail)
        self.assertIn("/ 2^", self.sem("shr rax, 2").detail)
        self.assertIn("invertidos", self.sem("not rax").detail)
        self.assertIn("bit a bit", self.sem("or rax, rbx").detail)

    def test_setcc(self) -> None:
        self.assertEqual(self.sem("sete al").label, "Booleano da condição")

    def test_leave_e_nop(self) -> None:
        self.assertIn("Restaura RSP", self.sem("leave").detail)
        self.assertEqual(self.sem("nop").label, "Nada")

    def test_instrucao_conhecida_sem_regra_especifica(self) -> None:
        self.assertIn("", self.sem("cpuid").detail)

    def test_instrucao_desconhecida(self) -> None:
        self.assertEqual(self.sem("xyzzy rax").tag, "unknown")

    def test_prologo_e_epilogo(self) -> None:
        analise = analyze("f:\n push rbp\n mov rbp, rsp\n pop rbp\n ret")
        self.assertEqual(analise.instrs[0].sem.label, "Prólogo da função")
        self.assertEqual(analise.instrs[1].sem.label, "Prólogo da função")
        self.assertEqual(analise.instrs[2].sem.label, "Epílogo da função")

    def test_argumentos_numerados(self) -> None:
        analise = analyze("f:\n ret\n_start:\n mov rdi, 1\n mov rsi, 2\n call f")
        chamada = [i for i in analise.instrs if i.mnemonic == "call"][0]
        self.assertIn("1º argumento", analise.instrs[1].sem.detail)
        self.assertIn("2º argumento", analise.instrs[2].sem.detail)
        self.assertEqual(chamada.sem.tag, "call")

    def test_argumentos_do_windows(self) -> None:
        analise = analyze(
            "extern ExitProcess\nsection .text\nmain:\n mov rcx, 0\n" " call ExitProcess"
        )
        self.assertIn("1º argumento", analise.instrs[0].sem.detail)

    def test_semantica_de_linha_sem_operandos(self) -> None:
        analise = analyze("syscall")
        self.assertEqual(
            semantics_of(
                analise.instrs[0],
                {
                    "platform": analise.platform,
                    "symbols": {},
                    "pending_syscall": None,
                    "last_compare": None,
                    "syscall_ahead": False,
                },
            ).tag,
            "syscall",
        )


class TestBlocos(unittest.TestCase):
    """Blocos básicos, arestas e motivos de saída."""

    def test_bloco_unico(self) -> None:
        blocos, label_at = build_blocks(parse("mov rax, 1\nmov rbx, 2"))
        self.assertEqual(len(blocos), 1)
        self.assertEqual(blocos[0].name, "início")
        self.assertEqual(blocos[0].exit, "fim do código")
        self.assertEqual(label_at, {})

    def test_ret_encerra_o_bloco(self) -> None:
        blocos, _ = build_blocks(parse("f:\n mov rax, 1\n ret"))
        self.assertEqual(blocos[-1].exit, "retorna para quem chamou")

    def test_syscall_de_saida_encerra(self) -> None:
        self.assertTrue(any(b.exit == "encerra o processo" for b in analyze(HELLO).blocks))

    def test_semantica_ausente_cai_no_fim_do_codigo(self) -> None:
        blocos, _ = build_blocks(parse("mov rax, 60\nsyscall"))
        self.assertIsNone(blocos[0].instrs[-1].sem)
        self.assertEqual(blocos[0].exit, "fim do código")

    def test_call_exitprocess_encerra(self) -> None:
        blocos, _ = build_blocks(
            parse("extern ExitProcess\nmain:\n call ExitProcess")
        )  # noqa: E501
        self.assertEqual(blocos[-1].exit, "encerra o processo")

    def test_desvio_para_fora(self) -> None:
        blocos, _ = build_blocks(parse("jmp lugar_nenhum"))
        self.assertIn("fora do código carregado", blocos[0].exit)

    def test_arestas_de_desvio(self) -> None:
        blocos, label_at = build_blocks(
            parse("f:\n cmp rax, 1\n je fim\n mov rbx, 1\n" "fim:\n ret")
        )
        self.assertIn("fim", label_at)
        tipos = {e.kind for b in blocos for e in b.succ}
        self.assertIn("taken", tipos)
        self.assertIn("fallthrough", tipos)

    def test_aresta_incondicional(self) -> None:
        blocos, _ = build_blocks(parse("a:\n jmp b\nb:\n ret"))
        self.assertTrue(any(e.kind == "jmp" for e in blocos[0].succ))

    def test_bloco_de_continuacao_tem_nome(self) -> None:
        blocos, _ = build_blocks(parse("f:\n cmp rax, 1\n je f\n mov rbx, 1\n mov rcx, 2"))
        self.assertTrue(any(b.name.startswith("continuação") for b in blocos))

    def test_chamadas_do_bloco(self) -> None:
        blocos, _ = build_blocks(parse("f:\n ret\n_start:\n call f"))
        self.assertIn("f", blocos[-1].calls)

    def test_predecessores(self) -> None:
        blocos, _ = build_blocks(parse("a:\n cmp rax, 1\n je a\n ret"))
        self.assertTrue(blocos[0].pred)
        self.assertEqual(blocos[0].pred[0].kind, "taken")

    def test_bloco_dataclass(self) -> None:
        bloco = Block(id=0, start=0, end=1, name="x", func=None)
        self.assertEqual(bloco.instrs, [])
        self.assertIsNone(bloco.exit)


class TestConsultas(unittest.TestCase):
    """Funções de apoio usadas pela interface."""

    def test_callers_of_com_call(self) -> None:
        chamadores = callers_of(analyze(FUNCAO), "soma")
        self.assertTrue(any("call" in c or "(" in c for c in chamadores))

    def test_callers_of_com_desvio(self) -> None:
        analise = analyze("_start:\n jmp destino\ndestino:\n ret")
        self.assertTrue(any("desvio" in c for c in callers_of(analise, "destino")))

    def test_callers_of_sem_chamadores(self) -> None:
        self.assertEqual(callers_of(analyze("f:\n ret"), "f"), [])

    def test_functions(self) -> None:
        self.assertIn("soma", functions(analyze(FUNCAO)))
        self.assertEqual(functions(analyze("mov rax, 1")), [])

    def test_estatisticas(self) -> None:
        analise = analyze(
            "section .data\nx dq 0\nsection .text\nf:\n mov rax, [x]\n"
            " xyzzy rax\n syscall\n call f\n ret"
        )
        self.assertEqual(analise.stats["instructions"], 5)
        self.assertEqual(analise.stats["syscalls"], 1)
        self.assertEqual(analise.stats["calls"], 1)
        self.assertEqual(analise.stats["unknown"], ["xyzzy"])
        self.assertEqual(analise.stats["labels"], 1)

    def test_symbols_do_analysis(self) -> None:
        analise = analyze("section .data\nx dq 1")
        self.assertIn("x", analise.symbols)

    def test_indice_de_rotulos(self) -> None:
        analise = analyze("a:\n mov rax, 1\nb:\n mov rbx, 2")
        self.assertEqual(analise.label_at, {"a": 0, "b": 1})

    def test_instrucoes_recebem_indice_e_bloco(self) -> None:
        analise = analyze("mov rax, 1\nmov rbx, 2")
        self.assertEqual(analise.instrs[0].idx, 0)
        self.assertEqual(analise.instrs[0].block, 0)

    def test_analysis_dataclass(self) -> None:
        analise = analyze("nop")
        self.assertIsInstance(analise, Analysis)
        self.assertIsInstance(analise.blocks[0], Block)

    def test_programa_vazio(self) -> None:
        analise = analyze("")
        self.assertEqual(analise.stats["instructions"], 0)
        self.assertEqual(analise.blocks, [])


if __name__ == "__main__":
    unittest.main()
