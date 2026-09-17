import unittest

from asmx.analyzer import analyze
from asmx.examples import EXAMPLES
from asmx.linter import ERRO, summary, validate


def codes(src):
    return {p.code for p in validate(analyze(src))}


def problems(src, code):
    return [p for p in validate(analyze(src)) if p.code == code]


LIMPO = EXAMPLES["linux-hello"]["code"]


class TestStrings(unittest.TestCase):

    def test_caractere_especial_na_string(self):
        src = 'section .data\n  msg db "Ação inválida", 10\n  tam equ $ - msg\n'
        p = problems(src, "STR001")
        self.assertTrue(p)
        self.assertIn("ASCII", p[0].message)

    def test_string_ascii_nao_reclama(self):
        src = 'section .data\n  msg db "Acao valida", 10\n'
        self.assertNotIn("STR001", codes(src))

    def test_aspas_nao_fechadas(self):
        src = 'section .data\n  msg db "faltou fechar, 10\n'
        self.assertIn("STR002", codes(src))

    def test_string_sem_terminador_para_funcao_c(self):
        src = ('extern printf\nsection .data\n  nome db "rafael"\n'
               'section .text\nmain:\n  mov rdi, nome\n  call printf\n  ret\n')
        self.assertIn("STR003", codes(src))

    def test_string_com_terminador_passa(self):
        src = ('extern printf\nsection .data\n  nome db "rafael", 0\n'
               'section .text\nmain:\n  mov rdi, nome\n  call printf\n  ret\n')
        self.assertNotIn("STR003", codes(src))


class TestDivisao(unittest.TestCase):

    def test_div_sem_preparar_rdx(self):
        src = "f:\n mov rax, 100\n mov rbx, 7\n div rbx\n ret"
        p = problems(src, "DIV001")
        self.assertTrue(p)
        self.assertEqual(p[0].severity, ERRO)
        self.assertIn("XOR RDX, RDX", p[0].hint)

    def test_div_preparado_nao_reclama(self):
        src = "f:\n xor rdx, rdx\n mov rax, 100\n mov rbx, 7\n div rbx\n ret"
        self.assertNotIn("DIV001", codes(src))

    def test_idiv_aceita_cqo(self):
        src = "f:\n mov rax, -100\n cqo\n mov rbx, 7\n idiv rbx\n ret"
        self.assertNotIn("DIV001", codes(src))

    def test_divisao_por_imediato(self):
        src = "f:\n xor rdx, rdx\n mov rax, 10\n div 0\n ret"
        c = codes(src)
        self.assertIn("DIV002", c)


class TestPilhaEAbi(unittest.TestCase):

    def test_push_sem_pop(self):
        src = "f:\n push rbx\n mov rax, 1\n ret"
        p = problems(src, "STK001")
        self.assertTrue(p)

    def test_push_com_pop_passa(self):
        src = "f:\n push rbx\n mov rax, 1\n pop rbx\n ret"
        self.assertNotIn("STK001", codes(src))

    def test_pop_a_mais(self):
        src = "f:\n pop rbx\n ret"
        self.assertIn("STK002", codes(src))

    def test_funcao_chamada_sem_ret(self):
        src = "_start:\n call f\nf:\n mov rax, 1"
        self.assertIn("STK003", codes(src))

    def test_callee_saved_sem_salvar(self):
        src = "f:\n mov rbx, 10\n ret"
        self.assertIn("ABI002", codes(src))

    def test_shadow_space_no_windows(self):
        src = ("extern ExitProcess\nsection .text\nglobal main\nmain:\n"
               "  xor rcx, rcx\n  call ExitProcess\n  ret\n")
        self.assertIn("ABI001", codes(src))

    def test_shadow_space_presente_passa(self):
        src = ("extern ExitProcess\nsection .text\nglobal main\nmain:\n"
               "  sub rsp, 40\n  xor rcx, rcx\n  call ExitProcess\n  ret\n")
        self.assertNotIn("ABI001", codes(src))


class TestOperandos(unittest.TestCase):

    def test_valor_alto_demais(self):
        p = problems("f:\n mov al, 300\n ret", "IMM001")
        self.assertTrue(p)
        self.assertIn("8 bits", p[0].message)

    def test_valor_que_cabe_passa(self):
        self.assertNotIn("IMM001", codes("f:\n mov al, 200\n ret"))

    def test_valor_enorme_em_registrador_grande(self):
        self.assertIn("IMM001", codes("f:\n mov eax, 0x1FFFFFFFFF\n ret"))

    def test_tamanho_ambiguo_em_memoria(self):
        self.assertIn("MEM001", codes("section .bss\nx resb 8\nsection .text\nf:\n mov [x], 1\n ret"))

    def test_tamanho_explicito_passa(self):
        self.assertNotIn("MEM001", codes("section .bss\nx resb 8\nsection .text\nf:\n mov qword [x], 1\n ret"))

    def test_memoria_dos_dois_lados(self):
        self.assertIn("MEM002", codes("f:\n mov [rax], [rbx]\n ret"))

    def test_deslocamento_maior_que_o_registrador(self):
        self.assertIn("SHF001", codes("f:\n mov al, 1\n shl al, 12\n ret"))

    def test_mnemonico_desconhecido(self):
        self.assertIn("UNK001", codes("f:\n movq2dq xmm0, mm0\n ret"))


class TestSimbolosEFluxo(unittest.TestCase):

    def test_desvio_para_rotulo_inexistente(self):
        p = problems("_start:\n jmp nao_existe", "SYM001")
        self.assertTrue(p)
        self.assertIn("nao_existe", p[0].message)

    def test_extern_nao_reclama(self):
        self.assertNotIn("SYM001", codes("extern printf\n_start:\n call printf"))

    def test_rotulo_nunca_usado(self):
        self.assertIn("SYM002", codes("_start:\n mov rax, 1\nesquecido:\n mov rbx, 2"))

    def test_entrada_sem_global(self):
        self.assertIn("ENT002", codes("section .text\n_start:\n mov rax, 60\n syscall"))

    def test_entrada_com_global_passa(self):
        src = "section .text\nglobal _start\n_start:\n mov rax, 60\n xor rdi, rdi\n syscall"
        self.assertNotIn("ENT002", codes(src))

    def test_laco_infinito_sem_alteracao(self):
        src = "global _start\nsection .text\n_start:\n.trava:\n jmp .trava"
        self.assertIn("FLOW002", codes(src))

    def test_bloco_inalcancavel(self):
        src = ("global _start\nsection .text\n_start:\n mov rax, 60\n xor rdi, rdi\n syscall\n"
               "orfao:\n mov rbx, 1\n jmp orfao\n")
        self.assertIn("FLOW001", codes(src))

    def test_sem_saida_explicita(self):
        self.assertIn("EXIT001", codes("global _start\nsection .text\n_start:\n mov rax, 1"))


class TestSyscallsESecoes(unittest.TestCase):

    def test_syscall_sem_rax(self):
        src = "global _start\nsection .text\n_start:\n mov rdi, 1\n syscall\n"
        self.assertIn("SYS001", codes(src))

    def test_rcx_apos_syscall(self):
        src = ("global _start\nsection .text\n_start:\n mov rax, 1\n syscall\n"
               " mov rbx, rcx\n mov rax, 60\n syscall\n")
        self.assertIn("SYS002", codes(src))

    def test_escrita_em_rodata(self):
        src = ("section .rodata\n  fixo dq 1\nsection .text\nglobal _start\n_start:\n"
               "  mov [fixo], rax\n  mov rax, 60\n  xor rdi, rdi\n  syscall\n")
        self.assertIn("SEC002", codes(src))

    def test_registrador_nao_inicializado(self):
        self.assertIn("REG001", codes("f:\n add rax, r12\n ret"))


class TestConjunto(unittest.TestCase):

    def test_exemplo_limpo_nao_tem_erros(self):
        problemas = validate(analyze(LIMPO))
        erros = [p for p in problemas if p.severity == ERRO]
        self.assertEqual(erros, [], "o exemplo bom não deveria ter erros: %s" % erros)

    def test_exemplos_bons_sem_erro(self):
        for nome in ("linux-loop", "linux-funcao", "bubble", "windows-hello"):
            with self.subTest(exemplo=nome):
                erros = [p for p in validate(analyze(EXAMPLES[nome]["code"]))
                         if p.severity == ERRO]
                self.assertEqual(erros, [], "%s: %s" % (nome, erros))

    def test_exemplo_quebrado_acusa_varios_problemas(self):
        c = codes(EXAMPLES["quebrado"]["code"])
        for esperado in ("STR001", "STR006", "DIV001", "IMM001", "STK001", "FLOW002", "SYM003"):
            self.assertIn(esperado, c, "faltou detectar %s" % esperado)

    def test_resumo(self):
        s = summary(validate(analyze(EXAMPLES["quebrado"]["code"])))
        self.assertIn("erro", s)

    def test_validacao_nao_quebra_com_lixo(self):
        for src in ("", "   ", ";;;;", "mov\n\n\n", "section", '"', "[[[", "f:"):
            with self.subTest(src=src):
                validate(analyze(src))


if __name__ == "__main__":
    unittest.main()
