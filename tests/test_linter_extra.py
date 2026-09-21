"""Testes das regras de validação: cada código de problema tem um caso."""

import unittest

from asmx.analyzer import analyze
from asmx.linter import ALL_CHECKS, ALERTA, ERRO, INFO, Problem, validate, summary


def codes(src: str) -> set:
    """Conjunto de códigos de problema para um código fonte."""
    return {p.code for p in validate(analyze(src))}


def problems(src: str, code: str) -> list:
    """Problemas de um código específico."""
    return [p for p in validate(analyze(src)) if p.code == code]


class TestStringsEAvisos(unittest.TestCase):
    """Regras que olham o texto e as strings."""

    def test_aspas_abertas(self) -> None:
        self.assertIn("STR002", codes('section .data\nmsg db "faltou, 10\n'))

    def test_caractere_fora_do_ascii(self) -> None:
        self.assertIn("STR001", codes('section .data\nmsg db "Ação", 10\ntam equ $ - msg\n'))

    def test_caractere_de_controle_literal(self) -> None:
        self.assertIn("STR004", codes('section .data\nmsg db "a\x01b", 10\n'))

    def test_barra_invertida_sem_escape(self) -> None:
        self.assertIn("STR005", codes('section .data\nmsg db "a\\b", 10\n'))

    def test_escape_conhecido_nao_reclama(self) -> None:
        self.assertNotIn("STR005", codes('section .data\nmsg db "a\\nb", 10\n'))

    def test_string_sem_terminador(self) -> None:
        self.assertIn("STR006", codes('section .data\nnome db "rafael"\n'))

    def test_string_com_terminador_passa(self) -> None:
        self.assertNotIn("STR006", codes('section .data\nnome db "rafael", 0\n'))

    def test_string_para_printf_sem_zero(self) -> None:
        src = (
            'extern printf\nsection .data\nnome db "rafael"\n'
            "section .text\nmain:\n mov rdi, nome\n call printf\n ret\n"
        )
        self.assertIn("STR003", codes(src))

    def test_string_com_tamanho_calculado_passa(self) -> None:
        self.assertNotIn("STR006", codes('section .data\nmsg db "abc"\ntam equ $ - msg\n'))


class TestDivisao(unittest.TestCase):
    """Divisão exige preparo de RDX."""

    def test_div_sem_preparo(self) -> None:
        self.assertIn("DIV001", codes("f:\n mov rax, 100\n mov rbx, 7\n div rbx\n ret"))

    def test_div_preparado_com_xor(self) -> None:
        self.assertNotIn(
            "DIV001", codes("f:\n xor rdx, rdx\n mov rax, 10\n mov rbx, 2\n" " div rbx\n ret")
        )

    def test_div_preparado_com_mov_zero(self) -> None:
        self.assertNotIn(
            "DIV001", codes("f:\n mov rdx, 0\n mov rax, 10\n mov rbx, 2\n" " div rbx\n ret")
        )

    def test_divisao_por_zero_literal(self) -> None:
        self.assertIn("DIV002", codes("f:\n xor rdx, rdx\n mov rax, 10\n div 0\n ret"))

    def test_divisor_imediato(self) -> None:
        self.assertIn("DIV003", codes("f:\n xor rdx, rdx\n mov rax, 10\n div 3\n ret"))

    def test_duas_divisoes_exigem_dois_preparos(self) -> None:
        src = (
            "f:\n xor rdx, rdx\n mov rax, 10\n mov rbx, 2\n div rbx\n"
            " mov rax, 20\n div rbx\n ret"
        )
        self.assertIn("DIV001", codes(src))


class TestPilha(unittest.TestCase):
    """Equilíbrio da pilha e retorno."""

    def test_push_sem_pop(self) -> None:
        self.assertIn("STK001", codes("f:\n push rbx\n mov rax, 1\n ret"))

    def test_pop_a_mais(self) -> None:
        self.assertIn("STK002", codes("f:\n pop rbx\n ret"))

    def test_leave_equilibra(self) -> None:
        self.assertNotIn("STK002", codes("f:\n push rbp\n mov rbp, rsp\n pop rbx\n" " leave\n ret"))

    def test_funcao_chamada_sem_ret(self) -> None:
        self.assertIn("STK003", codes("_start:\n call f\nf:\n mov rax, 1"))

    def test_funcao_com_jmp_como_saida_passa(self) -> None:
        self.assertNotIn("STK003", codes("_start:\n call f\nf:\n jmp _start"))


class TestAbi(unittest.TestCase):
    """Convenções de chamada dos dois sistemas."""

    def test_registrador_preservado_alterado(self) -> None:
        self.assertIn("ABI002", codes("f:\n mov rbx, 10\n ret"))

    def test_registrador_salvo_com_push_passa(self) -> None:
        self.assertNotIn("ABI002", codes("f:\n push rbx\n mov rbx, 10\n pop rbx\n ret"))

    def test_windows_sem_shadow_space(self) -> None:
        src = (
            "extern ExitProcess\nsection .text\nglobal main\nmain:\n xor rcx, rcx\n"
            " call ExitProcess\n ret\n"
        )
        self.assertIn("ABI001", codes(src))

    def test_windows_com_shadow_space_passa(self) -> None:
        src = (
            "extern ExitProcess\nsection .text\nglobal main\nmain:\n sub rsp, 40\n"
            " xor rcx, rcx\n call ExitProcess\n ret\n"
        )
        self.assertNotIn("ABI001", codes(src))

    def test_linux_nao_exige_shadow_space(self) -> None:
        src = "f:\n call g\n ret\ng:\n ret"
        self.assertNotIn("ABI001", codes(src))


class TestOperandos(unittest.TestCase):
    """Tamanho, imediatos e deslocamentos."""

    def test_imediato_grande_demais(self) -> None:
        self.assertIn("IMM001", codes("f:\n mov al, 300\n ret"))

    def test_imediato_de_64_bits_fora_do_mov(self) -> None:
        self.assertIn("IMM002", codes("f:\n mov rax, 0x1FFFFFFFF\n add rax, 0x1FFFFFFFF\n ret"))

    def test_mov_aceita_64_bits(self) -> None:
        self.assertNotIn("IMM002", codes("f:\n mov rax, 0x1FFFFFFFF\n ret"))

    def test_memoria_sem_tamanho(self) -> None:
        self.assertIn(
            "MEM001", codes("section .bss\nx resb 8\nsection .text\nf:\n" " mov [x], 1\n ret")
        )

    def test_memoria_com_tamanho(self) -> None:
        self.assertNotIn(
            "MEM001", codes("section .bss\nx resb 8\nsection .text\nf:\n" " mov byte [x], 1\n ret")
        )

    def test_memoria_dos_dois_lados(self) -> None:
        self.assertIn("MEM002", codes("f:\n mov [rax], [rbx]\n ret"))

    def test_deslocamento_maior_que_o_registrador(self) -> None:
        self.assertIn("SHF001", codes("f:\n mov al, 1\n shl al, 12\n ret"))

    def test_mnemonico_desconhecido(self) -> None:
        self.assertIn("UNK001", codes("f:\n xyzzy rax\n ret"))


class TestSimbolosEEntrada(unittest.TestCase):
    """Símbolos, ponto de entrada e saída."""

    def test_desvio_para_rotulo_inexistente(self) -> None:
        self.assertIn("SYM001", codes("_start:\n jmp nao_existe"))

    def test_variavel_inexistente(self) -> None:
        self.assertIn("SYM003", codes("f:\n mov rax, [nao_existe]\n ret"))

    def test_extern_nao_e_erro(self) -> None:
        self.assertNotIn("SYM001", codes("extern printf\n_start:\n call printf"))

    def test_rotulo_sem_uso(self) -> None:
        self.assertIn("SYM002", codes("_start:\n mov rax, 1\nesquecido:\n mov rbx, 2"))

    def test_sem_ponto_de_entrada(self) -> None:
        self.assertIn("ENT001", codes("f:\n mov rax, 1\n ret"))

    def test_entrada_sem_global(self) -> None:
        self.assertIn("ENT002", codes("section .text\n_start:\n mov rax, 60\n syscall"))

    def test_entrada_com_global(self) -> None:
        self.assertNotIn(
            "ENT002", codes("section .text\nglobal _start\n_start:\n" " mov rax, 60\n syscall")
        )

    def test_sem_saida_explicita(self) -> None:
        self.assertIn("EXIT001", codes("global _start\nsection .text\n_start:\n mov rax, 1"))

    def test_com_exit_passa(self) -> None:
        self.assertNotIn(
            "EXIT001", codes("global _start\nsection .text\n_start:\n" " mov rax, 60\n syscall")
        )

    def test_saida_pelo_exitprocess(self) -> None:
        self.assertNotIn(
            "EXIT001",
            codes("extern ExitProcess\nglobal main\nmain:\n" " xor rcx, rcx\n call ExitProcess"),
        )

    def test_saida_por_ret_no_main(self) -> None:
        self.assertNotIn("EXIT001", codes("global main\nmain:\n mov rax, 0\n ret"))


class TestFluxo(unittest.TestCase):
    """Blocos inalcançáveis e laços que não terminam."""

    def test_bloco_inalcancavel(self) -> None:
        src = (
            "global _start\nsection .text\n_start:\n mov rax, 60\n xor rdi, rdi\n"
            " syscall\norfao:\n mov rbx, 1\n jmp orfao\n"
        )
        self.assertIn("FLOW001", codes(src))

    def test_laco_sem_mudanca(self) -> None:
        self.assertIn(
            "FLOW002", codes("global _start\nsection .text\n_start:\n" ".trava:\n jmp .trava")
        )

    def test_laco_com_contador_passa(self) -> None:
        src = (
            "global _start\nsection .text\n_start:\n mov rcx, 5\n.laco:\n dec rcx\n"
            " jnz .laco\n mov rax, 60\n syscall\n"
        )
        self.assertNotIn("FLOW002", codes(src))


class TestSyscallsESecoes(unittest.TestCase):
    """Chamadas de sistema e seções."""

    def test_syscall_sem_rax(self) -> None:
        self.assertIn(
            "SYS001", codes("global _start\nsection .text\n_start:\n" " mov rdi, 1\n syscall\n")
        )

    def test_rcx_lido_depois_do_syscall(self) -> None:
        src = (
            "global _start\nsection .text\n_start:\n mov rax, 1\n syscall\n"
            " mov rbx, rcx\n mov rax, 60\n syscall\n"
        )
        self.assertIn("SYS002", codes(src))

    def test_instrucoes_fora_da_secao_de_codigo(self) -> None:
        self.assertIn(
            "SEC001", codes("section .data\nx db 1\nsection .rodata\ny db 2\n" "mov rax, 1")
        )

    def test_escrita_em_rodata(self) -> None:
        src = (
            "section .rodata\nfixo dq 1\nsection .text\nglobal _start\n_start:\n"
            " mov [fixo], rax\n mov rax, 60\n syscall\n"
        )
        self.assertIn("SEC002", codes(src))


class TestRegistradores(unittest.TestCase):
    """Leitura de registrador sem valor."""

    def test_registrador_nao_inicializado(self) -> None:
        self.assertIn("REG001", codes("f:\n add rax, r12\n ret"))

    def test_registrador_inicializado_passa(self) -> None:
        self.assertNotIn("REG001", codes("f:\n mov r12, 1\n add r12, 5\n ret"))

    def test_rax_lido_antes_de_receber_valor(self) -> None:
        """RAX é registrador de rascunho: ler antes de escrever é suspeito."""
        self.assertIn("REG001", codes("f:\n add rax, r12\n ret"))

    def test_argumento_nao_conta_como_nao_inicializado(self) -> None:
        self.assertNotIn("REG001", codes("f:\n mov rax, rdi\n ret"))


class TestInfraestrutura(unittest.TestCase):
    """O que envolve as regras: lista, resumo, ordenação e falha interna."""

    def test_lista_de_regras(self) -> None:
        self.assertEqual(len(ALL_CHECKS), 15)
        for regra in ALL_CHECKS:
            with self.subTest(regra=regra.__name__):
                self.assertEqual(regra(analyze("")), [])

    def test_problema_str(self) -> None:
        problema = Problem(3, ERRO, "XXX001", "algo", "dica")
        self.assertEqual(str(problema), "L3 [erro] XXX001: algo")

    def test_problema_to_dict(self) -> None:
        problema = Problem(3, ALERTA, "XXX002", "algo", "dica")
        self.assertEqual(
            problema.to_dict(),
            {"line": 3, "severity": ALERTA, "code": "XXX002", "message": "algo", "hint": "dica"},
        )

    def test_resumo(self) -> None:
        problemas = [
            Problem(1, ERRO, "A", "a"),
            Problem(2, ALERTA, "B", "b"),
            Problem(3, INFO, "C", "c"),
        ]
        self.assertEqual(summary(problemas), "1 erro(s), 1 alerta(s), 1 informação(ões)")

    def test_ordenacao_por_severidade_e_linha(self) -> None:
        problemas = validate(analyze("f:\n mov al, 300\n jmp nao_existe\n ret"))
        self.assertEqual(problemas[0].severity, ERRO)
        linhas = [p.line for p in problemas if p.severity == ERRO]
        self.assertEqual(linhas, sorted(linhas))

    def test_falha_interna_vira_info(self) -> None:
        from asmx import linter

        def regra_quebrada(analise: object) -> list:
            raise RuntimeError("explodiu de propósito")

        original = linter.ALL_CHECKS
        linter.ALL_CHECKS = [regra_quebrada]
        try:
            problemas = linter.validate(analyze("nop"))
        finally:
            linter.ALL_CHECKS = original
        self.assertEqual(problemas[0].code, "INT001")
        self.assertIn("explodiu de propósito", problemas[0].message)

    def test_codigo_vazio_nao_tem_problema(self) -> None:
        self.assertEqual(validate(analyze("")), [])


if __name__ == "__main__":
    unittest.main()
