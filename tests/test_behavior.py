"""Testes dos comportamentos: categorias, confiança, ATT&CK e honestidade.

Cada categoria tem um trecho de assembly escrito à mão, os exemplos prontos são
conferidos com o resultado que o relatório espera e as regras de confiança,
serialização, técnicas e resumo entram como casos próprios. Nenhum teste
escreve número de syscall à mão: tudo sai de :data:`asmx.isa.LINUX_SYSCALLS`.
"""

import types
import unittest
from dataclasses import FrozenInstanceError
from typing import Dict, List, Optional, Sequence, Set
from unittest import mock

from asmx.analyzer import analyze
from asmx.behavior import (
    BEHAVIOR_CATEGORIES,
    MITRE_TECHNIQUES,
    Behavior,
    by_tactic,
    classify,
    severity_rank,
    summary,
    techniques,
    to_dicts,
)
from asmx.examples import EXAMPLES
from asmx.isa import LINUX_SYSCALLS
from asmx.linter import Problem, validate

#: Nome da syscall -> número, lido do acervo.
NUMERO_DA_SYSCALL: Dict[str, int] = {
    dados[0]: numero for numero, dados in LINUX_SYSCALLS.items() if dados
}

#: Categorias exigidas e a gravidade de cada uma.
CATEGORIAS_ESPERADAS: Dict[str, str] = {
    "console-io": "baixo",
    "network": "alto",
    "filesystem": "medio",
    "process": "alto",
    "memory": "medio",
    "anti-analysis": "alto",
    "crypto": "medio",
    "persistence": "alto",
    "environment": "baixo",
    "data-processing": "baixo",
    "string-handling": "baixo",
    "self-modifying": "alto",
}

#: Exemplos prontos que o relatório mostra e que precisam continuar previsíveis.
EXEMPLOS_CONFERIDOS: Sequence[str] = (
    "linux-hello",
    "linux-loop",
    "linux-funcao",
    "windows-hello",
    "gcc-att",
    "bubble",
    "quebrado",
    "escala",
    "suspeito",
)

#: Táticas em pt-BR aceitas nas fichas do ATT&CK.
TATICAS: Set[str] = {
    "Execução",
    "Comando e Controle",
    "Descoberta",
    "Evasão de Defesa",
    "Persistência",
    "Impacto",
    "Coleta",
    "Exfiltração",
}


def fonte_syscalls(*nomes: str) -> str:
    """Monta um fonte com uma syscall por nome, usando os números do acervo.

    Args:
        *nomes: Nomes das syscalls, como estão em ``LINUX_SYSCALLS``.

    Returns:
        O código assembly pronto para :func:`asmx.analyzer.analyze`.
    """
    linhas = ["section .text", "_start:"]
    for nome in nomes:
        linhas.append("    mov rax, %d" % NUMERO_DA_SYSCALL[nome])
        linhas.append("    syscall")
    linhas.append("    ret")
    return "\n".join(linhas)


def comportamentos(codigo: str, com_problemas: bool = True) -> List[Behavior]:
    """Classifica um fonte e devolve os comportamentos encontrados.

    Args:
        codigo: Fonte assembly.
        com_problemas: Se deve passar os problemas do validador (``False``
            passa uma lista vazia, para medir só os sinais do próprio fonte).

    Returns:
        A lista devolvida por :func:`asmx.behavior.classify`.
    """
    analise = analyze(codigo)
    problemas = validate(analise) if com_problemas else []
    return classify(analise, problemas)


def categorias(codigo: str, com_problemas: bool = True) -> Set[str]:
    """Devolve o conjunto de categorias acionadas por um fonte.

    Args:
        codigo: Fonte assembly.
        com_problemas: Repassado para :func:`comportamentos`.

    Returns:
        Conjunto com as chaves das categorias encontradas.
    """
    return {b.category for b in comportamentos(codigo, com_problemas)}


def achar(codigo: str, categoria: str) -> Optional[Behavior]:
    """Procura o comportamento de uma categoria num fonte.

    Args:
        codigo: Fonte assembly.
        categoria: Chave procurada.

    Returns:
        O :class:`~asmx.behavior.Behavior` correspondente, ou ``None``.
    """
    for achado in comportamentos(codigo):
        if achado.category == categoria:
            return achado
    return None


def fabrica(mitre: Sequence[str] = ()) -> Behavior:
    """Monta um comportamento à mão, para testar serialização e técnicas.

    Args:
        mitre: Identificadores de técnica que o comportamento cita.

    Returns:
        Um :class:`~asmx.behavior.Behavior` de rede, com uma evidência.
    """
    return Behavior(
        category="network",
        label="Comunicação de rede",
        description="teste",
        severity="alto",
        confidence=60,
        lines=(1,),
        evidence=("linha 1: syscall socket (cria socket)",),
        mitre=tuple(mitre),
    )


class TestCatalogo(unittest.TestCase):
    """As tabelas públicas precisam bater com o que o relatório espera."""

    def test_categorias_exigidas(self) -> None:
        self.assertEqual(set(BEHAVIOR_CATEGORIES), set(CATEGORIAS_ESPERADAS))

    def test_gravidade_de_cada_categoria(self) -> None:
        for chave, gravidade in CATEGORIAS_ESPERADAS.items():
            with self.subTest(categoria=chave):
                self.assertEqual(BEHAVIOR_CATEGORIES[chave]["severity"], gravidade)

    def test_categorias_tem_rotulo_e_descricao(self) -> None:
        for chave, ficha in BEHAVIOR_CATEGORIES.items():
            with self.subTest(categoria=chave):
                self.assertEqual(set(ficha), {"label", "description", "severity"})
                self.assertTrue(ficha["label"].strip())
                self.assertTrue(ficha["description"].strip())

    def test_mitre_tem_as_tecnicas_do_projeto(self) -> None:
        esperadas = {
            "T1005",
            "T1012",
            "T1027",
            "T1041",
            "T1055",
            "T1057",
            "T1059",
            "T1071",
            "T1082",
            "T1083",
            "T1095",
            "T1105",
            "T1486",
            "T1497",
            "T1543",
            "T1547",
            "T1622",
        }
        self.assertEqual(set(MITRE_TECHNIQUES), esperadas)

    def test_mitre_tem_url_e_tatica_validas(self) -> None:
        for tecnica, ficha in MITRE_TECHNIQUES.items():
            with self.subTest(tecnica=tecnica):
                self.assertEqual(ficha["url"], "https://attack.mitre.org/techniques/%s/" % tecnica)
                self.assertIn(ficha["tactic"], TATICAS)
                self.assertTrue(ficha["name"].strip())

    def test_toda_descricao_de_tecnica_fala_em_indicio(self) -> None:
        for tecnica, ficha in MITRE_TECHNIQUES.items():
            with self.subTest(tecnica=tecnica):
                self.assertIn("Indício", ficha["description"])
                self.assertIn("não prova", ficha["description"])

    def test_mitre_dos_comportamentos_existe_no_catalogo(self) -> None:
        for nome in EXEMPLOS_CONFERIDOS:
            with self.subTest(exemplo=nome):
                for achado in comportamentos(EXAMPLES[nome]["code"]):
                    self.assertTrue(set(achado.mitre) <= set(MITRE_TECHNIQUES))

    def test_todas_as_categorias_sao_acionaveis(self) -> None:
        casos = {
            "console-io": fonte_syscalls("write"),
            "network": fonte_syscalls("socket"),
            "filesystem": fonte_syscalls("open"),
            "process": fonte_syscalls("execve"),
            "memory": "section .text\nmain:\n    mov rax, rdi\n    mov [rax], rbx\n    ret\n",
            "anti-analysis": "section .text\nmain:\n    int 3\n    ret\n",
            "crypto": fonte_syscalls("getrandom"),
            "persistence": 'section .data\n    c db "RunOnce", 0\nsection .text\nmain:\n    ret\n',
            "environment": fonte_syscalls("getpid"),
            "data-processing": "section .text\nmain:\n.laco:\n    add rax, 1\n    jmp .laco\n",
            "string-handling": "section .text\nmain:\n    rep movsb\n    ret\n",
            "self-modifying": (
                "section .text\nalvo:\n    nop\n_start:\n    mov byte [alvo], 1\n    ret\n"
            ),
        }
        self.assertEqual(set(casos), set(BEHAVIOR_CATEGORIES))
        for categoria, codigo in casos.items():
            with self.subTest(categoria=categoria):
                self.assertIn(categoria, categorias(codigo))


class TestConsoleERede(unittest.TestCase):
    """Console e rede: os sinais mais comuns num programa de exemplo."""

    def test_console_por_syscall_write(self) -> None:
        achado = achar(fonte_syscalls("write"), "console-io")
        assert achado is not None
        self.assertEqual(achado.severity, "baixo")
        self.assertIn("syscall write", achado.evidence[0])

    def test_console_por_syscall_read(self) -> None:
        achado = achar(fonte_syscalls("read"), "console-io")
        assert achado is not None
        self.assertIn("syscall read", achado.evidence[0])

    def test_console_pelas_apis_do_windows(self) -> None:
        codigo = (
            "extern GetStdHandle\n"
            "extern WriteConsoleA\n"
            "section .text\n"
            "main:\n"
            "    sub rsp, 40\n"
            "    mov rcx, -11\n"
            "    call GetStdHandle\n"
            "    mov rcx, rax\n"
            "    mov rdx, msg\n"
            "    mov r8, 5\n"
            "    mov r9, escritos\n"
            "    call WriteConsoleA\n"
            "    ret\n"
        )
        achado = achar(codigo, "console-io")
        assert achado is not None
        self.assertEqual(len(achado.evidence), 2)
        self.assertIn("GetStdHandle", achado.evidence[0])

    def test_rede_por_socket(self) -> None:
        achado = achar(fonte_syscalls("socket"), "network")
        assert achado is not None
        self.assertEqual(achado.severity, "alto")
        self.assertIn("T1095", achado.mitre)

    def test_rede_por_url_em_string(self) -> None:
        codigo = (
            "section .data\n"
            '    url db "https://coleta.exemplo.com/beacon", 0\n'
            "section .text\n"
            "main:\n"
            "    ret\n"
        )
        achado = achar(codigo, "network")
        assert achado is not None
        self.assertIn("https://coleta.exemplo.com/beacon", achado.evidence[0])
        self.assertIn("T1071", achado.mitre)

    def test_rede_por_ip_em_string(self) -> None:
        codigo = (
            "section .data\n" '    ip db "10.0.0.7", 0\n' "section .text\n" "main:\n" "    ret\n"
        )
        self.assertIn("network", categorias(codigo))

    def test_rede_por_wsastartup(self) -> None:
        codigo = "extern WSAStartup\nsection .text\nmain:\n    call WSAStartup\n    ret\n"
        achado = achar(codigo, "network")
        assert achado is not None
        self.assertIn("WSAStartup", achado.evidence[0])
        self.assertIn("T1095", achado.mitre)

    def test_rede_por_download_de_url(self) -> None:
        codigo = (
            "extern URLDownloadToFileA\n"
            "section .text\n"
            "main:\n"
            "    call URLDownloadToFileA\n"
            "    ret\n"
        )
        achado = achar(codigo, "network")
        assert achado is not None
        self.assertIn("T1105", achado.mitre)

    def test_linux_hello_nao_tem_rede(self) -> None:
        self.assertNotIn("network", categorias(EXAMPLES["linux-hello"]["code"]))

    def test_arquivos_por_syscall_open(self) -> None:
        achado = achar(fonte_syscalls("open"), "filesystem")
        assert achado is not None
        self.assertEqual(achado.severity, "medio")
        self.assertIn("T1005", achado.mitre)

    def test_arquivos_por_caminho_unix(self) -> None:
        codigo = (
            "section .data\n"
            '    caminho db "/etc/passwd", 0\n'
            "section .text\n"
            "main:\n"
            "    ret\n"
        )
        achado = achar(codigo, "filesystem")
        assert achado is not None
        self.assertIn("/etc/", achado.evidence[0])
        self.assertIn("T1083", achado.mitre)

    def test_arquivos_por_caminho_windows(self) -> None:
        codigo = (
            "section .data\n"
            '    caminho db "C:\\Users\\Public\\dados.txt", 0\n'
            "section .text\n"
            "main:\n"
            "    ret\n"
        )
        self.assertIn("filesystem", categorias(codigo))

    def test_arquivos_pela_api_createfile(self) -> None:
        codigo = "extern CreateFileA\nsection .text\nmain:\n    call CreateFileA\n    ret\n"
        achado = achar(codigo, "filesystem")
        assert achado is not None
        self.assertIn("CreateFileA", achado.evidence[0])


class TestProcessoEMemoria(unittest.TestCase):
    """Processo e memória, incluindo o alarme falso que foi corrigido."""

    def test_processo_por_execve(self) -> None:
        achado = achar(fonte_syscalls("execve"), "process")
        assert achado is not None
        self.assertEqual(achado.severity, "alto")
        self.assertIn("T1059", achado.mitre)

    def test_processo_por_createprocess(self) -> None:
        codigo = "extern CreateProcessA\nsection .text\nmain:\n    call CreateProcessA\n    ret\n"
        achado = achar(codigo, "process")
        assert achado is not None
        self.assertIn("CreateProcessA", achado.evidence[0])

    def test_processo_por_funcao_externa_de_execucao(self) -> None:
        codigo = "extern system\nsection .text\nmain:\n    call system\n    ret\n"
        achado = achar(codigo, "process")
        assert achado is not None
        self.assertIn("call system", achado.evidence[0])

    def test_encerrar_o_programa_nao_e_processo(self) -> None:
        exitprocess = (
            "extern ExitProcess\nsection .text\nmain:\n    xor rcx, rcx\n    call ExitProcess\n"
        )
        self.assertNotIn("process", categorias(exitprocess))
        self.assertEqual(categorias(exitprocess), set())
        self.assertNotIn("process", categorias(fonte_syscalls("exit")))

    def test_chamada_indireta_nao_e_funcao_externa(self) -> None:
        codigo = "section .text\nmain:\n    call [rbx]\n    ret\n"
        self.assertEqual(categorias(codigo), set())

    def test_memoria_por_escrita_em_ponteiro(self) -> None:
        codigo = "section .text\nmain:\n    mov rax, rdi\n    mov [rax], rbx\n    ret\n"
        achado = achar(codigo, "memory")
        assert achado is not None
        self.assertIn("endereço apontado", achado.evidence[0])

    def test_memoria_por_simbolo_nao_declarado(self) -> None:
        codigo = "section .text\nmain:\n    mov [contador], 1\n    ret\n"
        achado = achar(codigo, "memory")
        assert achado is not None
        self.assertIn("contador", achado.evidence[0])

    def test_memoria_por_mmap_e_mprotect(self) -> None:
        achado = achar(fonte_syscalls("mmap", "mprotect"), "memory")
        assert achado is not None
        self.assertIn("T1055", achado.mitre)

    def test_memoria_por_virtualalloc(self) -> None:
        codigo = "extern VirtualAlloc\nsection .text\nmain:\n    call VirtualAlloc\n    ret\n"
        achado = achar(codigo, "memory")
        assert achado is not None
        self.assertIn("VirtualAlloc", achado.evidence[0])

    def test_memoria_nao_dispara_em_variavel_local(self) -> None:
        codigo = "section .text\nmain:\n    mov [rbp-8], rax\n    mov rax, [rbp-8]\n    ret\n"
        self.assertNotIn("memory", categorias(codigo))


class TestEvasaoCryptoEPersistencia(unittest.TestCase):
    """Os sinais de gravidade alta e os indícios fracos."""

    def test_anti_analysis_por_int3(self) -> None:
        achado = achar("section .text\nmain:\n    int 3\n    ret\n", "anti-analysis")
        assert achado is not None
        self.assertIn("int 3", achado.evidence[0])
        self.assertIn("T1622", achado.mitre)

    def test_anti_analysis_por_cpuid_e_rdtsc(self) -> None:
        achado = achar("section .text\nmain:\n    cpuid\n    rdtsc\n    ret\n", "anti-analysis")
        assert achado is not None
        self.assertEqual(len(achado.evidence), 2)
        self.assertIn("T1497", achado.mitre)

    def test_anti_analysis_por_int3_colado(self) -> None:
        achado = achar("section .text\nmain:\n    int3\n    ret\n", "anti-analysis")
        assert achado is not None
        self.assertIn("int 3", achado.evidence[0])

    def test_anti_analysis_por_aviso_sem_instrucao_na_linha(self) -> None:
        codigo = "section .text\nmain:\n    nop\n"
        problemas = [Problem(2, "info", "INT001", "falha interna na regra check_x")]
        achados = classify(analyze(codigo), problemas)
        categorias_achadas = {b.category for b in achados}
        self.assertIn("anti-analysis", categorias_achadas)
        achado = [b for b in achados if b.category == "anti-analysis"][0]
        self.assertIn("check_x", achado.evidence[0])
        self.assertLessEqual(achado.confidence, 50)

    def test_anti_analysis_por_ptrace(self) -> None:
        achado = achar(fonte_syscalls("ptrace"), "anti-analysis")
        assert achado is not None
        self.assertIn("syscall ptrace", achado.evidence[0])
        self.assertIn("T1622", achado.mitre)

    def test_anti_analysis_por_tempo_em_laco_e_fraco(self) -> None:
        codigo = "section .text\nmain:\n.laco:\n    mov rax, 201\n    syscall\n    jmp .laco\n"
        achado = achar(codigo, "anti-analysis")
        assert achado is not None
        self.assertLessEqual(achado.confidence, 50)
        self.assertIn("indício", achado.evidence[0])

    def test_anti_analysis_com_aviso_de_fluxo_do_validador(self) -> None:
        codigo = "section .text\nmain:\n.parado:\n    jmp .parado\n"
        com = categorias(codigo)
        sem = categorias(codigo, com_problemas=False)
        self.assertIn("anti-analysis", com)
        self.assertNotIn("anti-analysis", sem)

    def test_anti_analysis_por_aviso_e_sempre_fraco(self) -> None:
        codigo = "section .text\nmain:\n.parado:\n    jmp .parado\n"
        achado = achar(codigo, "anti-analysis")
        assert achado is not None
        self.assertLessEqual(achado.confidence, 50)
        self.assertIn("FLOW002", achado.evidence[0])

    def test_crypto_por_getrandom(self) -> None:
        achado = achar(fonte_syscalls("getrandom"), "crypto")
        assert achado is not None
        self.assertEqual(achado.severity, "medio")
        self.assertIn("syscall getrandom", achado.evidence[0])

    def test_crypto_por_laco_de_bits_e_fraco(self) -> None:
        codigo = (
            "section .text\n"
            "main:\n"
            ".laco:\n"
            "    xor rbx, rcx\n"
            "    shl rbx, 3\n"
            "    shr rbx, 1\n"
            "    rol rbx, 2\n"
            "    ror rbx, 5\n"
            "    jmp .laco\n"
        )
        achado = achar(codigo, "crypto")
        assert achado is not None
        self.assertLessEqual(achado.confidence, 50)
        self.assertIn("indício", achado.evidence[0])
        self.assertIn("T1027", achado.mitre)

    def test_xor_de_zerar_nao_conta_como_cifra(self) -> None:
        codigo = (
            "section .text\n"
            "main:\n"
            ".laco:\n"
            "    xor rax, rax\n"
            "    xor rbx, rbx\n"
            "    xor rcx, rcx\n"
            "    xor rdx, rdx\n"
            "    jmp .laco\n"
        )
        self.assertNotIn("crypto", categorias(codigo))

    def test_persistencia_por_chave_run(self) -> None:
        codigo = (
            "section .data\n"
            '    chave db "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0\n'
            "section .text\n"
            "main:\n"
            "    ret\n"
        )
        achado = achar(codigo, "persistence")
        assert achado is not None
        self.assertEqual(achado.severity, "alto")
        self.assertIn("T1547", achado.mitre)

    def test_persistencia_por_cron(self) -> None:
        codigo = (
            "section .data\n"
            '    alvo db "/etc/cron.d/backdoor", 0\n'
            "section .text\n"
            "main:\n"
            "    ret\n"
        )
        achado = achar(codigo, "persistence")
        assert achado is not None
        self.assertIn("T1543", achado.mitre)

    def test_persistencia_por_arquivo_em_laco(self) -> None:
        codigo = (
            "section .data\n"
            '    nome db "x", 0\n'
            "section .text\n"
            "main:\n"
            ".laco:\n"
            "    mov rax, 2\n"
            "    syscall\n"
            "    jmp .laco\n"
        )
        achado = achar(codigo, "persistence")
        assert achado is not None
        self.assertIn("syscall open", achado.evidence[0])
        self.assertIn("filesystem", categorias(codigo))

    def test_persistencia_por_api_de_arquivo_em_laco(self) -> None:
        codigo = (
            "extern CreateFileA\n"
            "section .text\n"
            "main:\n"
            ".laco:\n"
            "    call CreateFileA\n"
            "    jmp .laco\n"
        )
        achado = achar(codigo, "persistence")
        assert achado is not None
        self.assertIn("API CreateFileA", achado.evidence[0])


class TestAmbienteEAlgoritmo(unittest.TestCase):
    """As categorias de gravidade baixa e o código automodificável."""

    def test_ambiente_por_getpid_e_time(self) -> None:
        achado = achar(fonte_syscalls("getpid", "time"), "environment")
        assert achado is not None
        self.assertIn("T1057", achado.mitre)
        self.assertIn("T1082", achado.mitre)

    def test_ambiente_pelas_apis_do_windows(self) -> None:
        codigo = (
            "extern GetLastError\n"
            "extern GetVersion\n"
            "section .text\n"
            "main:\n"
            "    call GetLastError\n"
            "    call GetVersion\n"
            "    ret\n"
        )
        achado = achar(codigo, "environment")
        assert achado is not None
        self.assertEqual(len(achado.evidence), 2)

    def test_processamento_de_dados_por_laco(self) -> None:
        codigo = (
            "section .text\n"
            "main:\n"
            "    mov rcx, 5\n"
            ".laco:\n"
            "    add rax, rcx\n"
            "    dec rcx\n"
            "    jnz .laco\n"
            "    ret\n"
        )
        achado = achar(codigo, "data-processing")
        assert achado is not None
        self.assertIn("add rax rcx", achado.evidence[0])
        self.assertEqual(achado.mitre, ())

    def test_laco_so_de_comparacao_nao_e_algoritmo(self) -> None:
        codigo = (
            "section .text\n" "main:\n" ".laco:\n" "    cmp rcx, 0\n" "    jne .laco\n" "    ret\n"
        )
        self.assertNotIn("data-processing", categorias(codigo))

    def test_string_handling_por_rep_movsb(self) -> None:
        codigo = "section .text\nmain:\n    cld\n    rep movsb\n    ret\n"
        achado = achar(codigo, "string-handling")
        assert achado is not None
        self.assertIn("rep movsb", achado.evidence[0])

    def test_string_handling_por_laco_indexado(self) -> None:
        codigo = (
            "section .data\n"
            "    vetor db 1, 2, 3, 4\n"
            "section .text\n"
            "main:\n"
            "    mov rsi, 0\n"
            ".laco:\n"
            "    mov al, [vetor + rsi]\n"
            "    mov [vetor + rsi], al\n"
            "    inc rsi\n"
            "    cmp rsi, 4\n"
            "    jb .laco\n"
            "    ret\n"
        )
        achado = achar(codigo, "string-handling")
        assert achado is not None
        self.assertLessEqual(achado.confidence, 50)

    def test_auto_modificavel_por_escrita_em_rotulo_de_codigo(self) -> None:
        codigo = (
            "section .text\n"
            "alvo:\n"
            "    nop\n"
            "_start:\n"
            "    mov byte [alvo], 0x90\n"
            "    ret\n"
        )
        achado = achar(codigo, "self-modifying")
        assert achado is not None
        self.assertEqual(achado.severity, "alto")
        self.assertIn("alvo", achado.evidence[0])
        self.assertIn("T1027", achado.mitre)

    def test_escrita_em_variavel_de_dados_nao_e_auto_modificavel(self) -> None:
        codigo = (
            "section .data\n"
            "    alvo db 0\n"
            "section .text\n"
            "main:\n"
            "    mov byte [alvo], 1\n"
            "    ret\n"
        )
        self.assertNotIn("self-modifying", categorias(codigo))

    def test_auto_modificavel_sem_diretiva_de_secao(self) -> None:
        codigo = "alvo:\n    nop\n_start:\n    mov byte [alvo], 0x90\n    ret\n"
        self.assertIn("self-modifying", categorias(codigo))

    def test_memoria_por_rtlmovememory(self) -> None:
        codigo = "extern RtlMoveMemory\nsection .text\nmain:\n    call RtlMoveMemory\n    ret\n"
        achado = achar(codigo, "memory")
        assert achado is not None
        self.assertIn("RtlMoveMemory", achado.evidence[0])
        self.assertIn("memória do processo", achado.evidence[0])


class TestExemplos(unittest.TestCase):
    """Os exemplos prontos precisam manter a leitura que o relatório promete."""

    def test_linux_hello(self) -> None:
        achados = comportamentos(EXAMPLES["linux-hello"]["code"])
        self.assertEqual([b.category for b in achados], ["console-io"])
        self.assertEqual(achados[0].severity, "baixo")

    def test_linux_loop(self) -> None:
        self.assertEqual(categorias(EXAMPLES["linux-loop"]["code"]), {"console-io"})

    def test_linux_funcao(self) -> None:
        achadas = categorias(EXAMPLES["linux-funcao"]["code"])
        self.assertIn("console-io", achadas)
        self.assertIn("memory", achadas)
        self.assertNotIn("network", achadas)

    def test_windows_hello_apenas_console(self) -> None:
        achados = comportamentos(EXAMPLES["windows-hello"]["code"])
        self.assertEqual([b.category for b in achados], ["console-io"])
        self.assertEqual(achados[0].severity, "baixo")

    def test_windows_hello_nao_tem_comportamento_alto(self) -> None:
        for achado in comportamentos(EXAMPLES["windows-hello"]["code"]):
            self.assertNotEqual(achado.severity, "alto")

    def test_gcc_att_nao_levanta_e_nao_inventa(self) -> None:
        achados = comportamentos(EXAMPLES["gcc-att"]["code"])
        self.assertEqual([b.category for b in achados], [])

    def test_bubble_e_algoritmo_e_bloco_de_bytes(self) -> None:
        achadas = categorias(EXAMPLES["bubble"]["code"])
        self.assertIn("data-processing", achadas)
        self.assertIn("string-handling", achadas)

    def test_quebrado_tem_pelo_menos_duas_categorias(self) -> None:
        achadas = categorias(EXAMPLES["quebrado"]["code"])
        self.assertGreaterEqual(len(achadas), 2)
        self.assertIn("anti-analysis", achadas)

    def test_escala_e_processamento_de_dados(self) -> None:
        achadas = categorias(EXAMPLES["escala"]["code"])
        self.assertIn("data-processing", achadas)
        self.assertNotIn("network", achadas)

    def test_suspeito_tem_rede_arquivo_e_cripto(self) -> None:
        achados = {b.category: b for b in comportamentos(EXAMPLES["suspeito"]["code"])}
        self.assertEqual(achados["network"].severity, "alto")
        self.assertEqual(achados["crypto"].severity, "medio")
        self.assertEqual(achados["filesystem"].severity, "medio")
        self.assertIn("console-io", achados)
        self.assertIn("environment", achados)

    def test_suspeito_nao_inventa_processo(self) -> None:
        self.assertNotIn("process", categorias(EXAMPLES["suspeito"]["code"]))

    def test_todo_exemplo_tem_evidencia_com_linha(self) -> None:
        for nome in EXEMPLOS_CONFERIDOS:
            with self.subTest(exemplo=nome):
                for achado in comportamentos(EXAMPLES[nome]["code"]):
                    self.assertTrue(achado.evidence)
                    for evidencia in achado.evidence:
                        self.assertRegex(evidencia, r"^linha \d+: \S")

    def test_todo_exemplo_devolve_lista(self) -> None:
        for nome in EXEMPLOS_CONFERIDOS:
            with self.subTest(exemplo=nome):
                self.assertIsInstance(comportamentos(EXAMPLES[nome]["code"]), list)


class TestRegras(unittest.TestCase):
    """Confiança, ordenação e formato das evidências."""

    def test_confianca_60_com_poucas_evidencias(self) -> None:
        uma = achar(fonte_syscalls("write"), "console-io")
        duas = achar(fonte_syscalls("write", "read"), "console-io")
        assert uma is not None and duas is not None
        self.assertEqual(uma.confidence, 60)
        self.assertEqual(duas.confidence, 60)

    def test_confianca_80_com_tres_a_cinco_evidencias(self) -> None:
        achado = achar(fonte_syscalls("socket", "connect", "bind"), "network")
        assert achado is not None
        self.assertEqual(len(achado.evidence), 3)
        self.assertEqual(achado.confidence, 80)

    def test_confianca_95_com_seis_evidencias(self) -> None:
        codigo = fonte_syscalls("socket", "connect", "bind", "listen", "accept", "sendto")
        achado = achar(codigo, "network")
        assert achado is not None
        self.assertEqual(len(achado.evidence), 6)
        self.assertEqual(achado.confidence, 95)

    def test_confianca_sempre_entre_zero_e_cem(self) -> None:
        for nome in EXEMPLOS_CONFERIDOS:
            for achado in comportamentos(EXAMPLES[nome]["code"]):
                self.assertGreaterEqual(achado.confidence, 0)
                self.assertLessEqual(achado.confidence, 100)

    def test_ordenacao_por_gravidade(self) -> None:
        achados = comportamentos(fonte_syscalls("socket", "write"))
        ranks = [severity_rank(b.severity) for b in achados]
        self.assertEqual(ranks, sorted(ranks))
        self.assertEqual(achados[0].category, "network")

    def test_linhas_ordenadas_e_sem_repeticao(self) -> None:
        for nome in EXEMPLOS_CONFERIDOS:
            for achado in comportamentos(EXAMPLES[nome]["code"]):
                self.assertEqual(list(achado.lines), sorted(set(achado.lines)))

    def test_evidencia_cita_linha_e_sinal(self) -> None:
        achado = achar(fonte_syscalls("socket", "connect"), "network")
        assert achado is not None
        for evidencia in achado.evidence:
            self.assertRegex(evidencia, r"^linha \d+: ")
        self.assertTrue(any("syscall socket" in e for e in achado.evidence))
        self.assertTrue(any("syscall connect" in e for e in achado.evidence))

    def test_categoria_sem_sinal_nao_aparece(self) -> None:
        codigo = "section .text\nmain:\n    mov rax, 1\n    add rax, 2\n    ret\n"
        self.assertEqual(categorias(codigo), set())

    def test_numero_de_syscall_desconhecido_nao_inventa_categoria(self) -> None:
        codigo = "section .text\n_start:\n    mov rax, 999\n    syscall\n    ret\n"
        self.assertEqual(categorias(codigo), set())

    def test_gravidade_do_comportamento_vem_do_catalogo(self) -> None:
        for nome in EXEMPLOS_CONFERIDOS:
            for achado in comportamentos(EXAMPLES[nome]["code"]):
                self.assertEqual(achado.severity, BEHAVIOR_CATEGORIES[achado.category]["severity"])


class TestSerializacao(unittest.TestCase):
    """``to_dicts``, ``techniques``, ``by_tactic``, ``summary`` e a ordenação."""

    def test_to_dicts_devolve_dicionarios(self) -> None:
        achados = comportamentos(EXAMPLES["suspeito"]["code"])
        dicionarios = to_dicts(achados)
        self.assertEqual(len(dicionarios), len(achados))
        for dicionario in dicionarios:
            self.assertEqual(
                set(dicionario),
                {
                    "category",
                    "label",
                    "description",
                    "severity",
                    "confidence",
                    "lines",
                    "evidence",
                    "mitre",
                },
            )

    def test_to_dicts_usa_listas(self) -> None:
        dicionario = to_dicts([fabrica(["T1095"])])[0]
        self.assertEqual(dicionario["lines"], [1])
        self.assertEqual(dicionario["evidence"], ["linha 1: syscall socket (cria socket)"])
        self.assertEqual(dicionario["mitre"], ["T1095"])

    def test_to_dicts_de_lista_vazia(self) -> None:
        self.assertEqual(to_dicts([]), [])

    def test_comportamento_e_imutavel(self) -> None:
        achado = fabrica()
        with self.assertRaises(FrozenInstanceError):
            setattr(achado, "category", "outra")

    def test_techniques_agrupa_por_tecnica(self) -> None:
        achados = comportamentos(EXAMPLES["suspeito"]["code"])
        lista = techniques(achados)
        ids = [tecnica["id"] for tecnica in lista]
        self.assertEqual(ids, sorted(ids))
        self.assertIn("T1095", ids)
        self.assertIn("T1071", ids)
        self.assertIn("T1486", ids)
        for tecnica in lista:
            self.assertTrue(tecnica["behaviors"])
            self.assertEqual(
                tecnica["url"], "https://attack.mitre.org/techniques/%s/" % tecnica["id"]
            )

    def test_techniques_sem_comportamento(self) -> None:
        self.assertEqual(techniques([]), [])

    def test_techniques_ignora_identificador_desconhecido(self) -> None:
        self.assertEqual(techniques([fabrica(["T9999"])]), [])

    def test_techniques_nao_repete_categoria(self) -> None:
        lista = techniques([fabrica(["T1095"]), fabrica(["T1095"])])
        self.assertEqual(lista[0]["behaviors"], ["network"])

    def test_by_tactic_com_tatica_fora_da_ordem(self) -> None:
        ficha = {
            "name": "Técnica de teste",
            "tactic": "Curiosidade",
            "url": "https://attack.mitre.org/techniques/T9999/",
            "description": "Indício derivado de padrões estáticos.",
        }
        with mock.patch.dict(MITRE_TECHNIQUES, {"T9999": ficha}):
            grupos = by_tactic([fabrica(["T9999"])])
        self.assertEqual(list(grupos), ["Curiosidade"])

    def test_by_tactic_ordena_as_taticas(self) -> None:
        achados = comportamentos(EXAMPLES["suspeito"]["code"])
        grupos = by_tactic(achados)
        self.assertEqual(
            list(grupos),
            ["Comando e Controle", "Descoberta", "Coleta", "Exfiltração", "Impacto"],
        )
        for tatica, lista in grupos.items():
            for tecnica in lista:
                self.assertEqual(tecnica["tactic"], tatica)

    def test_by_tactic_sem_comportamento(self) -> None:
        self.assertEqual(by_tactic([]), {})

    def test_summary_vazio(self) -> None:
        self.assertEqual(summary([]), "0 comportamento(s)")

    def test_summary_com_varios(self) -> None:
        achados = comportamentos(EXAMPLES["suspeito"]["code"])
        self.assertEqual(
            summary(achados),
            "5 comportamento(s): rede (alto), criptografia (medio), arquivos (medio), "
            "console (baixo), ambiente (baixo)",
        )

    def test_summary_com_um(self) -> None:
        self.assertEqual(
            summary(comportamentos(EXAMPLES["linux-hello"]["code"])),
            "1 comportamento(s): console (baixo)",
        )

    def test_severity_rank_ordena(self) -> None:
        self.assertEqual(severity_rank("alto"), 0)
        self.assertEqual(severity_rank("medio"), 1)
        self.assertEqual(severity_rank("baixo"), 2)

    def test_severity_rank_aceita_acento_e_caixa(self) -> None:
        self.assertEqual(severity_rank("MÉDIO"), 1)
        self.assertEqual(severity_rank(" Médio "), 1)

    def test_severity_rank_desconhecido(self) -> None:
        self.assertEqual(severity_rank("urgente"), 3)
        self.assertEqual(severity_rank(""), 3)


class TestBordas(unittest.TestCase):
    """Programa vazio, só dados, lixo e a costura com o validador."""

    def test_programa_vazio(self) -> None:
        self.assertEqual(classify(analyze("")), [])

    def test_programa_so_espacos(self) -> None:
        self.assertEqual(classify(analyze("\n\n   \n\t\n")), [])

    def test_programa_so_com_dados(self) -> None:
        codigo = 'section .data\n    msg db "texto simples", 10\n    tam equ $ - msg\n'
        self.assertEqual(categorias(codigo), set())

    def test_programa_so_com_dados_mas_com_url(self) -> None:
        codigo = 'section .data\n    u db "http://x.exemplo.com", 0\n'
        self.assertIn("network", categorias(codigo))

    def test_programa_windows_masm(self) -> None:
        codigo = (
            ".386\n"
            ".model flat, stdcall\n"
            "includelib kernel32.lib\n"
            ".data\n"
            '    msg db "ola", 0\n'
            ".code\n"
            "main PROC\n"
            "    sub rsp, 40\n"
            "    mov rcx, -11\n"
            "    call GetStdHandle\n"
            "    mov rcx, rax\n"
            "    mov rdx, msg\n"
            "    mov r8, 5\n"
            "    mov r9, escritos\n"
            "    call WriteConsoleA\n"
            "    ret\n"
            "main ENDP\n"
            "end main\n"
        )
        self.assertEqual(categorias(codigo), {"console-io"})

    def test_classify_nao_levanta_com_lixo(self) -> None:
        for codigo in ("\x00\x01 ??? @@\n", "a" * 500, "ПРИВЕТ\n mov ,,\n"):
            with self.subTest(codigo=codigo[:12]):
                self.assertIsInstance(classify(analyze(codigo)), list)

    def test_classify_aceita_problemas_none(self) -> None:
        codigo = "section .text\nmain:\n.parado:\n    jmp .parado\n"
        analise = analyze(codigo)
        automatico = [b.category for b in classify(analise)]
        explicito = [b.category for b in classify(analise, validate(analise))]
        self.assertEqual(automatico, explicito)

    def test_classify_sem_problemas_nao_usa_validador(self) -> None:
        codigo = "section .text\nmain:\n.parado:\n    jmp .parado\n"
        self.assertEqual(classify(analyze(codigo), []), [])

    def test_classify_com_analise_nula(self) -> None:
        self.assertEqual(classify(None), [])  # type: ignore[arg-type]

    def test_classify_com_programa_sem_linhas(self) -> None:
        vazio = types.SimpleNamespace(program=types.SimpleNamespace(lines=[]))
        self.assertEqual(classify(vazio), [])  # type: ignore[arg-type]

    def test_validador_que_falha_nao_derruba_o_relatorio(self) -> None:
        codigo = EXAMPLES["linux-hello"]["code"]
        with mock.patch("asmx.behavior.validate", side_effect=RuntimeError("quebrou")):
            achados = classify(analyze(codigo))
        self.assertEqual([b.category for b in achados], ["console-io"])

    def test_falha_interna_devolve_lista(self) -> None:
        codigo = "section .text\nmain:\n    mov rax, 1\n    syscall\n    ret\n"
        with mock.patch("asmx.behavior._context", side_effect=RuntimeError("quebrou")):
            self.assertEqual(classify(analyze(codigo)), [])


if __name__ == "__main__":
    unittest.main()
