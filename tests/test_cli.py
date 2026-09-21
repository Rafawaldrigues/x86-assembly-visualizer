"""Testes da linha de comando: comandos, códigos de saída e JSON."""

import contextlib
import io
import json
import os
import tempfile
import unittest
import unittest.mock

from asmx.cli import (
    EXIT_INPUT,
    EXIT_OK,
    EXIT_PROBLEMS,
    EXIT_TIMEOUT,
    EXIT_USAGE,
    Palette,
    build_parser,
    build_payload,
    describe_instruction,
    launch_gui,
    load_config,
    main,
)
from asmx.examples import EXAMPLES
from asmx.logging_setup import reset_logging

#: Programa limpo, usado na maioria dos casos.
LIMPO = EXAMPLES["linux-hello"]["code"]

#: Programa com defeitos de propósito.
QUEBRADO = EXAMPLES["quebrado"]["code"]

#: Programa que nunca termina sozinho.
INFINITO = "global _start\nsection .text\n_start:\n.trava:\n jmp .trava\n"


class BaseCLI(unittest.TestCase):
    """Arquivos temporários, captura de saída e logging limpo."""

    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.limpo = self.escreve("limpo.asm", LIMPO)
        self.quebrado = self.escreve("quebrado.asm", QUEBRADO)
        self.infinito = self.escreve("infinito.asm", INFINITO)
        self.escala = self.escreve("escala.asm", EXAMPLES["escala"]["code"])

    def tearDown(self) -> None:
        self.dir.cleanup()
        reset_logging()

    def escreve(self, nome: str, conteudo: str) -> str:
        caminho = os.path.join(self.dir.name, nome)
        with open(caminho, "w", encoding="utf-8") as arquivo:
            arquivo.write(conteudo)
        return caminho

    def run_cli(self, *argv: str) -> tuple:
        saida, erro = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(saida), contextlib.redirect_stderr(erro):
            codigo = main(list(argv))
        return codigo, saida.getvalue(), erro.getvalue()

    def run_json(self, *argv: str) -> tuple:
        codigo, saida, erro = self.run_cli(*argv, "--json")
        return codigo, json.loads(saida), erro


class TestVersionEObjetos(BaseCLI):
    """Comandos simples e funções auxiliares."""

    def test_version_texto(self) -> None:
        codigo, saida, _ = self.run_cli("version")
        self.assertEqual(codigo, EXIT_OK)
        self.assertIn("ASM X 1.0.0", saida)

    def test_version_json(self) -> None:
        codigo, dados, _ = self.run_json("version")
        self.assertEqual(codigo, EXIT_OK)
        self.assertEqual(dados["version"], "1.0.0")
        self.assertEqual(dados["schema"], "asmx-version/1")

    def test_info_texto(self) -> None:
        codigo, saida, _ = self.run_cli("info")
        self.assertEqual(codigo, EXIT_OK)
        self.assertIn("148 instruções", saida)
        self.assertIn("configuração:", saida)

    def test_info_json(self) -> None:
        codigo, dados, _ = self.run_json("info")
        self.assertEqual(codigo, EXIT_OK)
        self.assertEqual(dados["isa"]["mnemonics"], 148)
        self.assertEqual(dados["isa"]["linux_syscalls"], 43)
        self.assertEqual(dados["isa"]["examples"], 8)
        self.assertIn("tkinter", dados)
        self.assertIn("config", dados)
        self.assertIn("logging", dados)

    def test_sem_comando_mostra_ajuda(self) -> None:
        codigo, saida, _ = self.run_cli()
        self.assertEqual(codigo, EXIT_USAGE)
        self.assertIn("COMANDO", saida)

    def test_comando_inexistente_e_erro_de_uso(self) -> None:
        with self.assertRaises(SystemExit) as contexto:
            with contextlib.redirect_stderr(io.StringIO()):
                main(["inventado"])
        self.assertEqual(contexto.exception.code, EXIT_USAGE)

    def test_palette_desligada_nao_pinta(self) -> None:
        self.assertEqual(Palette(False).paint("erro", "erro"), "erro")
        self.assertIn("\033[", Palette(True).paint("erro", "erro"))
        self.assertEqual(Palette(True).paint("x", "cor_inexistente"), "x")

    def test_no_color_nao_emite_ansi(self) -> None:
        codigo, saida, _ = self.run_cli("check", self.quebrado, "--no-color")
        self.assertEqual(codigo, EXIT_PROBLEMS)
        self.assertNotIn("\033[", saida)

    def test_describe_instruction(self) -> None:
        from asmx.analyzer import analyze

        ficha = describe_instruction(analyze("mov rax, 1").instrs[0])
        self.assertEqual(ficha["mnemonic"], "mov")
        self.assertEqual(ficha["label"], "Define constante")
        self.assertEqual(ficha["operands"][0]["type"], "reg")
        self.assertEqual(ficha["documentation"]["syntax"], "MOV destino, origem")

    def test_build_payload(self) -> None:
        args = build_parser().parse_args(["check", "a.asm", "b.asm"])
        self.assertEqual(build_payload(args), {"command": "check", "files": ["a.asm", "b.asm"]})

    def test_load_config_junta_linha_de_comando(self) -> None:
        args = build_parser().parse_args(["-v", "--log-json", "check", "a.asm"])
        config = load_config(args)
        self.assertEqual(config.log_level, "DEBUG")
        self.assertTrue(config.log_json)

    def test_launch_gui_sem_display(self) -> None:
        erro = io.StringIO()
        with (
            unittest.mock.patch.dict(os.environ, {"DISPLAY": ""}),
            contextlib.redirect_stderr(erro),
        ):
            self.assertEqual(launch_gui(), EXIT_INPUT)
        self.assertIn("não consegui abrir a janela", erro.getvalue())


class TestCheck(BaseCLI):
    """Comando ``check``."""

    def test_arquivo_limpo(self) -> None:
        codigo, saida, _ = self.run_cli("check", self.limpo, "--no-color")
        self.assertEqual(codigo, EXIT_OK)
        self.assertIn("nenhum problema encontrado", saida)
        self.assertIn("plataforma  linux", saida)

    def test_arquivo_com_defeitos(self) -> None:
        codigo, saida, _ = self.run_cli("check", self.quebrado, "--no-color")
        self.assertEqual(codigo, EXIT_PROBLEMS)
        self.assertIn("DIV001", saida)
        self.assertIn("→", saida)

    def test_summary_only_esconde_a_lista(self) -> None:
        _, saida, _ = self.run_cli("check", self.quebrado, "--summary-only", "--no-color")
        self.assertNotIn("DIV001", saida)
        self.assertIn("erro(s)", saida)

    def test_exit_zero_forca_sucesso(self) -> None:
        codigo, _, _ = self.run_cli("check", self.quebrado, "--exit-zero")
        self.assertEqual(codigo, EXIT_OK)

    def test_min_severity_info_reprova_alertas(self) -> None:
        codigo, _, _ = self.run_cli("check", self.limpo, "--min-severity", "info")
        self.assertEqual(codigo, EXIT_OK)
        codigo, _, _ = self.run_cli("check", self.escala, "--min-severity", "alerta")
        self.assertEqual(codigo, EXIT_PROBLEMS)

    def test_json(self) -> None:
        codigo, dados, _ = self.run_json("check", self.quebrado)
        self.assertEqual(codigo, EXIT_PROBLEMS)
        arquivo = dados["files"][0]
        self.assertEqual(dados["schema"], "asmx-check/1")
        self.assertEqual(arquivo["source"]["name"], "quebrado.asm")
        self.assertEqual(arquivo["platform"]["os"], "linux")
        self.assertGreater(arquivo["summary"]["errors"], 0)
        self.assertEqual(arquivo["problems"][0]["line"] > 0, True)
        self.assertEqual(dados["exit_code"], EXIT_PROBLEMS)

    def test_varios_arquivos_resume_no_fim(self) -> None:
        codigo, saida, _ = self.run_cli("check", self.limpo, self.quebrado, "--no-color")
        self.assertEqual(codigo, EXIT_PROBLEMS)
        self.assertIn("2 arquivo(s)", saida)

    def test_json_de_varios_arquivos(self) -> None:
        _, dados, _ = self.run_json("check", self.limpo, self.quebrado)
        self.assertEqual(dados["summary"]["files"], 2)

    def test_arquivo_ausente(self) -> None:
        codigo, _, erro = self.run_cli("check", os.path.join(self.dir.name, "nada.asm"))
        self.assertEqual(codigo, EXIT_INPUT)
        self.assertIn("ERR_SOURCE_NOT_FOUND", erro)

    def test_extensao_recusada(self) -> None:
        caminho = self.escreve("programa.bin", "mov rax, 1")
        codigo, _, erro = self.run_cli("check", caminho)
        self.assertEqual(codigo, EXIT_INPUT)
        self.assertIn("ERR_UNSUPPORTED_SOURCE", erro)

    def test_codificacao_latin1_avisada(self) -> None:
        caminho = os.path.join(self.dir.name, "antigo.asm")
        with open(caminho, "wb") as arquivo:
            arquivo.write("; ação\nmov rax, 1\n".encode("latin-1"))
        _, saida, _ = self.run_cli("check", caminho, "--no-color")
        self.assertIn("latin-1", saida)


class TestRun(BaseCLI):
    """Comando ``run``."""

    def test_programa_limpo(self) -> None:
        codigo, saida, _ = self.run_cli("run", self.limpo)
        self.assertEqual(codigo, EXIT_OK)
        self.assertIn("Ola, mundo!", saida)
        self.assertIn("código de saída 0", saida)

    def test_json(self) -> None:
        codigo, dados, _ = self.run_json("run", self.limpo)
        self.assertEqual(codigo, EXIT_OK)
        self.assertEqual(dados["output"], "Ola, mundo!\n")
        self.assertEqual(dados["exit_code"], 0)
        self.assertTrue(dados["halted"])
        self.assertFalse(dados["timed_out"])
        self.assertEqual(dados["registers"]["rax"], "0x3c")
        self.assertIn("ZF", dados["flags"])

    def test_trace(self) -> None:
        _, dados, _ = self.run_json("run", self.limpo, "--trace", "--max-trace", "3")
        self.assertEqual(len(dados["trace"]), 3)
        self.assertIn("note", dados["trace"][0])

    def test_trace_em_texto(self) -> None:
        _, saida, _ = self.run_cli("run", self.limpo, "--trace", "--no-color")
        self.assertIn("histórico:", saida)

    def test_entrada_simulada(self) -> None:
        codigo = (
            "section .bss\nbuf resb 8\nsection .text\nglobal _start\n_start:\n"
            "mov rax, 0\nmov rdi, 0\nmov rsi, buf\nmov rdx, 3\nsyscall\n"
            "mov rax, 1\nmov rdi, 1\nmov rsi, buf\nmov rdx, 3\nsyscall\n"
            "mov rax, 60\nxor rdi, rdi\nsyscall"
        )
        caminho = self.escreve("le.asm", codigo)
        _, dados, _ = self.run_json("run", caminho, "--stdin", "abc")
        self.assertEqual(dados["output"], "abc")

    def test_funcao_isolada(self) -> None:
        _, dados, _ = self.run_json("run", self.escala, "--entry", "soma_ate")
        self.assertEqual(dados["entry"], "soma_ate")

    def test_rotulo_inexistente(self) -> None:
        codigo, _, erro = self.run_cli("run", self.limpo, "--entry", "nao_existe")
        self.assertEqual(codigo, EXIT_INPUT)
        self.assertIn("rótulo não encontrado", erro)

    def test_programa_com_problema(self) -> None:
        codigo, saida, _ = self.run_cli("run", self.quebrado, "--no-color")
        self.assertEqual(codigo, EXIT_PROBLEMS)
        self.assertTrue("⚠" in saida or "não" in saida)

    def test_limite_de_instrucoes(self) -> None:
        codigo, _, _ = self.run_cli("run", self.infinito, "--limit", "500")
        self.assertEqual(codigo, EXIT_PROBLEMS)

    def test_timeout(self) -> None:
        codigo, _, erro = self.run_cli(
            "run", self.infinito, "--limit", "100000", "--timeout", "0.000001"
        )
        self.assertEqual(codigo, EXIT_TIMEOUT)
        self.assertIn("ERR_TIMEOUT", erro)

    def test_sem_saida_mostra_vazio(self) -> None:
        caminho = self.escreve(
            "mudo.asm",
            "global _start\nsection .text\n_start:\n" "mov rax, 60\nxor rdi, rdi\nsyscall\n",
        )
        _, saida, _ = self.run_cli("run", caminho, "--no-color")
        self.assertIn("(vazia)", saida)


class TestExplain(BaseCLI):
    """Comando ``explain``."""

    def test_linha_de_instrucao(self) -> None:
        codigo, saida, _ = self.run_cli("explain", self.limpo, "--line", "12", "--no-color")
        self.assertEqual(codigo, EXIT_OK)
        self.assertIn("MOV", saida)
        self.assertIn("Define constante", saida)

    def test_linha_de_instrucao_json(self) -> None:
        _, dados, _ = self.run_json("explain", self.limpo, "--line", "12")
        self.assertEqual(dados["kind"], "instruction")
        self.assertEqual(dados["label"], "Define constante")
        self.assertEqual(dados["line"], 12)

    def test_linha_de_dado(self) -> None:
        codigo, saida, _ = self.run_cli("explain", self.limpo, "--line", "5", "--no-color")
        self.assertEqual(codigo, EXIT_OK)
        self.assertIn("msg", saida)
        self.assertIn("byte", saida)

    def test_linha_de_dado_json(self) -> None:
        _, dados, _ = self.run_json("explain", self.limpo, "--line", "5")
        self.assertEqual(dados["kind"], "data")
        self.assertEqual(dados["label"], "msg")

    def test_linha_de_diretiva(self) -> None:
        _, dados, _ = self.run_json("explain", self.limpo, "--line", "4")
        self.assertEqual(dados["kind"], "directive")
        self.assertEqual(dados["directive"], "section")

    def test_linha_inexistente(self) -> None:
        codigo, _, erro = self.run_cli("explain", self.limpo, "--line", "9999")
        self.assertEqual(codigo, EXIT_INPUT)
        self.assertIn("ERR_LINE_NOT_FOUND", erro)

    def test_mnemônico_conhecido(self) -> None:
        codigo, saida, _ = self.run_cli(
            "explain", self.limpo, "--mnemonic", "syscall", "--no-color"
        )
        self.assertEqual(codigo, EXIT_OK)
        self.assertIn("SYSCALL", saida)
        self.assertIn("sintaxe", saida)
        self.assertIn("flags", saida)

    def test_mnemônico_conhecido_json(self) -> None:
        _, dados, _ = self.run_json("explain", self.limpo, "--mnemonic", "mov")
        self.assertEqual(dados["kind"], "mnemonic")
        self.assertEqual(dados["documentation"]["cat"], "data")

    def test_mnemônico_desconhecido(self) -> None:
        codigo, _, erro = self.run_cli("explain", self.limpo, "--mnemonic", "xyzzy")
        self.assertEqual(codigo, EXIT_INPUT)
        self.assertIn("ERR_UNKNOWN_MNEMONIC", erro)

    def test_exige_uma_das_opcoes(self) -> None:
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                main(["explain", self.limpo])


class TestExamples(BaseCLI):
    """Comando ``examples``."""

    def test_lista(self) -> None:
        codigo, saida, _ = self.run_cli("examples", "--list")
        self.assertEqual(codigo, EXIT_OK)
        self.assertIn("linux-hello", saida)
        self.assertIn("bubble", saida)

    def test_show(self) -> None:
        codigo, saida, _ = self.run_cli("examples", "--show", "linux-hello")
        self.assertEqual(codigo, EXIT_OK)
        self.assertIn("global _start", saida)

    def test_show_desconhecido(self) -> None:
        codigo, _, erro = self.run_cli("examples", "--show", "nao_existe")
        self.assertEqual(codigo, EXIT_INPUT)
        self.assertIn("exemplo desconhecido", erro)

    def test_dump(self) -> None:
        destino = os.path.join(self.dir.name, "saida")
        codigo, saida, _ = self.run_cli("examples", "--dump", destino, "--no-color")
        self.assertEqual(codigo, EXIT_OK)
        self.assertEqual(len(os.listdir(destino)), 8)
        self.assertIn("8 exemplos", saida)

    def test_dump_json(self) -> None:
        destino = os.path.join(self.dir.name, "saida2")
        _, dados, _ = self.run_json("examples", "--dump", destino)
        self.assertEqual(len(dados["files"]), 8)

    def test_json_sem_dump(self) -> None:
        _, dados, _ = self.run_json("examples", "--list")
        self.assertEqual(len(dados["examples"]), 8)
        self.assertIn("title", dados["examples"][0])


class TestOpcoesGlobais(BaseCLI):
    """Opções que valem para qualquer comando."""

    def test_verbose_mostra_log(self) -> None:
        _, _, erro = self.run_cli("-v", "check", self.limpo)
        self.assertIn("check_finished", erro)

    def test_quiet_silencia(self) -> None:
        _, _, erro = self.run_cli("-q", "check", self.limpo)
        self.assertEqual(erro.strip(), "")

    def test_log_json(self) -> None:
        _, _, erro = self.run_cli("-v", "--log-json", "check", self.limpo)
        eventos = [
            json.loads(linha)["event"]
            for linha in erro.strip().split("\n")
            if linha.startswith("{")
        ]
        self.assertIn("command_started", eventos)
        self.assertIn("check_finished", eventos)
        self.assertEqual(eventos[-1], "command_finished")

    def test_log_em_arquivo(self) -> None:
        caminho = os.path.join(self.dir.name, "asmx.log")
        self.run_cli("-v", "--log-file", caminho, "check", self.limpo)
        with open(caminho, encoding="utf-8") as arquivo:
            self.assertIn("check_finished", arquivo.read())

    def test_config_invalido(self) -> None:
        caminho = os.path.join(self.dir.name, "config.json")
        with open(caminho, "w", encoding="utf-8") as arquivo:
            arquivo.write("{invalido}")
        codigo, _, erro = self.run_cli("--config", caminho, "info")
        self.assertEqual(codigo, EXIT_INPUT)
        self.assertIn("ERR_CONFIG", erro)

    def test_config_boa(self) -> None:
        caminho = os.path.join(self.dir.name, "config.json")
        with open(caminho, "w", encoding="utf-8") as arquivo:
            json.dump({"max_steps": 123, "log_level": "ERROR"}, arquivo)
        _, dados, _ = self.run_json("--config", caminho, "info")
        self.assertEqual(dados["config"]["max_steps"], 123)

    def test_help_global(self) -> None:
        with self.assertRaises(SystemExit) as contexto:
            with contextlib.redirect_stdout(io.StringIO()):
                main(["--help"])
        self.assertEqual(contexto.exception.code, EXIT_OK)

    def test_version_pela_opcao(self) -> None:
        with self.assertRaises(SystemExit) as contexto:
            with contextlib.redirect_stdout(io.StringIO()):
                main(["--version"])
        self.assertEqual(contexto.exception.code, EXIT_OK)


if __name__ == "__main__":
    unittest.main()
