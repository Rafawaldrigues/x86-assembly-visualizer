"""Testes da hierarquia de erros: códigos, contexto e compatibilidade."""

import unittest

from asmx.errors import (
    ERROR_CODES,
    AnalysisTimeoutError,
    AsmxError,
    BranchExistsError,
    BranchNotFoundError,
    ConfigError,
    EmulationError,
    EmptyBranchNameError,
    LastBranchError,
    LineNotFoundError,
    ParseError,
    ProjectError,
    ProjectFormatError,
    ScenarioError,
    SourceNotFoundError,
    SourceReadError,
    SourceWriteError,
    UnknownMnemonicError,
    UnsupportedSourceError,
)


class TestBase(unittest.TestCase):
    """Comportamento comum a todos os erros."""

    def test_str_mostra_o_codigo(self) -> None:
        erro = AsmxError("algo deu errado")
        self.assertEqual(str(erro), "[ERR_ASMX] algo deu errado")

    def test_codigo_pode_ser_trocado(self) -> None:
        erro = AsmxError("quebrou", code="ERR_PROPRIO", etapa="teste")
        self.assertEqual(erro.code, "ERR_PROPRIO")
        self.assertEqual(erro.context["etapa"], "teste")

    def test_repr_e_curto(self) -> None:
        self.assertEqual(repr(AsmxError("x")), "AsmxError(code='ERR_ASMX', message='x')")

    def test_to_dict_sem_contexto(self) -> None:
        dados = ProjectError("falhou").to_dict()
        self.assertEqual(
            dados, {"error": "ProjectError", "code": "ERR_PROJECT", "message": "falhou"}
        )

    def test_to_dict_com_contexto(self) -> None:
        dados = SourceNotFoundError("/tmp/x.asm").to_dict()
        self.assertEqual(dados["code"], "ERR_SOURCE_NOT_FOUND")
        self.assertEqual(dados["context"]["path"], "/tmp/x.asm")

    def test_indice_de_codigos_cobre_todas_as_classes(self) -> None:
        for classe in (
            SourceNotFoundError,
            SourceReadError,
            SourceWriteError,
            UnsupportedSourceError,
            ParseError,
            ProjectError,
            ProjectFormatError,
            BranchNotFoundError,
            BranchExistsError,
            EmptyBranchNameError,
            LastBranchError,
            ScenarioError,
            ConfigError,
            EmulationError,
            AnalysisTimeoutError,
            UnknownMnemonicError,
            LineNotFoundError,
        ):
            with self.subTest(classe=classe.__name__):
                self.assertIs(ERROR_CODES[classe.code], classe)

    def test_codigos_sao_unicos(self) -> None:
        codigos = [c.code for c in ERROR_CODES.values()]
        self.assertEqual(len(codigos), len(set(codigos)))

    def test_todos_comecam_com_err(self) -> None:
        for codigo in ERROR_CODES:
            with self.subTest(codigo=codigo):
                self.assertTrue(codigo.startswith("ERR_"))


class TestCompatibilidadeComErrosEmbutidos(unittest.TestCase):
    """Quem já tratava ValueError/KeyError continua funcionando."""

    def test_documento_ausente_e_file_not_found(self) -> None:
        with self.assertRaises(FileNotFoundError):
            raise SourceNotFoundError("/tmp/nada.asm")

    def test_projeto_invalido_e_value_error(self) -> None:
        with self.assertRaises(ValueError):
            raise ProjectFormatError("p.asmproj", "json quebrado")

    def test_branch_inexistente_e_key_error(self) -> None:
        with self.assertRaises(KeyError):
            raise BranchNotFoundError("nao_existe")

    def test_timeout_e_timeout_error(self) -> None:
        with self.assertRaises(TimeoutError):
            raise AnalysisTimeoutError(2.5, steps=100)

    def test_emulacao_e_runtime_error(self) -> None:
        with self.assertRaises(RuntimeError):
            raise EmulationError("não consegui começar")


class TestMensagens(unittest.TestCase):
    """As mensagens precisam ser úteis sozinhas."""

    def test_arquivo_nao_encontrado(self) -> None:
        self.assertIn("/tmp/x.asm", str(SourceNotFoundError("/tmp/x.asm")))

    def test_erro_de_leitura_traz_o_motivo(self) -> None:
        self.assertIn("permissão negada", str(SourceReadError("/etc/x", "permissão negada")))

    def test_erro_de_escrita(self) -> None:
        self.assertIn("não consegui gravar", str(SourceWriteError("/tmp/x", "disco cheio")))

    def test_extensao_recusada_lista_as_aceitas(self) -> None:
        erro = UnsupportedSourceError("a.bin", ".asm, .s")
        self.assertIn("a.bin", str(erro))
        self.assertIn(".asm", str(erro))
        self.assertEqual(erro.context["expected"], ".asm, .s")

    def test_branch_repetida(self) -> None:
        self.assertEqual(
            str(BranchExistsError("alt")), "[ERR_BRANCH_EXISTS] já existe uma branch chamada alt"
        )

    def test_nome_de_branch_vazio(self) -> None:
        self.assertIn("precisa de um nome", str(EmptyBranchNameError()))

    def test_ultima_branch(self) -> None:
        self.assertIn("pelo menos uma branch", str(LastBranchError()))

    def test_cenario_com_nome(self) -> None:
        erro = ScenarioError("limite inválido", scenario="grande")
        self.assertEqual(erro.scenario, "grande")
        self.assertEqual(erro.context["scenario"], "grande")

    def test_config_com_campo(self) -> None:
        erro = ConfigError("fora da faixa", path="asmx.json", field="timeout")
        self.assertEqual(erro.field, "timeout")
        self.assertEqual(erro.path, "asmx.json")

    def test_timeout_mostra_o_limite(self) -> None:
        erro = AnalysisTimeoutError(1.5, steps=256)
        self.assertIn("1.5 s", str(erro))
        self.assertEqual(erro.steps, 256)

    def test_mnemônico_desconhecido_mostra_o_tamanho_do_acervo(self) -> None:
        self.assertIn("148", str(UnknownMnemonicError("xyz", 148)))

    def test_linha_inexistente_mostra_o_total(self) -> None:
        erro = LineNotFoundError(99, 20)
        self.assertIn("99", str(erro))
        self.assertIn("20", str(erro))

    def test_erro_de_parse_guarda_a_linha(self) -> None:
        erro = ParseError("linha estranha", line=7)
        self.assertEqual(erro.line, 7)
        self.assertEqual(erro.context["line"], 7)


if __name__ == "__main__":
    unittest.main()
