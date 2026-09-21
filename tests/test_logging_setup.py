"""Testes do logging estruturado: formatos, níveis, ambiente e reconfiguração."""

import io
import json
import logging
import os
import tempfile
import unittest
import unittest.mock

from asmx.logging_setup import (
    LOGGER_NAME,
    LoggingState,
    TextFormatter,
    configure_logging,
    env_flag,
    get_logger,
    log_event,
    reset_logging,
    resolve_level,
)


class BaseLogging(unittest.TestCase):
    """Garante que um caso não deixe logging ligado para o próximo."""

    def setUp(self) -> None:
        reset_logging()

    def tearDown(self) -> None:
        reset_logging()

    def capture(self, nivel: str = "DEBUG", **kwargs: object) -> io.StringIO:
        fluxo = io.StringIO()
        configure_logging(nivel, json_output=True, stream=fluxo, force=True, **kwargs)
        return fluxo


class TestNiveis(unittest.TestCase):
    """Conversão de nome de nível e leitura de variável booleana."""

    def test_nome_minusculo(self) -> None:
        self.assertEqual(resolve_level("debug"), logging.DEBUG)

    def test_numero_passa_direto(self) -> None:
        self.assertEqual(resolve_level(42), 42)

    def test_none_vira_info(self) -> None:
        self.assertEqual(resolve_level(None), logging.INFO)

    def test_nome_invalido_explica(self) -> None:
        with self.assertRaises(ValueError) as contexto:
            resolve_level("barulhento")
        self.assertIn("DEBUG", str(contexto.exception))

    def test_env_flag_verdadeiros(self) -> None:
        for valor in ("1", "true", "TRUE", "yes", "on", "sim"):
            with self.subTest(valor=valor):
                with unittest.mock.patch.dict(os.environ, {"ASMX_TESTE": valor}):
                    self.assertTrue(env_flag("ASMX_TESTE"))

    def test_env_flag_falsos(self) -> None:
        for valor in ("0", "false", "no", "off", ""):
            with self.subTest(valor=valor):
                with unittest.mock.patch.dict(os.environ, {"ASMX_TESTE": valor}):
                    self.assertFalse(env_flag("ASMX_TESTE", default=True))

    def test_env_flag_ausente_usa_padrao(self) -> None:
        with unittest.mock.patch.dict(os.environ, {}, clear=True):
            self.assertTrue(env_flag("ASMX_NAO_EXISTE", default=True))
            self.assertFalse(env_flag("ASMX_NAO_EXISTE"))

    def test_env_flag_texto_estranho_usa_padrao(self) -> None:
        with unittest.mock.patch.dict(os.environ, {"ASMX_TESTE": "talvez"}):
            self.assertTrue(env_flag("ASMX_TESTE", default=True))


class TestJsonFormatter(BaseLogging):
    """O formato JSON é o contrato para CI e para o Docker."""

    def test_campos_obrigatorios(self) -> None:
        fluxo = self.capture()
        get_logger("asmx.teste").info("olá")
        dados = json.loads(fluxo.getvalue())
        self.assertEqual(dados["level"], "INFO")
        self.assertEqual(dados["logger"], "asmx.teste")
        self.assertEqual(dados["message"], "olá")
        self.assertRegex(dados["ts"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")

    def test_uma_linha_por_evento(self) -> None:
        fluxo = self.capture()
        log = get_logger("asmx.teste")
        log.info("primeiro")
        log.info("segundo")
        linhas = fluxo.getvalue().strip().split("\n")
        self.assertEqual(len(linhas), 2)

    def test_acentos_preservados(self) -> None:
        fluxo = self.capture()
        get_logger("asmx.teste").warning("não é emulada")
        self.assertIn("não é emulada", fluxo.getvalue())

    def test_campos_extras_viram_chaves(self) -> None:
        fluxo = self.capture()
        log_event(
            get_logger("asmx.teste"), "analysis_completed", instructions=12, blocks=4, ok=True
        )
        dados = json.loads(fluxo.getvalue())
        self.assertEqual(dados["event"], "analysis_completed")
        self.assertEqual(dados["instructions"], 12)
        self.assertEqual(dados["blocks"], 4)
        self.assertTrue(dados["ok"])

    def test_chave_protegida_recebe_prefixo(self) -> None:
        fluxo = self.capture()
        get_logger("asmx.teste").info("x", extra={"level": "alto"})
        self.assertEqual(json.loads(fluxo.getvalue())["extra_level"], "alto")

    def test_excecao_entra_no_json(self) -> None:
        fluxo = self.capture()
        try:
            raise ValueError("quebrou de propósito")
        except ValueError:
            get_logger("asmx.teste").error("falhou", exc_info=True)
        dados = json.loads(fluxo.getvalue())
        self.assertIn("ValueError", dados["exception"])

    def test_valor_nao_serializavel_vira_texto(self) -> None:
        fluxo = self.capture()
        log_event(get_logger("asmx.teste"), "conjunto", nomes={"b", "a"})
        self.assertEqual(json.loads(fluxo.getvalue())["nomes"], "a,b")


class TestTextFormatter(BaseLogging):
    """O formato de texto é o que aparece no terminal."""

    def test_mostra_evento_e_extras(self) -> None:
        fluxo = io.StringIO()
        configure_logging("INFO", json_output=False, stream=fluxo, force=True)
        log_event(get_logger("asmx.teste"), "check_finished", errors=0)
        linha = fluxo.getvalue()
        self.assertIn("check_finished", linha)
        self.assertIn("event=check_finished", linha)
        self.assertIn("errors=0", linha)

    def test_sem_extras(self) -> None:
        formatador = TextFormatter(show_extras=False)
        registro = logging.LogRecord("asmx.teste", logging.INFO, __file__, 1, "oi", None, None)
        self.assertNotIn("event=", formatador.format(registro))

    def test_excecao_aparece(self) -> None:
        fluxo = io.StringIO()
        configure_logging("INFO", json_output=False, stream=fluxo, force=True)
        try:
            raise KeyError("sumiu")
        except KeyError:
            get_logger("asmx.teste").error("falhou", exc_info=True)
        self.assertIn("KeyError", fluxo.getvalue())


class TestConfigureLogging(BaseLogging):
    """Configuração, reconfiguração e estado devolvido."""

    def test_estado_devolvido(self) -> None:
        estado = configure_logging("DEBUG", json_output=True, stream=io.StringIO(), force=True)
        self.assertIsInstance(estado, LoggingState)
        self.assertEqual(estado.level, "DEBUG")
        self.assertTrue(estado.json_output)
        self.assertEqual(estado.handlers, 1)
        self.assertEqual(estado.to_dict()["handlers"], 1)

    def test_nao_duplica_handler(self) -> None:
        configure_logging("INFO", stream=io.StringIO(), force=True)
        primeiro = configure_logging("INFO", stream=io.StringIO())
        self.assertEqual(primeiro.handlers, 1)
        self.assertEqual(len(logging.getLogger(LOGGER_NAME).handlers), 1)

    def test_force_reconfigura(self) -> None:
        configure_logging("INFO", json_output=False, stream=io.StringIO(), force=True)
        estado = configure_logging("ERROR", json_output=True, stream=io.StringIO(), force=True)
        self.assertEqual(estado.level, "ERROR")
        self.assertTrue(estado.json_output)

    def test_nivel_vem_do_ambiente(self) -> None:
        with unittest.mock.patch.dict(
            os.environ, {"ASMX_LOG_LEVEL": "WARNING", "ASMX_LOG_JSON": "1"}
        ):
            estado = configure_logging(stream=io.StringIO(), force=True)
        self.assertEqual(estado.level, "WARNING")
        self.assertTrue(estado.json_output)

    def test_arquivo_de_log_recebe_as_linhas(self) -> None:
        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "asmx.log")
            config = configure_logging(
                "INFO", json_output=True, log_file=caminho, stream=io.StringIO(), force=True
            )
            get_logger("asmx.teste").info("gravado no arquivo")
            logging.getLogger(LOGGER_NAME).handlers[1].flush()
            with open(caminho, encoding="utf-8") as arquivo:
                conteudo = arquivo.read()
        self.assertEqual(config.handlers, 2)
        self.assertEqual(config.log_file, caminho)
        self.assertIn("gravado no arquivo", conteudo)

    def test_nivel_invalido_levanta(self) -> None:
        with self.assertRaises(ValueError):
            configure_logging("gritaria", force=True)


class TestLogEvent(BaseLogging):
    """Eventos estruturados."""

    def test_evento_sem_mensagem_usa_o_nome(self) -> None:
        fluxo = self.capture()
        log_event(get_logger("asmx.teste"), "started")
        self.assertEqual(json.loads(fluxo.getvalue())["message"], "started")

    def test_mensagem_propria(self) -> None:
        fluxo = self.capture()
        log_event(get_logger("asmx.teste"), "started", message="começou agora")
        self.assertEqual(json.loads(fluxo.getvalue())["message"], "começou agora")

    def test_nivel_explicito(self) -> None:
        fluxo = self.capture()
        log_event(get_logger("asmx.teste"), "detalhe", level=logging.DEBUG, x=1)
        self.assertEqual(json.loads(fluxo.getvalue())["level"], "DEBUG")

    def test_campo_message_nao_duplica(self) -> None:
        fluxo = self.capture()
        log_event(get_logger("asmx.teste"), "evento", message="texto")
        dados = json.loads(fluxo.getvalue())
        self.assertNotIn("extra_message", dados)


class TestGetLogger(unittest.TestCase):
    """O namespace dos loggers é sempre asmx.*."""

    def test_nome_do_modulo(self) -> None:
        self.assertEqual(get_logger("asmx.parser").name, "asmx.parser")

    def test_nome_solto_recebe_prefixo(self) -> None:
        self.assertEqual(get_logger("parser").name, "asmx.parser")

    def test_sem_nome_e_a_raiz_do_projeto(self) -> None:
        self.assertEqual(get_logger().name, LOGGER_NAME)


class TestResetLogging(BaseLogging):
    """Desligar o logging devolve o namespace ao estado inicial."""

    def test_remove_handlers_e_volta_a_propagar(self) -> None:
        configure_logging("INFO", stream=io.StringIO(), force=True)
        reset_logging()
        logger = logging.getLogger(LOGGER_NAME)
        self.assertEqual(logger.handlers, [])
        self.assertTrue(logger.propagate)

    def test_sem_handler_nada_e_impresso(self) -> None:
        fluxo = io.StringIO()
        reset_logging()
        with unittest.mock.patch("sys.stderr", fluxo):
            get_logger("asmx.teste").info("silêncio")
        self.assertEqual(fluxo.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
