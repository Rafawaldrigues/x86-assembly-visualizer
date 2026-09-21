"""Testes da configuração: padrões, arquivos, ambiente e validação."""

import importlib.util
import json
import os
import sys
import tempfile
import unittest
import unittest.mock

from asmx.config import CANDIDATE_NAMES, CONFIG_ENV_VAR, SandboxConfig
from asmx.errors import ConfigError
from asmx.logging_setup import reset_logging

#: O YAML é opcional: os testes dele só rodam quando o PyYAML está instalado.
HAS_YAML = importlib.util.find_spec("yaml") is not None


class TestPadroes(unittest.TestCase):
    """A configuração sem argumento nenhum precisa ser sensata."""

    def test_padroes(self) -> None:
        config = SandboxConfig()
        self.assertEqual(config.timeout, 30.0)
        self.assertEqual(config.max_steps, 200000)
        self.assertEqual(config.max_memory, 512)
        self.assertFalse(config.enable_network)
        self.assertEqual(config.log_level, "INFO")
        self.assertEqual(config.workers, 4)

    def test_to_dict_e_field_names(self) -> None:
        config = SandboxConfig()
        self.assertEqual(tuple(config.to_dict()), config.field_names())
        self.assertEqual(len(config.field_names()), 10)

    def test_describe_em_uma_linha(self) -> None:
        texto = SandboxConfig(timeout=2, max_steps=10).describe()
        self.assertIn("timeout=2s", texto)
        self.assertIn("max_steps=10", texto)
        self.assertIn("rede=desligada", texto)

    def test_repr_usa_describe(self) -> None:
        self.assertTrue(repr(SandboxConfig()).startswith("SandboxConfig(timeout="))

    def test_conversao_de_tipos_na_construcao(self) -> None:
        config = SandboxConfig(
            timeout="5", max_steps="1000", workers="2", log_json="sim", strict="0"
        )
        self.assertEqual(config.timeout, 5.0)
        self.assertEqual(config.max_steps, 1000)
        self.assertEqual(config.workers, 2)
        self.assertTrue(config.log_json)
        self.assertFalse(config.strict)

    def test_nivel_de_log_em_minusculas(self) -> None:
        self.assertEqual(SandboxConfig(log_level="debug").log_level, "DEBUG")


class TestValidacao(unittest.TestCase):
    """Valores fora da faixa precisam ser recusados com o campo no contexto."""

    def verifica(self, campo: str, **valores: object) -> ConfigError:
        with self.assertRaises(ConfigError) as contexto:
            SandboxConfig(**valores).validate()
        self.assertEqual(contexto.exception.field, campo)
        return contexto.exception

    def test_timeout_precisa_ser_positivo(self) -> None:
        self.verifica("timeout", timeout=0)

    def test_timeout_absurdo(self) -> None:
        self.verifica("timeout", timeout=100000)

    def test_max_steps_minimo(self) -> None:
        self.verifica("max_steps", max_steps=0)

    def test_memoria_minima(self) -> None:
        self.verifica("max_memory", max_memory=1)

    def test_nivel_desconhecido(self) -> None:
        self.verifica("log_level", log_level="BARULHO")

    def test_workers_fora_da_faixa(self) -> None:
        self.verifica("workers", workers=0)
        self.verifica("workers", workers=999)

    def test_diretorio_de_saida_vazio(self) -> None:
        self.verifica("output_dir", output_dir="   ")

    def test_validate_devolve_a_propria_config(self) -> None:
        config = SandboxConfig()
        self.assertIs(config.validate(), config)

    def test_valor_booleano_invalido(self) -> None:
        with self.assertRaises(ConfigError):
            SandboxConfig(strict="talvez")

    def test_numero_invalido(self) -> None:
        with self.assertRaises(ConfigError):
            SandboxConfig(timeout="muito")


class TestFromDict(unittest.TestCase):
    """Leitura de dicionário, com sugestão para campo errado."""

    def test_campos_conhecidos(self) -> None:
        config = SandboxConfig.from_dict({"workers": "2", "strict": True})
        self.assertEqual(config.workers, 2)
        self.assertTrue(config.strict)

    def test_dict_vazio(self) -> None:
        self.assertEqual(SandboxConfig.from_dict(None).timeout, 30.0)

    def test_campo_desconhecido_com_sugestao(self) -> None:
        with self.assertRaises(ConfigError) as contexto:
            SandboxConfig.from_dict({"timeoutt": 5})
        self.assertIn("timeout", str(contexto.exception))
        self.assertEqual(contexto.exception.field, "timeoutt")

    def test_campo_desconhecido_sem_parecido(self) -> None:
        with self.assertRaises(ConfigError) as contexto:
            SandboxConfig.from_dict({"xyzzy": 1})
        self.assertNotIn("quis dizer", str(contexto.exception))

    def test_origem_aparece_na_mensagem(self) -> None:
        with self.assertRaises(ConfigError) as contexto:
            SandboxConfig.from_dict({"nada": 1}, path="asmx.json")
        self.assertIn("asmx.json", str(contexto.exception))

    def test_valor_invalido_no_dict(self) -> None:
        with self.assertRaises(ConfigError):
            SandboxConfig.from_dict({"timeout": -1})


class TestMerged(unittest.TestCase):
    """Sobreposição de campos."""

    def test_sobrepoe(self) -> None:
        config = SandboxConfig().merged(timeout=3, workers=2)
        self.assertEqual(config.timeout, 3.0)
        self.assertEqual(config.workers, 2)

    def test_none_e_ignorado(self) -> None:
        config = SandboxConfig(timeout=7).merged(timeout=None, workers=3)
        self.assertEqual(config.timeout, 7.0)
        self.assertEqual(config.workers, 3)

    def test_campo_desconhecido(self) -> None:
        with self.assertRaises(ConfigError):
            SandboxConfig().merged(inventado=1)

    def test_nao_muda_o_original(self) -> None:
        original = SandboxConfig()
        original.merged(timeout=1)
        self.assertEqual(original.timeout, 30.0)


class TestArquivos(unittest.TestCase):
    """Leitura e gravação em JSON e YAML."""

    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.json_path = os.path.join(self.dir.name, "config.json")
        with open(self.json_path, "w", encoding="utf-8") as arquivo:
            json.dump({"timeout": 5, "workers": 2, "log_level": "warning"}, arquivo)

    def tearDown(self) -> None:
        self.dir.cleanup()

    def test_json_valido(self) -> None:
        config = SandboxConfig.from_json_file(self.json_path)
        self.assertEqual(config.timeout, 5.0)
        self.assertEqual(config.workers, 2)
        self.assertEqual(config.log_level, "WARNING")

    def test_json_ausente(self) -> None:
        with self.assertRaises(ConfigError) as contexto:
            SandboxConfig.from_json_file(os.path.join(self.dir.name, "nada.json"))
        self.assertEqual(contexto.exception.path, os.path.join(self.dir.name, "nada.json"))

    def test_json_invalido(self) -> None:
        caminho = os.path.join(self.dir.name, "quebrado.json")
        with open(caminho, "w", encoding="utf-8") as arquivo:
            arquivo.write("{isso não é json}")
        with self.assertRaises(ConfigError) as contexto:
            SandboxConfig.from_json_file(caminho)
        self.assertIn("JSON inválido", str(contexto.exception))

    def test_json_precisa_ser_objeto(self) -> None:
        caminho = os.path.join(self.dir.name, "lista.json")
        with open(caminho, "w", encoding="utf-8") as arquivo:
            json.dump([1, 2], arquivo)
        with self.assertRaises(ConfigError):
            SandboxConfig.from_json_file(caminho)

    def test_from_file_por_extensao(self) -> None:
        self.assertEqual(SandboxConfig.from_file(self.json_path).timeout, 5.0)

    def test_from_file_extensao_desconhecida(self) -> None:
        with self.assertRaises(ConfigError) as contexto:
            SandboxConfig.from_file(os.path.join(self.dir.name, "config.ini"))
        self.assertIn("extensão", str(contexto.exception))

    @unittest.skipUnless(HAS_YAML, "PyYAML não instalado")
    def test_yaml_valido(self) -> None:
        caminho = os.path.join(self.dir.name, "asmx.yaml")
        with open(caminho, "w", encoding="utf-8") as arquivo:
            arquivo.write("timeout: 9\nworkers: 3\n")
        config = SandboxConfig.from_yaml_file(caminho)
        self.assertEqual(config.timeout, 9.0)
        self.assertEqual(config.workers, 3)

    @unittest.skipUnless(HAS_YAML, "PyYAML não instalado")
    def test_yaml_vazio_usa_padroes(self) -> None:
        caminho = os.path.join(self.dir.name, "vazio.yaml")
        with open(caminho, "w", encoding="utf-8") as arquivo:
            arquivo.write("")
        self.assertEqual(SandboxConfig.from_yaml_file(caminho).timeout, 30.0)

    @unittest.skipUnless(HAS_YAML, "PyYAML não instalado")
    def test_yaml_invalido(self) -> None:
        caminho = os.path.join(self.dir.name, "ruim.yaml")
        with open(caminho, "w", encoding="utf-8") as arquivo:
            arquivo.write("timeout: [1, 2\n")
        with self.assertRaises(ConfigError):
            SandboxConfig.from_yaml_file(caminho)

    def test_yaml_sem_pyyaml_explica_o_caminho(self) -> None:
        caminho = os.path.join(self.dir.name, "asmx.yaml")
        with open(caminho, "w", encoding="utf-8") as arquivo:
            arquivo.write("timeout: 1\n")
        with unittest.mock.patch.dict(sys.modules, {"yaml": None}):
            with self.assertRaises(ConfigError) as contexto:
                SandboxConfig.from_yaml_file(caminho)
        self.assertIn("PyYAML", str(contexto.exception))

    def test_salvar_e_reler_json(self) -> None:
        caminho = os.path.join(self.dir.name, "novo.json")
        SandboxConfig(timeout=4, workers=5).save(caminho)
        relido = SandboxConfig.from_file(caminho)
        self.assertEqual(relido.timeout, 4.0)
        self.assertEqual(relido.workers, 5)

    @unittest.skipUnless(HAS_YAML, "PyYAML não instalado")
    def test_salvar_yaml(self) -> None:
        caminho = os.path.join(self.dir.name, "novo.yaml")
        SandboxConfig(timeout=6).save(caminho)
        with open(caminho, encoding="utf-8") as arquivo:
            self.assertIn("timeout", arquivo.read())

    def test_formato_de_salvamento_desconhecido(self) -> None:
        with self.assertRaises(ConfigError):
            SandboxConfig().save(os.path.join(self.dir.name, "x.ini"))


class TestAmbiente(unittest.TestCase):
    """Variáveis de ambiente e ordem de precedência."""

    def test_from_env(self) -> None:
        with unittest.mock.patch.dict(
            os.environ, {"ASMX_TIMEOUT": "12", "ASMX_WORKERS": "7", "ASMX_STRICT": "1"}, clear=True
        ):
            config = SandboxConfig.from_env()
        self.assertEqual(config.timeout, 12.0)
        self.assertEqual(config.workers, 7)
        self.assertTrue(config.strict)

    def test_variavel_vazia_e_ignorada(self) -> None:
        with unittest.mock.patch.dict(os.environ, {"ASMX_TIMEOUT": ""}, clear=True):
            self.assertEqual(SandboxConfig.from_env().timeout, 30.0)

    def test_variavel_invalida(self) -> None:
        with unittest.mock.patch.dict(os.environ, {"ASMX_TIMEOUT": "muito"}, clear=True):
            with self.assertRaises(ConfigError):
                SandboxConfig.from_env()

    def test_ambiente_sobrepoe_arquivo(self) -> None:
        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "asmx.json")
            with open(caminho, "w", encoding="utf-8") as arquivo:
                json.dump({"timeout": 5, "workers": 2}, arquivo)
            with unittest.mock.patch.dict(os.environ, {"ASMX_WORKERS": "9"}, clear=True):
                config = SandboxConfig.load(caminho)
        self.assertEqual(config.timeout, 5.0)
        self.assertEqual(config.workers, 9)

    def test_arquivo_indicado_que_nao_existe(self) -> None:
        with self.assertRaises(ConfigError):
            SandboxConfig.load("/tmp/nao_existe_asmx.json")

    def test_variavel_de_ambiente_aponta_o_arquivo(self) -> None:
        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "config.json")
            with open(caminho, "w", encoding="utf-8") as arquivo:
                json.dump({"max_steps": 77}, arquivo)
            with unittest.mock.patch.dict(os.environ, {CONFIG_ENV_VAR: caminho}, clear=True):
                self.assertEqual(SandboxConfig.load().max_steps, 77)

    def test_sem_arquivo_usa_padroes(self) -> None:
        with tempfile.TemporaryDirectory() as pasta:
            with unittest.mock.patch.dict(os.environ, {}, clear=True):
                config = SandboxConfig.load(start=pasta)
        self.assertEqual(config.timeout, 30.0)


class TestFindFile(unittest.TestCase):
    """Busca automática do arquivo de configuração."""

    def test_encontra_no_diretorio_indicado(self) -> None:
        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, CANDIDATE_NAMES[0])
            with open(caminho, "w", encoding="utf-8") as arquivo:
                arquivo.write("timeout: 1\n")
            with unittest.mock.patch.dict(os.environ, {}, clear=True):
                self.assertEqual(SandboxConfig.find_file(pasta), caminho)

    def test_nada_encontrado(self) -> None:
        with tempfile.TemporaryDirectory() as pasta:
            with unittest.mock.patch.dict(os.environ, {"HOME": pasta}, clear=True):
                self.assertIsNone(SandboxConfig.find_file(pasta))

    def test_variavel_de_ambiente_tem_prioridade(self) -> None:
        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "meu.json")
            with open(caminho, "w", encoding="utf-8") as arquivo:
                arquivo.write("{}")
            with unittest.mock.patch.dict(os.environ, {CONFIG_ENV_VAR: caminho}, clear=True):
                self.assertEqual(SandboxConfig.find_file(pasta), caminho)


class TestApplyLogging(unittest.TestCase):
    """A configuração manda no logging."""

    def tearDown(self) -> None:
        reset_logging()

    def test_aplica_nivel_e_formato(self) -> None:
        import io

        estado = SandboxConfig(log_level="ERROR", log_json=True).apply_logging(io.StringIO())
        self.assertEqual(estado.level, "ERROR")
        self.assertTrue(estado.json_output)


if __name__ == "__main__":
    unittest.main()
