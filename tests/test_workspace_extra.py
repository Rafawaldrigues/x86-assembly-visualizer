"""Testes de canto do projeto: branches, cenários, gravação e erros."""

import json
import os
import tempfile
import unittest

from asmx.errors import (
    BranchExistsError,
    BranchNotFoundError,
    EmptyBranchNameError,
    LastBranchError,
    ProjectError,
    ProjectFormatError,
    ScenarioError,
    SourceNotFoundError,
    SourceWriteError,
)
from asmx.examples import EXAMPLES
from asmx.workspace import (
    FORMAT,
    Branch,
    Project,
    Scenario,
    ScenarioResult,
    parse_reg_values,
    run_all_scenarios,
    run_scenario,
)

HELLO = EXAMPLES["linux-hello"]["code"]


class BaseProjeto(unittest.TestCase):
    """Projeto com duas branches e diretório temporário à mão."""

    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.projeto = Project.new(code=HELLO, name="teste")

    def tearDown(self) -> None:
        self.dir.cleanup()

    def caminho(self, nome: str) -> str:
        return os.path.join(self.dir.name, nome)


class TestBranches(BaseProjeto):
    """Caminhos de erro e operações de branch."""

    def test_fork_de_origem_inexistente(self) -> None:
        with self.assertRaises(BranchNotFoundError):
            self.projeto.fork("nova", from_branch="nao_existe")

    def test_nome_repetido(self) -> None:
        self.projeto.fork("a")
        with self.assertRaises(BranchExistsError):
            self.projeto.fork("a")

    def test_nome_vazio(self) -> None:
        with self.assertRaises(EmptyBranchNameError):
            self.projeto.fork("   ")

    def test_switch_inexistente(self) -> None:
        with self.assertRaises(BranchNotFoundError):
            self.projeto.switch("nao_existe")

    def test_apagar_inexistente(self) -> None:
        with self.assertRaises(BranchNotFoundError):
            self.projeto.delete_branch("nao_existe")

    def test_apagar_ultima(self) -> None:
        with self.assertRaises(LastBranchError):
            self.projeto.delete_branch("principal")

    def test_apagar_deixa_filhas_sem_pai(self) -> None:
        self.projeto.fork("filha")
        self.projeto.delete_branch("principal")
        self.assertIsNone(self.projeto.branches["filha"].parent)

    def test_renomear_inexistente(self) -> None:
        with self.assertRaises(BranchNotFoundError):
            self.projeto.rename_branch("nao_existe", "nova")

    def test_renomear_para_nome_existente(self) -> None:
        self.projeto.fork("b")
        with self.assertRaises(BranchExistsError):
            self.projeto.rename_branch("principal", "b")

    def test_diff_de_branch_inexistente(self) -> None:
        with self.assertRaises(BranchNotFoundError):
            self.projeto.diff("principal", "nao_existe")

    def test_branch_ativa_inexistente_volta_para_a_primeira(self) -> None:
        self.projeto.active = "sumiu"
        self.assertEqual(self.projeto.branch.name, "principal")

    def test_fork_copia_anotacoes_e_breakpoints(self) -> None:
        self.projeto.set_note(1, "nota")
        self.projeto.toggle_breakpoint(3)
        copia = self.projeto.fork("copia")
        self.assertEqual(copia.notes["1"], "nota")
        self.assertEqual(copia.breakpoints, [3])

    def test_rename_branch_dataclass(self) -> None:
        branch = Branch(name="x", code="nop")
        self.assertEqual(branch.to_dict()["name"], "x")
        self.assertIn("created", branch.to_dict())


class TestCenarios(BaseProjeto):
    """Cenários: adicionar, remover, buscar e executar."""

    def test_adicionar_e_substituir(self) -> None:
        self.projeto.add_scenario(Scenario(name="a", expect_exit=0))
        self.projeto.add_scenario(Scenario(name="a", expect_exit=1))
        self.assertEqual(len(self.projeto.branch.scenarios), 1)
        self.assertEqual(self.projeto.scenario("a").expect_exit, 1)

    def test_remover(self) -> None:
        self.projeto.add_scenario(Scenario(name="a"))
        self.projeto.remove_scenario("a")
        self.assertEqual(self.projeto.branch.scenarios, [])

    def test_buscar_inexistente(self) -> None:
        with self.assertRaises(ScenarioError):
            self.projeto.scenario("nao_existe")

    def test_entrada_inexistente(self) -> None:
        with self.assertRaises(ScenarioError):
            run_scenario(HELLO, Scenario(name="x", entry="nao_existe"))

    def test_saida_esperada_errada(self) -> None:
        resultado = run_scenario(HELLO, Scenario(name="x", expect_output="outra"))
        self.assertFalse(resultado.passed)
        self.assertIn("saída diferente", resultado.reason)

    def test_codigo_de_saida_errado(self) -> None:
        resultado = run_scenario(HELLO, Scenario(name="x", expect_exit=7))
        self.assertFalse(resultado.passed)
        self.assertIn("código de saída", resultado.reason)

    def test_espera_problema_que_nao_acontece(self) -> None:
        resultado = run_scenario(HELLO, Scenario(name="x", expect_issue=True))
        self.assertFalse(resultado.passed)
        self.assertIn("esperava", resultado.reason)

    def test_problema_inesperado_reprova(self) -> None:
        resultado = run_scenario("inicio:\njmp inicio", Scenario(name="x", max_steps=500))
        self.assertFalse(resultado.passed)
        self.assertIn("laço infinito", resultado.reason)

    def test_timeout_reprova_com_motivo(self) -> None:
        codigo = "inicio:\njmp inicio"
        resultado = run_scenario(codigo, Scenario(name="x", max_steps=100000, timeout=0.0))
        self.assertFalse(resultado.passed)
        self.assertIn("timeout", resultado.reason)

    def test_todos_os_cenarios(self) -> None:
        cenarios = [Scenario(name="a", expect_exit=0), Scenario(name="b", expect_exit=9)]
        resultados = run_all_scenarios(HELLO, cenarios)
        self.assertEqual([r.passed for r in resultados], [True, False])
        self.assertEqual(resultados[0].scenario, "a")

    def test_resultado_serializa(self) -> None:
        resultado = run_scenario(HELLO, Scenario(name="x", expect_exit=0))
        dados = resultado.to_dict()
        self.assertEqual(dados["scenario"], "x")
        self.assertTrue(dados["passed"])
        self.assertIsInstance(resultado, ScenarioResult)

    def test_scenario_from_dict_ignora_campos_novos(self) -> None:
        cenario = Scenario.from_dict({"name": "a", "campo_do_futuro": 1, "max_steps": 10})
        self.assertEqual(cenario.name, "a")
        self.assertEqual(cenario.max_steps, 10)

    def test_registradores_iniciais_aceitam_texto_e_numero(self) -> None:
        codigo = EXAMPLES["escala"]["code"]
        resultado = run_scenario(codigo, Scenario(name="x", entry="soma_ate", regs={"rdi": "0x10"}))
        self.assertTrue(resultado.passed, resultado.reason)
        self.assertGreater(resultado.steps, 0)

    def test_parse_reg_values_variantes(self) -> None:
        self.assertEqual(parse_reg_values("rax=1;rbx=2\nrcx=3"), {"rax": 1, "rbx": 2, "rcx": 3})
        self.assertEqual(parse_reg_values(""), {})
        self.assertEqual(parse_reg_values("lixo"), {})


class TestPersistencia(BaseProjeto):
    """Gravar, carregar e recusar arquivos estranhos."""

    def test_to_dict(self) -> None:
        dados = self.projeto.to_dict()
        self.assertEqual(dados["format"], FORMAT)
        self.assertEqual(dados["active"], "principal")
        self.assertIn("saved", dados)
        self.assertIn("principal", dados["branches"])

    def test_salvar_sem_caminho(self) -> None:
        with self.assertRaises(ProjectError):
            self.projeto.save()

    def test_salvar_em_diretorio(self) -> None:
        with self.assertRaises(SourceWriteError):
            self.projeto.save(self.dir.name)

    def test_carregar_inexistente(self) -> None:
        with self.assertRaises(SourceNotFoundError):
            Project.load(self.caminho("nada.asmproj"))

    def test_carregar_json_invalido(self) -> None:
        caminho = self.caminho("ruim.asmproj")
        with open(caminho, "w", encoding="utf-8") as arquivo:
            arquivo.write("{nao e json}")
        with self.assertRaises(ProjectFormatError):
            Project.load(caminho)

    def test_carregar_lista_em_vez_de_objeto(self) -> None:
        caminho = self.caminho("lista.asmproj")
        with open(caminho, "w", encoding="utf-8") as arquivo:
            json.dump([1, 2], arquivo)
        with self.assertRaises(ProjectFormatError):
            Project.load(caminho)

    def test_carregar_formato_de_outro_programa(self) -> None:
        caminho = self.caminho("outro.asmproj")
        with open(caminho, "w", encoding="utf-8") as arquivo:
            json.dump({"format": "outra-ferramenta/9", "branches": {}}, arquivo)
        with self.assertRaises(ProjectFormatError):
            Project.load(caminho)

    def test_carregar_branch_que_nao_e_objeto(self) -> None:
        caminho = self.caminho("estranho.asmproj")
        with open(caminho, "w", encoding="utf-8") as arquivo:
            json.dump({"format": FORMAT, "branches": {"a": 3}}, arquivo)
        with self.assertRaises(ProjectFormatError):
            Project.load(caminho)

    def test_carregar_sem_branches_cria_principal(self) -> None:
        caminho = self.caminho("vazio.asmproj")
        with open(caminho, "w", encoding="utf-8") as arquivo:
            json.dump({"name": "vazio", "branches": {}}, arquivo)
        projeto = Project.load(caminho)
        self.assertEqual(list(projeto.branches), ["principal"])
        self.assertFalse(projeto.dirty)

    def test_branch_ativa_invalida_no_arquivo(self) -> None:
        caminho = self.caminho("ativo.asmproj")
        with open(caminho, "w", encoding="utf-8") as arquivo:
            json.dump({"active": "sumiu", "branches": {"principal": {"code": "nop"}}}, arquivo)
        self.assertEqual(Project.load(caminho).active, "principal")

    def test_importar_asm(self) -> None:
        caminho = self.caminho("fonte.asm")
        with open(caminho, "w", encoding="utf-8") as arquivo:
            arquivo.write(HELLO)
        projeto = Project.from_asm_file(caminho)
        self.assertEqual(projeto.name, "fonte")
        self.assertEqual(projeto.code, HELLO)

    def test_exportar_para_caminho_invalido(self) -> None:
        with self.assertRaises(SourceWriteError):
            self.projeto.export_asm(self.dir.name)

    def test_exportar_e_reimportar(self) -> None:
        destino = self.caminho("saida.asm")
        self.projeto.export_asm(destino)
        with open(destino, encoding="utf-8") as arquivo:
            self.assertEqual(arquivo.read(), HELLO)


class TestMarcas(BaseProjeto):
    """Anotações, breakpoints e a marca de alteração."""

    def test_anotacao_vazia_remove(self) -> None:
        self.projeto.set_note(2, "algo")
        self.projeto.set_note(2, "   ")
        self.assertEqual(self.projeto.note(2), "")

    def test_anotacao_apara_espacos(self) -> None:
        self.projeto.set_note(2, "  olha isto  ")
        self.assertEqual(self.projeto.note(2), "olha isto")

    def test_breakpoints_ordenados(self) -> None:
        self.projeto.toggle_breakpoint(9)
        self.projeto.toggle_breakpoint(3)
        self.assertEqual(self.projeto.branch.breakpoints, [3, 9])

    def test_dirty_ao_anotar_e_ao_mexer_em_breakpoint(self) -> None:
        self.projeto.dirty = False
        self.projeto.set_note(1, "x")
        self.assertTrue(self.projeto.dirty)
        self.projeto.dirty = False
        self.projeto.toggle_breakpoint(1)
        self.assertTrue(self.projeto.dirty)

    def test_set_code_igual_nao_suja(self) -> None:
        self.projeto.set_code(HELLO)
        self.assertFalse(self.projeto.dirty)

    def test_salvar_marca_limpo_e_renomeia(self) -> None:
        self.projeto.set_code("nop")
        caminho = self.projeto.save(self.caminho("meu.asmproj"))
        self.assertEqual(caminho, self.caminho("meu.asmproj"))
        self.assertFalse(self.projeto.dirty)
        self.assertEqual(self.projeto.name, "meu")


if __name__ == "__main__":
    unittest.main()
