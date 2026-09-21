"""Testes da janela principal, do editor de código e do tema (asmx.ui.app).

Nenhuma janela modal de verdade é aberta: os diálogos do módulo e as caixas do
``tkinter.messagebox``/``tkinter.filedialog`` são trocados por dublês.
"""

from __future__ import annotations

import os
import tempfile
import time
import unittest
from typing import Any, List, Tuple
from unittest import mock

try:
    import tkinter as tk

    TK_OK = True
except ImportError:  # pragma: no cover
    TK_OK = False

HAS_DISPLAY = bool(os.environ.get("DISPLAY")) or os.name == "nt"

#: Código com todos os tipos de linha que a documentação explica.
CODIGO_COMPLETO = """section .data
msg: db "Oi", 0
buf: resb 16
TAM equ 4
tab: times 4 db 0

section .text
    global _start
_start:
.loop:
    mov rax, [msg]
    nop
"""

#: Código que empilha valores e guarda um endereço de retorno na pilha.
CODIGO_PILHA = """section .text
    global _start
_start:
    call funcao
    mov rax, 1
funcao:
    push 1
    push 2
    push 3
    push 4
    push 5
    nop
"""


def fake_dialog(valor: Any) -> type:
    """Cria um diálogo falso (sem Tk) que devolve sempre o mesmo valor.

    Args:
        valor: Valor devolvido por :meth:`show`.

    Returns:
        Uma classe compatível com o construtor dos diálogos reais.
    """

    class FakeDialog:
        """Diálogo de mentira: aceita os argumentos e devolve um valor fixo."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            """Guarda os argumentos recebidos, sem abrir janela nenhuma.

            Args:
                *args: Argumentos posicionais do diálogo real.
                **kwargs: Argumentos nomeados do diálogo real.
            """
            self.args = args
            self.kwargs = kwargs

        def show(self) -> Any:
            """Devolve o valor combinado sem esperar o usuário.

            Returns:
                O valor passado para :func:`fake_dialog`.
            """
            return valor

    return FakeDialog


class EventoFalso:
    """Evento de Tk falso, para chamar os manipuladores sem mouse nem teclado."""

    def __init__(self, num: int = 0, delta: int = 0, y: int = 0) -> None:
        """Guarda os campos consultados pelos manipuladores do editor.

        Args:
            num: Número do botão, como o Tk entrega no Linux (4/5 = roda).
            delta: Deslocamento da roda nos sistemas que usam delta.
            y: Coordenada vertical do clique.
        """
        self.num = num
        self.delta = delta
        self.y = y


class BaseAppTest(unittest.TestCase):
    """Base com a janela principal criada e destruída a cada teste."""

    @classmethod
    def setUpClass(cls) -> None:
        from asmx.ui.app import AsmXApp

        cls.AsmXApp = AsmXApp

    def setUp(self) -> None:
        self.app = self.AsmXApp()
        self.app.update()

    def tearDown(self) -> None:
        self.cancelar_realces_pendentes()
        try:
            self.app.destroy()
        except tk.TclError:
            pass

    def cancelar_realces_pendentes(self) -> None:
        """Cancela realces agendados que ficariam órfãos ao fechar a janela.

        ``toggle_comment`` chama ``highlight()`` direto e deixa o trabalho
        agendado para trás; quando ele vence depois do destroy o Tk imprime
        ``invalid command name ...highlight`` no meio da suíte.
        """
        try:
            for trabalho in self.app.tk.call("after", "info"):
                if "highlight" in str(self.app.tk.call("after", "info", trabalho)):
                    self.app.after_cancel(trabalho)
        except tk.TclError:
            pass

    def pump(self) -> None:
        """Deixa o Tk processar o que estiver pendente."""
        for _ in range(3):
            self.app.update_idletasks()
            self.app.update()

    def set_code(self, code: str) -> None:
        """Troca o código do editor e espera a reanálise.

        Args:
            code: Código que vai para o editor.
        """
        self.app.editor.set_code(code)
        self.app.on_code_change()
        self.pump()

    def itens(self, tree: Any, pai: str = "") -> List[str]:
        """Lista os iids de uma árvore, em profundidade.

        Args:
            tree: Árvore a percorrer.
            pai: Item de partida; vazio começa pela raiz.

        Returns:
            Os iids na ordem de visita.
        """
        saida: List[str] = []
        for iid in tree.get_children(pai):
            saida.append(iid)
            saida.extend(self.itens(tree, iid))
        return saida

    def item_com_linha(self, tree: Any) -> Tuple[str, int]:
        """Acha um item da árvore cujas tags apontam para uma linha.

        Args:
            tree: Árvore onde procurar.

        Returns:
            O iid e o número da linha apontada.
        """
        for iid in self.itens(tree):
            linha = self.app._tag_line(tree.item(iid, "tags"))
            if linha:
                return iid, linha
        raise AssertionError("nenhum item da árvore aponta para uma linha")

    def item_sem_linha(self, tree: Any) -> str:
        """Acha um item da árvore que não aponta para nenhuma linha.

        Args:
            tree: Árvore onde procurar.

        Returns:
            O iid do item.
        """
        for iid in self.itens(tree):
            if not self.app._tag_line(tree.item(iid, "tags")):
                return iid
        raise AssertionError("todos os itens da árvore apontam para linhas")


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "sem Tkinter ou sem display")
class TestAppArquivo(BaseAppTest):
    """Comandos do menu Arquivo e o descarte de alterações."""

    def test_carregar_exemplo_troca_o_projeto(self) -> None:
        from asmx.examples import EXAMPLES

        self.app.load_example("linux-loop")
        self.pump()
        self.assertEqual(self.app.project.name, "linux-loop")
        self.assertIn(EXAMPLES["linux-loop"]["title"], self.app.title())
        self.assertEqual(self.app.editor.get_code(), EXAMPLES["linux-loop"]["code"])

    def test_carregar_exemplo_cancelado_mantem_o_projeto(self) -> None:
        from asmx.ui import app as appmod

        self.app.project.dirty = True
        with mock.patch.object(appmod.messagebox, "askyesnocancel", return_value=None):
            self.app.load_example("linux-loop")
        self.assertEqual(self.app.project.name, "projeto")

    def test_novo_projeto_cria_codigo_vazio(self) -> None:
        self.app.new_project()
        self.pump()
        self.assertIn("novo programa", self.app.editor.get_code())
        self.assertEqual(self.app.title(), "ASM X")

    def test_novo_projeto_cancelado_mantem_o_codigo(self) -> None:
        from asmx.ui import app as appmod

        self.app.project.dirty = True
        with mock.patch.object(appmod.messagebox, "askyesnocancel", return_value=None):
            self.app.new_project()
        self.assertIn("Ola, mundo!", self.app.editor.get_code())

    def test_abrir_projeto_salvo(self) -> None:
        from asmx.ui import app as appmod
        from asmx.workspace import Project

        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "guardado.asmproj")
            self.app.project.set_code("mov rax, 7")
            self.app.project.save(caminho)
            with mock.patch.object(appmod.filedialog, "askopenfilename", return_value=caminho):
                self.app.open_project()
        self.pump()
        self.assertIn("mov rax, 7", self.app.editor.get_code())
        self.assertTrue(self.app.title().endswith("guardado.asmproj"))
        self.assertEqual(self.app.project.path, caminho)
        self.assertIsInstance(self.app.project, Project)

    def test_abrir_projeto_cancelado_nao_faz_nada(self) -> None:
        from asmx.ui import app as appmod

        with mock.patch.object(appmod.filedialog, "askopenfilename", return_value=""):
            self.app.open_project()
        self.assertIn("Ola, mundo!", self.app.editor.get_code())

    def test_abrir_projeto_corrompido_mostra_erro(self) -> None:
        from asmx.ui import app as appmod

        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "ruim.asmproj")
            with open(caminho, "w", encoding="utf-8") as arquivo:
                arquivo.write("{isto não é json")
            with (
                mock.patch.object(appmod.filedialog, "askopenfilename", return_value=caminho),
                mock.patch.object(appmod.messagebox, "showerror") as erro,
            ):
                self.app.open_project()
        erro.assert_called_once()
        self.assertIn("Ola, mundo!", self.app.editor.get_code())
        self.assertEqual(self.app.title(), "ASM X")

    def test_salvar_projeto_como(self) -> None:
        from asmx.ui import app as appmod

        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "novo.asmproj")
            self.app.editor.set_code("mov rax, 1")
            with mock.patch.object(appmod.filedialog, "asksaveasfilename", return_value=caminho):
                self.assertTrue(self.app.save_project_as())
            self.assertTrue(os.path.exists(caminho))
        self.assertTrue(self.app.title().endswith("novo.asmproj"))
        self.assertIn("salvo em", self.app.status.cget("text"))

    def test_salvar_projeto_como_cancelado(self) -> None:
        from asmx.ui import app as appmod

        self.assertFalse(self.app.project.dirty)
        with mock.patch.object(appmod.filedialog, "asksaveasfilename", return_value=""):
            self.assertFalse(self.app.save_project_as())

    def test_salvar_projeto_ja_com_caminho(self) -> None:
        from asmx.ui import app as appmod

        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "p.asmproj")
            self.app.project.path = caminho
            self.app.project.dirty = True
            self.app.editor.set_code("mov rbx, 9")
            with mock.patch.object(appmod.filedialog, "asksaveasfilename") as pedir:
                self.assertTrue(self.app.save_project())
            pedir.assert_not_called()
            self.assertTrue(os.path.exists(caminho))
        self.assertFalse(self.app.project.dirty)

    def test_salvar_projeto_sem_caminho_pede_o_destino(self) -> None:
        from asmx.ui import app as appmod

        self.assertIsNone(self.app.project.path)
        with mock.patch.object(appmod.filedialog, "asksaveasfilename", return_value="") as pedir:
            self.assertFalse(self.app.save_project())
        pedir.assert_called_once()

    def test_importar_asm_cria_projeto_novo(self) -> None:
        from asmx.ui import app as appmod

        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "solto.asm")
            with open(caminho, "w", encoding="utf-8") as arquivo:
                arquivo.write("mov rax, 3\n")
            with mock.patch.object(appmod.filedialog, "askopenfilename", return_value=caminho):
                self.app.import_asm()
        self.pump()
        self.assertIn("mov rax, 3", self.app.editor.get_code())
        self.assertTrue(self.app.title().endswith("solto.asm"))

    def test_importar_asm_cancelado_nao_faz_nada(self) -> None:
        from asmx.ui import app as appmod

        with mock.patch.object(appmod.filedialog, "askopenfilename", return_value=""):
            self.app.import_asm()
        self.assertEqual(self.app.project.name, "projeto")

    def test_importar_asm_recusado_mantem_o_projeto(self) -> None:
        from asmx.ui import app as appmod

        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "solto.asm")
            with open(caminho, "w", encoding="utf-8") as arquivo:
                arquivo.write("mov rax, 3\n")
            self.app.project.dirty = True
            with (
                mock.patch.object(appmod.filedialog, "askopenfilename", return_value=caminho),
                mock.patch.object(appmod.messagebox, "askyesnocancel", return_value=None),
            ):
                self.app.import_asm()
        self.assertIn("Ola, mundo!", self.app.editor.get_code())

    def test_exportar_branch_como_asm(self) -> None:
        from asmx.ui import app as appmod

        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "saida.asm")
            self.app.editor.set_code("mov rax, 42")
            with mock.patch.object(appmod.filedialog, "asksaveasfilename", return_value=caminho):
                self.app.export_asm()
            with open(caminho, encoding="utf-8") as arquivo:
                self.assertIn("mov rax, 42", arquivo.read())
        self.assertIn("exportada para", self.app.status.cget("text"))

    def test_exportar_branch_cancelado(self) -> None:
        from asmx.ui import app as appmod

        with mock.patch.object(appmod.filedialog, "asksaveasfilename", return_value=""):
            self.app.export_asm()
        self.assertNotIn("exportada", self.app.status.cget("text"))

    def test_confirm_discard_sem_alteracoes(self) -> None:
        self.app.project.dirty = False
        with mock.patch.object(self.app, "save_project") as salvar:
            self.assertTrue(self.app.confirm_discard())
        salvar.assert_not_called()

    def test_confirm_discard_salva_o_projeto(self) -> None:
        from asmx.ui import app as appmod

        self.app.project.dirty = True
        with (
            mock.patch.object(appmod.messagebox, "askyesnocancel", return_value=True),
            mock.patch.object(self.app, "save_project", return_value=True) as salvar,
        ):
            self.assertTrue(self.app.confirm_discard())
        salvar.assert_called_once()

    def test_confirm_discard_salva_mas_falha(self) -> None:
        from asmx.ui import app as appmod

        self.app.project.dirty = True
        with (
            mock.patch.object(appmod.messagebox, "askyesnocancel", return_value=True),
            mock.patch.object(self.app, "save_project", return_value=False),
        ):
            self.assertFalse(self.app.confirm_discard())

    def test_confirm_discard_descarta(self) -> None:
        from asmx.ui import app as appmod

        self.app.project.dirty = True
        with (
            mock.patch.object(appmod.messagebox, "askyesnocancel", return_value=False),
            mock.patch.object(self.app, "save_project") as salvar,
        ):
            self.assertTrue(self.app.confirm_discard())
        salvar.assert_not_called()

    def test_confirm_discard_cancela(self) -> None:
        from asmx.ui import app as appmod

        self.app.project.dirty = True
        with (
            mock.patch.object(appmod.messagebox, "askyesnocancel", return_value=None),
            mock.patch.object(self.app, "save_project") as salvar,
        ):
            self.assertFalse(self.app.confirm_discard())
        salvar.assert_not_called()

    def test_on_close_fecha_a_janela(self) -> None:
        with mock.patch.object(self.app, "destroy") as destruir:
            self.app.on_close()
        destruir.assert_called_once()

    def test_on_close_cancelado_nao_fecha(self) -> None:
        from asmx.ui import app as appmod

        self.app.project.dirty = True
        with (
            mock.patch.object(appmod.messagebox, "askyesnocancel", return_value=None),
            mock.patch.object(self.app, "destroy") as destruir,
        ):
            self.app.on_close()
        destruir.assert_not_called()


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "sem Tkinter ou sem display")
class TestAppBranches(BaseAppTest):
    """Comandos do menu Branch."""

    def test_nova_branch_pelo_dialogo(self) -> None:
        from asmx.ui import app as appmod

        with mock.patch.object(appmod, "TextPromptDialog", fake_dialog("experimento")):
            self.app.branch_new()
        self.pump()
        self.assertEqual(self.app.project.active, "experimento")
        self.assertIn("experimento", self.app.branch_box.cget("values"))
        self.assertIn("criada a partir de principal", self.app.status.cget("text"))

    def test_nova_branch_cancelada(self) -> None:
        from asmx.ui import app as appmod

        with mock.patch.object(appmod, "TextPromptDialog", fake_dialog("")):
            self.app.branch_new()
        self.assertEqual(sorted(self.app.project.branches), ["principal"])

    def test_nova_branch_sem_nome_mostra_erro(self) -> None:
        from asmx.ui import app as appmod

        with (
            mock.patch.object(appmod, "TextPromptDialog", fake_dialog("   ")),
            mock.patch.object(appmod.messagebox, "showerror") as erro,
        ):
            self.app.branch_new()
        erro.assert_called_once()
        self.assertEqual(sorted(self.app.project.branches), ["principal"])

    def test_nova_branch_repetida_mostra_erro(self) -> None:
        from asmx.ui import app as appmod

        with (
            mock.patch.object(appmod, "TextPromptDialog", fake_dialog("principal")),
            mock.patch.object(appmod.messagebox, "showerror") as erro,
        ):
            self.app.branch_new()
        erro.assert_called_once()
        self.assertEqual(sorted(self.app.project.branches), ["principal"])

    def test_trocar_de_branch_recarrega_o_editor(self) -> None:
        self.app.project.fork("alt")
        self.app.project.switch("alt")
        self.app.project.set_code("mov rax, 99")
        self.app.project.switch("principal")
        self.app.refresh_branches()
        self.app.load_branch_into_editor()
        self.pump()
        self.app.branch_switch("alt")
        self.pump()
        self.assertEqual(self.app.project.active, "alt")
        self.assertIn("mov rax, 99", self.app.editor.get_code())
        self.assertIn("agora editando a branch alt", self.app.status.cget("text"))

    def test_trocar_para_a_mesma_branch_nao_faz_nada(self) -> None:
        self.app.editor.set_code("mov rax, 5")
        self.app.branch_switch("principal")
        self.assertNotIn("agora editando", self.app.status.cget("text"))
        self.assertIn("mov rax, 5", self.app.editor.get_code())

    def test_renomear_branch(self) -> None:
        from asmx.ui import app as appmod

        with mock.patch.object(appmod, "TextPromptDialog", fake_dialog("renomeada")):
            self.app.branch_rename()
        self.assertEqual(self.app.project.active, "renomeada")
        self.assertIn("renomeada", self.app.branch_box.cget("values"))

    def test_renomear_branch_cancelado(self) -> None:
        from asmx.ui import app as appmod

        with mock.patch.object(appmod, "TextPromptDialog", fake_dialog("")):
            self.app.branch_rename()
        self.assertEqual(self.app.project.active, "principal")

    def test_renomear_branch_para_nome_existente_mostra_erro(self) -> None:
        from asmx.ui import app as appmod

        self.app.project.fork("alt")
        self.app.refresh_branches()
        with (
            mock.patch.object(appmod, "TextPromptDialog", fake_dialog("alt")),
            mock.patch.object(appmod.messagebox, "showerror") as erro,
        ):
            self.app.branch_rename()
        erro.assert_called_once()
        self.assertEqual(self.app.project.active, "principal")

    def test_excluir_branch_confirmado(self) -> None:
        from asmx.ui import app as appmod

        self.app.project.fork("alt")
        self.app.branch_switch("alt")
        self.pump()
        with mock.patch.object(appmod.messagebox, "askyesno", return_value=True):
            self.app.branch_delete()
        self.pump()
        self.assertNotIn("alt", self.app.project.branches)
        self.assertEqual(self.app.project.active, "principal")

    def test_excluir_branch_recusado(self) -> None:
        from asmx.ui import app as appmod

        self.app.project.fork("alt")
        self.app.refresh_branches()
        with mock.patch.object(appmod.messagebox, "askyesno", return_value=False):
            self.app.branch_delete()
        self.assertIn("alt", self.app.project.branches)

    def test_excluir_a_unica_branch_mostra_erro(self) -> None:
        from asmx.ui import app as appmod

        with (
            mock.patch.object(appmod.messagebox, "askyesno", return_value=True),
            mock.patch.object(appmod.messagebox, "showerror") as erro,
        ):
            self.app.branch_delete()
        erro.assert_called_once()
        self.assertEqual(sorted(self.app.project.branches), ["principal"])

    def test_comparar_branches_abre_a_janela(self) -> None:
        from asmx.ui import app as appmod

        self.app.project.fork("alt")
        self.app.project.switch("alt")
        self.app.project.set_code("mov rax, 2")
        self.app.project.switch("principal")
        self.app.refresh_branches()
        with (
            mock.patch.object(appmod, "TextPromptDialog", fake_dialog("alt")),
            mock.patch.object(appmod, "DiffDialog") as janela,
        ):
            self.app.branch_diff()
        janela.assert_called_once()
        self.assertEqual(janela.call_args[0][1], "principal ↔ alt")
        self.assertIn("+mov rax, 2", janela.call_args[0][2])

    def test_comparar_com_uma_branch_so_avisa(self) -> None:
        from asmx.ui import app as appmod

        with (
            mock.patch.object(appmod.messagebox, "showinfo") as aviso,
            mock.patch.object(appmod, "DiffDialog") as janela,
        ):
            self.app.branch_diff()
        aviso.assert_called_once()
        janela.assert_not_called()

    def test_comparar_branch_inexistente_nao_abre(self) -> None:
        from asmx.ui import app as appmod

        self.app.project.fork("alt")
        with (
            mock.patch.object(appmod, "TextPromptDialog", fake_dialog("naoexiste")),
            mock.patch.object(appmod, "DiffDialog") as janela,
        ):
            self.app.branch_diff()
        janela.assert_not_called()

    def test_comparar_branch_cancelado(self) -> None:
        from asmx.ui import app as appmod

        self.app.project.fork("alt")
        with (
            mock.patch.object(appmod, "TextPromptDialog", fake_dialog(None)),
            mock.patch.object(appmod, "DiffDialog") as janela,
        ):
            self.app.branch_diff()
        janela.assert_not_called()


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "sem Tkinter ou sem display")
class TestAppCenarios(BaseAppTest):
    """Comandos da aba Testes."""

    def test_criar_cenario_pelo_dialogo(self) -> None:
        from asmx.ui import app as appmod
        from asmx.workspace import Scenario

        novo = Scenario(name="novo", expect_output="Ola, mundo!\n")
        with mock.patch.object(appmod, "ScenarioDialog", fake_dialog(novo)):
            self.app.scenario_new()
        self.pump()
        self.assertIn("novo", self.app.scenario_tree.get_children())

    def test_criar_cenario_cancelado(self) -> None:
        from asmx.ui import app as appmod

        with mock.patch.object(appmod, "ScenarioDialog", fake_dialog(None)):
            self.app.scenario_new()
        self.assertEqual(self.app.project.branch.scenarios, [])

    def test_editar_cenario_trocando_o_nome(self) -> None:
        from asmx.ui import app as appmod
        from asmx.workspace import Scenario

        self.app.project.add_scenario(Scenario(name="antigo"))
        self.app.refresh_scenarios()
        self.app.scenario_tree.selection_set("antigo")
        with mock.patch.object(
            appmod, "ScenarioDialog", fake_dialog(Scenario(name="novo", expect_exit=0))
        ):
            self.app.scenario_edit()
        self.pump()
        self.assertEqual([s.name for s in self.app.project.branch.scenarios], ["novo"])
        self.assertIn("novo", self.app.scenario_tree.get_children())
        self.assertNotIn("antigo", self.app.scenario_tree.get_children())

    def test_editar_cenario_mantendo_o_nome(self) -> None:
        from asmx.ui import app as appmod
        from asmx.workspace import Scenario

        self.app.project.add_scenario(Scenario(name="unico"))
        self.app.refresh_scenarios()
        self.app.scenario_tree.selection_set("unico")
        with mock.patch.object(
            appmod, "ScenarioDialog", fake_dialog(Scenario(name="unico", expect_exit=3))
        ):
            self.app.scenario_edit()
        self.pump()
        self.assertEqual([s.name for s in self.app.project.branch.scenarios], ["unico"])
        self.assertEqual(self.app.project.branch.scenarios[0].expect_exit, 3)

    def test_editar_cenario_sem_selecao_avisa(self) -> None:
        from asmx.ui import app as appmod

        with mock.patch.object(appmod, "ScenarioDialog") as janela:
            self.app.scenario_edit()
        janela.assert_not_called()
        self.assertIn("selecione um cenário", self.app.status.cget("text"))

    def test_editar_cenario_cancelado_nao_muda_nada(self) -> None:
        from asmx.ui import app as appmod
        from asmx.workspace import Scenario

        self.app.project.add_scenario(Scenario(name="fica"))
        self.app.refresh_scenarios()
        self.app.scenario_tree.selection_set("fica")
        with mock.patch.object(appmod, "ScenarioDialog", fake_dialog(None)):
            self.app.scenario_edit()
        self.assertEqual([s.name for s in self.app.project.branch.scenarios], ["fica"])

    def test_excluir_cenario(self) -> None:
        from asmx.workspace import Scenario

        self.app.project.add_scenario(Scenario(name="descartavel"))
        self.app.refresh_scenarios()
        self.app.scenario_tree.selection_set("descartavel")
        self.app.scenario_delete()
        self.pump()
        self.assertEqual(self.app.project.branch.scenarios, [])
        self.assertNotIn("descartavel", self.app.scenario_tree.get_children())

    def test_excluir_cenario_sem_selecao_nao_faz_nada(self) -> None:
        from asmx.workspace import Scenario

        self.app.project.add_scenario(Scenario(name="fica"))
        self.app.refresh_scenarios()
        self.app.scenario_delete()
        self.assertEqual([s.name for s in self.app.project.branch.scenarios], ["fica"])

    def test_rodar_cenario_selecionado(self) -> None:
        from asmx.workspace import Scenario

        self.app.project.add_scenario(Scenario(name="passa", expect_output="Ola, mundo!\n"))
        self.app.refresh_scenarios()
        self.app.scenario_tree.selection_set("passa")
        self.app.run_selected_scenario()
        self.pump()
        self.assertEqual(self.app.scenario_tree.item("passa", "tags"), ("ok",))
        self.assertIn("passou", self.app.status.cget("text"))

    def test_rodar_cenario_sem_selecao_avisa(self) -> None:
        self.app.run_selected_scenario()
        self.assertIn("selecione um cenário", self.app.status.cget("text"))

    def test_rodar_todos_sem_cenarios_avisa(self) -> None:
        self.app.run_all_scenarios()
        self.assertIn("nenhum cenário", self.app.status.cget("text"))

    def test_detalhe_de_cenario_que_nunca_rodou(self) -> None:
        from asmx.workspace import Scenario

        self.app.project.add_scenario(Scenario(name="parado", entry="_start", regs={"rdi": "1"}))
        self.app.refresh_scenarios()
        self.app.scenario_tree.selection_set("parado")
        self.app.on_scenario_select()
        texto = self.app.scenario_detail.cget("text")
        self.assertIn("ainda não rodou", texto)
        self.assertIn("_start", texto)

    def test_detalhe_de_cenario_sem_selecao(self) -> None:
        antes = self.app.scenario_detail.cget("text")
        self.app.on_scenario_select()
        self.assertEqual(self.app.scenario_detail.cget("text"), antes)

    def test_detalhe_de_cenario_que_passou(self) -> None:
        from asmx.ui import theme
        from asmx.workspace import Scenario

        self.app.project.add_scenario(Scenario(name="passa", expect_output="Ola, mundo!\n"))
        self.app.refresh_scenarios()
        self.app.run_all_scenarios()
        self.app.scenario_tree.selection_set("passa")
        self.app.on_scenario_select()
        texto = self.app.scenario_detail.cget("text")
        self.assertIn("passou", texto)
        self.assertIn("instruções executadas", texto)
        self.assertEqual(str(self.app.scenario_detail.cget("foreground")), theme.CALL)

    def test_detalhe_de_cenario_que_falhou_com_problemas(self) -> None:
        from asmx.examples import EXAMPLES
        from asmx.ui import theme
        from asmx.workspace import Scenario

        self.set_code(EXAMPLES["linux-loop"]["code"])
        self.app.project.add_scenario(Scenario(name="laco", max_steps=5))
        self.app.refresh_scenarios()
        self.app.run_all_scenarios()
        self.pump()
        self.app.scenario_tree.selection_set("laco")
        self.app.on_scenario_select()
        texto = self.app.scenario_detail.cget("text")
        self.assertIn("FALHOU", texto)
        self.assertIn("problemas detectados", texto)
        self.assertEqual(str(self.app.scenario_detail.cget("foreground")), theme.SEV_COLOR["erro"])

    def test_rodar_todos_conta_os_que_passaram(self) -> None:
        from asmx.workspace import Scenario

        self.app.project.add_scenario(Scenario(name="passa", expect_output="Ola, mundo!\n"))
        self.app.project.add_scenario(Scenario(name="falha", expect_output="nada disso"))
        self.app.refresh_scenarios()
        self.app.run_all_scenarios()
        self.pump()
        self.assertEqual(self.app.scenario_tree.item("passa", "tags"), ("ok",))
        self.assertEqual(self.app.scenario_tree.item("falha", "tags"), ("falhou",))
        self.assertIn("1 de 2", self.app.status.cget("text"))


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "sem Tkinter ou sem display")
class TestAppNotas(BaseAppTest):
    """Anotações por linha."""

    def test_anotar_linha_do_cursor(self) -> None:
        from asmx.ui import app as appmod

        self.app.editor.goto_line(3)
        with mock.patch.object(appmod, "TextPromptDialog", fake_dialog("lembrete")):
            self.app.edit_note()
        self.pump()
        self.assertEqual(self.app.project.note(3), "lembrete")
        self.assertIn("3", self.app.note_tree.get_children())
        self.assertIn("salva na linha 3", self.app.status.cget("text"))

    def test_anotacao_vazia_remove_a_linha(self) -> None:
        from asmx.ui import app as appmod

        self.app.editor.goto_line(3)
        self.app.project.set_note(3, "antiga")
        self.app.refresh_notes()
        with mock.patch.object(appmod, "TextPromptDialog", fake_dialog("")):
            self.app.edit_note()
        self.pump()
        self.assertEqual(self.app.project.note(3), "")
        self.assertNotIn("3", self.app.note_tree.get_children())
        self.assertIn("removida na linha 3", self.app.status.cget("text"))

    def test_anotacao_cancelada_nao_muda_nada(self) -> None:
        from asmx.ui import app as appmod

        self.app.editor.goto_line(3)
        self.app.project.set_note(3, "antiga")
        self.app.refresh_notes()
        with mock.patch.object(appmod, "TextPromptDialog", fake_dialog(None)):
            self.app.edit_note()
        self.assertEqual(self.app.project.note(3), "antiga")

    def test_abrir_anotacao_pula_para_a_linha(self) -> None:
        self.app.project.set_note(2, "volte aqui")
        self.app.refresh_notes()
        self.app.note_tree.selection_set("2")
        self.app.on_note_open()
        self.pump()
        self.assertEqual(self.app.editor.cursor_line(), 2)

    def test_abrir_anotacao_sem_selecao(self) -> None:
        self.app.editor.goto_line(1)
        self.app.on_note_open()
        self.assertEqual(self.app.editor.cursor_line(), 1)

    def test_remover_anotacao_selecionada(self) -> None:
        self.app.project.set_note(4, "some depois")
        self.app.refresh_notes()
        self.app.note_tree.selection_set("4")
        self.app.delete_note()
        self.pump()
        self.assertEqual(self.app.project.note(4), "")
        self.assertEqual(self.app.note_tree.get_children(), ())

    def test_remover_anotacao_sem_selecao(self) -> None:
        self.app.project.set_note(4, "fica")
        self.app.refresh_notes()
        self.app.delete_note()
        self.assertEqual(self.app.project.note(4), "fica")

    def test_aba_de_notas_e_limpa_ao_trocar_de_branch(self) -> None:
        self.app.project.set_note(2, "nota da principal")
        self.app.refresh_notes()
        self.assertEqual(len(self.app.note_tree.get_children()), 1)
        self.app.project.fork("alt")
        self.app.branch_switch("alt")
        self.pump()
        self.assertEqual(len(self.app.note_tree.get_children()), 1)


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "sem Tkinter ou sem display")
class TestAppDocumentacao(BaseAppTest):
    """Painel de documentação e explicação de linhas."""

    def test_explica_rotulo_local(self) -> None:
        self.set_code(CODIGO_COMPLETO)
        linha = next(item.n for item in self.app.analysis.program.lines if item.local_label)
        self.app.on_cursor(linha, 1)
        texto = self.app.doc_text.get("1.0", "end-1c")
        self.assertIn("Rótulo", texto)
        self.assertIn("rótulo local", texto)

    def test_on_cursor_percorre_todos_os_tipos_de_linha(self) -> None:
        self.set_code(CODIGO_COMPLETO)
        vistos = set()
        for linha in self.app.analysis.program.lines:
            self.app.on_cursor(linha.n, 1)
            self.assertTrue(self.app.doc_text.get("1.0", "end-1c").strip())
            vistos.add(linha.kind)
        self.assertIn("empty", vistos)
        self.assertIn("label", vistos)
        self.assertIn("data", vistos)
        self.assertIn("directive", vistos)

    def test_describe_line_de_cada_tipo(self) -> None:
        from asmx.parser import Line

        casos = [
            (Line(n=9, raw=".loop:", kind="label", label=".loop", local_label=True), "Rótulo"),
            (
                Line(
                    n=3,
                    raw="buf: resb 16",
                    kind="data",
                    label="buf",
                    directive="resb",
                    args=["16"],
                    reserve=True,
                ),
                "Reserva",
            ),
            (
                Line(
                    n=2,
                    raw="msg: db 1",
                    kind="data",
                    label="msg",
                    directive="db",
                    args=["1"],
                    unit=1,
                ),
                "Dado",
            ),
            (
                Line(
                    n=4,
                    raw="TAM equ 4",
                    kind="data",
                    label="TAM",
                    directive="equ",
                    args=["4"],
                    unit=4,
                ),
                "Constante",
            ),
            (
                Line(
                    n=5,
                    raw="tab: times 4 db 0",
                    kind="directive",
                    directive="times",
                    args=["4", "db", "0"],
                ),
                "Diretiva",
            ),
        ]
        for linha, esperado in casos:
            with self.subTest(tipo=linha.kind, diretiva=linha.directive):
                self.app.describe_line(linha)
                self.assertIn(esperado, self.app.doc_text.get("1.0", "end-1c"))

    def test_on_cursor_sem_analise_nao_quebra(self) -> None:
        self.app.analysis = None
        self.app.on_cursor(1, 1)
        self.assertIn("Ln 1, Col 1", self.app.status.cget("text"))

    def test_lista_de_documentacao_com_e_sem_busca(self) -> None:
        self.app.doc_query.delete(0, "end")
        self.app.refresh_doc_list()
        todos = self.app.doc_list.get(0, "end")
        self.assertGreater(len(todos), 10)
        self.app.doc_query.insert(0, "jn")
        self.app.refresh_doc_list()
        filtrados = self.app.doc_list.get(0, "end")
        self.assertTrue(filtrados)
        self.assertTrue(all(nome.startswith("jn") for nome in filtrados))
        self.assertLess(len(filtrados), len(todos))

    def test_escolher_mnemonico_na_lista_mostra_a_ajuda(self) -> None:
        self.app.doc_query.delete(0, "end")
        self.app.refresh_doc_list()
        self.app.doc_list.selection_clear(0, "end")
        self.app.doc_list.selection_set(0)
        self.app.on_doc_select()
        escolhido = self.app.doc_list.get(0)
        self.assertIn(escolhido.upper(), self.app.doc_text.get("1.0", "end-1c"))

    def test_on_doc_select_sem_selecao_nao_faz_nada(self) -> None:
        antes = self.app.doc_text.get("1.0", "end-1c")
        self.app.doc_list.selection_clear(0, "end")
        self.app.on_doc_select()
        self.assertEqual(self.app.doc_text.get("1.0", "end-1c"), antes)

    def test_documentacao_de_mnemonico_conhecido_e_desconhecido(self) -> None:
        self.app.show_doc("mov")
        self.assertIn("MOV", self.app.doc_text.get("1.0", "end-1c"))
        self.app.show_doc("naoexiste")
        self.assertIn("Sem documentação", self.app.doc_text.get("1.0", "end-1c"))
        self.app.show_doc(None)
        self.assertIn("Sem documentação", self.app.doc_text.get("1.0", "end-1c"))

    def test_documentacao_de_instrucao_com_memoria(self) -> None:
        self.set_code("section .text\n_start:\n    mov rax, [rbp - 8]\n")
        instrucao = next(i for i in self.app.analysis.instrs if i.mnemonic == "mov")
        self.app.show_doc(instrucao.mnemonic, instrucao)
        texto = self.app.doc_text.get("1.0", "end-1c")
        self.assertIn("MOV", texto)
        self.assertIn("RAX", texto)
        self.assertIn("RBP", texto)

    def test_documentacao_de_instrucao_com_anotacao(self) -> None:
        instrucao = next(i for i in self.app.analysis.instrs if i.mnemonic == "syscall")
        self.app.show_doc(instrucao.mnemonic, instrucao)
        texto = self.app.doc_text.get("1.0", "end-1c")
        self.assertIn("SYSCALL", texto)
        self.assertIn("Flags do processador", texto)

    def test_documentacao_de_mnemonico_com_anotacao(self) -> None:
        from asmx.isa import ISA

        com_nota = next(k for k, v in ISA.items() if v.get("note"))
        self.app.show_doc(com_nota)
        self.assertIn(ISA[com_nota]["note"], self.app.doc_text.get("1.0", "end-1c"))

    def test_documentacao_de_instrucao_com_registradores_sem_verbetes(self) -> None:
        self.set_code("section .text\n_start:\n    movups xmm0, [rbp - 8]\n")
        instrucao = next(i for i in self.app.analysis.instrs if i.mnemonic == "movups")
        self.app.show_doc(instrucao.mnemonic, instrucao)
        texto = self.app.doc_text.get("1.0", "end-1c")
        self.assertIn("RBP", texto)
        self.assertIn("sem documentação", texto.lower())

    def test_selecionar_registrador_explica_a_funcao(self) -> None:
        self.app.reg_tree.selection_set("rax")
        self.app.on_reg_select()
        self.assertIn("RAX", self.app.status.cget("text"))
        self.app.reg_tree.selection_remove("rax")
        antes = self.app.status.cget("text")
        self.app.on_reg_select()
        self.assertEqual(self.app.status.cget("text"), antes)


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "sem Tkinter ou sem display")
class TestAppEstruturaEProblemas(BaseAppTest):
    """Árvore de estrutura, lista de problemas e breakpoints."""

    def test_clicar_na_estrutura_pula_para_a_linha(self) -> None:
        iid, linha = self.item_com_linha(self.app.tree)
        self.app.tree.selection_set(iid)
        self.app.on_tree_select()
        self.pump()
        self.assertEqual(self.app.editor.cursor_line(), linha)

    def test_clicar_na_estrutura_sem_selecao(self) -> None:
        self.app.editor.goto_line(1)
        self.app.tree.selection_remove(*self.app.tree.selection())
        self.app.on_tree_select()
        self.assertEqual(self.app.editor.cursor_line(), 1)

    def test_clicar_na_estrutura_sem_linha_nao_pula(self) -> None:
        iid = self.item_sem_linha(self.app.tree)
        self.app.editor.goto_line(1)
        self.app.tree.selection_set(iid)
        self.app.on_tree_select()
        self.assertEqual(self.app.editor.cursor_line(), 1)

    def test_tag_line_devolve_none_sem_tag_de_linha(self) -> None:
        self.assertIsNone(self.app._tag_line(("blk", "sec")))
        self.assertEqual(self.app._tag_line(("linha:7", "sem_mov")), 7)
        self.assertIsNone(self.app._tag_line(""))

    def test_selecionar_problema_mostra_a_dica(self) -> None:
        from asmx.examples import EXAMPLES

        self.set_code(EXAMPLES["quebrado"]["code"])
        self.app.validate_now()
        self.pump()
        primeiro = self.app.problem_tree.get_children()[0]
        self.app.problem_tree.selection_set(primeiro)
        self.app.on_problem_select()
        self.assertTrue(self.app.problem_hint.cget("text"))

    def test_selecionar_problema_sem_selecao(self) -> None:
        self.app.problem_tree.selection_remove(*self.app.problem_tree.selection())
        self.app.on_problem_select()
        self.assertEqual(self.app.problem_hint.cget("text"), "")

    def test_selecionar_problema_sem_linha_conhecida(self) -> None:
        self.app.problem_tree.insert(
            "", "end", iid="extra", values=(0, "X", "sem linha"), tags=("erro",)
        )
        self.app.problem_tree.selection_set("extra")
        self.app.on_problem_select()
        self.assertEqual(self.app.problem_hint.cget("text"), "")

    def test_abrir_problema_pula_para_a_linha(self) -> None:
        from asmx.examples import EXAMPLES

        self.set_code(EXAMPLES["quebrado"]["code"])
        self.app.validate_now()
        self.pump()
        primeiro = self.app.problem_tree.get_children()[0]
        linha = int(self.app.problem_tree.item(primeiro, "values")[0])
        self.app.problem_tree.selection_set(primeiro)
        self.app.on_problem_open()
        self.pump()
        self.assertEqual(self.app.editor.cursor_line(), linha)

    def test_abrir_problema_sem_selecao(self) -> None:
        self.app.editor.goto_line(1)
        self.app.problem_tree.selection_remove(*self.app.problem_tree.selection())
        self.app.on_problem_open()
        self.assertEqual(self.app.editor.cursor_line(), 1)

    def test_abrir_problema_sem_linha_nao_pula(self) -> None:
        self.app.problem_tree.insert("", "end", iid="semlinha", values=(0, "X", "?"))
        self.app.editor.goto_line(1)
        self.app.problem_tree.selection_set("semlinha")
        self.app.on_problem_open()
        self.assertEqual(self.app.editor.cursor_line(), 1)

    def test_estrutura_sem_analise_fica_vazia(self) -> None:
        self.app.analysis = None
        self.app.refresh_structure()
        self.assertEqual(self.app.tree.get_children(), ())

    def test_refresh_dos_paineis_nao_quebra(self) -> None:
        self.app.refresh_problems()
        self.app.refresh_scenarios()
        self.app.refresh_notes()
        self.assertIn("Problemas", self.app.bottom.tab(self.app.bottom.select(), "text"))

    def test_breakpoint_e_guardado_no_projeto(self) -> None:
        self.app.editor.breakpoints = {3}
        self.app.on_breakpoint(3, True)
        self.assertEqual(self.app.project.branch.breakpoints, [3])
        self.assertIn("breakpoint ligado na linha 3", self.app.status.cget("text"))
        self.app.on_breakpoint(3, False)
        self.assertIn("desligado", self.app.status.cget("text"))


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "sem Tkinter ou sem display")
class TestAppExecucao(BaseAppTest):
    """Menu Executar: passos, execução, pilha e depuração isolada."""

    def test_reiniciar_sem_analise_nao_faz_nada(self) -> None:
        maquina = mock.MagicMock()
        self.app.analysis = None
        self.app.machine = maquina
        self.app.reset_machine()
        self.assertIs(self.app.machine, maquina)

    def test_ensure_machine_cria_a_maquina_que_falta(self) -> None:
        self.app.machine = None
        maquina = self.app._ensure_machine()
        self.assertIsNotNone(maquina)
        self.assertIs(maquina, self.app.machine)

    def test_passo_depois_de_parar_avisa(self) -> None:
        self.app.run()
        self.pump()
        self.assertTrue(self.app.machine.halted)
        self.app.step()
        self.assertIn("já terminou", self.app.status.cget("text"))

    def test_rodar_depois_de_parar_reinicia_sozinho(self) -> None:
        self.app.run()
        self.pump()
        primeira = self.app.machine
        self.app.run()
        self.pump()
        self.assertIsNot(self.app.machine, primeira)
        self.assertIn("Ola, mundo!", self.app.output_text.get("1.0", "end-1c"))
        self.assertIn("execução encerrada", self.app.status.cget("text"))

    def test_rodar_ate_o_cursor_sem_instrucao_avisa(self) -> None:
        self.set_code("section .text\n_start:\n    nop\n")
        self.app.editor.goto_line(1)
        self.app.run_to_cursor()
        self.assertIn("não há instrução", self.app.status.cget("text"))

    def test_depurar_funcao_sem_analise(self) -> None:
        self.app.analysis = None
        self.app.debug_function()
        self.assertIn("máquina reiniciada", self.app.status.cget("text"))

    def test_depurar_funcao_sem_rotulos_avisa(self) -> None:
        from asmx.ui import app as appmod

        self.set_code("    mov rax, 1\n    nop\n")
        with mock.patch.object(appmod.messagebox, "showinfo") as aviso:
            self.app.debug_function()
        aviso.assert_called_once()

    def test_depurar_funcao_inexistente_nao_faz_nada(self) -> None:
        from asmx.ui import app as appmod

        antes = self.app.machine
        with mock.patch.object(appmod, "TextPromptDialog", fake_dialog("nao_existe")):
            self.app.debug_function()
        self.assertIs(self.app.machine, antes)

    def test_depurar_funcao_cancelada_nao_faz_nada(self) -> None:
        from asmx.ui import app as appmod

        antes = self.app.machine
        with mock.patch.object(appmod, "TextPromptDialog", fake_dialog(None)):
            self.app.debug_function()
        self.assertIs(self.app.machine, antes)

    def test_painel_da_maquina_sem_maquina(self) -> None:
        antes = self.app.reg_tree.get_children()
        self.app.machine = None
        self.app.refresh_machine()
        self.assertEqual(self.app.reg_tree.get_children(), antes)

    def test_pilha_mostra_endereco_de_retorno(self) -> None:
        self.set_code(CODIGO_PILHA)
        self.app.reset_machine()
        for _ in range(6):
            self.app.step()
        self.pump()
        raiz = self.app.mem_tree.get_children()[0]
        notas = [
            self.app.mem_tree.item(i, "values")[1] for i in self.app.mem_tree.get_children(raiz)
        ]
        self.assertEqual(len(notas), 6)
        self.assertEqual(notas[0], "RSP")
        self.assertIn("endereço de retorno", notas[-1])

    def test_falha_na_analise_avisa_no_rodape(self) -> None:
        from asmx.ui import app as appmod

        with mock.patch.object(appmod, "analyze", side_effect=ValueError("quebrou")):
            self.app.analyze_now()
        self.assertIn("falha ao analisar", self.app.status.cget("text"))

    def test_mudanca_suspensa_nao_reanalisa(self) -> None:
        antes = self.app.analysis
        self.app._suspend_change = True
        self.app.editor.set_code("mov rax, 123")
        self.app.on_code_change()
        self.assertIs(self.app.analysis, antes)
        self.app._suspend_change = False


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "sem Tkinter ou sem display")
class TestAppStatus(BaseAppTest):
    """Linha de status, validação e atalhos de edição."""

    def test_status_com_cursor_e_mensagem(self) -> None:
        self.app.set_status("recado importante", cursor=(4, 5))
        texto = self.app.status.cget("text")
        self.assertIn("Ln 4, Col 5", texto)
        self.assertIn("branch: principal", texto)
        self.assertIn("recado importante", texto)

    def test_status_sem_analise_e_sem_argumentos(self) -> None:
        self.app.analysis = None
        self.app.set_status()
        texto = self.app.status.cget("text")
        self.assertIn("Ln ", texto)
        self.assertNotIn("instruções", texto)

    def test_status_avisa_que_nao_foi_salvo(self) -> None:
        self.app.project.dirty = True
        self.app.set_status()
        self.assertIn("não salvo", self.app.status.cget("text"))

    def test_validar_codigo_limpo(self) -> None:
        self.app.validate_now()
        self.pump()
        self.assertIn("nenhum problema encontrado", self.app.status.cget("text"))

    def test_validar_codigo_quebrado(self) -> None:
        from asmx.examples import EXAMPLES

        self.set_code(EXAMPLES["quebrado"]["code"])
        self.app.validate_now()
        self.pump()
        self.assertTrue(self.app.problems)
        self.assertIn("Problemas", self.app.bottom.tab(self.app.bottom.select(), "text"))

    def test_comentar_pelo_menu(self) -> None:
        self.set_code("mov rax, 1\nmov rbx, 2")
        self.app.editor.goto_line(1)
        self.app.editor_toggle_comment()
        self.pump()
        self.assertTrue(self.app.editor.get_code().startswith("; mov rax, 1"))

    def test_procurar_com_e_sem_sucesso(self) -> None:
        from asmx.ui import app as appmod

        with mock.patch.object(appmod, "TextPromptDialog", fake_dialog("Ola")):
            self.app.find()
        self.assertTrue(self.app.editor.text.tag_ranges("found"))
        with mock.patch.object(appmod, "TextPromptDialog", fake_dialog("naoexiste")):
            self.app.find()
        self.assertIn("não encontrei", self.app.status.cget("text"))

    def test_procurar_cancelado(self) -> None:
        from asmx.ui import app as appmod

        with mock.patch.object(appmod, "TextPromptDialog", fake_dialog(None)):
            self.app.find()
        self.assertFalse(self.app.editor.text.tag_ranges("found"))

    def test_ir_para_a_linha(self) -> None:
        from asmx.ui import app as appmod

        with mock.patch.object(appmod, "TextPromptDialog", fake_dialog("3")):
            self.app.goto_line()
        self.assertEqual(self.app.editor.cursor_line(), 3)

    def test_ir_para_linha_invalida_e_cancelado(self) -> None:
        from asmx.ui import app as appmod

        self.app.editor.goto_line(2)
        for resposta in ("abc", "", None, "   "):
            with self.subTest(resposta=resposta):
                with mock.patch.object(appmod, "TextPromptDialog", fake_dialog(resposta)):
                    self.app.goto_line()
                self.assertEqual(self.app.editor.cursor_line(), 2)

    def test_mostrar_sobre(self) -> None:
        from asmx.ui import app as appmod

        janela = mock.MagicMock()
        with mock.patch.object(appmod, "AboutDialog", janela):
            self.app.show_about()
        janela.assert_called_once()
        janela.return_value.show.assert_called_once()


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "sem Tkinter ou sem display")
class TestEditorWidget(BaseAppTest):
    """Métodos do editor que não dependem de digitação real."""

    def test_set_code_mantendo_a_rolagem(self) -> None:
        ed = self.app.editor
        codigo = "\n".join("linha %d" % i for i in range(300))
        ed.set_code(codigo)
        self.pump()
        ed.text.yview_moveto(0.6)
        self.pump()
        self.assertGreater(ed.text.yview()[0], 0.1)
        ed.set_code(codigo, keep_view=True)
        self.pump()
        self.assertGreater(ed.text.yview()[0], 0.1)

    def test_contagem_de_linhas_e_cursor(self) -> None:
        ed = self.app.editor
        ed.set_code("mov rax, 1\nmov rbx, 2\nmov rcx, 3")
        self.pump()
        self.assertEqual(ed.line_count(), 3)
        ed.goto_line(2, focus=False)
        self.assertEqual(ed.cursor_line(), 2)
        self.assertEqual(ed.cursor_col(), 1)
        ed.goto_line(3)
        self.assertEqual(ed.cursor_line(), 3)

    def test_inserir_no_cursor(self) -> None:
        ed = self.app.editor
        ed.set_code("mov rax, 1")
        ed.goto_line(1)
        ed.insert_at_cursor("; nota\n")
        self.pump()
        self.assertTrue(ed.get_code().startswith("; nota\n"))
        self.assertIn("; nota", ed.get_code())

    def test_procurar_acha_miss_e_termo_vazio(self) -> None:
        ed = self.app.editor
        ed.set_code("mov rax, 1\nmov rbx, 2")
        self.pump()
        self.assertTrue(ed.find("rbx"))
        self.assertTrue(ed.text.tag_ranges("found"))
        self.assertTrue(ed.find("mov"))
        self.assertTrue(ed.find("mov", from_start=True))
        self.assertFalse(ed.find("naoexiste"))
        self.assertFalse(ed.find(""))

    def test_comentar_e_descomentar_uma_selecao(self) -> None:
        ed = self.app.editor
        ed.set_code("mov rax, 1\n\nmov rbx, 2")
        self.pump()
        ed.text.tag_add("sel", "1.0", "3.end")
        ed.toggle_comment()
        self.pump()
        linhas = ed.get_code().split("\n")
        self.assertEqual(linhas[0], "; mov rax, 1")
        self.assertEqual(linhas[1], "")
        self.assertEqual(linhas[2], "; mov rbx, 2")
        ed.text.tag_add("sel", "1.0", "3.end")
        ed.toggle_comment()
        self.pump()
        self.assertEqual(ed.get_code(), "mov rax, 1\n\nmov rbx, 2")

    def test_descomentar_linha_ja_comentada(self) -> None:
        ed = self.app.editor
        ed.set_code("; mov rax, 1")
        self.pump()
        ed.goto_line(1)
        ed.toggle_comment()
        self.pump()
        self.assertEqual(ed.get_code(), "mov rax, 1")

    def test_marcar_linhas_com_erro(self) -> None:
        ed = self.app.editor
        ed.set_code("mov rax, 1\nmov rbx, 2\nmov rcx, 3")
        self.pump()
        ed.mark_error_lines([1, 3])
        self.assertEqual(len(ed.text.tag_ranges("errorline")) // 2, 2)
        with mock.patch.object(ed.text, "tag_add", side_effect=tk.TclError("índice inválido")):
            ed.mark_error_lines([1])

    def test_marcar_linha_em_execucao(self) -> None:
        ed = self.app.editor
        ed.set_code("mov rax, 1\nmov rbx, 2")
        self.pump()
        ed.set_exec_line(2)
        self.assertTrue(ed.text.tag_ranges("exec"))
        ed.set_exec_line(None)
        self.assertFalse(ed.text.tag_ranges("exec"))

    def test_marcar_linha_do_cursor(self) -> None:
        ed = self.app.editor
        ed.set_code("mov rax, 1\nmov rbx, 2")
        ed.goto_line(2)
        self.pump()
        ed.mark_current_line()
        self.assertTrue(ed.text.tag_ranges("current"))

    def test_agendar_e_refazer_o_realce(self) -> None:
        ed = self.app.editor
        ed.set_code('; comentario\nmsg: db "texto", 0x10\n    mov rax, 0x10\n')
        self.pump()
        ed.schedule_highlight()
        ed.schedule_highlight()
        self.assertIsNotNone(ed._highlight_job)
        limite = time.time() + 3.0
        while ed._highlight_job and time.time() < limite:
            self.pump()
            time.sleep(0.02)
        self.assertIsNone(ed._highlight_job, "o realce agendado deveria ter rodado")
        for tag in ("comment", "string", "directive", "label", "number", "register", "mnemonic"):
            with self.subTest(tag=tag):
                self.assertTrue(ed.text.tag_ranges(tag), "tag %s sem marcas" % tag)

    def test_realce_nao_marca_mnemonico_no_meio_da_linha(self) -> None:
        ed = self.app.editor
        ed.set_code("mov rax, call")
        self.pump()
        ed.highlight()
        marcas = ed.text.tag_ranges("mnemonic")
        self.assertEqual(len(marcas), 2)
        self.assertEqual(ed.text.get(marcas[0], marcas[1]), "mov")

    def test_tab_insere_quatro_espacos(self) -> None:
        ed = self.app.editor
        ed.set_code("")
        ed.goto_line(1)
        self.assertEqual(ed._tab(EventoFalso()), "break")
        self.assertEqual(ed.get_code(), "    ")

    def test_roda_do_mouse_rola_nos_dois_sentidos(self) -> None:
        ed = self.app.editor
        ed.set_code("\n".join("linha %d" % i for i in range(300)))
        self.pump()
        ed.text.yview_moveto(0.5)
        self.pump()
        meio = ed.text.yview()[0]
        self.assertEqual(ed._wheel(EventoFalso(num=4)), "break")
        acima = ed.text.yview()[0]
        self.assertLess(acima, meio)
        self.assertEqual(ed._wheel(EventoFalso(num=5)), "break")
        abaixo = ed.text.yview()[0]
        self.assertGreater(abaixo, acima)
        ed._wheel(EventoFalso(delta=120))
        com_delta = ed.text.yview()[0]
        self.assertLess(com_delta, abaixo)
        ed._wheel(EventoFalso(delta=-120))
        self.assertGreater(ed.text.yview()[0], com_delta)

    def test_clique_na_calha_liga_e_desliga_breakpoint(self) -> None:
        ed = self.app.editor
        ed.set_code("\n".join("mov rax, %d" % i for i in range(20)))
        self.pump()
        info = ed.text.dlineinfo("3.0")
        self.assertIsNotNone(info)
        y = int(info[1]) + 3
        ed._gutter_click(EventoFalso(y=y))
        self.assertIn(3, ed.breakpoints)
        self.assertIn(3, self.app.project.branch.breakpoints)
        ed._gutter_click(EventoFalso(y=y))
        self.assertNotIn(3, ed.breakpoints)
        self.app.editor.on_breakpoint = None
        ed._gutter_click(EventoFalso(y=y))
        self.assertIn(3, ed.breakpoints)

    def test_clique_fora_do_texto_e_ignorado(self) -> None:
        ed = self.app.editor
        ed.set_code("mov rax, 1\nmov rbx, 2")
        self.pump()
        ed.breakpoints = set()
        with mock.patch.object(ed, "line_count", return_value=0):
            ed._gutter_click(EventoFalso(y=5))
        self.assertEqual(ed.breakpoints, set())

    def test_limpar_trabalhos_agendados(self) -> None:
        ed = self.app.editor
        ed.schedule_highlight()
        ed._cleanup()
        self.assertIsNone(ed._highlight_job)
        self.assertIsNone(ed._change_job)
        ed.schedule_highlight()
        self.assertIsNone(ed._highlight_job, "editor destruído não agenda realce")
        ed._highlight_job = "trabalho-falso"
        with mock.patch.object(ed, "after_cancel", side_effect=tk.TclError("sumiu")):
            ed._cleanup()
        self.assertIsNone(ed._highlight_job)

    def test_rolagem_repassada_e_barra_sincronizada(self) -> None:
        ed = self.app.editor
        ed.set_code("\n".join("linha %d" % i for i in range(200)))
        self.pump()
        ed._yview("moveto", 0.25)
        self.assertGreater(ed.text.yview()[0], 0.0)
        ed._on_text_scroll(0.0, 1.0)
        primeiro, ultimo = ed.scroll.get()
        self.assertGreaterEqual(primeiro, 0.0)
        self.assertGreater(ultimo, primeiro)

    def test_calha_desenha_marcas(self) -> None:
        ed = self.app.editor
        ed.set_code("\n".join("mov rax, %d" % i for i in range(20)))
        self.pump()
        ed.breakpoints = {2}
        ed.notes = {"3": "anotação"}
        ed.set_exec_line(4)
        self.pump()
        self.assertTrue(ed.gutter.find_all())

    def test_calha_sobrevive_a_texto_sem_indice(self) -> None:
        ed = self.app.editor
        with mock.patch.object(ed.text, "index", side_effect=tk.TclError("sem widget")):
            ed.redraw_gutter()

    def test_editar_sem_observadores(self) -> None:
        ed = self.app.editor
        ed.set_code("mov rax, 1")
        ed.on_change = None
        ed.on_cursor = None
        ed._changed()
        ed._cursor_moved()
        ed._cleanup()
        self.assertTrue(ed.get_code())


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "sem Tkinter ou sem display")
class TestTema(unittest.TestCase):
    """Fontes e tema ttk, incluindo os caminhos de emergência."""

    def setUp(self) -> None:
        self.root = tk.Tk()
        self.root.update()

    def tearDown(self) -> None:
        try:
            self.root.destroy()
        except tk.TclError:
            pass

    def test_fontes_normais(self) -> None:
        from asmx.ui import theme

        self.assertTrue(theme.mono(11).actual("family"))
        self.assertTrue(theme.mono(11, "bold").actual("family"))
        self.assertTrue(theme.ui(10).actual("family"))
        self.assertTrue(theme.ui(12, "bold").actual("family"))

    def test_mono_cai_no_courier_quando_tudo_falha(self) -> None:
        from asmx.ui import theme

        reserva = mock.MagicMock()
        reserva.actual.return_value = "Courier"

        def fonte_falsa(*args: Any, **kwargs: Any) -> Any:
            if kwargs.get("family") == "Courier":
                return reserva
            raise tk.TclError("fonte indisponível")

        with mock.patch.object(theme.tkfont, "Font", side_effect=fonte_falsa):
            self.assertIs(theme.mono(11), reserva)

    def test_mono_pula_fonte_sem_familia(self) -> None:
        from asmx.ui import theme

        vazia = mock.MagicMock()
        vazia.actual.return_value = ""
        boa = mock.MagicMock()
        boa.actual.return_value = "DejaVu Sans Mono"

        def fonte_falsa(*args: Any, **kwargs: Any) -> Any:
            familia = kwargs.get("family")
            if familia == "JetBrains Mono":
                return vazia
            if familia == "DejaVu Sans Mono":
                return boa
            raise tk.TclError("fonte indisponível")

        with mock.patch.object(theme.tkfont, "Font", side_effect=fonte_falsa):
            self.assertIs(theme.mono(11), boa)

    def test_ui_usa_a_fonte_padrao_quando_tudo_falha(self) -> None:
        from asmx.ui import theme

        reserva = mock.MagicMock()
        reserva.actual.return_value = "TkDefaultFont"

        def fonte_falsa(*args: Any, **kwargs: Any) -> Any:
            if kwargs.get("family") is None:
                return reserva
            raise tk.TclError("fonte indisponível")

        with mock.patch.object(theme.tkfont, "Font", side_effect=fonte_falsa):
            self.assertIs(theme.ui(10), reserva)

    def test_ui_pula_fonte_sem_familia(self) -> None:
        from asmx.ui import theme

        vazia = mock.MagicMock()
        vazia.actual.return_value = ""
        boa = mock.MagicMock()
        boa.actual.return_value = "DejaVu Sans"

        def fonte_falsa(*args: Any, **kwargs: Any) -> Any:
            familia = kwargs.get("family")
            if familia == "Segoe UI":
                return vazia
            if familia == "DejaVu Sans":
                return boa
            raise tk.TclError("fonte indisponível")

        with mock.patch.object(theme.tkfont, "Font", side_effect=fonte_falsa):
            self.assertIs(theme.ui(10), boa)

    def test_tema_ttk_sobrevive_a_theme_use_quebrado(self) -> None:
        from tkinter import ttk
        from asmx.ui import theme

        with mock.patch.object(ttk.Style, "theme_use", side_effect=tk.TclError("sem tema")):
            estilo = theme.apply_ttk_theme(self.root)
        self.assertIsInstance(estilo, ttk.Style)
        self.assertTrue(estilo.configure("TFrame", "background"))


if __name__ == "__main__":
    unittest.main()
