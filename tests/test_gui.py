"""Testes da GUI. Precisam de Tkinter e de um display (use xvfb-run)."""

import os
import tempfile
import unittest

try:
    import tkinter as tk
    TK_OK = True
except ImportError:                                   # pragma: no cover
    TK_OK = False

HAS_DISPLAY = bool(os.environ.get("DISPLAY")) or os.name == "nt"


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "sem Tkinter ou sem display")
class TestGUI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from asmx.ui.app import AsmXApp
        cls.AsmXApp = AsmXApp

    def setUp(self):
        self.app = self.AsmXApp()
        self.app.update()

    def tearDown(self):
        try:
            self.app.destroy()
        except tk.TclError:
            pass

    def pump(self):
        for _ in range(3):
            self.app.update_idletasks()
            self.app.update()

    def set_code(self, code):
        self.app.editor.set_code(code)
        self.app.on_code_change()
        self.pump()

    # ------------------------------------------------------------ básico --
    def test_abre_com_exemplo_e_analisa(self):
        self.assertIn("Ola, mundo!", self.app.editor.get_code())
        self.assertIsNotNone(self.app.analysis)
        self.assertIn("Linux", self.app.platform_label.cget("text"))
        self.assertTrue(self.app.tree.get_children(), "a árvore de estrutura deveria ter itens")

    def test_status_mostra_branch_e_contagem(self):
        self.app.set_status()
        texto = self.app.status.cget("text")
        self.assertIn("branch: principal", texto)
        self.assertIn("instruções", texto)

    def test_troca_de_exemplo_reanalisa(self):
        from asmx.examples import EXAMPLES
        self.set_code(EXAMPLES["windows-hello"]["code"])
        self.assertIn("Windows", self.app.platform_label.cget("text"))

    # ---------------------------------------------------------- problemas -
    def test_validacao_lista_problemas_e_marca_linhas(self):
        from asmx.examples import EXAMPLES
        self.set_code(EXAMPLES["quebrado"]["code"])
        self.app.validate_now()
        self.pump()
        itens = self.app.problem_tree.get_children()
        self.assertTrue(itens, "o exemplo quebrado deveria listar problemas")
        codigos = {self.app.problem_tree.item(i, "values")[1] for i in itens}
        self.assertIn("DIV001", codigos)
        self.assertIn("IMM001", codigos)
        ranges = self.app.editor.text.tag_ranges("errorline")
        self.assertTrue(ranges, "as linhas com erro deveriam ficar marcadas no editor")

    def test_clique_no_problema_pula_para_a_linha(self):
        from asmx.examples import EXAMPLES
        self.set_code(EXAMPLES["quebrado"]["code"])
        self.app.validate_now()
        self.pump()
        primeiro = self.app.problem_tree.get_children()[0]
        linha_esperada = int(self.app.problem_tree.item(primeiro, "values")[0])
        self.app.problem_tree.selection_set(primeiro)
        self.app.on_problem_open()
        self.pump()
        self.assertEqual(self.app.editor.cursor_line(), linha_esperada)

    def test_codigo_limpo_nao_lista_erros(self):
        self.app.validate_now()
        self.pump()
        severidades = [self.app.problem_tree.item(i, "tags")[0]
                       for i in self.app.problem_tree.get_children()]
        self.assertNotIn("erro", severidades)

    # ---------------------------------------------------------- execução --
    def test_passo_atualiza_registradores(self):
        self.app.reset_machine()
        self.app.step()
        self.pump()
        valores = self.app.reg_tree.item("rax", "values")
        self.assertEqual(valores[1], "1")
        self.assertIn("próxima", self.app.exec_label.cget("text"))

    def test_rodar_mostra_saida(self):
        self.app.reset_machine()
        self.app.run()
        self.pump()
        saida = self.app.output_text.get("1.0", "end-1c")
        self.assertIn("Ola, mundo!", saida)
        self.assertTrue(self.app.trace_tree.get_children())

    def test_breakpoint_para_a_execucao(self):
        self.app.reset_machine()
        linha_syscall = next(i.n for i in self.app.analysis.instrs if i.mnemonic == "syscall")
        self.app.editor.breakpoints = {linha_syscall}
        self.app.run()
        self.pump()
        self.assertFalse(self.app.machine.halted)
        self.assertEqual(self.app.machine.current.n, linha_syscall)

    def test_rodar_ate_o_cursor(self):
        self.app.reset_machine()
        alvo = self.app.analysis.instrs[2].n
        self.app.editor.goto_line(alvo)
        self.app.run_to_cursor()
        self.pump()
        self.assertEqual(self.app.machine.current.n, alvo)

    def test_reiniciar_zera_estado(self):
        self.app.run()
        self.app.reset_machine()
        self.pump()
        self.assertEqual(self.app.machine.regs["rax"], 0)
        self.assertEqual(self.app.output_text.get("1.0", "end-1c"), "")

    def test_depurar_funcao_isolada(self):
        from asmx.examples import EXAMPLES
        from asmx.ui import app as appmod

        self.set_code(EXAMPLES["escala"]["code"])

        class FakeDialog:
            def __init__(self, *a, **k):
                pass

            def show(self):
                return "soma_ate"

        original = appmod.TextPromptDialog
        appmod.TextPromptDialog = FakeDialog
        try:
            self.app.debug_function()
        finally:
            appmod.TextPromptDialog = original
        self.pump()
        self.assertEqual(self.app.machine.current.n,
                         next(i.n for i in self.app.analysis.instrs
                              if i.func == "soma_ate"))

    # ----------------------------------------------------------- branches -
    def test_criar_branch_pela_interface(self):
        from asmx.ui import app as appmod

        class FakeDialog:
            def __init__(self, *a, **k):
                pass

            def show(self):
                return "experimento"

        original = appmod.TextPromptDialog
        appmod.TextPromptDialog = FakeDialog
        try:
            self.app.branch_new()
        finally:
            appmod.TextPromptDialog = original
        self.pump()
        self.assertEqual(self.app.project.active, "experimento")
        self.assertIn("experimento", self.app.branch_box.cget("values"))

    def test_branches_guardam_codigos_diferentes(self):
        self.app.project.fork("alt")
        self.app.project.switch("alt")
        self.app.load_branch_into_editor()
        self.set_code("mov rax, 99")
        self.app.branch_switch("principal")
        self.pump()
        self.assertIn("Ola, mundo!", self.app.editor.get_code())
        self.app.branch_switch("alt")
        self.pump()
        self.assertIn("mov rax, 99", self.app.editor.get_code())

    # ---------------------------------------------------------- anotações -
    def test_anotacao_aparece_na_lista(self):
        self.app.project.set_note(4, "aqui mora a string")
        self.app.refresh_notes()
        self.pump()
        itens = self.app.note_tree.get_children()
        self.assertIn("4", itens)
        self.assertEqual(self.app.note_tree.item("4", "values")[0], "aqui mora a string")

    def test_comentar_linha_com_atalho(self):
        self.set_code("mov rax, 1\nmov rbx, 2")
        self.app.editor.goto_line(1)
        self.app.editor_toggle_comment()
        self.pump()
        self.assertTrue(self.app.editor.get_code().startswith("; mov rax, 1"))
        self.app.editor.goto_line(1)
        self.app.editor_toggle_comment()
        self.pump()
        self.assertTrue(self.app.editor.get_code().startswith("mov rax, 1"))

    # ------------------------------------------------------------ testes --
    def test_cenarios_rodam_e_mostram_resultado(self):
        from asmx.workspace import Scenario
        self.app.project.add_scenario(Scenario(name="saída certa",
                                               expect_output="Ola, mundo!\n"))
        self.app.project.add_scenario(Scenario(name="saída errada",
                                               expect_output="qualquer coisa"))
        self.app.run_all_scenarios()
        self.pump()
        self.assertEqual(self.app.scenario_tree.item("saída certa", "tags"), ("ok",))
        self.assertEqual(self.app.scenario_tree.item("saída errada", "tags"), ("falhou",))
        self.assertIn("1 de 2", self.app.status.cget("text"))

    def test_cenario_criado_pelo_dialogo(self):
        from asmx.ui import app as appmod
        from asmx.workspace import Scenario

        class FakeDialog:
            def __init__(self, *a, **k):
                pass

            def show(self):
                return Scenario(name="valor gigante", entry="_start",
                                regs={"rdi": "0xFFFFFFFF"}, expect_issue=True)

        original = appmod.ScenarioDialog
        appmod.ScenarioDialog = FakeDialog
        try:
            self.app.scenario_new()
        finally:
            appmod.ScenarioDialog = original
        self.pump()
        self.assertIn("valor gigante", self.app.scenario_tree.get_children())

    # ------------------------------------------------------- persistência -
    def test_salvar_e_reabrir_projeto(self):
        from asmx.workspace import Project
        self.app.project.set_note(2, "nota")
        self.app.project.fork("b2")
        with tempfile.TemporaryDirectory() as d:
            caminho = os.path.join(d, "p.asmproj")
            self.app.project.save(caminho)
            recarregado = Project.load(caminho)
        self.assertEqual(set(recarregado.branches), {"principal", "b2"})
        self.assertEqual(recarregado.note(2), "nota")

    # ------------------------------------------------------ documentação --
    def test_documentacao_responde_ao_cursor(self):
        linha = next(i.n for i in self.app.analysis.instrs if i.mnemonic == "syscall")
        self.app.editor.goto_line(linha)
        self.app.on_cursor(linha, 1)
        self.pump()
        texto = self.app.doc_text.get("1.0", "end-1c")
        self.assertIn("SYSCALL", texto)
        self.assertIn("kernel", texto.lower())

    def test_busca_na_documentacao(self):
        self.app.doc_query.insert(0, "jn")
        self.app.refresh_doc_list()
        self.pump()
        itens = self.app.doc_list.get(0, "end")
        self.assertTrue(all(i.startswith("jn") for i in itens))
        self.assertIn("jne", itens)

    # ------------------------------------------------------- robustez ----
    def test_codigo_invalido_nao_derruba_a_interface(self):
        for lixo in ("", "   ", "???", "mov", "[[[", '"', "section"):
            with self.subTest(codigo=lixo):
                self.set_code(lixo)
                self.app.validate_now()
                self.app.reset_machine()
                self.app.step()
                self.pump()
        self.assertTrue(self.app.winfo_exists())


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "sem Tkinter ou sem display")
class TestGUIExtra(unittest.TestCase):
    """Casos que nasceram de defeitos encontrados na revisão visual."""

    @classmethod
    def setUpClass(cls):
        from asmx.ui.app import AsmXApp
        cls.AsmXApp = AsmXApp

    def setUp(self):
        self.app = self.AsmXApp()
        self.app.update()

    def tearDown(self):
        try:
            self.app.destroy()
        except tk.TclError:
            pass

    def test_coluna_de_bloco_nao_vira_lista(self):
        """values precisa ser tupla, senão o Tcl quebra o texto em palavras."""
        raiz = [i for i in self.app.tree.get_children()
                if self.app.tree.item(i, "tags") and "fn" in self.app.tree.item(i, "tags")]
        self.assertTrue(raiz)
        bloco = self.app.tree.get_children(raiz[0])[0]
        info = self.app.tree.item(bloco, "values")[0]
        self.assertIn("instr", info, "a descrição do bloco foi truncada: %r" % info)

    def test_registrador_grande_nao_mostra_decimal_ilegivel(self):
        self.app.reset_machine()
        self.app.refresh_machine()
        self.assertEqual(self.app.reg_tree.item("rsp", "values")[1], "")
        self.assertNotEqual(self.app.reg_tree.item("rsp", "values")[0], "")

    def test_cursor_sobre_rotulo_explica_o_rotulo(self):
        linha = next(l.n for l in self.app.analysis.program.lines if l.kind == "label")
        self.app.on_cursor(linha, 1)
        self.app.update()
        texto = self.app.doc_text.get("1.0", "end-1c")
        self.assertIn("Rótulo", texto)

    def test_cursor_sobre_dado_explica_o_dado(self):
        linha = next(l.n for l in self.app.analysis.program.lines if l.kind == "data")
        self.app.on_cursor(linha, 1)
        self.app.update()
        texto = self.app.doc_text.get("1.0", "end-1c")
        self.assertTrue("Dado" in texto or "Constante" in texto or "Reserva" in texto)

    def test_plataforma_tem_explicacao_completa(self):
        self.assertTrue(hasattr(self.app, "platform_detail"))
        self.assertIn("System V", self.app.platform_detail)

    def test_detalhe_do_cenario_mostra_motivo(self):
        from asmx.workspace import Scenario
        self.app.project.add_scenario(Scenario(name="falha", expect_exit=42))
        self.app.run_all_scenarios()
        self.app.scenario_tree.selection_set("falha")
        self.app.on_scenario_select()
        self.app.update()
        texto = self.app.scenario_detail.cget("text")
        self.assertIn("FALHOU", texto)
        self.assertIn("instruções executadas", texto)

    def test_maquina_acompanha_codigo_novo_quando_parada(self):
        self.app.editor.set_code("mov rax, 7")
        self.app.on_code_change()
        self.app.update()
        self.app.step()
        self.assertEqual(self.app.machine.regs["rax"], 7)

    def test_maquina_avisa_quando_o_codigo_muda_no_meio(self):
        self.app.reset_machine()
        self.app.step()
        self.app.editor.set_code("mov rbx, 1\nmov rcx, 2")
        self.app.on_code_change()
        self.app.update()
        self.assertIn("reinicie", self.app.exec_label.cget("text"))
