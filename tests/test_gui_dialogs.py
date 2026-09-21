"""Testes das janelas auxiliares (asmx.ui.dialogs), sem abrir modal de verdade."""

from __future__ import annotations

import os
import unittest
from typing import Any, List, Optional

try:
    import tkinter as tk

    TK_OK = True
except ImportError:  # pragma: no cover
    TK_OK = False

HAS_DISPLAY = bool(os.environ.get("DISPLAY")) or os.name == "nt"


def fecha(janela: tk.Misc) -> None:
    """Fecha uma janela ignorando o erro de aplicação já destruída.

    Args:
        janela: Widget a destruir.
    """
    try:
        janela.destroy()
    except tk.TclError:
        pass


def fake_modal(valor: Any) -> type:
    """Cria uma subclasse de ModalDialog cujo collect() devolve sempre o valor.

    Args:
        valor: Valor devolvido por :meth:`collect`.

    Returns:
        A classe pronta para ser instanciada com ``(master, titulo)``.
    """
    from asmx.ui.dialogs import ModalDialog

    class FakeModal(ModalDialog):
        """Modal de teste: não espera o usuário e devolve um valor fixo."""

        def collect(self) -> Any:
            """Devolve o valor combinado, como um formulário já preenchido.

            Returns:
                O valor passado para :func:`fake_modal`.
            """
            return valor

    return FakeModal


def fake_prompt(valor: Any) -> type:
    """Cria um diálogo falso (sem Tk) que devolve sempre o mesmo valor.

    Args:
        valor: Valor devolvido por :meth:`show`.

    Returns:
        A classe, compatível com o construtor dos diálogos reais.
    """

    class FakePrompt:
        """Diálogo falso usado no lugar das janelas modais."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            """Aceita (e ignora) os mesmos argumentos do diálogo real."""

        def show(self) -> Any:
            """Devolve o valor combinado sem abrir janela nenhuma.

            Returns:
                O valor passado para :func:`fake_prompt`.
            """
            return valor

    return FakePrompt


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "sem Tkinter ou sem display")
class TestModalDialog(unittest.TestCase):
    """Base dos modais: botões, confirmar, cancelar e show()."""

    def setUp(self) -> None:
        self.root = tk.Tk()
        self.root.geometry("320x240")
        self.root.update()

    def tearDown(self) -> None:
        try:
            self.root.destroy()
        except tk.TclError:
            pass

    def test_base_monta_corpo_botoes_e_coleta_nada(self) -> None:
        from asmx.ui.dialogs import ModalDialog

        dlg = ModalDialog(self.root, "base", 300, 200)
        self.addCleanup(fecha, dlg)
        self.root.update()
        self.assertTrue(dlg.body.winfo_exists())
        self.assertTrue(dlg.buttons.winfo_exists())
        self.assertEqual(dlg.title(), "base")
        self.assertIsNone(dlg.collect())
        self.assertIsNone(dlg.result)

    def test_add_buttons_cria_cancelar_e_confirmar(self) -> None:
        from asmx.ui.dialogs import ModalDialog

        dlg = ModalDialog(self.root, "base", 300, 200)
        self.addCleanup(fecha, dlg)
        dlg.add_buttons("Salvar cenário")
        self.root.update()
        textos = [w.cget("text") for w in dlg.buttons.winfo_children()]
        self.assertIn("Salvar cenário", textos)
        self.assertIn("Cancelar", textos)

    def test_confirm_guarda_resultado_e_fecha(self) -> None:
        dlg = fake_modal("pronto")(self.root, "teste")
        self.addCleanup(fecha, dlg)
        self.root.update()
        dlg.confirm()
        self.assertEqual(dlg.result, "pronto")
        self.assertEqual(dlg.winfo_exists(), 0)

    def test_confirm_sem_resultado_mantem_a_janela(self) -> None:
        from asmx.ui.dialogs import ModalDialog

        dlg = ModalDialog(self.root, "teste")
        self.addCleanup(fecha, dlg)
        self.root.update()
        dlg.confirm()
        self.assertIsNone(dlg.result)
        self.assertEqual(dlg.winfo_exists(), 1)

    def test_cancel_zera_o_resultado_e_fecha(self) -> None:
        dlg = fake_modal("qualquer")(self.root, "teste")
        self.addCleanup(fecha, dlg)
        self.root.update()
        dlg.cancel()
        self.assertIsNone(dlg.result)
        self.assertEqual(dlg.winfo_exists(), 0)

    def test_show_devolve_o_resultado_confirmado(self) -> None:
        dlg = fake_modal("resultado")(self.root, "teste")
        self.addCleanup(fecha, dlg)
        self.root.update()
        dlg.after(10, dlg.confirm)
        self.assertEqual(dlg.show(), "resultado")

    def test_show_cancelado_devolve_none(self) -> None:
        dlg = fake_modal("resultado")(self.root, "teste")
        self.addCleanup(fecha, dlg)
        self.root.update()
        dlg.after(10, dlg.cancel)
        self.assertIsNone(dlg.show())


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "sem Tkinter ou sem display")
class TestScenarioDialog(unittest.TestCase):
    """Formulário de cenário: preenchimento, validação e coleta."""

    def setUp(self) -> None:
        self.root = tk.Tk()
        self.root.geometry("640x520")
        self.root.update()

    def tearDown(self) -> None:
        try:
            self.root.destroy()
        except tk.TclError:
            pass

    def abre(self, labels: Optional[List[str]] = None, scenario: Any = None) -> Any:
        """Abre um ScenarioDialog e registra o fechamento no fim do teste.

        Args:
            labels: Rótulos oferecidos no campo "Começar em".
            scenario: Cenário a editar; None cria um novo.

        Returns:
            O diálogo pronto para uso.
        """
        from asmx.ui.dialogs import ScenarioDialog

        dlg = ScenarioDialog(self.root, labels or [], scenario)
        self.addCleanup(fecha, dlg)
        self.root.update()
        return dlg

    def test_campos_vem_preenchidos_do_cenario(self) -> None:
        from asmx.workspace import Scenario

        cenario = Scenario(
            name="c1",
            entry="_start",
            regs={"rdi": "1000000"},
            stdin="abc",
            expect_output="Ola\n",
            expect_exit=3,
            expect_issue=True,
            max_steps=77,
        )
        dlg = self.abre(["_start", "soma"], cenario)
        self.assertEqual(dlg.nome.get(), "c1")
        self.assertEqual(dlg.entrada.get(), "_start")
        self.assertEqual(dlg.entrada.cget("values")[0], "")
        self.assertIn("_start", dlg.entrada.cget("values"))
        self.assertEqual(dlg.regs.get(), "rdi=1000000")
        self.assertEqual(dlg.stdin.get(), "abc")
        self.assertEqual(dlg.saida.get("1.0", "end-1c"), "Ola\n")
        self.assertEqual(dlg.exit_code.get(), "3")
        self.assertTrue(dlg.espera_problema.get())
        self.assertEqual(dlg.max_steps.get(), "77")

    def test_collect_monta_o_cenario_digitado(self) -> None:
        dlg = self.abre(["_start"])
        dlg.nome.insert(0, "  valor grande  ")
        dlg.entrada.set("_start")
        dlg.regs.insert(0, "rdi=1000000, rsi=0x20, naoexiste=5")
        dlg.stdin.insert(0, "entrada\n")
        dlg.saida.insert("1.0", "saida esperada")
        dlg.exit_code.insert(0, "42")
        dlg.espera_problema.set(True)
        dlg.max_steps.delete(0, "end")
        dlg.max_steps.insert(0, "1234")
        cenario = dlg.collect()
        self.assertIsNotNone(cenario)
        self.assertEqual(cenario.name, "valor grande")
        self.assertEqual(cenario.entry, "_start")
        self.assertEqual(cenario.regs, {"rdi": "1000000", "rsi": "32"})
        self.assertEqual(cenario.stdin, "entrada\n")
        self.assertEqual(cenario.expect_output, "saida esperada")
        self.assertEqual(cenario.expect_exit, 42)
        self.assertTrue(cenario.expect_issue)
        self.assertEqual(cenario.max_steps, 1234)

    def test_collect_sem_nome_avisa_e_devolve_none(self) -> None:
        dlg = self.abre()
        dlg.nome.delete(0, "end")
        self.assertIsNone(dlg.collect())
        self.assertIn("nome", dlg.error.cget("text"))

    def test_collect_com_limite_nao_numerico_avisa(self) -> None:
        dlg = self.abre()
        dlg.nome.insert(0, "cenario")
        dlg.max_steps.delete(0, "end")
        dlg.max_steps.insert(0, "muitas")
        self.assertIsNone(dlg.collect())
        self.assertIn("número", dlg.error.cget("text"))

    def test_collect_com_codigo_de_saida_nao_numerico_avisa(self) -> None:
        dlg = self.abre()
        dlg.nome.insert(0, "cenario")
        dlg.exit_code.insert(0, "zero")
        self.assertIsNone(dlg.collect())
        self.assertIn("número", dlg.error.cget("text"))

    def test_collect_usa_padroes_quando_campos_ficam_vazios(self) -> None:
        dlg = self.abre()
        dlg.nome.insert(0, "cenario")
        self.assertEqual(dlg.max_steps.get(), "200000")
        dlg.max_steps.delete(0, "end")
        cenario = dlg.collect()
        self.assertIsNotNone(cenario)
        self.assertEqual(cenario.max_steps, 200000)
        self.assertIsNone(cenario.expect_output)
        self.assertIsNone(cenario.expect_exit)
        self.assertEqual(cenario.entry, "")
        self.assertFalse(cenario.expect_issue)

    def test_confirm_fecha_e_guarda_o_cenario(self) -> None:
        dlg = self.abre()
        dlg.nome.insert(0, "cenario")
        dlg.confirm()
        self.assertIsNotNone(dlg.result)
        self.assertEqual(dlg.result.name, "cenario")
        self.assertEqual(dlg.winfo_exists(), 0)


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "sem Tkinter ou sem display")
class TestTextPromptDialog(unittest.TestCase):
    """Pergunta de texto curto, de uma linha e de várias."""

    def setUp(self) -> None:
        self.root = tk.Tk()
        self.root.geometry("480x260")
        self.root.update()

    def tearDown(self) -> None:
        try:
            self.root.destroy()
        except tk.TclError:
            pass

    def abre(self, **kwargs: Any) -> Any:
        """Abre um TextPromptDialog e registra o fechamento no fim do teste.

        Args:
            **kwargs: Argumentos repassados ao diálogo.

        Returns:
            O diálogo pronto para uso.
        """
        from asmx.ui.dialogs import TextPromptDialog

        dlg = TextPromptDialog(self.root, "Pergunta", "Qual o valor?", **kwargs)
        self.addCleanup(fecha, dlg)
        self.root.update()
        return dlg

    def test_collect_de_uma_linha(self) -> None:
        dlg = self.abre(value="inicial", hint="dica de ajuda")
        self.assertFalse(dlg.multiline)
        self.assertEqual(dlg.collect(), "inicial")
        dlg.entry.delete(0, "end")
        dlg.entry.insert(0, "digitado")
        self.assertEqual(dlg.collect(), "digitado")

    def test_collect_de_varias_linhas(self) -> None:
        dlg = self.abre(value="linha 1\nlinha 2", multiline=True)
        self.assertTrue(dlg.multiline)
        self.assertEqual(dlg.collect(), "linha 1\nlinha 2")
        dlg.entry.insert("end", "\nlinha 3")
        self.assertEqual(dlg.collect(), "linha 1\nlinha 2\nlinha 3")

    def test_enter_do_campo_curto_confirma(self) -> None:
        """O Enter precisa estar ligado a confirmar o diálogo.

        Em xvfb não há gerenciador de janelas, então o foco nunca chega ao
        campo e um evento de tecla gerado não seria entregue; por isso o teste
        confere a ligação e chama o mesmo método que ela chama.
        """
        dlg = self.abre(value="texto")
        self.assertTrue(dlg.entry.bind("<Return>"), "o Enter precisa estar ligado a confirmar")
        dlg.confirm()
        self.root.update()
        self.assertEqual(dlg.result, "texto")
        self.assertEqual(dlg.winfo_exists(), 0)

    def test_sem_hint_e_sem_valor_inicial(self) -> None:
        dlg = self.abre()
        self.assertEqual(dlg.collect(), "")
        self.assertEqual(dlg.error.cget("text"), "")
        self.assertTrue(dlg.entry.winfo_exists())


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "sem Tkinter ou sem display")
class TestDiffDialog(unittest.TestCase):
    """Janela de comparação entre branches."""

    def setUp(self) -> None:
        self.root = tk.Tk()
        self.root.geometry("400x300")
        self.root.update()

    def tearDown(self) -> None:
        try:
            self.root.destroy()
        except tk.TclError:
            pass

    def abre(self, diff_text: str) -> Any:
        """Abre um DiffDialog e devolve o widget de texto com o diff.

        Args:
            diff_text: Diff unificado mostrado na janela.

        Returns:
            O :class:`tkinter.Text` usado para exibir o diff.
        """
        from asmx.ui.dialogs import DiffDialog

        dlg = DiffDialog(self.root, "principal ↔ alt", diff_text)
        self.addCleanup(fecha, dlg)
        self.root.update()
        textos = [w for w in dlg.winfo_children() if isinstance(w, tk.Text)]
        self.assertEqual(len(textos), 1)
        return textos[0]

    def test_diff_vazio_avisa_que_o_codigo_e_igual(self) -> None:
        texto = self.abre("")
        self.assertIn("exatamente o mesmo código", texto.get("1.0", "end-1c"))
        self.assertEqual(texto.cget("state"), "disabled")

    def test_diff_espacos_em_branco_tambem_e_vazio(self) -> None:
        texto = self.abre("   \n\n")
        self.assertIn("exatamente o mesmo código", texto.get("1.0", "end-1c"))

    def test_diff_real_colore_por_tipo_de_linha(self) -> None:
        """Cabeçalho, adição, remoção e contexto ganham cores diferentes.

        O cabeçalho do diff (`---`, `+++`, `@@`) tem de ser reconhecido antes
        das linhas de adição e remoção: `+++` começa com `+` e `---` começa com
        `-`, então a ordem dos testes é o que separa cabeçalho de conteúdo.
        """
        diff = "--- principal\n+++ alt\n@@ -1,3 +1,3 @@\n-linha antiga\n+linha nova\n" "linha igual"
        texto = self.abre(diff)
        self.assertIn("linha nova", texto.get("1.0", "end-1c"))
        # as três linhas de cabeçalho ficam contíguas, então o Tk as une numa
        # única faixa marcada
        cabecalho = texto.get(*texto.tag_ranges("head")[0:2])
        for marca in ("---", "+++", "@@"):
            self.assertIn(marca, cabecalho)
        self.assertEqual(len(texto.tag_ranges("add")) // 2, 1)
        self.assertEqual(len(texto.tag_ranges("del")) // 2, 1)
        self.assertEqual(texto.cget("state"), "disabled")

    def test_cabecalho_do_diff_nao_vira_adicao(self) -> None:
        texto = self.abre("--- a\n+++ b\n@@ -1 +1 @@\n")
        adicoes = texto.get(*texto.tag_ranges("add")[0:2]) if texto.tag_ranges("add") else ""
        remocoes = texto.get(*texto.tag_ranges("del")[0:2]) if texto.tag_ranges("del") else ""
        self.assertNotIn("+++", adicoes)
        self.assertNotIn("---", remocoes)


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "sem Tkinter ou sem display")
class TestAboutDialog(unittest.TestCase):
    """Janela "Sobre", com versão e atalhos."""

    def setUp(self) -> None:
        self.root = tk.Tk()
        self.root.geometry("400x300")
        self.root.update()

    def tearDown(self) -> None:
        try:
            self.root.destroy()
        except tk.TclError:
            pass

    def test_mostra_versao_e_atalhos(self) -> None:
        from asmx.ui.dialogs import AboutDialog

        dlg = AboutDialog(self.root, "9.9.9")
        self.addCleanup(fecha, dlg)
        self.root.update()
        self.assertEqual(dlg.title(), "Sobre")
        textos = []
        for filho in dlg.body.winfo_children():
            try:
                textos.append(filho.cget("text"))
            except tk.TclError:
                pass
        self.assertTrue(any("ASM X" == t for t in textos))
        self.assertTrue(any("9.9.9" in t for t in textos))
        caixas = [w for w in dlg.body.winfo_children() if isinstance(w, tk.Text)]
        self.assertEqual(len(caixas), 1)
        self.assertIn("F8", caixas[0].get("1.0", "end-1c"))

    def test_botao_fechar_cancela_a_janela(self) -> None:
        from asmx.ui.dialogs import AboutDialog

        dlg = AboutDialog(self.root, "1.0")
        self.addCleanup(fecha, dlg)
        self.root.update()
        botoes = [w for w in dlg.buttons.winfo_children() if isinstance(w, tk.Widget)]
        self.assertTrue(any(w.cget("text") == "Fechar" for w in botoes))
        dlg.after(10, dlg.cancel)
        self.assertIsNone(dlg.show())
        self.assertEqual(dlg.winfo_exists(), 0)


if __name__ == "__main__":
    unittest.main()
