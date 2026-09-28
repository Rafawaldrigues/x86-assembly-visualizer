"""Testes do relatório gerado pela interface gráfica (Ctrl+R)."""

import os
import tempfile
import unittest
import unittest.mock

from asmx.logging_setup import reset_logging

try:
    import tkinter as tk

    TK_OK = True
except ImportError:  # pragma: no cover
    TK_OK = False

HAS_DISPLAY = bool(os.environ.get("DISPLAY")) or os.name == "nt"


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "sem Tkinter ou sem display")
class TestRelatorioNaInterface(unittest.TestCase):
    """O menu "Gerar relatório..." precisa funcionar de ponta a ponta."""

    @classmethod
    def setUpClass(cls) -> None:
        from asmx.ui.app import AsmXApp

        cls.AsmXApp = AsmXApp

    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.app = self.AsmXApp()
        self.app.update()

    def tearDown(self) -> None:
        try:
            self.app.destroy()
        except tk.TclError:
            pass
        self.dir.cleanup()
        reset_logging()

    def destino(self, nome: str = "rel.html") -> str:
        return os.path.join(self.dir.name, nome)

    def test_gera_html_e_abre_no_navegador(self) -> None:
        caminho = self.destino()
        with (
            unittest.mock.patch("asmx.ui.app.filedialog.asksaveasfilename", return_value=caminho),
            unittest.mock.patch("asmx.ui.app.webbrowser.open") as abrir,
        ):
            self.app.generate_report()
        self.assertTrue(os.path.exists(caminho))
        with open(caminho, encoding="utf-8") as arquivo:
            conteudo = arquivo.read()
        self.assertIn("<!DOCTYPE html>", conteudo)
        self.assertIn("ASM X", conteudo)
        self.assertIn("Ola, mundo!", conteudo)
        abrir.assert_called_once()
        self.assertIn("relatório gravado em", self.app.status.cget("text"))

    def test_cancelar_nao_grava_nada(self) -> None:
        with (
            unittest.mock.patch("asmx.ui.app.filedialog.asksaveasfilename", return_value=""),
            unittest.mock.patch("asmx.ui.app.webbrowser.open") as abrir,
        ):
            self.app.generate_report()
        self.assertEqual(os.listdir(self.dir.name), [])
        abrir.assert_not_called()

    def test_erro_ao_gravar_avisa_sem_derrubar(self) -> None:
        with (
            unittest.mock.patch(
                "asmx.ui.app.filedialog.asksaveasfilename", return_value=self.dir.name
            ),
            unittest.mock.patch("asmx.ui.app.messagebox.showerror") as erro,
            unittest.mock.patch("asmx.ui.app.webbrowser.open") as abrir,
        ):
            self.app.generate_report()
        erro.assert_called_once()
        abrir.assert_not_called()
        self.assertTrue(self.app.winfo_exists())

    def test_relatorio_usa_o_codigo_atual_do_editor(self) -> None:
        self.app.editor.set_code('section .data\nmsg db "INTERESSANTE", 0\n')
        self.app.on_code_change()
        caminho = self.destino("atual.html")
        with (
            unittest.mock.patch("asmx.ui.app.filedialog.asksaveasfilename", return_value=caminho),
            unittest.mock.patch("asmx.ui.app.webbrowser.open"),
        ):
            self.app.generate_report()
        with open(caminho, encoding="utf-8") as arquivo:
            self.assertIn("INTERESSANTE", arquivo.read())


if __name__ == "__main__":
    unittest.main()
