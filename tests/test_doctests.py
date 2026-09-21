"""Roda os exemplos de código que estão dentro das docstrings.

Docstring que não roda envelhece mentindo: estes testes executam cada exemplo
dos módulos do pacote e falham se algum deixar de bater com o código.
"""

import doctest
import importlib
import pkgutil
import unittest

import asmx

#: Módulos que só fazem sentido com uma tela ligada.
SEM_DOCTEST = ("asmx.ui",)

#: Quantidade mínima de exemplos que precisam existir, para o teste não passar
#: por acidente quando alguém apaga as docstrings.
MINIMO_DE_EXEMPLOS = 40


def modulos_do_pacote() -> list:
    """Lista os módulos importáveis do pacote ``asmx``."""
    nomes = []
    for info in pkgutil.iter_modules(asmx.__path__, "asmx."):
        if info.name.startswith(SEM_DOCTEST):
            continue
        nomes.append(info.name)
    nomes.append("asmx")
    return sorted(nomes)


class TestDoctests(unittest.TestCase):
    """Os exemplos das docstrings precisam continuar verdadeiros."""

    def test_todos_os_exemplos_passam(self) -> None:
        total = 0
        for nome in modulos_do_pacote():
            with self.subTest(modulo=nome):
                modulo = importlib.import_module(nome)
                resultado = doctest.testmod(
                    modulo, verbose=False, report=False, optionflags=doctest.ELLIPSIS
                )
                total += resultado.attempted
                self.assertEqual(resultado.failed, 0, "exemplo quebrado em %s" % nome)
        self.assertGreaterEqual(
            total,
            MINIMO_DE_EXEMPLOS,
            "esperava pelo menos %d exemplos nas docstrings" % MINIMO_DE_EXEMPLOS,
        )

    def test_modulos_do_pacote_sao_importaveis(self) -> None:
        self.assertIn("asmx.cli", modulos_do_pacote())
        self.assertIn("asmx.workspace", modulos_do_pacote())
        self.assertNotIn("asmx.ui.app", modulos_do_pacote())


if __name__ == "__main__":
    unittest.main()
