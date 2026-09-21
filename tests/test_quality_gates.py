"""Testes dos portões de qualidade: 100% de anotações e docstrings."""

import contextlib
import io
import os
import tempfile
import unittest

from tools import quality_gates as qg


def silencioso(funcao: object, *args: object) -> int:
    """Roda uma função do portão engolindo o que ela imprime.

    Args:
        funcao: Função a chamar.
        *args: Argumentos dela.

    Returns:
        O código de saída devolvido pela função.
    """
    with contextlib.redirect_stdout(io.StringIO()):
        return funcao(*args)  # type: ignore[operator]


def escreve(texto: str) -> str:
    """Grava um módulo temporário e devolve o caminho absoluto."""
    arquivo = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8")
    arquivo.write(texto)
    arquivo.close()
    return arquivo.name


class TestDeteccao(unittest.TestCase):
    """O portão precisa realmente encontrar os problemas que promete achar."""

    def setUp(self) -> None:
        self.criados = []

    def tearDown(self) -> None:
        for caminho in self.criados:
            os.unlink(caminho)

    def violacoes(self, codigo: str, **kwargs: object) -> list:
        caminho = escreve(codigo)
        self.criados.append(caminho)
        return qg.check_file(caminho, **kwargs)  # type: ignore[arg-type]

    def codigos(self, codigo: str, **kwargs: object) -> set:
        return {v.kind for v in self.violacoes(codigo, **kwargs)}

    def test_modulo_sem_docstring(self) -> None:
        self.assertIn("docstring", self.codigos("x = 1\n"))

    def test_funcao_sem_anotacao(self) -> None:
        self.assertIn(
            "annotation",
            self.codigos('"""Doc."""\n\n\ndef f(a):\n    """Faz algo."""\n    return a\n'),
        )

    def test_metodo_sem_retorno_anotado(self) -> None:
        codigo = (
            '"""Doc."""\n\n\nclass C:\n    """Classe."""\n\n'
            '    def m(self, a: int):\n        """Método."""\n'
        )
        self.assertIn("annotation", self.codigos(codigo))

    def test_args_obrigatorio_a_partir_de_tres(self) -> None:
        codigo = (
            '"""Doc."""\n\n\ndef f(a: int, b: int, c: int) -> int:\n'
            '    """Soma."""\n    return a + b + c\n'
        )
        self.assertIn("args", self.codigos(codigo))

    def test_args_com_parametro_faltando(self) -> None:
        codigo = (
            '"""Doc."""\n\n\ndef f(a: int, b: int, c: int) -> int:\n'
            '    """Soma.\n\n    Args:\n        a: primeiro.\n        b: segundo.\n    """\n'
            "    return a + b + c\n"
        )
        violacoes = self.violacoes(codigo)
        self.assertTrue(any(v.kind == "args" and "c" in v.detail for v in violacoes))

    def test_returns_obrigatorio(self) -> None:
        codigo = '"""Doc."""\n\n\ndef f() -> int:\n    """Devolve."""\n    return 1\n'
        self.assertIn("returns", self.codigos(codigo))

    def test_raises_obrigatorio(self) -> None:
        codigo = (
            '"""Doc."""\n\n\ndef f() -> None:\n    """Levanta."""\n' '    raise ValueError("x")\n'
        )
        self.assertIn("raises", self.codigos(codigo))

    def test_primeira_linha_sem_pontuacao(self) -> None:
        codigo = '"""Doc."""\n\n\ndef f() -> None:\n    """sem ponto final"""\n'
        self.assertIn("docstring", self.codigos(codigo))

    def test_modo_sem_docstring_so_cobra_anotacao(self) -> None:
        codigo = '"""Doc."""\n\n\ndef f(a: int) -> int:  # sem docstring\n    return a\n'
        self.assertEqual(self.violacoes(codigo, require_docstrings=False), [])

    def test_erro_de_sintaxe_e_reportado(self) -> None:
        violacoes = self.violacoes("def f(:\n")
        self.assertEqual(violacoes[0].kind, "sintaxe")

    def test_varargs_anotados(self) -> None:
        codigo = (
            '"""Doc."""\n\n\ndef f(*args: int, **kwargs: str) -> None:\n' '    """Recebe tudo."""\n'
        )
        self.assertEqual(self.violacoes(codigo, require_docstrings=False), [])

    def test_funcao_aninhada_e_conferida(self) -> None:
        codigo = (
            '"""Doc."""\n\n\ndef f() -> None:\n    """Externa."""\n\n'
            "    def interna():\n        pass\n"
        )
        self.assertIn("annotation", self.codigos(codigo))

    def test_metodo_estatico_e_de_classe(self) -> None:
        codigo = (
            '"""Doc."""\n\n\nclass C:\n    """Classe."""\n\n'
            '    @staticmethod\n    def a() -> None:\n        """A."""\n\n'
            '    @classmethod\n    def b(cls) -> None:\n        """B."""\n'
        )
        self.assertEqual(self.violacoes(codigo), [])

    def test_resumo_conta_por_tipo(self) -> None:
        contagem = qg.summarize(
            [
                qg.Violation("a.py", 1, "f", "args", "x"),
                qg.Violation("a.py", 2, "g", "args", "y"),
                qg.Violation("a.py", 3, "h", "docstring", "z"),
            ]
        )
        self.assertEqual(contagem, {"args": 2, "docstring": 1})

    def test_violacao_str(self) -> None:
        texto = str(qg.Violation("a.py", 7, "f", "args", "faltou b"))
        self.assertEqual(texto, "a.py:7: args f — faltou b")


class TestRepositorio(unittest.TestCase):
    """O próprio projeto precisa passar nos portões."""

    def test_anotacoes_e_docstrings_do_codigo(self) -> None:
        violacoes = qg.check_paths(list(qg.PADRAO))
        self.assertEqual(
            [str(v) for v in violacoes],
            [],
            "o código do pacote precisa estar 100% anotado e documentado",
        )

    def test_anotacoes_dos_testes(self) -> None:
        violacoes = qg.check_paths(list(qg.TESTES), require_docstrings=False)
        anotacoes = [str(v) for v in violacoes if v.kind == "annotation"]
        self.assertEqual(anotacoes, [], "os testes também precisam de anotações")

    def test_lista_de_arquivos(self) -> None:
        arquivos = qg.iter_python_files(["asmx"])
        self.assertIn("asmx/cli.py", arquivos)
        self.assertTrue(all(a.endswith(".py") for a in arquivos))

    def test_ignora_ambiente_virtual(self) -> None:
        arquivos = qg.iter_python_files(["."])
        self.assertFalse([a for a in arquivos if a.startswith(".venv")])

    def test_main_aprova_o_projeto(self) -> None:
        self.assertEqual(silencioso(qg.main, ["asmx", "--quiet"]), 0)

    def test_main_reprova_arquivo_ruim(self) -> None:
        caminho = escreve("def f(a):\n    return a\n")
        try:
            self.assertEqual(silencioso(qg.main, [caminho, "--quiet"]), 1)
        finally:
            os.unlink(caminho)

    def test_parser_de_argumentos(self) -> None:
        args = qg.build_parser().parse_args([])
        self.assertEqual(tuple(args.paths), qg.PADRAO)
        self.assertFalse(args.quiet)


if __name__ == "__main__":
    unittest.main()
