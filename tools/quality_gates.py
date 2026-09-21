#!/usr/bin/env python3
"""Portões de qualidade do ASM X: anotações de tipo e docstrings.

O plano do projeto promete "100% de anotações de tipo" e "docstrings no padrão
Google". Promessa que ninguém confere vira desculpa, então estas duas checagens
são automáticas — rodam no ``make quality``, no CI e no teste
``tests/test_quality_gates.py``. O que é cobrado:

* toda função, método, classe e módulo tem docstring;
* a primeira linha da docstring é uma frase terminada em pontuação;
* a função tem ``Args:`` descrevendo todos os parâmetros quando tem três ou
  mais (``self`` e ``cls`` não contam);
* a função tem ``Returns:`` quando devolve valor e ``Raises:`` quando levanta
  exceção explicitamente;
* todos os parâmetros e o retorno têm anotação de tipo.

O código é lido com :mod:`ast`, então nada é importado nem executado.

Usage:
    python3 tools/quality_gates.py            # checa asmx/, tools/, asmx.py, tests/
    python3 tools/quality_gates.py asmx/      # checa só um caminho
    python3 tools/quality_gates.py --quiet    # só o resultado final

Exit codes:
    0  nenhuma violação
    1  pelo menos uma violação
"""

from __future__ import annotations

import argparse
import ast
import os
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: Caminhos conferidos quando nenhum é indicado na linha de comando.
PADRAO: Tuple[str, ...] = ("asmx", "tools", "asmx.py")

#: Caminhos conferidos só quanto a anotações (os testes não exigem docstring).
TESTES: Tuple[str, ...] = ("tests",)

#: Pastas ignoradas na varredura.
IGNORAR = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        "build",
        "dist",
        ".mypy_cache",
        ".pytest_cache",
        "node_modules",
    }
)

#: Nomes que não contam como parâmetro a documentar.
AUTO_PARAMS = frozenset({"self", "cls"})

#: Pontuação aceita no fim da primeira linha da docstring.
PONTUACAO = (".", "?", "!", ":")


@dataclass(frozen=True)
class Violation:
    """Uma quebra de regra encontrada no código.

    Attributes:
        path: Arquivo onde está o problema, relativo à raiz.
        line: Linha do nó (função, classe...).
        name: Nome qualificado do nó (``Classe.metodo``).
        kind: Regra quebrada (``docstring``, ``args``, ``returns``, ``raises``,
            ``annotation``).
        detail: Explicação curta do que faltou.
    """

    path: str
    line: int
    name: str
    kind: str
    detail: str

    def __str__(self) -> str:
        """Formata a violação como ``arquivo:linha: tipo nome — detalhe``.

        Returns:
            A linha pronta para imprimir.
        """
        return "%s:%d: %s %s — %s" % (self.path, self.line, self.kind, self.name, self.detail)


def iter_python_files(paths: Sequence[str]) -> List[str]:
    """Lista os arquivos ``.py`` de uma lista de arquivos e diretórios.

    Args:
        paths: Caminhos absolutos ou relativos à raiz do projeto.

    Returns:
        Caminhos relativos à raiz, em ordem alfabética.
    """
    arquivos: List[str] = []
    for caminho in paths:
        absoluto = caminho if os.path.isabs(caminho) else os.path.join(RAIZ, caminho)
        if os.path.isfile(absoluto):
            if absoluto.endswith(".py"):
                arquivos.append(absoluto)
            continue
        for pasta, subpastas, nomes in os.walk(absoluto):
            subpastas[:] = [s for s in subpastas if s not in IGNORAR]
            for nome in nomes:
                if nome.endswith(".py"):
                    arquivos.append(os.path.join(pasta, nome))
    return sorted(os.path.relpath(a, RAIZ) for a in arquivos)


def _qualified(node: ast.AST, prefixo: str = "") -> str:
    """Monta o nome do nó incluindo a classe/escopo onde ele está.

    Args:
        node: Nó do :mod:`ast` (função, classe...).
        prefixo: Nome do escopo onde o nó aparece.

    Returns:
        Nome qualificado, como ``Project.fork``.
    """
    nome = getattr(node, "name", "<anônimo>")
    return "%s.%s" % (prefixo, nome) if prefixo else nome


def _docstring(node: ast.AST) -> Optional[str]:
    """Devolve a docstring do nó, ou ``None`` quando não existe.

    Returns:
        O texto da docstring ou ``None``.
    """
    corpo = getattr(node, "body", None)
    if not corpo:
        return None
    primeiro = corpo[0]
    if (
        isinstance(primeiro, ast.Expr)
        and isinstance(primeiro.value, ast.Constant)
        and isinstance(primeiro.value.value, str)
    ):
        return primeiro.value.value
    return None


def _params(node: ast.AST) -> List[str]:
    """Lista os nomes dos parâmetros de uma função, sem ``self``/``cls``.

    Returns:
        Nomes na ordem da assinatura, com ``*args`` e ``**kwargs`` inclusive.
    """
    args = node.args  # type: ignore[attr-defined]
    nomes = [a.arg for a in list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)]
    if args.vararg:
        nomes.append("*" + args.vararg.arg)
    if args.kwarg:
        nomes.append("**" + args.kwarg.arg)
    return [n for n in nomes if n not in AUTO_PARAMS]


def _iter_corpo(node: ast.AST) -> Iterable[ast.AST]:
    """Percorre o corpo de uma função sem entrar em funções aninhadas.

    O que uma função aninhada devolve ou levanta é problema da docstring dela,
    não da função de fora.

    Args:
        node: Nó da função.

    Yields:
        Cada nó do corpo, exceto o interior de funções, classes e lambdas.
    """
    pilha = list(getattr(node, "body", []))
    while pilha:
        atual = pilha.pop()
        yield atual
        if isinstance(atual, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        pilha.extend(ast.iter_child_nodes(atual))


def _returns_value(node: ast.AST) -> bool:
    """Diz se a função tem algum ``return`` que devolve valor.

    Returns:
        ``True`` quando existe ``return`` com expressão no corpo da própria
        função.
    """
    return any(
        isinstance(filho, ast.Return) and filho.value is not None for filho in _iter_corpo(node)
    )


def _raises(node: ast.AST) -> bool:
    """Diz se a função levanta exceção explicitamente.

    Returns:
        ``True`` quando existe ``raise`` no corpo da própria função.
    """
    return any(isinstance(filho, ast.Raise) for filho in _iter_corpo(node))


def _has_section(doc: str, titulo: str) -> bool:
    """Diz se a docstring tem uma seção ``Titulo:`` (Google style).

    Args:
        doc: Texto da docstring.
        titulo: Nome da seção, sem os dois pontos (``Args``, ``Returns``...).

    Returns:
        ``True`` quando a seção existe.
    """
    return any(linha.strip() == titulo + ":" for linha in doc.splitlines())


def _section_names(doc: str, titulo: str) -> Set[str]:
    """Extrai os nomes documentados dentro de uma seção do tipo ``nome:``.

    Args:
        doc: Texto da docstring.
        titulo: Nome da seção a varrer.

    Returns:
        Conjunto com os nomes encontrados antes dos dois pontos.
    """
    nomes: Set[str] = set()
    dentro = False
    for linha in doc.splitlines():
        if linha.strip() == titulo + ":":
            dentro = True
            continue
        if dentro:
            if linha.strip() and not linha.startswith(" " * 8):
                break
            texto = linha.strip()
            if ":" in texto:
                nomes.add(texto.split(":", 1)[0].strip().lstrip("*"))
    return nomes


def check_file(
    path: str, *, args_min_params: int = 3, require_docstrings: bool = True
) -> List[Violation]:
    """Confere anotações e docstrings de um arquivo.

    Args:
        path: Caminho relativo à raiz do projeto.
        args_min_params: A partir de quantos parâmetros a seção ``Args:``
            passa a ser obrigatória.
        require_docstrings: Quando ``False``, cobra só as anotações de tipo
            (é o modo usado nos arquivos de teste, onde o nome do caso já
            explica o que ele faz).

    Returns:
        Lista de violações encontradas (vazia quando o arquivo está em dia).
    """
    with open(os.path.join(RAIZ, path), encoding="utf-8") as arquivo:
        try:
            arvore = ast.parse(arquivo.read(), filename=path)
        except SyntaxError as erro:
            return [Violation(path, erro.lineno or 0, "<módulo>", "sintaxe", str(erro.msg))]

    violacoes: List[Violation] = []
    if require_docstrings:
        _verifica_docstring_modulo(arvore, path, violacoes)

    def visitar(node: ast.AST, prefixo: str) -> None:
        """Percorre a árvore conferindo classes e funções aninhadas."""
        for filho in ast.iter_child_nodes(node):
            if isinstance(filho, ast.ClassDef):
                nome = _qualified(filho, prefixo)
                if require_docstrings:
                    _verifica_classe(filho, path, nome, violacoes, args_min_params)
                visitar(filho, nome)
            elif isinstance(filho, (ast.FunctionDef, ast.AsyncFunctionDef)):
                nome = _qualified(filho, prefixo)
                _verifica_funcao(filho, path, nome, violacoes, args_min_params, require_docstrings)
                visitar(filho, nome)
            elif isinstance(filho, (ast.If, ast.Try, ast.With, ast.For, ast.While)):
                visitar(filho, prefixo)

    visitar(arvore, "")
    return violacoes


def _verifica_docstring_modulo(arvore: ast.Module, path: str, violacoes: List[Violation]) -> None:
    """Confere a docstring do módulo.

    Args:
        arvore: Árvore sintática do arquivo.
        path: Caminho relativo, usado nas violações.
        violacoes: Lista onde as violações são acumuladas.
    """
    doc = _docstring(arvore)
    if doc is None:
        violacoes.append(Violation(path, 1, "<módulo>", "docstring", "módulo sem docstring"))
        return
    if not doc.strip().splitlines()[0].strip().endswith(PONTUACAO):
        violacoes.append(
            Violation(
                path, 1, "<módulo>", "docstring", "a primeira linha precisa terminar em pontuação"
            )
        )


def _verifica_classe(
    node: ast.ClassDef, path: str, nome: str, violacoes: List[Violation], args_min_params: int
) -> None:
    """Confere a docstring da classe, incluindo os atributos de dataclass.

    Args:
        node: Nó da classe.
        path: Caminho relativo do arquivo.
        nome: Nome qualificado da classe.
        violacoes: Lista onde as violações são acumuladas.
        args_min_params: Limite de parâmetros para exigir ``Args:`` nos métodos.
    """
    doc = _docstring(node)
    if doc is None:
        violacoes.append(Violation(path, node.lineno, nome, "docstring", "classe sem docstring"))
    elif not doc.strip().splitlines()[0].strip().endswith(PONTUACAO):
        violacoes.append(
            Violation(
                path,
                node.lineno,
                nome,
                "docstring",
                "a primeira linha precisa terminar em pontuação",
            )
        )


def _verifica_funcao(
    node: ast.AST,
    path: str,
    nome: str,
    violacoes: List[Violation],
    args_min_params: int,
    require_docstrings: bool = True,
) -> None:
    """Confere anotações, docstring e seções de uma função ou método.

    Args:
        node: Nó da função ou método.
        path: Caminho relativo do arquivo.
        nome: Nome qualificado da função.
        violacoes: Lista onde as violações são acumuladas.
        args_min_params: A partir de quantos parâmetros ``Args:`` é exigido.
        require_docstrings: Se as seções de docstring são cobradas.
    """
    doc = _docstring(node)
    if doc is None and require_docstrings:
        violacoes.append(Violation(path, node.lineno, nome, "docstring", "sem docstring"))
    elif doc is not None and require_docstrings:
        primeira = doc.strip().splitlines()[0].strip() if doc.strip() else ""
        if not primeira:
            violacoes.append(Violation(path, node.lineno, nome, "docstring", "docstring vazia"))
        elif not primeira.endswith(PONTUACAO):
            violacoes.append(
                Violation(
                    path,
                    node.lineno,
                    nome,
                    "docstring",
                    "a primeira linha precisa terminar em pontuação",
                )
            )
        parametros = _params(node)
        if not require_docstrings:
            parametros = []
        if len(parametros) >= args_min_params and not _has_section(doc, "Args"):
            violacoes.append(
                Violation(
                    path,
                    node.lineno,
                    nome,
                    "args",
                    "tem %d parâmetros e nenhuma seção Args:" % len(parametros),
                )
            )
        elif _has_section(doc, "Args"):
            documentados = _section_names(doc, "Args")
            faltando = [p for p in parametros if p.lstrip("*") not in documentados]
            if faltando:
                violacoes.append(
                    Violation(
                        path,
                        node.lineno,
                        nome,
                        "args",
                        "parâmetros sem descrição: " + ", ".join(faltando),
                    )
                )
        if require_docstrings and _returns_value(node) and not _has_section(doc, "Returns"):
            violacoes.append(
                Violation(
                    path, node.lineno, nome, "returns", "devolve valor e não tem seção Returns:"
                )
            )
        if require_docstrings and _raises(node) and not _has_section(doc, "Raises"):
            violacoes.append(
                Violation(
                    path, node.lineno, nome, "raises", "levanta exceção e não tem seção Raises:"
                )
            )

    for parametro in _params(node):
        alvo = (
            node.args.vararg
            if parametro.startswith("*") and not parametro.startswith("**")
            else node.args.kwarg if parametro.startswith("**") else None
        )
        if alvo is not None:
            if alvo.annotation is None:
                violacoes.append(
                    Violation(
                        path,
                        node.lineno,
                        nome,
                        "annotation",
                        "parâmetro %s sem anotação" % parametro,
                    )
                )
            continue
        for argumento in (
            list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs)
        ):
            if argumento.arg == parametro and argumento.annotation is None:
                violacoes.append(
                    Violation(
                        path,
                        node.lineno,
                        nome,
                        "annotation",
                        "parâmetro %s sem anotação" % parametro,
                    )
                )
    if getattr(node, "returns", None) is None:
        violacoes.append(Violation(path, node.lineno, nome, "annotation", "retorno sem anotação"))


def check_paths(
    paths: Sequence[str], *, args_min_params: int = 3, require_docstrings: bool = True
) -> List[Violation]:
    """Confere todos os arquivos indicados.

    Args:
        paths: Arquivos e diretórios a conferir.
        args_min_params: Repassado para :func:`check_file`.
        require_docstrings: Repassado para :func:`check_file`.

    Returns:
        Lista de violações, ordenada por arquivo e linha.
    """
    violacoes: List[Violation] = []
    for path in iter_python_files(paths):
        violacoes.extend(
            check_file(path, args_min_params=args_min_params, require_docstrings=require_docstrings)
        )
    return sorted(violacoes, key=lambda v: (v.path, v.line, v.kind))


def summarize(violacoes: Iterable[Violation]) -> Dict[str, int]:
    """Conta as violações por tipo.

    Args:
        violacoes: Violações encontradas.

    Returns:
        Dicionário ``tipo -> quantidade``.
    """
    contagem: Dict[str, int] = {}
    for violacao in violacoes:
        contagem[violacao.kind] = contagem.get(violacao.kind, 0) + 1
    return contagem


def build_parser() -> argparse.ArgumentParser:
    """Monta o analisador de argumentos do utilitário.

    Returns:
        O parser com os caminhos posicionais e as opções.
    """
    parser = argparse.ArgumentParser(
        prog="quality_gates", description="Confere anotações de tipo e docstrings do ASM X."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=list(PADRAO),
        help="arquivos ou diretórios (padrão: %s)" % ", ".join(PADRAO),
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="mostra só o resumo final")
    parser.add_argument("--max", type=int, default=40, help="quantas violações listar (padrão: 40)")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Ponto de entrada do utilitário.

    Args:
        argv: Argumentos sem o nome do programa.

    Returns:
        ``0`` quando não há violação, ``1`` quando há.
    """
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    violacoes = check_paths(args.paths or list(PADRAO))
    if violacoes:
        if not args.quiet:
            for violacao in violacoes[: args.max]:
                print(violacao)
        print(
            "falharam %d verificação(ões): %s"
            % (
                len(violacoes),
                ", ".join("%s=%d" % kv for kv in sorted(summarize(violacoes).items())),
            )
        )
        return 1
    print(
        "tudo em ordem: %d arquivo(s) com 100%% de anotações e docstrings"
        % len(iter_python_files(args.paths or list(PADRAO)))
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
