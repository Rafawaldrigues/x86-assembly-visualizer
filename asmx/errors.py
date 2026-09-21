"""Erros do ASM X: cada situação tem uma exceção própria e um código estável.

Por que não usar só ``ValueError``: quem chama a biblioteca (a interface, a linha
de comando, um script de CI) precisa distinguir "o arquivo não existe" de "o
projeto está corrompido" sem inspecionar texto de mensagem. Cada classe daqui
carrega um ``code`` fixo — o mesmo contrato que aparece no JSON de
``python -m asmx ... --json`` e nos testes.

Todas as exceções também herdam do erro embutido equivalente
(``FileNotFoundError``, ``ValueError``, ``KeyError``...). Assim o código que já
existia continua funcionando com ``except ValueError`` e ganha,
de graça, o código de erro e o contexto::

    try:
        projeto.load(caminho)
    except ProjectFormatError as erro:
        print(erro.code, erro.context["path"])

Example:
    >>> from asmx.errors import BranchExistsError
    >>> erro = BranchExistsError("teste")
    >>> print(erro)
    [ERR_BRANCH_EXISTS] já existe uma branch chamada teste
"""

from __future__ import annotations

from typing import Any, Dict, Optional

__all__ = [
    "AsmxError",
    "SourceNotFoundError",
    "SourceReadError",
    "SourceWriteError",
    "UnsupportedSourceError",
    "ParseError",
    "ProjectError",
    "ProjectFormatError",
    "BranchNotFoundError",
    "BranchExistsError",
    "EmptyBranchNameError",
    "LastBranchError",
    "ScenarioError",
    "ConfigError",
    "EmulationError",
    "AnalysisTimeoutError",
    "UnknownMnemonicError",
    "LineNotFoundError",
    "ERROR_CODES",
]


class AsmxError(Exception):
    """Base de todos os erros do ASM X.

    Attributes:
        code: Código estável no formato ``ERR_ALGO``, usado em relatórios e no
            JSON da linha de comando.
        message: Mensagem legível, em português, sem prefixo de código.
        context: Dados extras do erro (caminho, linha, valor recebido) para
            quem quiser montar um relatório estruturado.
    """

    code: str = "ERR_ASMX"

    def __init__(self, message: str, code: Optional[str] = None, **context: Any) -> None:
        """Inicializa o erro.

        Args:
            message: Descrição legível do problema.
            code: Código que sobrepõe o padrão da classe (opcional).
            **context: Pares chave/valor guardados em ``self.context``.
        """
        super().__init__(message)
        self.message = message
        if code:
            self.code = code
        self.context: Dict[str, Any] = dict(context)

    def __str__(self) -> str:
        """Devolve ``[CÓDIGO] mensagem``.

        Returns:
            A mensagem formatada com o código entre colchetes.
        """
        return "[%s] %s" % (self.code, self.message)

    def __repr__(self) -> str:
        """Representação curta, útil em logs.

        Returns:
            Texto como ``SourceNotFoundError(code='ERR_...', message='...')``.
        """
        return "%s(code=%r, message=%r)" % (type(self).__name__, self.code, self.message)

    def to_dict(self) -> Dict[str, Any]:
        """Converte o erro em dicionário pronto para JSON.

        Returns:
            Dicionário com ``error`` (nome da classe), ``code``, ``message`` e,
            quando houver, ``context``.
        """
        data: Dict[str, Any] = {
            "error": type(self).__name__,
            "code": self.code,
            "message": self.message,
        }
        if self.context:
            data["context"] = dict(self.context)
        return data


# ----------------------------------------------------------------- arquivos --
class SourceNotFoundError(AsmxError, FileNotFoundError):
    """O arquivo de código fonte indicado não existe."""

    code = "ERR_SOURCE_NOT_FOUND"

    def __init__(self, path: str) -> None:
        """Monta o erro a partir do caminho que faltou.

        Args:
            path: Caminho procurado.
        """
        super().__init__("arquivo não encontrado: %s" % path, path=path)
        self.path = path


class SourceReadError(AsmxError, OSError):
    """O arquivo existe, mas não pôde ser lido (permissão, diretório, I/O)."""

    code = "ERR_SOURCE_READ"

    def __init__(self, path: str, detail: str = "") -> None:
        """Monta o erro a partir do caminho e do motivo.

        Args:
            path: Caminho que falhou.
            detail: Mensagem original do sistema operacional.
        """
        mensagem = "não consegui ler %s" % path
        if detail:
            mensagem += ": %s" % detail
        super().__init__(mensagem, path=path, detail=detail)
        self.path = path


class SourceWriteError(AsmxError, OSError):
    """Não foi possível gravar um arquivo (permissão, disco, diretório)."""

    code = "ERR_SOURCE_WRITE"

    def __init__(self, path: str, detail: str = "") -> None:
        """Monta o erro a partir do caminho e do motivo.

        Args:
            path: Caminho que não pôde ser gravado.
            detail: Mensagem original do sistema operacional.
        """
        mensagem = "não consegui gravar %s" % path
        if detail:
            mensagem += ": %s" % detail
        super().__init__(mensagem, path=path, detail=detail)
        self.path = path


class UnsupportedSourceError(AsmxError, ValueError):
    """A extensão do arquivo não é de um formato que o ASM X entenda."""

    code = "ERR_UNSUPPORTED_SOURCE"

    def __init__(self, path: str, expected: str) -> None:
        """Monta o erro com a lista de extensões aceitas.

        Args:
            path: Caminho recusado.
            expected: Texto descrevendo as extensões aceitas.
        """
        super().__init__(
            "formato não suportado em %s (esperado: %s)" % (path, expected),
            path=path,
            expected=expected,
        )
        self.path = path


class ParseError(AsmxError, ValueError):
    """O texto não pôde ser interpretado como assembly."""

    code = "ERR_PARSE"

    def __init__(self, message: str, line: Optional[int] = None) -> None:
        """Monta o erro, opcionalmente com a linha problemática.

        Args:
            message: Descrição do problema.
            line: Número da linha (1-based) onde o problema foi visto.
        """
        super().__init__(message, line=line)
        self.line = line


# ---------------------------------------------------------------- projeto --
class ProjectError(AsmxError, ValueError):
    """Erro genérico de manipulação de projeto (branch, cenário, arquivo)."""

    code = "ERR_PROJECT"


class ProjectFormatError(AsmxError, ValueError):
    """O arquivo ``.asmproj`` existe mas não é um projeto válido do ASM X."""

    code = "ERR_PROJECT_FORMAT"

    def __init__(self, path: str, detail: str = "") -> None:
        """Monta o erro a partir do caminho e do motivo.

        Args:
            path: Arquivo de projeto lido.
            detail: Explicação curta da inconsistência.
        """
        mensagem = "projeto inválido em %s" % path
        if detail:
            mensagem += ": %s" % detail
        super().__init__(mensagem, path=path, detail=detail)
        self.path = path


class BranchNotFoundError(AsmxError, KeyError):
    """A branch pedida não existe no projeto."""

    code = "ERR_BRANCH_NOT_FOUND"

    def __init__(self, name: str) -> None:
        """Monta o erro a partir do nome da branch.

        Args:
            name: Nome procurado.
        """
        super().__init__("branch inexistente: %s" % name, branch=name)
        self.name = name


class BranchExistsError(AsmxError, ValueError):
    """Já existe uma branch com esse nome."""

    code = "ERR_BRANCH_EXISTS"

    def __init__(self, name: str) -> None:
        """Monta o erro a partir do nome repetido.

        Args:
            name: Nome que já está em uso.
        """
        super().__init__("já existe uma branch chamada %s" % name, branch=name)
        self.name = name


class EmptyBranchNameError(AsmxError, ValueError):
    """Tentaram criar uma branch sem nome."""

    code = "ERR_BRANCH_EMPTY_NAME"

    def __init__(self) -> None:
        """Monta o erro padrão de nome vazio."""
        super().__init__("a branch precisa de um nome")


class LastBranchError(AsmxError, ValueError):
    """Tentaram apagar a única branch do projeto."""

    code = "ERR_BRANCH_LAST"

    def __init__(self) -> None:
        """Monta o erro padrão de última branch."""
        super().__init__("o projeto precisa de pelo menos uma branch")


class ScenarioError(AsmxError, ValueError):
    """Cenário de teste inválido (rótulo inexistente, limite negativo...)."""

    code = "ERR_SCENARIO"

    def __init__(self, message: str, scenario: Optional[str] = None) -> None:
        """Monta o erro.

        Args:
            message: Descrição do problema.
            scenario: Nome do cenário envolvido (opcional).
        """
        super().__init__(message, scenario=scenario)
        self.scenario = scenario


# ---------------------------------------------------------- configuração --
class ConfigError(AsmxError, ValueError):
    """Configuração ausente, ilegível ou com valor fora da faixa."""

    code = "ERR_CONFIG"

    def __init__(
        self, message: str, path: Optional[str] = None, field: Optional[str] = None
    ) -> None:
        """Monta o erro.

        Args:
            message: Descrição do problema.
            path: Arquivo de configuração envolvido (opcional).
            field: Campo rejeitado (opcional).
        """
        super().__init__(message, path=path, field=field)
        self.path = path
        self.field = field


# ------------------------------------------------------------- execução --
class EmulationError(AsmxError, RuntimeError):
    """A máquina virtual não conseguiu começar ou continuar a execução."""

    code = "ERR_EMULATION"

    def __init__(self, message: str, line: Optional[int] = None) -> None:
        """Monta o erro, opcionalmente com a linha.

        Args:
            message: Descrição do problema.
            line: Linha do código onde a execução parou.
        """
        super().__init__(message, line=line)
        self.line = line


class AnalysisTimeoutError(AsmxError, TimeoutError):
    """A execução passou do tempo limite configurado."""

    code = "ERR_TIMEOUT"

    def __init__(self, timeout: float, steps: int = 0) -> None:
        """Monta o erro com o limite estourado.

        Args:
            timeout: Tempo limite em segundos.
            steps: Quantas instruções foram executadas até parar.
        """
        super().__init__(
            "a execução passou de %g s (timeout)" % timeout, timeout=timeout, steps=steps
        )
        self.timeout = timeout
        self.steps = steps


# ---------------------------------------------------------------- consulta --
class UnknownMnemonicError(AsmxError, KeyError):
    """Pediram documentação de uma instrução que não está no acervo."""

    code = "ERR_UNKNOWN_MNEMONIC"

    def __init__(self, mnemonic: str, known: int = 0) -> None:
        """Monta o erro.

        Args:
            mnemonic: Mnemônico procurado.
            known: Quantas instruções o acervo tem, para dar noção do tamanho.
        """
        detalhe = " (%d instruções documentadas)" % known if known else ""
        super().__init__(
            "não há documentação para %r%s" % (mnemonic, detalhe), mnemonic=mnemonic, known=known
        )
        self.mnemonic = mnemonic


class LineNotFoundError(AsmxError, KeyError):
    """A linha pedida não existe no arquivo analisado."""

    code = "ERR_LINE_NOT_FOUND"

    def __init__(self, line: int, total: int = 0) -> None:
        """Monta o erro.

        Args:
            line: Linha procurada (1-based).
            total: Quantas linhas o arquivo tem.
        """
        detalhe = " (o arquivo tem %d linha(s))" % total if total else ""
        super().__init__("não existe a linha %d%s" % (line, detalhe), line=line, total=total)
        self.line = line


#: Índice ``código -> classe``, usado pela linha de comando e pela documentação.
ERROR_CODES: Dict[str, type] = {
    classe.code: classe
    for classe in (
        AsmxError,
        SourceNotFoundError,
        SourceReadError,
        SourceWriteError,
        UnsupportedSourceError,
        ParseError,
        ProjectError,
        ProjectFormatError,
        BranchNotFoundError,
        BranchExistsError,
        EmptyBranchNameError,
        LastBranchError,
        ScenarioError,
        ConfigError,
        EmulationError,
        AnalysisTimeoutError,
        UnknownMnemonicError,
        LineNotFoundError,
    )
}
