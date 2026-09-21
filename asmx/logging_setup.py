"""Logging estruturado do ASM X, sem dependência externa.

Dois formatos, o mesmo conteúdo:

* **texto** — legível no terminal, usado por padrão quando alguém roda a
  ferramenta à mão;
* **JSON** — um objeto por linha, com ``ts``, ``level``, ``logger``, ``event``,
  ``message`` e os campos extras do evento. É o formato para CI, para o
  Docker e para qualquer coisa que vá ler os logs com ``jq``.

O logger raiz usado aqui é o namespace ``asmx``: a biblioteca nunca mexe no
logging global de quem a importa, então embutir o ASM X num programa maior não
duplica mensagem nem rouba configuração.

Example:
    >>> from asmx.logging_setup import configure_logging, get_logger, log_event
    >>> estado = configure_logging(level="DEBUG", json_output=True)
    >>> log = get_logger("asmx.exemplo")
    >>> log_event(log, "analysis_started", instructions=12)  # doctest: +SKIP
    >>> reset_logging()
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
import os
import sys
from dataclasses import dataclass
from typing import Any, Dict, IO, Optional, Union

__all__ = [
    "LOGGER_NAME",
    "LOG_LEVELS",
    "JsonFormatter",
    "TextFormatter",
    "LoggingState",
    "configure_logging",
    "get_logger",
    "log_event",
    "reset_logging",
    "resolve_level",
    "env_flag",
]

#: Namespace dos loggers da aplicação (nunca o logger raiz).
LOGGER_NAME = "asmx"

#: Níveis aceitos na configuração, do mais verboso ao mais silencioso.
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

#: Campos que o próprio :mod:`logging` cria em cada registro.
_STANDARD_ATTRS = frozenset(
    vars(logging.LogRecord("", logging.NOTSET, "", 0, "", (), None)).keys()
) | {"message", "asctime", "taskName"}

#: Campos extras que não podem virar chave de topo no JSON sem confusão.
_PROTECTED_KEYS = frozenset({"ts", "level", "logger", "event", "message", "exception", "stack"})


def env_flag(name: str, default: bool = False) -> bool:
    """Lê uma variável de ambiente no formato booleano.

    Aceita ``1``, ``true``, ``yes``, ``on`` (sem diferenciar maiúsculas) como
    verdadeiro e ``0``, ``false``, ``no``, ``off``, vazio como falso. Qualquer
    outro texto devolve o padrão.

    Args:
        name: Nome da variável de ambiente.
        default: Valor devolvido quando a variável não existe ou é ambígua.

    Returns:
        O booleano lido do ambiente.

    Example:
        >>> env_flag("ASMX_NAO_EXISTE", default=True)
        True
    """
    raw = os.environ.get(name)
    if raw is None:
        return default
    texto = raw.strip().lower()
    if texto in ("1", "true", "yes", "on", "sim"):
        return True
    if texto in ("0", "false", "no", "off", "", "nao", "não"):
        return False
    return default


def resolve_level(level: Union[str, int, None]) -> int:
    """Converte nome ou número de nível no valor numérico do :mod:`logging`.

    Args:
        level: ``"debug"``, ``"INFO"``, ``10`` ou ``None`` (que vale INFO).

    Returns:
        Número do nível, pronto para ``logger.setLevel``.

    Raises:
        ValueError: Se o nome não for um dos :data:`LOG_LEVELS`.

    Example:
        >>> resolve_level("debug") == logging.DEBUG
        True
    """
    if level is None:
        return logging.INFO
    if isinstance(level, int):
        return level
    nome = str(level).strip().upper()
    if nome not in LOG_LEVELS:
        raise ValueError("nível de log desconhecido: %s (use %s)" % (level, ", ".join(LOG_LEVELS)))
    return int(getattr(logging, nome))


def _json_default(value: Any) -> str:
    """Serializa o que o :mod:`json` não conhece (set, objeto, dataclass).

    Returns:
        Uma representação em texto que o :mod:`json` aceita.
    """
    if isinstance(value, (set, frozenset)):
        return ",".join(sorted(str(v) for v in value))
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


class JsonFormatter(logging.Formatter):
    """Formata cada registro como uma linha JSON.

    Attributes:
        timestamp_key: Nome do campo de data/hora (padrão ``ts``).
        include_exception: Se o rastreamento da exceção entra no JSON.
    """

    def __init__(self, timestamp_key: str = "ts", include_exception: bool = True) -> None:
        """Inicializa o formatador.

        Args:
            timestamp_key: Chave usada para a data/hora ISO-8601.
            include_exception: Inclui ``exception`` quando há ``exc_info``.
        """
        super().__init__()
        self.timestamp_key = timestamp_key
        self.include_exception = include_exception

    def format(self, record: logging.LogRecord) -> str:
        """Converte o registro em uma linha JSON.

        Args:
            record: Registro criado pelo :mod:`logging`.

        Returns:
            String JSON de uma linha, com ``ensure_ascii=False`` para preservar
            acentos das mensagens em português.
        """
        payload: Dict[str, Any] = {
            self.timestamp_key: self.timestamp(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        event = record.__dict__.get("event")
        if event:
            payload["event"] = event
        for chave, valor in record.__dict__.items():
            if chave in _STANDARD_ATTRS or chave == "event":
                continue
            if chave in _PROTECTED_KEYS:
                payload["extra_" + chave] = valor
            else:
                payload[chave] = valor
        if self.include_exception and record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack"] = self.formatStack(record.stack_info)
        return json.dumps(payload, ensure_ascii=False, default=_json_default)

    @staticmethod
    def timestamp(record: logging.LogRecord) -> str:
        """Devolve a hora do registro em ISO-8601 UTC com milissegundos.

        Args:
            record: Registro de log.

        Returns:
            Texto como ``2026-09-21T18:04:11.123Z``.
        """
        momento = _dt.datetime.fromtimestamp(record.created, tz=_dt.timezone.utc)
        return momento.isoformat(timespec="milliseconds").replace("+00:00", "Z")


class TextFormatter(logging.Formatter):
    """Formata o registro para leitura humana, mostrando os campos extras."""

    def __init__(self, show_extras: bool = True) -> None:
        """Inicializa o formatador.

        Args:
            show_extras: Anexa ``event`` e os campos extras ao fim da linha.
        """
        super().__init__(
            fmt="%(asctime)s %(levelname)-7s %(name)s: %(message)s", datefmt="%H:%M:%S"
        )
        self.show_extras = show_extras

    def format(self, record: logging.LogRecord) -> str:
        """Monta a linha de texto do registro.

        Args:
            record: Registro criado pelo :mod:`logging`.

        Returns:
            Linha terminada sem quebra, no formato
            ``12:00:01 INFO    asmx.cli: mensagem event=... chave=valor``.
        """
        linha = super().format(record)
        if self.show_extras:
            linha += self._extras(record)
        if record.exc_info:
            linha += "\n" + self.formatException(record.exc_info)
        return linha

    @staticmethod
    def _extras(record: logging.LogRecord) -> str:
        """Descreve os campos extras do registro como ``chave=valor``.

        Returns:
            Sufixo pronto para colar na linha, ou string vazia.
        """
        partes = []
        event = record.__dict__.get("event")
        if event:
            partes.append("event=%s" % event)
        for chave, valor in record.__dict__.items():
            if chave in _STANDARD_ATTRS or chave == "event":
                continue
            partes.append("%s=%s" % (chave, valor))
        return ("  " + " ".join(partes)) if partes else ""


@dataclass(frozen=True)
class LoggingState:
    """Retrato da configuração de logging aplicada.

    Attributes:
        level: Nome do nível em uso (``DEBUG``, ``INFO``...).
        json_output: Se a saída está em JSON.
        log_file: Caminho do arquivo de log, quando houver.
        handlers: Quantos handlers ficaram instalados no logger ``asmx``.
    """

    level: str
    json_output: bool
    log_file: Optional[str]
    handlers: int

    def to_dict(self) -> Dict[str, Any]:
        """Converte o estado em dicionário serializável.

        Returns:
            Dicionário com os quatro campos do estado.
        """
        return {
            "level": self.level,
            "json_output": self.json_output,
            "log_file": self.log_file,
            "handlers": self.handlers,
        }


def configure_logging(
    level: Union[str, int, None] = None,
    *,
    json_output: Optional[bool] = None,
    log_file: Optional[str] = None,
    stream: Optional[IO[str]] = None,
    force: bool = False,
) -> LoggingState:
    """Liga o logging estruturado do ASM X.

    Chamar duas vezes não duplica handler: os anteriores do logger ``asmx`` são
    removidos antes de instalar os novos. Quando um argumento é ``None``, o
    valor vem do ambiente (``ASMX_LOG_LEVEL``, ``ASMX_LOG_JSON``,
    ``ASMX_LOG_FILE``) e, se o ambiente também estiver vazio, do padrão
    ``INFO`` em texto no ``stderr``.

    Args:
        level: Nível mínimo (nome ou número). ``None`` = ambiente ou INFO.
        json_output: Força (ou desliga) o formato JSON. ``None`` = ambiente.
        log_file: Arquivo que recebe as mesmas linhas do console.
        stream: Fluxo de saída; padrão ``sys.stderr``.
        force: Reconfigura mesmo se já houver configuração aplicada.

    Returns:
        O :class:`LoggingState` com o que ficou valendo.

    Raises:
        ValueError: Se o nível pedido não existir.

    Example:
        >>> estado = configure_logging("DEBUG", json_output=False, stream=sys.stderr)
        >>> estado.level
        'DEBUG'
        >>> reset_logging()
    """
    logger = logging.getLogger(LOGGER_NAME)
    if getattr(logger, "_asmx_configured", False) and not force:
        atual = logger._asmx_state  # type: ignore[attr-defined]
        return atual

    if level is None:
        level = os.environ.get("ASMX_LOG_LEVEL") or "INFO"
    if json_output is None:
        json_output = env_flag("ASMX_LOG_JSON", False)
    if log_file is None:
        log_file = os.environ.get("ASMX_LOG_FILE") or None

    numero = resolve_level(level)
    nome = logging.getLevelName(numero)
    formato: logging.Formatter = JsonFormatter() if json_output else TextFormatter()

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        try:
            handler.close()
        except Exception:  # pragma: no cover - handler exótico de terceiros
            pass

    console = logging.StreamHandler(stream if stream is not None else sys.stderr)
    console.setFormatter(formato)
    console.setLevel(numero)
    logger.addHandler(console)

    if log_file:
        arquivo = logging.FileHandler(log_file, encoding="utf-8")
        arquivo.setFormatter(formato)
        arquivo.setLevel(numero)
        logger.addHandler(arquivo)

    logger.setLevel(numero)
    logger.propagate = False
    estado = LoggingState(
        level=str(nome),
        json_output=bool(json_output),
        log_file=log_file,
        handlers=len(logger.handlers),
    )
    logger._asmx_configured = True  # type: ignore[attr-defined]
    logger._asmx_state = estado  # type: ignore[attr-defined]
    return estado


def reset_logging() -> None:
    """Desliga o logging do ASM X e devolve o namespace ao estado inicial.

    Remove os handlers instalados por :func:`configure_logging`, apaga a marca
    de configuração e volta a deixar o logger ``asmx`` propagar para o logger
    raiz. É o que os testes usam para que um caso não contamine o seguinte.
    """
    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        try:
            handler.close()
        except Exception:  # pragma: no cover - handler exótico de terceiros
            pass
    logger.setLevel(logging.NOTSET)
    logger.propagate = True
    logger.__dict__.pop("_asmx_configured", None)
    logger.__dict__.pop("_asmx_state", None)


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Devolve um logger dentro do namespace ``asmx``.

    Args:
        name: Nome do módulo (use ``__name__``). ``None`` devolve o logger raiz
            do ASM X.

    Returns:
        Logger pronto para uso; sem handler instalado, nada é impresso.

    Example:
        >>> get_logger("asmx.parser").name
        'asmx.parser'
    """
    if not name or name == LOGGER_NAME or name.startswith(LOGGER_NAME + "."):
        return logging.getLogger(name or LOGGER_NAME)
    return logging.getLogger("%s.%s" % (LOGGER_NAME, name))


def log_event(
    logger: logging.Logger,
    event: str,
    *,
    level: int = logging.INFO,
    message: Optional[str] = None,
    exc_info: bool = False,
    **fields: Any,
) -> None:
    """Emite um evento estruturado.

    O campo ``event`` vira uma chave de topo no JSON (``analysis_completed``,
    ``project_saved``...), o que permite filtrar logs por acontecimento sem
    interpretar texto livre.

    Args:
        logger: Logger devolvido por :func:`get_logger`.
        event: Nome curto do acontecimento, em ``snake_case``.
        level: Nível do registro (padrão ``INFO``).
        message: Texto legível; quando vazio, usa o próprio nome do evento.
        exc_info: Anexa o rastreamento da exceção corrente.
        **fields: Campos extras do evento (contagens, caminhos, códigos).

    Example:
        >>> log = get_logger("asmx.exemplo")
        >>> log_event(log, "validation_finished", errors=0, warnings=2)
    """
    extras = {
        chave: valor
        for chave, valor in fields.items()
        if chave not in _STANDARD_ATTRS and chave != "event"
    }
    logger.log(level, message or event, extra={"event": event, **extras}, exc_info=exc_info)
