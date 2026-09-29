"""Structured logging for ASM X, with no external dependency.

Two formats, the same content:

* **text** — readable in the terminal, used by default when someone runs the
  tool by hand;
* **JSON** — one object per line, with ``ts``, ``level``, ``logger``, ``event``,
  ``message`` and the extra fields of the event. It is the format for CI, for
  Docker and for anything that will read the logs with ``jq``.

The root logger used here is the ``asmx`` namespace: the library never touches
the global logging of whoever imports it, so embedding ASM X in a bigger
program neither duplicates messages nor steals configuration.

Example:
    >>> from asmx.logging_setup import configure_logging, get_logger, log_event
    >>> state = configure_logging(level="DEBUG", json_output=True)
    >>> log = get_logger("asmx.example")
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

#: Namespace of the application loggers (never the root logger).
LOGGER_NAME = "asmx"

#: Levels accepted in the configuration, from the most verbose to the quietest.
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

#: Fields that :mod:`logging` itself creates in every record.
_STANDARD_ATTRS = frozenset(
    vars(logging.LogRecord("", logging.NOTSET, "", 0, "", (), None)).keys()
) | {"message", "asctime", "taskName"}

#: Extra fields that cannot become a top level JSON key without confusion.
_PROTECTED_KEYS = frozenset({"ts", "level", "logger", "event", "message", "exception", "stack"})


def env_flag(name: str, default: bool = False) -> bool:
    """Reads an environment variable in the boolean format.

    Accepts ``1``, ``true``, ``yes``, ``on`` (case-insensitive) as true and
    ``0``, ``false``, ``no``, ``off``, empty as false. The Portuguese words
    ``sim`` and ``nao`` are also accepted, as a courtesy for existing setups.
    Any other text returns the default.

    Args:
        name: Name of the environment variable.
        default: Value returned when the variable does not exist or is ambiguous.

    Returns:
        The boolean read from the environment.

    Example:
        >>> env_flag("ASMX_DOES_NOT_EXIST", default=True)
        True
    """
    raw = os.environ.get(name)
    if raw is None:
        return default
    text = raw.strip().lower()
    if text in ("1", "true", "yes", "on", "sim"):
        return True
    if text in ("0", "false", "no", "off", "", "nao", "n\u00e3o"):
        return False
    return default


def resolve_level(level: Union[str, int, None]) -> int:
    """Converts a level name or number into the :mod:`logging` numeric value.

    Args:
        level: ``"debug"``, ``"INFO"``, ``10`` or ``None`` (which means INFO).

    Returns:
        The level number, ready for ``logger.setLevel``.

    Raises:
        ValueError: When the name is not one of :data:`LOG_LEVELS`.

    Example:
        >>> resolve_level("debug") == logging.DEBUG
        True
    """
    if level is None:
        return logging.INFO
    if isinstance(level, int):
        return level
    name = str(level).strip().upper()
    if name not in LOG_LEVELS:
        raise ValueError("unknown log level: %s (use %s)" % (level, ", ".join(LOG_LEVELS)))
    return int(getattr(logging, name))


def _json_default(value: Any) -> str:
    """Serializes what :mod:`json` does not know (set, object, dataclass).

    Returns:
        A text representation that :mod:`json` accepts.
    """
    if isinstance(value, (set, frozenset)):
        return ",".join(sorted(str(v) for v in value))
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


class JsonFormatter(logging.Formatter):
    """Formats every record as one JSON line.

    Attributes:
        timestamp_key: Name of the date/time field (default ``ts``).
        include_exception: Whether the exception traceback enters the JSON.
    """

    def __init__(self, timestamp_key: str = "ts", include_exception: bool = True) -> None:
        """Initializes the formatter.

        Args:
            timestamp_key: Key used for the ISO-8601 date/time.
            include_exception: Includes ``exception`` when there is ``exc_info``.
        """
        super().__init__()
        self.timestamp_key = timestamp_key
        self.include_exception = include_exception

    def format(self, record: logging.LogRecord) -> str:
        """Converts the record into one JSON line.

        Args:
            record: Record created by :mod:`logging`.

        Returns:
            One-line JSON string, with ``ensure_ascii=False`` so non-ASCII
            characters of the messages stay readable instead of escaped.
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
        for key, value in record.__dict__.items():
            if key in _STANDARD_ATTRS or key == "event":
                continue
            if key in _PROTECTED_KEYS:
                payload["extra_" + key] = value
            else:
                payload[key] = value
        if self.include_exception and record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack"] = self.formatStack(record.stack_info)
        return json.dumps(payload, ensure_ascii=False, default=_json_default)

    @staticmethod
    def timestamp(record: logging.LogRecord) -> str:
        """Returns the time of the record in ISO-8601 UTC with milliseconds.

        Args:
            record: Log record.

        Returns:
            Text such as ``2026-09-21T18:04:11.123Z``.
        """
        moment = _dt.datetime.fromtimestamp(record.created, tz=_dt.timezone.utc)
        return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


class TextFormatter(logging.Formatter):
    """Formats the record for human reading, showing the extra fields."""

    def __init__(self, show_extras: bool = True) -> None:
        """Initializes the formatter.

        Args:
            show_extras: Appends ``event`` and the extra fields to the end of the line.
        """
        super().__init__(
            fmt="%(asctime)s %(levelname)-7s %(name)s: %(message)s", datefmt="%H:%M:%S"
        )
        self.show_extras = show_extras

    def format(self, record: logging.LogRecord) -> str:
        """Builds the text line of the record.

        Args:
            record: Record created by :mod:`logging`.

        Returns:
            Line with no trailing break, in the format
            ``12:00:01 INFO    asmx.cli: message event=... key=value``.
        """
        line = super().format(record)
        if self.show_extras:
            line += self._extras(record)
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line

    @staticmethod
    def _extras(record: logging.LogRecord) -> str:
        """Describes the extra fields of the record as ``key=value``.

        Returns:
            Suffix ready to be glued to the line, or an empty string.
        """
        parts = []
        event = record.__dict__.get("event")
        if event:
            parts.append("event=%s" % event)
        for key, value in record.__dict__.items():
            if key in _STANDARD_ATTRS or key == "event":
                continue
            parts.append("%s=%s" % (key, value))
        return ("  " + " ".join(parts)) if parts else ""


@dataclass(frozen=True)
class LoggingState:
    """Snapshot of the logging configuration that was applied.

    Attributes:
        level: Name of the level in use (``DEBUG``, ``INFO``...).
        json_output: Whether the output is JSON.
        log_file: Path of the log file, when there is one.
        handlers: How many handlers were installed on the ``asmx`` logger.
    """

    level: str
    json_output: bool
    log_file: Optional[str]
    handlers: int

    def to_dict(self) -> Dict[str, Any]:
        """Converts the state into a serializable dictionary.

        Returns:
            Dictionary with the four fields of the state.
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
    """Turns on the structured logging of ASM X.

    Calling it twice does not duplicate a handler: the previous ones of the
    ``asmx`` logger are removed before the new ones are installed. When an
    argument is ``None``, the value comes from the environment
    (``ASMX_LOG_LEVEL``, ``ASMX_LOG_JSON``, ``ASMX_LOG_FILE``) and, if the
    environment is empty too, from the default ``INFO`` in text on ``stderr``.

    Args:
        level: Minimum level (name or number). ``None`` = environment or INFO.
        json_output: Forces (or turns off) the JSON format. ``None`` = environment.
        log_file: File that receives the same lines as the console.
        stream: Output stream; default ``sys.stderr``.
        force: Reconfigures even when a configuration is already applied.

    Returns:
        The :class:`LoggingState` with what ended up in effect.

    Raises:
        ValueError: When the requested level does not exist.

    Example:
        >>> state = configure_logging("DEBUG", json_output=False, stream=sys.stderr)
        >>> state.level
        'DEBUG'
        >>> reset_logging()
    """
    logger = logging.getLogger(LOGGER_NAME)
    if getattr(logger, "_asmx_configured", False) and not force:
        current = logger._asmx_state  # type: ignore[attr-defined]
        return current

    if level is None:
        level = os.environ.get("ASMX_LOG_LEVEL") or "INFO"
    if json_output is None:
        json_output = env_flag("ASMX_LOG_JSON", False)
    if log_file is None:
        log_file = os.environ.get("ASMX_LOG_FILE") or None

    number = resolve_level(level)
    name = logging.getLevelName(number)
    formatter: logging.Formatter = JsonFormatter() if json_output else TextFormatter()

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        try:
            handler.close()
        except Exception:  # pragma: no cover - exotic third party handler
            pass

    console = logging.StreamHandler(stream if stream is not None else sys.stderr)
    console.setFormatter(formatter)
    console.setLevel(number)
    logger.addHandler(console)

    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        file_handler.setLevel(number)
        logger.addHandler(file_handler)

    logger.setLevel(number)
    logger.propagate = False
    state = LoggingState(
        level=str(name),
        json_output=bool(json_output),
        log_file=log_file,
        handlers=len(logger.handlers),
    )
    logger._asmx_configured = True  # type: ignore[attr-defined]
    logger._asmx_state = state  # type: ignore[attr-defined]
    return state


def reset_logging() -> None:
    """Turns off ASM X logging and returns the namespace to its initial state.

    It removes the handlers installed by :func:`configure_logging`, erases the
    configuration mark and lets the ``asmx`` logger propagate to the root
    logger again. It is what the tests use so that one case does not
    contaminate the next one.
    """
    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        try:
            handler.close()
        except Exception:  # pragma: no cover - exotic third party handler
            pass
    logger.setLevel(logging.NOTSET)
    logger.propagate = True
    logger.__dict__.pop("_asmx_configured", None)
    logger.__dict__.pop("_asmx_state", None)


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Returns a logger inside the ``asmx`` namespace.

    Args:
        name: Module name (use ``__name__``). ``None`` returns the ASM X root
            logger.

    Returns:
        Logger ready to use; with no handler installed, nothing is printed.

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
    """Emits a structured event.

    The ``event`` field becomes a top level JSON key (``analysis_completed``,
    ``project_saved``...), which allows filtering logs by occurrence without
    interpreting free text.

    Args:
        logger: Logger returned by :func:`get_logger`.
        event: Short name of the occurrence, in ``snake_case``.
        level: Level of the record (default ``INFO``).
        message: Readable text; when empty, it uses the event name itself.
        exc_info: Appends the traceback of the current exception.
        **fields: Extra fields of the event (counts, paths, codes).

    Example:
        >>> log = get_logger("asmx.example")
        >>> log_event(log, "validation_finished", errors=0, warnings=2)
    """
    extras = {
        key: value for key, value in fields.items() if key not in _STANDARD_ATTRS and key != "event"
    }
    logger.log(level, message or event, extra={"event": event, **extras}, exc_info=exc_info)
