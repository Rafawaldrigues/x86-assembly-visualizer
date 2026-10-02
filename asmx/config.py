"""ASM X configuration: one dataclass, an optional file and environment variables.

The precedence order is always the same, from the most specific to the most
general:

1. explicit argument (``--timeout 5`` on the command line);
2. environment variables (``ASMX_TIMEOUT=5``);
3. configuration file (``asmx.yaml``, ``asmx.json`` or ``--config``);
4. defaults of :class:`SandboxConfig`.

YAML is optional on purpose: ASM X has no mandatory dependency, so
``from_yaml_file`` only works when PyYAML is installed. JSON uses only the
standard library and always works.

Example:
    >>> from asmx.config import SandboxConfig
    >>> config = SandboxConfig.from_dict({"timeout": 5, "log_level": "debug"})
    >>> config.timeout, config.log_level
    (5.0, 'DEBUG')
"""

from __future__ import annotations

import difflib
import json
import os
from dataclasses import dataclass, fields, replace
from typing import Any, ClassVar, Dict, Mapping, Optional, Tuple

from .errors import ConfigError
from .logging_setup import LOG_LEVELS, LoggingState, configure_logging

__all__ = [
    "SandboxConfig",
    "CONFIG_ENV_VAR",
    "CANDIDATE_NAMES",
    "USER_DIRS",
]

#: Environment variable that points to the configuration file.
CONFIG_ENV_VAR = "ASMX_CONFIG"

#: Names searched in the current directory, in this order.
CANDIDATE_NAMES: Tuple[str, ...] = (
    "asmx.yaml",
    "asmx.yml",
    "asmx.json",
    ".asmx.yaml",
    ".asmx.json",
)

#: User directories searched after the current directory.
USER_DIRS: Tuple[str, ...] = ("~/.config/asmx", "~/.asmx")

#: Extensions recognized by :meth:`SandboxConfig.from_file`.
YAML_SUFFIXES = (".yaml", ".yml")

#: Smallest accepted memory, in MB.
MIN_MEMORY_MB = 16


def _as_bool(value: Any) -> bool:
    """Converts file/environment values into a boolean.

    Args:
        value: Raw value (``True``, ``"yes"``, ``"0"``, ``1``...). The
            Portuguese words ``sim`` and ``nao`` are also accepted, as a
            courtesy for existing files.

    Returns:
        The corresponding boolean, using the same words as
        :func:`asmx.logging_setup.env_flag`.

    Raises:
        ConfigError: When the text is not a recognized boolean.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "on", "sim"):
        return True
    if text in ("0", "false", "no", "off", "", "nao", "n\u00e3o"):
        return False
    raise ConfigError("invalid boolean value: %r (use true/false)" % (value,))


def _as_float(value: Any, field_name: str) -> float:
    """Converts to ``float``, naming the field when it fails.

    Returns:
        The converted value.

    Raises:
        ConfigError: When the text is not a number.
    """
    try:
        return float(value)
    except (TypeError, ValueError) as error:
        raise ConfigError(
            "the field %s needs to be a number (got %r)" % (field_name, value), field=field_name
        ) from error


def _as_int(value: Any, field_name: str) -> int:
    """Converts to ``int``, naming the field when it fails.

    Returns:
        The converted value, accepting hexadecimal and octal.

    Raises:
        ConfigError: When the text is not an integer.
    """
    try:
        return int(str(value).strip(), 0)
    except (TypeError, ValueError) as error:
        raise ConfigError(
            "the field %s needs to be an integer (got %r)" % (field_name, value), field=field_name
        ) from error


@dataclass
class SandboxConfig:
    """Parameters that control analysis and execution.

    Attributes:
        timeout: Maximum wall clock time, in seconds, for one run.
        max_steps: Instruction limit per run (protects against infinite loops).
        max_memory: Maximum simulated allocation in MiB, enforced per machine.
        enable_network: Reserved for external integrations; the ASM X virtual
            machine never accesses the network.
        log_level: ``DEBUG``, ``INFO``, ``WARNING``, ``ERROR`` or ``CRITICAL``.
        log_json: Emits the log as JSON (one line per event).
        log_file: File that receives a copy of the logs.
        workers: Parallel processes used when analyzing several files.
        output_dir: Directory where the reports are written.
        strict: Turns a detected problem into an exception, instead of a warning.
    """

    timeout: float = 30.0
    max_steps: int = 200_000
    max_memory: int = 512
    enable_network: bool = False
    log_level: str = "INFO"
    log_json: bool = False
    log_file: Optional[str] = None
    workers: int = 4
    output_dir: str = "results"
    strict: bool = False

    #: Names of the fields, in the order they appear in the reports.
    FIELD_NAMES: ClassVar[Tuple[str, ...]] = (
        "timeout",
        "max_steps",
        "max_memory",
        "enable_network",
        "log_level",
        "log_json",
        "log_file",
        "workers",
        "output_dir",
        "strict",
    )

    #: Environment variables recognized, by field.
    ENV_NAMES: ClassVar[Dict[str, str]] = {
        "timeout": "ASMX_TIMEOUT",
        "max_steps": "ASMX_MAX_STEPS",
        "max_memory": "ASMX_MAX_MEMORY",
        "enable_network": "ASMX_ENABLE_NETWORK",
        "log_level": "ASMX_LOG_LEVEL",
        "log_json": "ASMX_LOG_JSON",
        "log_file": "ASMX_LOG_FILE",
        "workers": "ASMX_WORKERS",
        "output_dir": "ASMX_OUTPUT_DIR",
        "strict": "ASMX_STRICT",
    }

    def __post_init__(self) -> None:
        """Normalizes types and the case of the log level after construction."""
        self.timeout = _as_float(self.timeout, "timeout")
        self.max_steps = _as_int(self.max_steps, "max_steps")
        self.max_memory = _as_int(self.max_memory, "max_memory")
        self.workers = _as_int(self.workers, "workers")
        self.enable_network = _as_bool(self.enable_network)
        self.log_json = _as_bool(self.log_json)
        self.strict = _as_bool(self.strict)
        self.log_level = str(self.log_level).strip().upper()
        if self.log_file is not None:
            self.log_file = str(self.log_file)
        self.output_dir = str(self.output_dir)

    # ------------------------------------------------------------ validation -
    def validate(self) -> "SandboxConfig":
        """Checks the range of every field.

        Returns:
            The object itself, to chain calls.

        Raises:
            ConfigError: On the first field out of range, with the field name
                in ``context["field"]``.

        Example:
            >>> SandboxConfig(timeout=1).validate().timeout
            1.0
        """
        if not 0 < self.timeout <= 86_400:
            raise ConfigError(
                "timeout needs to be between 0 and 86400 seconds (got %g)" % self.timeout,
                field="timeout",
            )
        if self.max_steps < 1:
            raise ConfigError(
                "max_steps needs to be at least 1 (got %d)" % self.max_steps, field="max_steps"
            )
        if self.max_memory < MIN_MEMORY_MB:
            raise ConfigError(
                "max_memory needs to be at least %d MiB (got %d)"
                % (MIN_MEMORY_MB, self.max_memory),
                field="max_memory",
            )
        if self.log_level not in LOG_LEVELS:
            raise ConfigError(
                "unknown log_level: %s (use %s)" % (self.log_level, ", ".join(LOG_LEVELS)),
                field="log_level",
            )
        if not 1 <= self.workers <= 256:
            raise ConfigError(
                "workers needs to be between 1 and 256 (got %d)" % self.workers, field="workers"
            )
        if not self.output_dir.strip():
            raise ConfigError("output_dir cannot be empty", field="output_dir")
        return self

    # -------------------------------------------------------- serialization -
    def to_dict(self) -> Dict[str, Any]:
        """Converts the configuration into a dictionary.

        Returns:
            Dictionary with all :data:`FIELD_NAMES` in simple types.
        """
        return {name: getattr(self, name) for name in self.FIELD_NAMES}

    def describe(self) -> str:
        """Summarizes the configuration in one readable line.

        Returns:
            Text with the fields that change the behavior of the run.

        Example:
            >>> SandboxConfig(timeout=2, max_steps=10).describe()
            'timeout=2s · max_steps=10 · memory=512MiB · network=off · log=INFO · workers=4'
        """
        return "timeout=%gs · max_steps=%d · memory=%dMiB · network=%s · log=%s · workers=%d" % (
            self.timeout,
            self.max_steps,
            self.max_memory,
            "on" if self.enable_network else "off",
            self.log_level,
            self.workers,
        )

    @classmethod
    def from_dict(
        cls, data: Optional[Mapping[str, Any]] = None, *, path: Optional[str] = None
    ) -> "SandboxConfig":
        """Creates the configuration from a mapping.

        Args:
            data: Fields that override the defaults. ``None`` means ``{}``.
            path: Source file, used in the error messages.

        Returns:
            Validated configuration.

        Raises:
            ConfigError: On an unknown field (with a suggestion of a similar
                name) or a value out of range.

        Example:
            >>> SandboxConfig.from_dict({"workers": "2"}).workers
            2
        """
        values: Dict[str, Any] = dict(data or {})
        known = set(cls.FIELD_NAMES)
        unknown = [key for key in values if key not in known]
        if unknown:
            key = unknown[0]
            similar = difflib.get_close_matches(key, sorted(known), n=1)
            hint = " (did you mean %s?)" % similar[0] if similar else ""
            origin = " in %s" % path if path else ""
            raise ConfigError("unknown field%s: %s%s" % (origin, key, hint), path=path, field=key)
        try:
            config = cls(**values)
        except TypeError as error:
            raise ConfigError(
                "invalid configuration%s: %s" % (" in %s" % path if path else "", error), path=path
            ) from error
        return config.validate()

    # --------------------------------------------------------------- files -
    @classmethod
    def from_json_file(cls, path: str) -> "SandboxConfig":
        """Reads the configuration from a JSON file.

        Args:
            path: Path of the ``.json``.

        Returns:
            Validated configuration.

        Raises:
            ConfigError: Missing file, invalid JSON or unknown field.
        """
        try:
            with open(path, encoding="utf-8") as file:
                data = json.load(file)
        except OSError as error:
            raise ConfigError(
                "could not open the configuration %s: %s" % (path, error), path=path
            ) from error
        except json.JSONDecodeError as error:
            raise ConfigError(
                "invalid JSON in %s (line %d, column %d): %s"
                % (path, error.lineno, error.colno, error.msg),
                path=path,
            ) from error
        if not isinstance(data, dict):
            raise ConfigError("the configuration in %s needs to be a JSON object" % path, path=path)
        return cls.from_dict(data, path=path)

    @classmethod
    def from_yaml_file(cls, path: str) -> "SandboxConfig":
        """Reads the configuration from a YAML file (requires PyYAML installed).

        Args:
            path: Path of the ``.yaml`` or ``.yml``.

        Returns:
            Validated configuration.

        Raises:
            ConfigError: PyYAML missing, unreadable file or invalid content.
        """
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError as error:
            raise ConfigError(
                "to read %s install PyYAML (pip install pyyaml) or use a "
                ".json file, which needs no dependency" % path,
                path=path,
            ) from error
        try:
            with open(path, encoding="utf-8") as file:
                data = yaml.safe_load(file)
        except OSError as error:
            raise ConfigError(
                "could not open the configuration %s: %s" % (path, error), path=path
            ) from error
        except yaml.YAMLError as error:
            raise ConfigError("invalid YAML in %s: %s" % (path, error), path=path) from error
        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise ConfigError("the configuration in %s needs to be a YAML map" % path, path=path)
        return cls.from_dict(data, path=path)

    @classmethod
    def from_file(cls, path: str) -> "SandboxConfig":
        """Reads the configuration, choosing the format by the extension.

        Args:
            path: ``.json``, ``.yaml`` or ``.yml``.

        Returns:
            Validated configuration.

        Raises:
            ConfigError: Unrecognized extension or invalid content.

        Example:
            >>> SandboxConfig.from_file("does_not_exist.json")   # doctest: +SKIP
        """
        extension = os.path.splitext(path)[1].lower()
        if extension in YAML_SUFFIXES:
            return cls.from_yaml_file(path)
        if extension == ".json":
            return cls.from_json_file(path)
        raise ConfigError(
            "unrecognized configuration extension: %s (use .json, .yaml or .yml)"
            % (extension or path),
            path=path,
        )

    @classmethod
    def find_file(cls, start: Optional[str] = None) -> Optional[str]:
        """Searches for a configuration file in the conventional places.

        It looks first at ``$ASMX_CONFIG``, then at :data:`CANDIDATE_NAMES` in
        the ``start`` directory (default: the current directory) and finally at
        ``config.yaml``/``config.json`` inside :data:`USER_DIRS`.

        Args:
            start: Initial directory of the search.

        Returns:
            Path of the first file found, or ``None``.
        """
        pointed = os.environ.get(CONFIG_ENV_VAR)
        if pointed and os.path.isfile(pointed):
            return pointed
        base = os.path.abspath(os.path.expanduser(start or os.getcwd()))
        candidates = [os.path.join(base, name) for name in CANDIDATE_NAMES]
        for folder in USER_DIRS:
            root = os.path.expanduser(folder)
            candidates += [os.path.join(root, name) for name in CANDIDATE_NAMES]
            candidates += [os.path.join(root, "config.yaml"), os.path.join(root, "config.json")]
        for candidate in candidates:
            if os.path.isfile(candidate):
                return candidate
        return None

    # ----------------------------------------------------------- environment -
    @classmethod
    def from_env(cls, environ: Optional[Mapping[str, str]] = None) -> "SandboxConfig":
        """Builds the configuration from environment variables only.

        Args:
            environ: Environment map; default ``os.environ``.

        Returns:
            Validated configuration (defaults when no variable exists).

        Raises:
            ConfigError: Variable present with an invalid value.
        """
        source = os.environ if environ is None else environ
        values: Dict[str, Any] = {}
        for field_name, variable in cls.ENV_NAMES.items():
            if variable in source and str(source[variable]).strip() != "":
                values[field_name] = source[variable]
        return cls.from_dict(values)

    @classmethod
    def load(
        cls,
        path: Optional[str] = None,
        *,
        environ: Optional[Mapping[str, str]] = None,
        start: Optional[str] = None,
    ) -> "SandboxConfig":
        """Loads the complete configuration (file + environment).

        Without ``path``, it searches for a file with :meth:`find_file`. The
        environment variables override the file, and the result is validated.

        Args:
            path: Explicit configuration file.
            environ: Environment map used in the override.
            start: Initial directory of the automatic search.

        Returns:
            Validated configuration.

        Raises:
            ConfigError: Indicated file missing or invalid content.
        """
        source = os.environ if environ is None else environ
        chosen = path or source.get(CONFIG_ENV_VAR)
        base = cls()
        if chosen:
            if not os.path.isfile(chosen):
                raise ConfigError("configuration not found: %s" % chosen, path=chosen)
            base = cls.from_file(chosen)
        else:
            found = cls.find_file(start)
            if found:
                base = cls.from_file(found)
        from_environment = cls.from_env(source)
        return base.merged(**cls._only_set(from_environment, source))

    @staticmethod
    def _only_set(config: "SandboxConfig", environ: Mapping[str, str]) -> Dict[str, Any]:
        """Finds out which fields really came from the environment.

        Returns:
            Dictionary with only the fields whose variable is defined.
        """
        return {
            field_name: getattr(config, field_name)
            for field_name, variable in SandboxConfig.ENV_NAMES.items()
            if variable in environ and str(environ[variable]).strip() != ""
        }

    def merged(self, **overrides: Any) -> "SandboxConfig":
        """Returns a copy with swapped fields.

        Args:
            **overrides: Fields to replace (``None`` is ignored).

        Returns:
            New validated configuration.

        Raises:
            ConfigError: Unknown field or invalid value.

        Example:
            >>> SandboxConfig().merged(timeout=3).timeout
            3.0
        """
        cleaned = {key: value for key, value in overrides.items() if value is not None}
        unknown = [key for key in cleaned if key not in self.FIELD_NAMES]
        if unknown:
            raise ConfigError("unknown field: %s" % unknown[0], field=unknown[0])
        return replace(self, **cleaned).validate()

    def save(self, path: str, *, fmt: Optional[str] = None) -> str:
        """Writes the configuration to disk.

        Args:
            path: Destination file.
            fmt: ``"json"`` or ``"yaml"``; by default the extension decides.

        Returns:
            The path that was written.

        Raises:
            ConfigError: Unknown format, PyYAML missing or I/O failure.
        """
        fmt_name = (fmt or os.path.splitext(path)[1].lstrip(".") or "json").lower()
        if fmt_name in ("yml", "yaml"):
            try:
                import yaml
            except ImportError as error:
                raise ConfigError(
                    "to write YAML install PyYAML; use .json as an alternative", path=path
                ) from error
            content = yaml.safe_dump(self.to_dict(), allow_unicode=True, sort_keys=False)
        elif fmt_name == "json":
            content = json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n"
        else:
            raise ConfigError("unsupported configuration format: %s" % fmt_name, path=path)
        try:
            with open(path, "w", encoding="utf-8") as file:
                file.write(content)
        except OSError as error:
            raise ConfigError("could not write %s: %s" % (path, error), path=path) from error
        return path

    # -------------------------------------------------------------- extra --
    def apply_logging(self, stream: Any = None, *, force: bool = True) -> LoggingState:
        """Applies the log fields of this configuration to the application logging.

        Args:
            stream: Output stream (default ``sys.stderr``); useful in tests.
            force: Reconfigures even when a configuration is already applied.

        Returns:
            The resulting :class:`~asmx.logging_setup.LoggingState`.
        """
        return configure_logging(
            self.log_level,
            json_output=self.log_json,
            log_file=self.log_file,
            stream=stream,
            force=force,
        )

    def __repr__(self) -> str:
        """Short representation with the fields that matter in a run.

        Returns:
            Text such as ``SandboxConfig(timeout=30s · ...)``.
        """
        return "SandboxConfig(%s)" % self.describe()

    def field_names(self) -> Tuple[str, ...]:
        """Lists the fields in the order of :data:`FIELD_NAMES`.

        Returns:
            Tuple with the names of the fields.

        Example:
            >>> len(SandboxConfig().field_names())
            10
        """
        return tuple(f.name for f in fields(self))
