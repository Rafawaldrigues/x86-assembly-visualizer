"""Configuração do ASM X: um dataclass, arquivo opcional e variáveis de ambiente.

A ordem de precedência é sempre a mesma, do mais específico para o mais geral:

1. argumento explícito (``--timeout 5`` na linha de comando);
2. variáveis de ambiente (``ASMX_TIMEOUT=5``);
3. arquivo de configuração (``asmx.yaml``, ``asmx.json`` ou ``--config``);
4. padrões do :class:`SandboxConfig`.

YAML é opcional de propósito: o ASM X não tem dependência obrigatória, então
``from_yaml_file`` só funciona se o PyYAML estiver instalado. JSON usa só a
biblioteca padrão e sempre funciona.

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

#: Variável de ambiente que aponta para o arquivo de configuração.
CONFIG_ENV_VAR = "ASMX_CONFIG"

#: Nomes procurados no diretório atual, nesta ordem.
CANDIDATE_NAMES: Tuple[str, ...] = (
    "asmx.yaml",
    "asmx.yml",
    "asmx.json",
    ".asmx.yaml",
    ".asmx.json",
)

#: Diretórios do usuário procurados depois do diretório atual.
USER_DIRS: Tuple[str, ...] = ("~/.config/asmx", "~/.asmx")

#: Extensões reconhecidas por :meth:`SandboxConfig.from_file`.
YAML_SUFFIXES = (".yaml", ".yml")

#: Menor memória aceita, em MB.
MIN_MEMORY_MB = 16


def _as_bool(value: Any) -> bool:
    """Converte valores de arquivo/ambiente em booleano.

    Args:
        value: Valor bruto (``True``, ``"sim"``, ``"0"``, ``1``...).

    Returns:
        O booleano correspondente, usando as mesmas palavras de
        :func:`asmx.logging_setup.env_flag`.

    Raises:
        ConfigError: Quando o texto não é um booleano reconhecido.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    texto = str(value).strip().lower()
    if texto in ("1", "true", "yes", "on", "sim"):
        return True
    if texto in ("0", "false", "no", "off", "", "nao", "não"):
        return False
    raise ConfigError("valor booleano inválido: %r (use true/false)" % (value,))


def _as_float(value: Any, field_name: str) -> float:
    """Converte para ``float`` explicando o campo em caso de erro.

    Returns:
        O valor convertido.

    Raises:
        ConfigError: Quando o texto não é um número.
    """
    try:
        return float(value)
    except (TypeError, ValueError) as erro:
        raise ConfigError(
            "o campo %s precisa ser um número (recebi %r)" % (field_name, value), field=field_name
        ) from erro


def _as_int(value: Any, field_name: str) -> int:
    """Converte para ``int`` explicando o campo em caso de erro.

    Returns:
        O valor convertido, aceitando hexadecimal e octal.

    Raises:
        ConfigError: Quando o texto não é um inteiro.
    """
    try:
        return int(str(value).strip(), 0)
    except (TypeError, ValueError) as erro:
        raise ConfigError(
            "o campo %s precisa ser um inteiro (recebi %r)" % (field_name, value), field=field_name
        ) from erro


@dataclass
class SandboxConfig:
    """Parâmetros que controlam análise e execução.

    Attributes:
        timeout: Tempo máximo de parede, em segundos, para uma execução.
        max_steps: Limite de instruções por execução (protege de laço infinito).
        max_memory: Memória reservada ao sandbox, em MB (informativo).
        enable_network: Reservado para integrações externas; a máquina virtual
            do ASM X nunca acessa a rede.
        log_level: ``DEBUG``, ``INFO``, ``WARNING``, ``ERROR`` ou ``CRITICAL``.
        log_json: Emite o log em JSON (uma linha por evento).
        log_file: Arquivo que recebe a cópia dos logs.
        workers: Processos paralelos usados em análise de vários arquivos.
        output_dir: Diretório onde os relatórios são gravados.
        strict: Transforma problema detectado em exceção, em vez de aviso.
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

    #: Nomes dos campos, na ordem em que aparecem nos relatórios.
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

    #: Variáveis de ambiente reconhecidas, por campo.
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
        """Normaliza tipos e caixa do nível de log depois da construção."""
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

    # ----------------------------------------------------------- validação -
    def validate(self) -> "SandboxConfig":
        """Confere as faixas de cada campo.

        Returns:
            O próprio objeto, para encadear chamadas.

        Raises:
            ConfigError: No primeiro campo fora da faixa, com o nome do campo
                em ``context["field"]``.

        Example:
            >>> SandboxConfig(timeout=1).validate().timeout
            1.0
        """
        if not 0 < self.timeout <= 86_400:
            raise ConfigError(
                "timeout precisa ficar entre 0 e 86400 segundos (recebi %g)" % self.timeout,
                field="timeout",
            )
        if self.max_steps < 1:
            raise ConfigError(
                "max_steps precisa ser pelo menos 1 (recebi %d)" % self.max_steps, field="max_steps"
            )
        if self.max_memory < MIN_MEMORY_MB:
            raise ConfigError(
                "max_memory precisa ser pelo menos %d MB (recebi %d)"
                % (MIN_MEMORY_MB, self.max_memory),
                field="max_memory",
            )
        if self.log_level not in LOG_LEVELS:
            raise ConfigError(
                "log_level desconhecido: %s (use %s)" % (self.log_level, ", ".join(LOG_LEVELS)),
                field="log_level",
            )
        if not 1 <= self.workers <= 256:
            raise ConfigError(
                "workers precisa ficar entre 1 e 256 (recebi %d)" % self.workers, field="workers"
            )
        if not self.output_dir.strip():
            raise ConfigError("output_dir não pode ficar vazio", field="output_dir")
        return self

    # -------------------------------------------------------- serialização -
    def to_dict(self) -> Dict[str, Any]:
        """Converte a configuração em dicionário.

        Returns:
            Dicionário com todos os :data:`FIELD_NAMES` em tipos simples.
        """
        return {nome: getattr(self, nome) for nome in self.FIELD_NAMES}

    def describe(self) -> str:
        """Resume a configuração em uma linha legível.

        Returns:
            Texto com os campos que mudam o comportamento da execução.

        Example:
            >>> SandboxConfig(timeout=2, max_steps=10).describe()
            'timeout=2s · max_steps=10 · memória=512MB · rede=desligada · log=INFO · workers=4'
        """
        return "timeout=%gs · max_steps=%d · memória=%dMB · rede=%s · log=%s · workers=%d" % (
            self.timeout,
            self.max_steps,
            self.max_memory,
            "ligada" if self.enable_network else "desligada",
            self.log_level,
            self.workers,
        )

    @classmethod
    def from_dict(
        cls, data: Optional[Mapping[str, Any]] = None, *, path: Optional[str] = None
    ) -> "SandboxConfig":
        """Cria a configuração a partir de um mapeamento.

        Args:
            data: Campos a sobrepor aos padrões. ``None`` equivale a ``{}``.
            path: Arquivo de origem, usado nas mensagens de erro.

        Returns:
            Configuração validada.

        Raises:
            ConfigError: Se houver campo desconhecido (com sugestão do nome
                parecido) ou valor fora da faixa.

        Example:
            >>> SandboxConfig.from_dict({"workers": "2"}).workers
            2
        """
        valores: Dict[str, Any] = dict(data or {})
        conhecidos = set(cls.FIELD_NAMES)
        desconhecidos = [chave for chave in valores if chave not in conhecidos]
        if desconhecidos:
            chave = desconhecidos[0]
            parecidos = difflib.get_close_matches(chave, sorted(conhecidos), n=1)
            dica = " (você quis dizer %s?)" % parecidos[0] if parecidos else ""
            origem = " em %s" % path if path else ""
            raise ConfigError(
                "campo desconhecido%s: %s%s" % (origem, chave, dica), path=path, field=chave
            )
        try:
            config = cls(**valores)
        except TypeError as erro:
            raise ConfigError(
                "configuração inválida%s: %s" % (" em %s" % path if path else "", erro), path=path
            ) from erro
        return config.validate()

    # ------------------------------------------------------------- arquivos -
    @classmethod
    def from_json_file(cls, path: str) -> "SandboxConfig":
        """Lê a configuração de um arquivo JSON.

        Args:
            path: Caminho do ``.json``.

        Returns:
            Configuração validada.

        Raises:
            ConfigError: Arquivo ausente, JSON inválido ou campo desconhecido.
        """
        try:
            with open(path, encoding="utf-8") as arquivo:
                dados = json.load(arquivo)
        except OSError as erro:
            raise ConfigError(
                "não consegui abrir a configuração %s: %s" % (path, erro), path=path
            ) from erro
        except json.JSONDecodeError as erro:
            raise ConfigError(
                "JSON inválido em %s (linha %d, coluna %d): %s"
                % (path, erro.lineno, erro.colno, erro.msg),
                path=path,
            ) from erro
        if not isinstance(dados, dict):
            raise ConfigError("a configuração em %s precisa ser um objeto JSON" % path, path=path)
        return cls.from_dict(dados, path=path)

    @classmethod
    def from_yaml_file(cls, path: str) -> "SandboxConfig":
        """Lê a configuração de um arquivo YAML (exige PyYAML instalado).

        Args:
            path: Caminho do ``.yaml`` ou ``.yml``.

        Returns:
            Configuração validada.

        Raises:
            ConfigError: PyYAML ausente, arquivo ilegível ou conteúdo inválido.
        """
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError as erro:
            raise ConfigError(
                "para ler %s instale o PyYAML (pip install pyyaml) ou use um "
                "arquivo .json, que não precisa de dependência" % path,
                path=path,
            ) from erro
        try:
            with open(path, encoding="utf-8") as arquivo:
                dados = yaml.safe_load(arquivo)
        except OSError as erro:
            raise ConfigError(
                "não consegui abrir a configuração %s: %s" % (path, erro), path=path
            ) from erro
        except yaml.YAMLError as erro:
            raise ConfigError("YAML inválido em %s: %s" % (path, erro), path=path) from erro
        if dados is None:
            dados = {}
        if not isinstance(dados, dict):
            raise ConfigError("a configuração em %s precisa ser um mapa YAML" % path, path=path)
        return cls.from_dict(dados, path=path)

    @classmethod
    def from_file(cls, path: str) -> "SandboxConfig":
        """Lê a configuração escolhendo o formato pela extensão.

        Args:
            path: ``.json``, ``.yaml`` ou ``.yml``.

        Returns:
            Configuração validada.

        Raises:
            ConfigError: Extensão não reconhecida ou conteúdo inválido.

        Example:
            >>> SandboxConfig.from_file("nao_existe.json")   # doctest: +SKIP
        """
        extensao = os.path.splitext(path)[1].lower()
        if extensao in YAML_SUFFIXES:
            return cls.from_yaml_file(path)
        if extensao == ".json":
            return cls.from_json_file(path)
        raise ConfigError(
            "extensão de configuração não reconhecida: %s (use .json, .yaml ou .yml)"
            % (extensao or path),
            path=path,
        )

    @classmethod
    def find_file(cls, start: Optional[str] = None) -> Optional[str]:
        """Procura um arquivo de configuração nos lugares convencionais.

        Olha primeiro ``$ASMX_CONFIG``, depois :data:`CANDIDATE_NAMES` no
        diretório ``start`` (padrão: diretório atual) e por fim
        ``config.yaml``/``config.json`` dentro de :data:`USER_DIRS`.

        Args:
            start: Diretório inicial da busca.

        Returns:
            Caminho do primeiro arquivo encontrado, ou ``None``.
        """
        apontado = os.environ.get(CONFIG_ENV_VAR)
        if apontado and os.path.isfile(apontado):
            return apontado
        base = os.path.abspath(os.path.expanduser(start or os.getcwd()))
        candidatos = [os.path.join(base, nome) for nome in CANDIDATE_NAMES]
        for pasta in USER_DIRS:
            raiz = os.path.expanduser(pasta)
            candidatos += [os.path.join(raiz, nome) for nome in CANDIDATE_NAMES]
            candidatos += [os.path.join(raiz, "config.yaml"), os.path.join(raiz, "config.json")]
        for caminho in candidatos:
            if os.path.isfile(caminho):
                return caminho
        return None

    # ------------------------------------------------------------ ambiente -
    @classmethod
    def from_env(cls, environ: Optional[Mapping[str, str]] = None) -> "SandboxConfig":
        """Monta a configuração só com variáveis de ambiente.

        Args:
            environ: Mapa de ambiente; padrão ``os.environ``.

        Returns:
            Configuração validada (padrões quando nenhuma variável existe).

        Raises:
            ConfigError: Variável presente com valor inválido.
        """
        fonte = os.environ if environ is None else environ
        valores: Dict[str, Any] = {}
        for campo, variavel in cls.ENV_NAMES.items():
            if variavel in fonte and str(fonte[variavel]).strip() != "":
                valores[campo] = fonte[variavel]
        return cls.from_dict(valores)

    @classmethod
    def load(
        cls,
        path: Optional[str] = None,
        *,
        environ: Optional[Mapping[str, str]] = None,
        start: Optional[str] = None,
    ) -> "SandboxConfig":
        """Carrega a configuração completa (arquivo + ambiente).

        Sem ``path``, procura um arquivo com :meth:`find_file`. As variáveis de
        ambiente sobrepõem o arquivo, e o resultado é validado.

        Args:
            path: Arquivo explícito de configuração.
            environ: Mapa de ambiente usado na sobreposição.
            start: Diretório inicial da busca automática.

        Returns:
            Configuração validada.

        Raises:
            ConfigError: Arquivo indicado inexistente ou conteúdo inválido.
        """
        fonte = os.environ if environ is None else environ
        escolhido = path or fonte.get(CONFIG_ENV_VAR)
        base = cls()
        if escolhido:
            if not os.path.isfile(escolhido):
                raise ConfigError("configuração não encontrada: %s" % escolhido, path=escolhido)
            base = cls.from_file(escolhido)
        else:
            encontrado = cls.find_file(start)
            if encontrado:
                base = cls.from_file(encontrado)
        do_ambiente = cls.from_env(fonte)
        return base.merged(**cls._only_set(do_ambiente, fonte))

    @staticmethod
    def _only_set(config: "SandboxConfig", environ: Mapping[str, str]) -> Dict[str, Any]:
        """Descobre quais campos vieram mesmo do ambiente.

        Returns:
            Dicionário apenas com os campos cuja variável está definida.
        """
        return {
            campo: getattr(config, campo)
            for campo, variavel in SandboxConfig.ENV_NAMES.items()
            if variavel in environ and str(environ[variavel]).strip() != ""
        }

    def merged(self, **overrides: Any) -> "SandboxConfig":
        """Devolve uma cópia com campos trocados.

        Args:
            **overrides: Campos a substituir (``None`` é ignorado).

        Returns:
            Nova configuração validada.

        Raises:
            ConfigError: Campo desconhecido ou valor inválido.

        Example:
            >>> SandboxConfig().merged(timeout=3).timeout
            3.0
        """
        limpos = {chave: valor for chave, valor in overrides.items() if valor is not None}
        desconhecidos = [chave for chave in limpos if chave not in self.FIELD_NAMES]
        if desconhecidos:
            raise ConfigError("campo desconhecido: %s" % desconhecidos[0], field=desconhecidos[0])
        return replace(self, **limpos).validate()

    def save(self, path: str, *, fmt: Optional[str] = None) -> str:
        """Grava a configuração em disco.

        Args:
            path: Arquivo de destino.
            fmt: ``"json"`` ou ``"yaml"``; por padrão a extensão decide.

        Returns:
            O caminho gravado.

        Raises:
            ConfigError: Formato desconhecido, PyYAML ausente ou falha de I/O.
        """
        formato = (fmt or os.path.splitext(path)[1].lstrip(".") or "json").lower()
        if formato in ("yml", "yaml"):
            try:
                import yaml
            except ImportError as erro:
                raise ConfigError(
                    "para gravar YAML instale o PyYAML; use .json como alternativa", path=path
                ) from erro
            conteudo = yaml.safe_dump(self.to_dict(), allow_unicode=True, sort_keys=False)
        elif formato == "json":
            conteudo = json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n"
        else:
            raise ConfigError("formato de configuração não suportado: %s" % formato, path=path)
        try:
            with open(path, "w", encoding="utf-8") as arquivo:
                arquivo.write(conteudo)
        except OSError as erro:
            raise ConfigError("não consegui gravar %s: %s" % (path, erro), path=path) from erro
        return path

    # --------------------------------------------------------------- extra -
    def apply_logging(self, stream: Any = None, *, force: bool = True) -> LoggingState:
        """Aplica os campos de log desta configuração ao logging da aplicação.

        Args:
            stream: Fluxo de saída (padrão ``sys.stderr``); útil nos testes.
            force: Reconfigura mesmo que já exista configuração aplicada.

        Returns:
            O :class:`~asmx.logging_setup.LoggingState` resultante.
        """
        return configure_logging(
            self.log_level,
            json_output=self.log_json,
            log_file=self.log_file,
            stream=stream,
            force=force,
        )

    def __repr__(self) -> str:
        """Representação curta com os campos que importam na execução.

        Returns:
            Texto como ``SandboxConfig(timeout=30s · ...)``.
        """
        return "SandboxConfig(%s)" % self.describe()

    def field_names(self) -> Tuple[str, ...]:
        """Lista os campos na ordem de :data:`FIELD_NAMES`.

        Returns:
            Tupla com os nomes dos campos.

        Example:
            >>> len(SandboxConfig().field_names())
            10
        """
        return tuple(f.name for f in fields(self))
