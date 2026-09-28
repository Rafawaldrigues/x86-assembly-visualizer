"""Comportamentos: o que o programa faz, com mapeamento honesto para o ATT&CK.

Esta é a camada que responde "o que este programa faz?" a partir da
:class:`~asmx.analyzer.Analysis`: cada :class:`Behavior` reúne evidências
concretas (linha + mnemônico, syscall ou API) e, quando existe sinal de
verdade, um ou mais identificadores do MITRE ATT&CK.

**Isto é indício, não veredito.** Toda detecção sai de padrões estáticos do
fonte — nomes de syscalls, APIs chamadas, texto das strings e o formato dos
laços — e nenhuma delas prova comportamento malicioso: um programa didático
que abre um arquivo e um coletor de dados usam exatamente a mesma chamada. O
mapeamento para o ATT&CK é uma pista para o analista, com a mesma ressalva, e
por isso toda descrição de técnica diz que se trata de indício derivado de
padrões estáticos, não de prova.

Regras de honestidade aplicadas aqui:

* todo comportamento tem pelo menos uma evidência que cita a linha e o
  mnemônico, a syscall ou a API observada;
* a confiança vem da quantidade de evidências (1-2 -> 60, 3-5 -> 80, 6+ -> 95)
  e indícios fracos (cifra caseira, espera ou medição de tempo em laço, avisos
  do validador) ficam limitados a 50;
* categoria sem sinal nenhum não aparece: é melhor uma lista vazia do que uma
  suspeita inventada;
* :func:`classify` nunca levanta exceção — um programa vazio devolve ``[]``.

Limitações conhecidas, para ninguém ler a saída como algo que ela não é:

* ``process`` exige execução, criação ou manipulação de processo de verdade;
  terminar o próprio programa (``ExitProcess``, ``exit``, ``exit_group``) não
  conta, porque todo programa termina — chamada externa só entra na categoria
  quando a função externa é de execução (``system``, ``execve``...);
* a detecção por syscall só enxerga os serviços presentes em
  :data:`asmx.isa.LINUX_SYSCALLS`; nomes como ``chmod``, ``clone``,
  ``mremap`` ou ``clock_gettime`` não estão naquela tabela e por isso nunca
  disparam (a lista de cada categoria continua lá, para o dia em que a tabela
  crescer);
* ``string-handling`` também marca laços que carregam e descarregam memória
  por registrador indexado, porque é assim que se copia um bloco de bytes sem
  as instruções ``rep movs*`` — é um indício fraco e o texto diz isso;
* ``self-modifying`` só reconhece escrita cujo endereço é um rótulo de código
  declarado; o mesmo acesso feito por um ponteiro calculado antes não é
  rastreável estaticamente;
* nada é executado: quem quiser comportamento de verdade precisa da máquina
  virtual.

Example:
    >>> from asmx.analyzer import analyze
    >>> from asmx.behavior import classify, summary
    >>> fonte = "section .text\\n_start:\\n mov rax, 1\\n syscall"
    >>> summary(classify(analyze(fonte)))
    '1 comportamento(s): console (baixo)'
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from .analyzer import Analysis, Block, Line
from .isa import LINUX_SYSCALLS, WIN_APIS
from .linter import Problem, validate
from .logging_setup import get_logger
from .parser import Operand

logger = get_logger(__name__)

# ---------------------------------------------------------------- catálogo --

#: Categorias de comportamento: chave -> rótulo, descrição e gravidade.
BEHAVIOR_CATEGORIES: Dict[str, Dict[str, str]] = {
    "console-io": {
        "label": "Entrada e saída de console",
        "description": "Lê ou escreve texto no console: write/read no Linux, "
        "GetStdHandle/WriteConsoleA/ReadConsoleA/MessageBoxA no Windows.",
        "severity": "baixo",
    },
    "network": {
        "label": "Comunicação de rede",
        "description": "Abre sockets, conecta, escuta ou usa APIs de rede "
        "(WinINet/WinHTTP) e carrega strings com cara de host, IP ou URL.",
        "severity": "alto",
    },
    "filesystem": {
        "label": "Acesso a arquivos",
        "description": "Abre, cria, apaga ou renomeia arquivos e cita caminhos "
        "do sistema (/etc/, /tmp/, C:\\).",
        "severity": "medio",
    },
    "process": {
        "label": "Manipulação de processos",
        "description": "Executa ou cria processos, envia sinais, depura com "
        "ptrace ou chama função de execução (system, execve, CreateProcessA).",
        "severity": "alto",
    },
    "memory": {
        "label": "Manipulação de memória",
        "description": "Mapeia ou protege regiões de memória (mmap, mprotect, "
        "VirtualAlloc) e escreve em endereço calculado em tempo de execução.",
        "severity": "medio",
    },
    "anti-analysis": {
        "label": "Evasão de análise",
        "description": "Breakpoint (int 3), identificação da máquina "
        "(cpuid/rdtsc), ptrace e espera ou medição de tempo dentro de laço.",
        "severity": "alto",
    },
    "crypto": {
        "label": "Criptografia ou ofuscação",
        "description": "Pede bytes aleatórios ao kernel e laços com muitas "
        "operações de bits — indício de cifra caseira ou de ofuscação.",
        "severity": "medio",
    },
    "persistence": {
        "label": "Persistência",
        "description": "Cita inicialização automática (Run, RunOnce, cron, "
        "systemd, .bashrc) ou repete operação de arquivo dentro de laço.",
        "severity": "alto",
    },
    "environment": {
        "label": "Informações do sistema",
        "description": "Consulta PID, usuário, versão do sistema, módulo "
        "carregado ou último erro da API.",
        "severity": "baixo",
    },
    "data-processing": {
        "label": "Processamento de dados",
        "description": "Laços que só mexem em registradores e memória, sem "
        "chamada externa: é o algoritmo do programa (soma, ordenação, "
        "conversão).",
        "severity": "baixo",
    },
    "string-handling": {
        "label": "Manipulação de blocos de bytes",
        "description": "Copia, preenche ou compara regiões de memória "
        "(rep movs*/stos*/lods*/scas*) ou movimenta bytes indexados em laço.",
        "severity": "baixo",
    },
    "self-modifying": {
        "label": "Código automodificável",
        "description": "Escreve em endereço que pertence a um rótulo de "
        "código: o programa altera as próprias instruções.",
        "severity": "alto",
    },
}

#: Técnicas do MITRE ATT&CK usadas pelo módulo: id -> ficha da técnica.
MITRE_TECHNIQUES: Dict[str, Dict[str, str]] = {
    "T1005": {
        "name": "Data from Local System",
        "tactic": "Coleta",
        "url": "https://attack.mitre.org/techniques/T1005/",
        "description": "Coleta de dados guardados na máquina local. Indício "
        "derivado de padrões estáticos, não prova de comportamento malicioso.",
    },
    "T1012": {
        "name": "Query Registry",
        "tactic": "Descoberta",
        "url": "https://attack.mitre.org/techniques/T1012/",
        "description": "Consulta ao Registro do Windows para descobrir "
        "configurações. Indício derivado de padrões estáticos, não prova de "
        "comportamento malicioso.",
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Evasão de Defesa",
        "url": "https://attack.mitre.org/techniques/T1027/",
        "description": "Dificulta a leitura do próprio código ou dos dados. "
        "Indício derivado de padrões estáticos, não prova de comportamento "
        "malicioso.",
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltração",
        "url": "https://attack.mitre.org/techniques/T1041/",
        "description": "Envio de dados para fora pelo canal de comando e "
        "controle. Indício derivado de padrões estáticos, não prova de "
        "comportamento malicioso.",
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "Evasão de Defesa",
        "url": "https://attack.mitre.org/techniques/T1055/",
        "description": "Injeção de código em outro processo, típica de quem "
        "aloca e protege memória executável. Indício derivado de padrões "
        "estáticos, não prova de comportamento malicioso.",
    },
    "T1057": {
        "name": "Process Discovery",
        "tactic": "Descoberta",
        "url": "https://attack.mitre.org/techniques/T1057/",
        "description": "Descoberta de processos e de identificadores em "
        "execução. Indício derivado de padrões estáticos, não prova de "
        "comportamento malicioso.",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execução",
        "url": "https://attack.mitre.org/techniques/T1059/",
        "description": "Execução de comandos ou de outro programa. Indício "
        "derivado de padrões estáticos, não prova de comportamento malicioso.",
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Comando e Controle",
        "url": "https://attack.mitre.org/techniques/T1071/",
        "description": "Comunicação por protocolo de aplicação (HTTP e "
        "afins). Indício derivado de padrões estáticos, não prova de "
        "comportamento malicioso.",
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Descoberta",
        "url": "https://attack.mitre.org/techniques/T1082/",
        "description": "Levantamento de versão, arquitetura e configuração do "
        "sistema. Indício derivado de padrões estáticos, não prova de "
        "comportamento malicioso.",
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "tactic": "Descoberta",
        "url": "https://attack.mitre.org/techniques/T1083/",
        "description": "Varredura de arquivos e diretórios de interesse. "
        "Indício derivado de padrões estáticos, não prova de comportamento "
        "malicioso.",
    },
    "T1095": {
        "name": "Non-Application Layer Protocol",
        "tactic": "Comando e Controle",
        "url": "https://attack.mitre.org/techniques/T1095/",
        "description": "Comunicação por protocolo cru, sem camada de "
        "aplicação. Indício derivado de padrões estáticos, não prova de "
        "comportamento malicioso.",
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Comando e Controle",
        "url": "https://attack.mitre.org/techniques/T1105/",
        "description": "Transferência de arquivo de fora para a máquina "
        "analisada. Indício derivado de padrões estáticos, não prova de "
        "comportamento malicioso.",
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impacto",
        "url": "https://attack.mitre.org/techniques/T1486/",
        "description": "Cifra de dados locais para prejudicar o dono. Indício "
        "derivado de padrões estáticos, não prova de comportamento malicioso.",
    },
    "T1497": {
        "name": "Virtualization/Sandbox Evasion",
        "tactic": "Evasão de Defesa",
        "url": "https://attack.mitre.org/techniques/T1497/",
        "description": "Detecção de máquina virtual, sandbox ou ambiente de "
        "análise. Indício derivado de padrões estáticos, não prova de "
        "comportamento malicioso.",
    },
    "T1543": {
        "name": "Create or Modify System Process",
        "tactic": "Persistência",
        "url": "https://attack.mitre.org/techniques/T1543/",
        "description": "Criação ou alteração de serviço do sistema para "
        "sobreviver ao reinício. Indício derivado de padrões estáticos, não "
        "prova de comportamento malicioso.",
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistência",
        "url": "https://attack.mitre.org/techniques/T1547/",
        "description": "Configuração de execução automática no boot ou no "
        "logon. Indício derivado de padrões estáticos, não prova de "
        "comportamento malicioso.",
    },
    "T1622": {
        "name": "Debugger Evasion",
        "tactic": "Evasão de Defesa",
        "url": "https://attack.mitre.org/techniques/T1622/",
        "description": "Detecção ou atrapalho de depurador. Indício derivado "
        "de padrões estáticos, não prova de comportamento malicioso.",
    },
}

#: Rótulo curto de cada categoria, usado por :func:`summary`.
_SHORT_LABELS: Dict[str, str] = {
    "console-io": "console",
    "network": "rede",
    "filesystem": "arquivos",
    "process": "processos",
    "memory": "memória",
    "anti-analysis": "anti-análise",
    "crypto": "criptografia",
    "persistence": "persistência",
    "environment": "ambiente",
    "data-processing": "processamento de dados",
    "string-handling": "blocos de bytes",
    "self-modifying": "código automodificável",
}

#: Gravidade -> posição na ordenação (menor vem primeiro).
_SEVERITY_RANK: Dict[str, int] = {"alto": 0, "medio": 1, "baixo": 2}

#: Táticas na ordem em que o relatório deve mostrá-las.
_TACTIC_ORDER: Tuple[str, ...] = (
    "Execução",
    "Comando e Controle",
    "Descoberta",
    "Evasão de Defesa",
    "Persistência",
    "Coleta",
    "Exfiltração",
    "Impacto",
)

#: Acentuação removida antes de comparar gravidades (``médio`` -> ``medio``).
_ACCENTS = str.maketrans("áàâãäéèêëíìîïóòôõöúùûüç", "aaaaaeeeeiiiiooooouuuuc")

#: Confiança máxima de um comportamento sustentado só por indício fraco.
_WEAK_CONFIDENCE = 50

#: Seções cujos rótulos contam como código.
_CODE_SECTIONS = frozenset({"text", "code"})

#: Registradores que ancoram variáveis locais, não blocos de memória.
_FRAME_REGS = frozenset({"rbp", "rsp", "rip"})

#: Operações de bits que contam para o indício de cifra caseira.
_BIT_OPS: Tuple[str, ...] = ("xor", "shl", "sal", "shr", "sar", "rol", "ror")

#: Quantas operações de bits no mesmo laço já sugerem cifra ou ofuscação.
_BIT_OPS_MIN = 3

#: Raízes dos mnemônicos que movem blocos de memória (movsb, stosq, lodsb...).
_STRING_STEMS: Tuple[str, ...] = ("movs", "stos", "lods", "scas", "cmps")

#: Avisos do validador que entram como indício fraco de evasão de análise.
_WEAK_PROBLEMS = frozenset({"INT001", "FLOW002"})

#: Nomes de syscall (conforme :data:`asmx.isa.LINUX_SYSCALLS`) por categoria.
_SYSCALLS_BY_CATEGORY: Dict[str, Tuple[str, ...]] = {
    "console-io": ("write", "read"),
    "network": (
        "socket",
        "connect",
        "bind",
        "listen",
        "accept",
        "sendto",
        "recvfrom",
        "setsockopt",
    ),
    "filesystem": ("open", "openat", "creat", "unlink", "rename", "mkdir", "chmod"),
    "process": ("execve", "fork", "clone", "kill", "ptrace"),
    # Em anti-analysis, só ptrace conta fora de laço; as syscalls de tempo e os
    # mnemônicos (int 3, cpuid, rdtsc) têm regras próprias.
    "anti-analysis": ("ptrace",),
    "memory": ("brk", "mmap", "mprotect", "mremap"),
    "crypto": ("getrandom", "getentropy"),
    "environment": ("getpid", "getuid", "uname", "sysinfo", "time"),
}

#: APIs do Windows (minúsculas) que caracterizam cada categoria.
_APIS_BY_CATEGORY: Dict[str, Tuple[str, ...]] = {
    "console-io": (
        "getstdhandle",
        "writeconsolea",
        "writeconsolew",
        "readconsolea",
        "readconsolew",
        "messageboxa",
        "messageboxw",
    ),
    "network": (
        "wsastartup",
        "wsasocketa",
        "internetopena",
        "internetopenw",
        "internetopenurla",
        "internetopenurlw",
        "winhttpopen",
        "urldownloadtofilea",
        "urldownloadtofilew",
    ),
    "filesystem": (
        "createfilea",
        "createfilew",
        "writefile",
        "deletefilea",
        "deletefilew",
        "gettemppatha",
        "gettempathw",
    ),
    "process": (
        "createprocessa",
        "createprocessw",
        "shellexecutea",
        "shellexecutew",
        "winexec",
    ),
    "memory": ("virtualalloc", "virtualprotect", "heapalloc", "rtlmovememory"),
    "environment": ("getlasterror", "getmodulehandlea", "getmodulehandlew", "getversion"),
    "persistence": (
        "regopenkeyexa",
        "regqueryvalueexa",
        "regsetvalueexa",
        "regcreatekeyexa",
        "regcreatekeyw",
    ),
}

#: Texto curto de algumas syscalls, mais específico que a descrição do acervo.
_SYSCALL_HINTS: Dict[str, str] = {
    "write": "saída para console ou arquivo",
    "read": "entrada de console ou arquivo",
}

#: Técnicas sugeridas por cada syscall, quando existe sinal de verdade.
_SYSCALL_MITRE: Dict[str, Tuple[str, ...]] = {
    "socket": ("T1095",),
    "connect": ("T1095",),
    "bind": ("T1095",),
    "listen": ("T1095",),
    "accept": ("T1095",),
    "sendto": ("T1095",),
    "recvfrom": ("T1095",),
    "setsockopt": ("T1095",),
    "open": ("T1005",),
    "openat": ("T1005",),
    "creat": ("T1005",),
    "execve": ("T1059",),
    "fork": ("T1059",),
    "clone": ("T1059",),
    "ptrace": ("T1622", "T1055"),
    "mprotect": ("T1055",),
    "getpid": ("T1057",),
    "getuid": ("T1082",),
    "uname": ("T1082",),
    "sysinfo": ("T1082",),
    "time": ("T1082",),
}

#: Descrição curta das APIs que não estão no acervo :data:`asmx.isa.WIN_APIS`.
_API_HINTS: Dict[str, str] = {
    "writeconsolew": "escreve no console (Unicode)",
    "readconsolew": "lê do console (Unicode)",
    "wsastartup": "inicializa a biblioteca de sockets do Windows",
    "wsasocketa": "cria socket pela Winsock",
    "internetopena": "abre uma sessão WinINet",
    "internetopenw": "abre uma sessão WinINet",
    "internetopenurla": "abre uma URL pela WinINet",
    "internetopenurlw": "abre uma URL pela WinINet",
    "winhttpopen": "abre uma sessão WinHTTP",
    "urldownloadtofilea": "baixa um arquivo de uma URL",
    "urldownloadtofilew": "baixa um arquivo de uma URL",
    "createfilew": "abre ou cria arquivo (Unicode)",
    "deletefilea": "apaga arquivo",
    "deletefilew": "apaga arquivo (Unicode)",
    "gettemppatha": "descobre a pasta temporária",
    "gettempathw": "descobre a pasta temporária (Unicode)",
    "createprocessw": "cria um processo (Unicode)",
    "shellexecutea": "abre programa ou documento pelo shell",
    "shellexecutew": "abre programa ou documento pelo shell (Unicode)",
    "winexec": "executa um programa",
    "getmodulehandlew": "handle do módulo carregado (Unicode)",
    "getversion": "versão do Windows",
    "heapalloc": "reserva memória no heap do processo",
    "rtlmovememory": "copia bytes na memória do processo",
    "regopenkeyexa": "abre uma chave do Registro",
    "regqueryvalueexa": "lê um valor do Registro",
    "regsetvalueexa": "grava um valor no Registro",
    "regcreatekeyexa": "cria uma chave do Registro",
    "regcreatekeyw": "cria uma chave do Registro (Unicode)",
}

#: Técnicas sugeridas por cada API, quando existe sinal de verdade.
_API_MITRE: Dict[str, Tuple[str, ...]] = {
    "wsastartup": ("T1095",),
    "wsasocketa": ("T1095",),
    "internetopena": ("T1071",),
    "internetopenw": ("T1071",),
    "internetopenurla": ("T1105", "T1071"),
    "internetopenurlw": ("T1105", "T1071"),
    "winhttpopen": ("T1071",),
    "urldownloadtofilea": ("T1105", "T1071"),
    "urldownloadtofilew": ("T1105", "T1071"),
    "createfilea": ("T1005",),
    "createfilew": ("T1005",),
    "createprocessa": ("T1059",),
    "createprocessw": ("T1059",),
    "shellexecutea": ("T1059",),
    "shellexecutew": ("T1059",),
    "winexec": ("T1059",),
    "virtualalloc": ("T1055",),
    "virtualprotect": ("T1055",),
    "rtlmovememory": ("T1055",),
    "getlasterror": ("T1082",),
    "getmodulehandlea": ("T1082",),
    "getmodulehandlew": ("T1082",),
    "getversion": ("T1082",),
    "regopenkeyexa": ("T1012",),
    "regqueryvalueexa": ("T1012",),
    "regsetvalueexa": ("T1547",),
    "regcreatekeyexa": ("T1547",),
    "regcreatekeyw": ("T1547",),
}

#: Syscalls de tempo ou espera: só viram indício dentro de um laço.
_LOOP_TIME_SYSCALLS: Tuple[str, ...] = ("nanosleep", "clock_gettime", "time", "gettimeofday")

#: Funções externas de execução (libc), que contam como ``process``.
_EXEC_NAMES: frozenset = frozenset(
    {
        "system",
        "popen",
        "execl",
        "execle",
        "execlp",
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "fexecve",
        "posix_spawn",
        "posix_spawnp",
        "fork",
        "vfork",
    }
)

#: IP no formato decimal, como aparece em strings de configuração.
_RE_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

#: URL completa com esquema HTTP ou HTTPS.
_RE_URL = re.compile(r"https?://[^\s\"']+", re.I)

#: Domínio com TLD conhecido (evita casar com ``.text`` ou ``nome.asm``).
_TLDS: Tuple[str, ...] = (
    "com",
    "net",
    "org",
    "edu",
    "gov",
    "int",
    "mil",
    "br",
    "pt",
    "us",
    "uk",
    "de",
    "fr",
    "it",
    "nl",
    "se",
    "ch",
    "es",
    "ru",
    "cn",
    "jp",
    "au",
    "ca",
    "io",
    "dev",
    "info",
    "biz",
    "xyz",
    "online",
    "site",
    "top",
    "onion",
)
_RE_DOMAIN = re.compile(
    r"\b[a-z0-9][a-z0-9-]{0,62}(?:\.[a-z0-9-]{1,63})*\.(?:%s)\b" % "|".join(_TLDS), re.I
)

#: Caminho de diretório típico de Unix, escrito no fonte.
_RE_UNIX_PATH = re.compile(r"/(?:etc|tmp|var|usr|home|root|proc|dev|opt|bin|sbin|boot|srv|sys)/")

#: Caminho no estilo Windows (``C:\``) ou UNC (``\\servidor\``).
_RE_WIN_PATH = re.compile(r"[A-Za-z]:\\|\\\\[A-Za-z0-9_.-]+\\")

#: Strings de execução automática no logon ou no boot.
_RE_AUTOSTART = re.compile(r"runonce|currentversion\\run|\brun\\|\.bashrc", re.I)

#: Strings de serviço, tarefa agendada ou inicialização do sistema.
_RE_SERVICE = re.compile(r"\bcron|systemd|\bservices\b", re.I)

#: Diretório de configuração do sistema: persistência possível, sem técnica
#: própria, porque ``/etc/passwd`` e ``/etc/cron.d`` não são a mesma coisa.
_RE_SYSCONF = re.compile(r"/etc/", re.I)


def _invert(table: Dict[str, Tuple[str, ...]]) -> Dict[str, Tuple[str, ...]]:
    """Inverte um mapa ``chave -> nomes`` em ``nome -> chaves``.

    Args:
        table: Mapa cujos valores são sequências de nomes.

    Returns:
        Mapa de cada nome para as chaves onde ele aparece, na ordem original.
    """
    out: Dict[str, List[str]] = {}
    for key, names in table.items():
        for name in names:
            out.setdefault(name, []).append(key)
    return {name: tuple(keys) for name, keys in out.items()}


#: Syscall -> categorias a que ela pertence.
_SYSCALL_CATEGORIES: Dict[str, Tuple[str, ...]] = _invert(_SYSCALLS_BY_CATEGORY)

#: API -> categorias a que ela pertence.
_API_CATEGORIES: Dict[str, Tuple[str, ...]] = _invert(_APIS_BY_CATEGORY)

#: Número da syscall -> nome, montado a partir do acervo (nada escrito à mão).
_SYSCALL_NAMES_BY_NUMBER: Dict[int, str] = {
    number: data[0] for number, data in LINUX_SYSCALLS.items() if data
}

#: Nome da syscall -> descrição do acervo.
_SYSCALL_DOC: Dict[str, str] = {
    data[0]: data[1] for data in LINUX_SYSCALLS.values() if len(data) > 1
}


# ------------------------------------------------------------------ modelo --
@dataclass(frozen=True)
class Behavior:
    """Um comportamento observado no programa, com as evidências que o sustentam.

    Attributes:
        category: Chave de :data:`BEHAVIOR_CATEGORIES`.
        label: Rótulo legível da categoria.
        description: O que a categoria significa em uma frase.
        severity: ``alto``, ``medio`` ou ``baixo``.
        confidence: Confiança de 0 a 100, derivada da quantidade de evidências.
        lines: Linhas de evidência, em ordem crescente e sem repetição.
        evidence: Frases curtas em pt-BR, cada uma citando linha e sinal.
        mitre: Identificadores presentes em :data:`MITRE_TECHNIQUES`.
    """

    category: str
    label: str
    description: str
    severity: str
    confidence: int
    lines: Tuple[int, ...]
    evidence: Tuple[str, ...]
    mitre: Tuple[str, ...]

    def to_dict(self) -> Dict[str, Any]:
        """Converte o comportamento em dicionário pronto para JSON.

        Returns:
            Dicionário com ``category``, ``label``, ``description``,
            ``severity``, ``confidence``, ``lines``, ``evidence`` e ``mitre``,
            com as sequências já convertidas em listas.
        """
        return {
            "category": self.category,
            "label": self.label,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "lines": list(self.lines),
            "evidence": list(self.evidence),
            "mitre": list(self.mitre),
        }


@dataclass
class _Evidence:
    """Uma evidência isolada, com o sinal que a gerou.

    Attributes:
        line: Linha do fonte onde o padrão foi visto.
        text: Frase pronta em pt-BR, já começando por ``linha N:``.
        signal: Nome curto do sinal (``syscall socket``, ``API WriteFile``),
            usado nas evidências de combinação.
        weak: Se é indício fraco (limita a confiança do comportamento a 50).
        mitre: Técnicas sugeridas por esta evidência.
    """

    line: int
    text: str
    signal: str
    weak: bool = False
    mitre: Tuple[str, ...] = ()


class _Collector:
    """Junta evidências por categoria e monta os comportamentos.

    Attributes:
        items: Categoria -> evidências, na ordem em que foram encontradas.
    """

    def __init__(self) -> None:
        """Cria um coletor vazio."""
        self.items: Dict[str, List[_Evidence]] = {}

    def add(
        self,
        category: str,
        line: int,
        text: str,
        signal: str,
        weak: bool = False,
        mitre: Sequence[str] = (),
    ) -> None:
        """Registra uma evidência, ignorando categoria ou texto inválidos.

        Args:
            category: Chave de :data:`BEHAVIOR_CATEGORIES`.
            line: Linha do fonte da evidência.
            text: Frase pronta, começando por ``linha N:``.
            signal: Nome curto do sinal, para as combinações.
            weak: Marca a evidência como indício fraco.
            mitre: Técnicas sugeridas por esta evidência.
        """
        if category not in BEHAVIOR_CATEGORIES or not text:
            return
        self.items.setdefault(category, []).append(
            _Evidence(line=line, text=text, signal=signal, weak=weak, mitre=tuple(mitre))
        )

    def mark(self, category: str, mitre: str, text: str, signal: str) -> None:
        """Acrescenta uma evidência de combinação a uma categoria já existente.

        Args:
            category: Categoria que já tem pelo menos uma evidência.
            mitre: Técnica acrescentada pela combinação.
            text: Frase da evidência de combinação.
            signal: Nome curto do sinal combinado.
        """
        found = self.items.get(category)
        if not found:
            return
        found.append(_Evidence(line=found[0].line, text=text, signal=signal, mitre=(mitre,)))

    def first(self, category: str) -> Optional[_Evidence]:
        """Devolve a evidência de menor linha de uma categoria.

        Args:
            category: Chave da categoria.

        Returns:
            A evidência, ou ``None`` quando a categoria não tem nenhuma.
        """
        found = self.items.get(category) or []
        return min(found, key=lambda item: item.line) if found else None

    def behaviors(self) -> List[Behavior]:
        """Monta a lista final de comportamentos.

        Returns:
            Comportamentos sem evidência repetida, ordenados por gravidade,
            confiança (maior primeiro) e chave da categoria.
        """
        out: List[Behavior] = []
        for category, found in self.items.items():
            unique: List[_Evidence] = []
            seen: Set[str] = set()
            for item in found:
                if item.text in seen:
                    continue
                seen.add(item.text)
                unique.append(item)
            if not unique:
                continue
            info = BEHAVIOR_CATEGORIES[category]
            confidence = _confidence(len(unique))
            if not any(not item.weak for item in unique):
                confidence = min(confidence, _WEAK_CONFIDENCE)
            out.append(
                Behavior(
                    category=category,
                    label=info["label"],
                    description=info["description"],
                    severity=info["severity"],
                    confidence=confidence,
                    lines=tuple(sorted({item.line for item in unique})),
                    evidence=tuple(item.text for item in unique),
                    mitre=_mitre_of(unique),
                )
            )
        out.sort(
            key=lambda behavior: (
                severity_rank(behavior.severity),
                -behavior.confidence,
                behavior.category,
            )
        )
        return out


@dataclass
class _Context:
    """Dados derivados da análise que todas as detecções consultam.

    Attributes:
        analysis: Análise do fonte.
        syscalls: Índice da instrução -> nome da syscall, quando resolvido.
        loops: Laços do programa; cada laço é a lista dos seus blocos.
        code_labels: Rótulos que apontam para código (``.text``/``code``).
    """

    analysis: Analysis
    syscalls: Dict[int, str]
    loops: List[List[Block]]
    code_labels: Set[str]


# ------------------------------------------------------------- utilidades --
def _confidence(count: int) -> int:
    """Traduz a quantidade de evidências em confiança de 0 a 100.

    Args:
        count: Número de evidências do comportamento.

    Returns:
        ``60`` para 1 ou 2 evidências, ``80`` para 3 a 5, ``95`` para 6 ou mais
        e ``0`` quando não há nenhuma.
    """
    if count <= 0:
        return 0
    if count <= 2:
        return 60
    if count <= 5:
        return 80
    return 95


def _mitre_of(items: Sequence[_Evidence]) -> Tuple[str, ...]:
    """Reúne as técnicas citadas pelas evidências, sem repetição.

    Args:
        items: Evidências de um comportamento.

    Returns:
        Identificadores em ordem alfabética, restritos a
        :data:`MITRE_TECHNIQUES`.
    """
    ids: Set[str] = set()
    for item in items:
        for technique in item.mitre:
            if technique in MITRE_TECHNIQUES:
                ids.add(technique)
    return tuple(sorted(ids))


def _instruction_text(ins: Line) -> str:
    """Monta o texto curto de uma instrução, com prefixo e operandos.

    Args:
        ins: Instrução a descrever.

    Returns:
        Texto como ``rep movsb`` ou ``mov [vetor + rsi], bl``.
    """
    parts = [ins.mnemonic or "?"]
    parts.extend(operand.text for operand in ins.operands)
    prefix = (ins.prefix + " ") if ins.prefix else ""
    return prefix + " ".join(parts)


def _tag_of(ins: Line) -> str:
    """Devolve a etiqueta semântica de uma instrução.

    Args:
        ins: Instrução a examinar.

    Returns:
        O ``tag`` do :class:`~asmx.analyzer.Semantic` (``arith``, ``load``...)
        ou string vazia quando a semântica não foi preenchida.
    """
    sem = ins.sem
    return str(getattr(sem, "tag", "") or "") if sem is not None else ""


def _clean_name(raw: str) -> str:
    """Limpa um nome de função para comparar com as tabelas do módulo.

    Tira o ``%`` do AT&T, o prefixo ``_``/``__imp_`` do MASM, o sufixo ``@N``
    das funções decoradas e o ``@plt``/``@got`` do GAS, e passa para
    minúsculas.

    Args:
        raw: Texto do símbolo como apareceu no fonte.

    Returns:
        O nome normalizado em minúsculas.
    """
    name = str(raw or "").strip().lstrip("%")
    name = re.sub(r"^_+", "", name)
    name = re.sub(r"@(plt|got[a-z.]*)$", "", name, flags=re.I)
    name = re.sub(r"@\d+$", "", name)
    return name.lower()


def _api_label(clean: str, raw: str) -> str:
    """Escolhe como mostrar o nome de uma API.

    Args:
        clean: Nome normalizado (minúsculas, sem decoração).
        raw: Símbolo como apareceu no fonte.

    Returns:
        O nome oficial vindo de :data:`asmx.isa.WIN_APIS` quando existe; caso
        contrário, o símbolo original sem decoração.
    """
    data = WIN_APIS.get(clean)
    if data:
        return data[0]
    return re.sub(r"^_+|@\d+$", "", str(raw or "").strip())


def _api_hint(clean: str) -> str:
    """Descreve em poucas palavras o que a API faz.

    Args:
        clean: Nome normalizado da API.

    Returns:
        A descrição do acervo :data:`asmx.isa.WIN_APIS`, um texto próprio do
        módulo, ou ``"API externa"``.
    """
    if clean in _API_HINTS:
        return _API_HINTS[clean]
    data = WIN_APIS.get(clean)
    if data and len(data) > 1:
        return data[1]
    return "API externa"


def _call_api(ins: Line) -> Optional[Tuple[str, str]]:
    """Reconhece uma chamada a API que interessa ao relatório.

    Args:
        ins: Instrução a examinar.

    Returns:
        A tupla ``(nome normalizado, rótulo)``, ou ``None`` quando não é uma
        chamada ou o alvo não está em :data:`_APIS_BY_CATEGORY`.
    """
    if ins.mnemonic != "call" or not ins.operands:
        return None
    raw = ins.operands[0].symbol or ins.operands[0].text
    clean = _clean_name(raw)
    if clean not in _API_CATEGORIES:
        return None
    return clean, _api_label(clean, raw)


def _syscall_hint(name: str) -> str:
    """Descreve em poucas palavras o que a syscall faz.

    Args:
        name: Nome da syscall, como está em :data:`asmx.isa.LINUX_SYSCALLS`.

    Returns:
        O texto próprio do módulo, a descrição do acervo, ou
        ``"chamada de sistema"``.
    """
    if name in _SYSCALL_HINTS:
        return _SYSCALL_HINTS[name]
    return _SYSCALL_DOC.get(name, "chamada de sistema")


def _pending_number(ins: Line) -> Optional[int]:
    """Interpreta ``mov rax, N`` ou ``xor rax, rax`` como número de serviço.

    Args:
        ins: Instrução que escreve em RAX ou EAX.

    Returns:
        O número do serviço, ou ``None`` quando o valor não é conhecido.
    """
    ops = ins.operands
    if len(ops) > 1 and ops[1].type == "imm":
        return ops[1].value
    if ins.mnemonic == "xor" and len(ops) > 1 and ops[0].text == ops[1].text:
        return 0
    return None


def _resolve_syscalls(analysis: Analysis) -> Dict[int, str]:
    """Resolve o nome da syscall de cada instrução pelo número em RAX.

    O analisador já faz isso na maioria dos casos; esta passagem repete o
    trabalho para que a classificação continue funcionando mesmo quando a
    semântica não veio preenchida. Os números saem de
    :data:`asmx.isa.LINUX_SYSCALLS`, nunca de constantes escritas à mão.

    Args:
        analysis: Análise do fonte.

    Returns:
        Dicionário ``índice da instrução -> nome da syscall``.
    """
    out: Dict[int, str] = {}
    pending: Optional[int] = None
    for ins in analysis.instrs:
        if ins.idx is None:
            continue
        mnemonic = ins.mnemonic or ""
        if ins.operands and ins.operands[0].reg in ("rax", "eax"):
            pending = _pending_number(ins) if mnemonic in ("mov", "xor") else None
        gate = mnemonic in ("syscall", "sysenter") or (
            mnemonic == "int" and bool(ins.operands) and ins.operands[0].value == 0x80
        )
        if gate:
            name = _SYSCALL_NAMES_BY_NUMBER.get(pending) if pending is not None else None
            if name:
                out[ins.idx] = name
            pending = None
        elif mnemonic in ("call", "ret") or mnemonic.startswith("j"):
            pending = None
    return out


def _syscall_name(ctx: _Context, ins: Line) -> Optional[str]:
    """Descobre o nome da syscall de uma instrução.

    Usa o nome resolvido pelo analisador e, quando ele não existe, o mapa
    montado por :func:`_resolve_syscalls`.

    Args:
        ctx: Dados derivados da análise.
        ins: Instrução a examinar.

    Returns:
        O nome do serviço, ou ``None`` quando a instrução não é uma chamada de
        sistema reconhecida.
    """
    if ins.mnemonic not in ("syscall", "int", "sysenter"):
        return None
    sem = ins.sem
    name = getattr(sem, "syscall_name", None) if sem is not None else None
    if name:
        return str(name)
    if ins.idx is None:
        return None
    return ctx.syscalls.get(ins.idx)


def _loop_groups(analysis: Analysis) -> List[List[Block]]:
    """Agrupa os blocos de cada laço do programa.

    Um laço existe quando uma aresta volta para um bloco de índice menor ou
    igual; o laço reúne todos os blocos entre o destino e a origem da aresta.
    Olhar o laço inteiro, e não um bloco só, é o que permite reconhecer a troca
    de bytes que uma decisão no meio divide em dois blocos.

    Args:
        analysis: Análise do fonte.

    Returns:
        Lista de laços; cada laço é a lista dos seus blocos, na ordem do
        código.
    """
    blocks = list(getattr(analysis, "blocks", None) or [])
    by_id = {block.id: block for block in blocks}
    groups: List[List[Block]] = []
    seen: Set[Tuple[int, int]] = set()
    for block in blocks:
        for edge in list(getattr(block, "succ", None) or []):
            if edge.target > block.id or (edge.target, block.id) in seen:
                continue
            seen.add((edge.target, block.id))
            groups.append([by_id[i] for i in range(edge.target, block.id + 1) if i in by_id])
    return groups


def _instruction_at(analysis: Analysis, line: int) -> Optional[Line]:
    """Procura a instrução que está numa linha do fonte.

    Args:
        analysis: Análise do fonte.
        line: Número da linha.

    Returns:
        A instrução daquela linha, ou ``None``.
    """
    for ins in analysis.instrs:
        if ins.n == line:
            return ins
    return None


def _context(analysis: Analysis) -> _Context:
    """Monta os dados derivados usados pelas detecções.

    Args:
        analysis: Análise do fonte.

    Returns:
        O :class:`_Context` com syscalls resolvidas, laços e rótulos de código.
    """
    code_labels: Set[str] = set()
    for name, info in analysis.symbols.items():
        if info.get("type") != "label":
            continue
        section = str(info.get("section") or "").lstrip(".").lower()
        if section in _CODE_SECTIONS or (not section and name in analysis.label_at):
            code_labels.add(name)
    return _Context(
        analysis=analysis,
        syscalls=_resolve_syscalls(analysis),
        loops=_loop_groups(analysis),
        code_labels=code_labels,
    )


def _is_int3(ins: Line) -> bool:
    """Diz se a instrução é um breakpoint ``int 3``.

    Args:
        ins: Instrução a examinar.

    Returns:
        ``True`` para ``int 3`` e ``int3``.
    """
    if ins.mnemonic == "int3":
        return True
    if ins.mnemonic != "int" or not ins.operands:
        return False
    return ins.operands[0].value == 3


def _is_bit_op(ins: Line) -> bool:
    """Diz se a instrução é uma operação de bits que conta para cifra caseira.

    ``xor r, r`` fica de fora: é o jeito idiomático de zerar registrador e não
    tem nada a ver com cifra.

    Args:
        ins: Instrução a examinar.

    Returns:
        ``True`` para deslocamento, rotação e XOR entre operandos diferentes.
    """
    mnemonic = ins.mnemonic or ""
    if mnemonic not in _BIT_OPS:
        return False
    ops = ins.operands
    if mnemonic == "xor" and len(ops) > 1 and ops[0].text == ops[1].text:
        return False
    return True


def _indexed_memory(instrs: Sequence[Line], tag: str) -> Optional[Line]:
    """Acha o primeiro acesso à memória por registrador indexado.

    Endereços ancorados em RBP/RSP são variáveis locais, não um bloco de
    memória; só contam bases como RSI, RDI, RBX ou R12.

    Args:
        instrs: Instruções do laço.
        tag: Etiqueta procurada (``load`` ou ``store``).

    Returns:
        A instrução encontrada, ou ``None`` quando nenhuma serve.
    """
    for ins in instrs:
        if _tag_of(ins) != tag or not ins.operands:
            continue
        operand: Optional[Operand] = ins.operands[0]
        if tag != "store":
            operand = ins.operands[1] if len(ins.operands) > 1 else None
        if operand is None or operand.type != "mem":
            continue
        if [reg for reg in operand.regs if reg not in _FRAME_REGS]:
            return ins
    return None


def _code_text(linha: Line) -> str:
    """Devolve a linha do fonte sem o comentário.

    Args:
        linha: Linha do fonte.

    Returns:
        O trecho de código, já aparado; string vazia quando não sobra nada.
    """
    raw = linha.raw or ""
    comment = linha.comment or ""
    code = raw[: len(raw) - len(comment)] if comment else raw
    return code.strip()


def _host_token(code: str) -> str:
    """Extrai o primeiro trecho com cara de host, IP ou URL.

    Args:
        code: Linha já sem comentário.

    Returns:
        O trecho encontrado (até 60 caracteres), ou string vazia.
    """
    for pattern in (_RE_URL, _RE_IPV4, _RE_DOMAIN):
        found = pattern.search(code)
        if found:
            return found.group(0)[:60]
    return ""


# --------------------------------------------------------------- detecções --
def _scan_syscall(ctx: _Context, ins: Line, collector: _Collector) -> None:
    """Marca a syscall da instrução nas categorias a que ela pertence.

    Args:
        ctx: Dados derivados da análise.
        ins: Instrução a examinar.
        collector: Coletor onde as evidências entram.
    """
    name = _syscall_name(ctx, ins)
    if not name:
        return
    text = "linha %d: syscall %s (%s)" % (ins.n, name, _syscall_hint(name))
    for category in _SYSCALL_CATEGORIES.get(name, ()):
        collector.add(category, ins.n, text, "syscall " + name, mitre=_SYSCALL_MITRE.get(name, ()))


def _scan_api(ins: Line, collector: _Collector) -> None:
    """Marca chamadas às APIs do Windows que interessam ao relatório.

    Args:
        ins: Instrução a examinar.
        collector: Coletor onde as evidências entram.
    """
    found = _call_api(ins)
    if found is None:
        return
    clean, label = found
    text = "linha %d: chamada à API %s (%s)" % (ins.n, label, _api_hint(clean))
    for category in _API_CATEGORIES.get(clean, ()):
        collector.add(category, ins.n, text, "API " + label, mitre=_API_MITRE.get(clean, ()))


def _scan_mnemonic(ins: Line, collector: _Collector) -> None:
    """Reconhece instruções que não são syscall nem API, mas dizem muito.

    São elas: ``int 3`` (breakpoint de depurador), ``cpuid``/``rdtsc``/
    ``rdtscp`` (identificação ou cronometragem da máquina) e ``rep movs*`` com
    companhia (movimentação de bloco de bytes).

    Args:
        ins: Instrução a examinar.
        collector: Coletor onde as evidências entram.
    """
    mnemonic = ins.mnemonic or ""
    if _is_int3(ins):
        collector.add(
            "anti-analysis",
            ins.n,
            "linha %d: int 3 (breakpoint de depurador)" % ins.n,
            "int 3",
            mitre=("T1622",),
        )
        return
    if mnemonic in ("cpuid", "rdtsc", "rdtscp"):
        collector.add(
            "anti-analysis",
            ins.n,
            "linha %d: %s (identifica ou cronometra a máquina — indício de evasão)"
            % (ins.n, mnemonic),
            mnemonic,
            mitre=("T1497",),
        )
        return
    if ins.prefix and ins.prefix.startswith("rep") and mnemonic.startswith(_STRING_STEMS):
        text = _instruction_text(ins)
        collector.add(
            "string-handling",
            ins.n,
            "linha %d: %s (cópia, preenchimento ou varredura de bloco de bytes)" % (ins.n, text),
            text,
        )


def _scan_memory_write(ctx: _Context, ins: Line, collector: _Collector) -> None:
    """Marca escrita em memória por ponteiro ou em símbolo não declarado.

    Args:
        ctx: Dados derivados da análise.
        ins: Instrução a examinar.
        collector: Coletor onde as evidências entram.
    """
    sem = ins.sem
    if sem is None or getattr(sem, "tag", None) != "store" or not ins.operands:
        return
    operand = ins.operands[0]
    if operand.type != "mem":
        return
    detail = str(getattr(sem, "detail", "") or "")
    if "endereço apontado" in detail:
        collector.add(
            "memory",
            ins.n,
            "linha %d: %s (escrita em endereço apontado, calculado em execução)"
            % (ins.n, _instruction_text(ins)),
            "escrita por ponteiro",
        )
        return
    symbol = operand.symbol
    if symbol and symbol not in ctx.analysis.symbols:
        collector.add(
            "memory",
            ins.n,
            "linha %d: %s (escrita em %s, símbolo que o fonte não declara)"
            % (ins.n, _instruction_text(ins), symbol),
            "escrita em símbolo desconhecido",
        )


def _scan_self_modifying(ctx: _Context, ins: Line, collector: _Collector) -> None:
    """Marca escrita em endereço que pertence a um rótulo de código.

    Args:
        ctx: Dados derivados da análise.
        ins: Instrução a examinar.
        collector: Coletor onde as evidências entram.
    """
    sem = ins.sem
    if sem is None or getattr(sem, "tag", None) != "store" or not ins.operands:
        return
    operand = ins.operands[0]
    if operand.type != "mem" or not operand.symbol or operand.symbol not in ctx.code_labels:
        return
    info = ctx.analysis.symbols.get(operand.symbol, {})
    section = str(info.get("section") or "text").lstrip(".").lower()
    collector.add(
        "self-modifying",
        ins.n,
        "linha %d: %s (escreve em %s, rótulo de código em .%s)"
        % (ins.n, _instruction_text(ins), operand.symbol, section),
        "escrita em código",
        mitre=("T1027",),
    )


def _scan_external_call(ctx: _Context, ins: Line, collector: _Collector) -> None:
    """Marca chamadas a funções externas de execução.

    Encerrar o próprio programa (``ExitProcess``, ``exit``, ``exit_group``) não
    entra aqui: todo programa termina, e contar isso como manipulação de
    processo seria alarme falso. Funções externas que não executam nada também
    ficam de fora — o que interessa é o efeito, não a ligação.

    Args:
        ctx: Dados derivados da análise.
        ins: Instrução a examinar.
        collector: Coletor onde as evidências entram.
    """
    if ins.mnemonic != "call" or not ins.operands:
        return
    name = ins.operands[0].symbol
    if not name:
        return
    info = ctx.analysis.symbols.get(name, {})
    if info.get("type") != "extern" or _clean_name(name) not in _EXEC_NAMES:
        return
    collector.add(
        "process",
        ins.n,
        "linha %d: call %s (função externa de execução, resolvida na ligação)" % (ins.n, name),
        "call " + name,
        mitre=("T1059",),
    )


def _scan_instructions(ctx: _Context, collector: _Collector) -> None:
    """Percorre as instruções aplicando as regras por syscall, API e mnemônico.

    Args:
        ctx: Dados derivados da análise.
        collector: Coletor onde as evidências entram.
    """
    for ins in ctx.analysis.instrs:
        _scan_syscall(ctx, ins, collector)
        _scan_api(ins, collector)
        _scan_mnemonic(ins, collector)
        _scan_memory_write(ctx, ins, collector)
        _scan_self_modifying(ctx, ins, collector)
        _scan_external_call(ctx, ins, collector)


def _scan_loop_memory(instrs: Sequence[Line], collector: _Collector) -> None:
    """Procura carga e descarga indexadas dentro do mesmo laço.

    É assim que se movimenta um bloco de bytes sem as instruções ``rep movs*``;
    por ser uma leitura mais ampla, a evidência entra como indício fraco. O
    laço inteiro é considerado porque uma decisão no meio costuma separar a
    carga da descarga em dois blocos.

    Args:
        instrs: Instruções de todos os blocos do laço.
        collector: Coletor onde as evidências entram.
    """
    if not instrs:
        return
    store = _indexed_memory(instrs, "store")
    if store is None or _indexed_memory(instrs, "load") is None:
        return
    collector.add(
        "string-handling",
        store.n,
        "linha %d: %s — carga e descarga indexadas no laço das linhas %d-%d "
        "(movimentação byte a byte)"
        % (store.n, _instruction_text(store), instrs[0].n, instrs[-1].n),
        "laço sobre memória",
        weak=True,
    )


def _scan_loop_time(ctx: _Context, instrs: Sequence[Line], collector: _Collector) -> None:
    """Marca espera ou medição de tempo dentro de laço.

    Args:
        ctx: Dados derivados da análise.
        instrs: Instruções de todos os blocos do laço.
        collector: Coletor onde as evidências entram.
    """
    for ins in instrs:
        name = _syscall_name(ctx, ins)
        if name not in _LOOP_TIME_SYSCALLS:
            continue
        collector.add(
            "anti-analysis",
            ins.n,
            "linha %d: syscall %s no laço das linhas %d-%d "
            "(espera ou medição de tempo — indício)" % (ins.n, name, instrs[0].n, instrs[-1].n),
            "syscall " + name,
            weak=True,
            mitre=("T1497",),
        )
        return


def _scan_loop_bits(block: Block, collector: _Collector) -> None:
    """Conta operações de bits no bloco; muitas delas sugerem cifra caseira.

    Args:
        block: Bloco que faz parte de um laço.
        collector: Coletor onde as evidências entram.
    """
    instrs = list(getattr(block, "instrs", None) or [])
    ops = [ins for ins in instrs if _is_bit_op(ins)]
    if len(ops) < _BIT_OPS_MIN:
        return
    sample = ops[0]
    collector.add(
        "crypto",
        sample.n,
        "linha %d: %s — %d operações de bits no mesmo bloco de laço "
        "(indício de cifra caseira ou de ofuscação)"
        % (sample.n, _instruction_text(sample), len(ops)),
        "laço de bits",
        weak=True,
        mitre=("T1027",),
    )


def _scan_loop_files(ctx: _Context, instrs: Sequence[Line], collector: _Collector) -> None:
    """Marca operação de arquivo repetida dentro de laço.

    Args:
        ctx: Dados derivados da análise.
        instrs: Instruções de todos os blocos do laço.
        collector: Coletor onde as evidências entram.
    """
    for ins in instrs:
        signal = ""
        name = _syscall_name(ctx, ins)
        if name and "filesystem" in _SYSCALL_CATEGORIES.get(name, ()):
            signal = "syscall " + name
        else:
            found = _call_api(ins)
            if found is not None and "filesystem" in _API_CATEGORIES.get(found[0], ()):
                signal = "API " + found[1]
        if not signal:
            continue
        collector.add(
            "persistence",
            ins.n,
            "linha %d: %s no laço das linhas %d-%d (operação de arquivo repetida)"
            % (ins.n, signal, instrs[0].n, instrs[-1].n),
            signal,
        )
        return


def _scan_loop(group: Sequence[Block], ctx: _Context, collector: _Collector) -> None:
    """Aplica todas as regras que dependem de um laço inteiro.

    Um laço pode render quatro leituras diferentes: algoritmo puro
    (``data-processing``, bloco a bloco), movimentação byte a byte
    (``string-handling``), espera ou medição de tempo (``anti-analysis``) e
    cifra caseira (``crypto``).

    Args:
        group: Blocos que formam o laço, na ordem do código.
        ctx: Dados derivados da análise.
        collector: Coletor onde as evidências entram.
    """
    blocks = [block for block in group if getattr(block, "instrs", None)]
    if not blocks:
        return
    instrs = [ins for block in blocks for ins in block.instrs]
    for block in blocks:
        _scan_loop_block(block, collector)
    _scan_loop_memory(instrs, collector)
    _scan_loop_time(ctx, instrs, collector)
    for block in blocks:
        _scan_loop_bits(block, collector)
    _scan_loop_files(ctx, instrs, collector)


def _scan_loop_block(block: Block, collector: _Collector) -> None:
    """Marca o bloco de laço que só manipula registradores e memória.

    Args:
        block: Bloco que faz parte de um laço.
        collector: Coletor onde as evidências entram.
    """
    instrs = list(getattr(block, "instrs", None) or [])
    if not instrs or any(ins.mnemonic in ("syscall", "int", "call") for ins in instrs):
        return
    calc = [ins for ins in instrs if _tag_of(ins) in ("arith", "logic", "load", "store")]
    if not calc:
        return
    sample = calc[0]
    collector.add(
        "data-processing",
        sample.n,
        "linha %d: %s — laço das linhas %d-%d sem chamada externa "
        "(só registradores e memória)"
        % (sample.n, _instruction_text(sample), instrs[0].n, instrs[-1].n),
        "laço de cálculo",
    )


def _scan_loops(ctx: _Context, collector: _Collector) -> None:
    """Examina cada laço do programa.

    Args:
        ctx: Dados derivados da análise.
        collector: Coletor onde as evidências entram.
    """
    for group in ctx.loops:
        _scan_loop(group, ctx, collector)


def _scan_text_network(code: str, line: int, collector: _Collector) -> None:
    """Marca strings com cara de host, IP ou URL.

    Args:
        code: Linha do fonte sem o comentário.
        line: Número da linha.
        collector: Coletor onde as evidências entram.
    """
    token = _host_token(code)
    if not token:
        return
    collector.add(
        "network",
        line,
        "linha %d: string com possível host/URL: %s" % (line, token),
        "string " + token,
        mitre=("T1071",),
    )


def _scan_text_paths(code: str, line: int, collector: _Collector) -> None:
    """Marca caminhos de sistema citados no fonte.

    Args:
        code: Linha do fonte sem o comentário.
        line: Número da linha.
        collector: Coletor onde as evidências entram.
    """
    found = _RE_UNIX_PATH.search(code) or _RE_WIN_PATH.search(code)
    if found is None:
        return
    token = found.group(0)[:60]
    collector.add(
        "filesystem",
        line,
        "linha %d: caminho de sistema no fonte: %s" % (line, token),
        "caminho " + token,
        mitre=("T1083",),
    )


def _scan_text_persistence(code: str, line: int, collector: _Collector) -> None:
    """Marca strings típicas de execução automática ou de serviço.

    Args:
        code: Linha do fonte sem o comentário.
        line: Número da linha.
        collector: Coletor onde as evidências entram.
    """
    for pattern, mitre in (
        (_RE_AUTOSTART, ("T1547",)),
        (_RE_SERVICE, ("T1543",)),
        (_RE_SYSCONF, ()),
    ):
        found = pattern.search(code)
        if found is None:
            continue
        token = found.group(0)[:60]
        collector.add(
            "persistence",
            line,
            "linha %d: string de persistência no fonte: %s" % (line, token),
            "string " + token,
            mitre=mitre,
        )


def _scan_text(ctx: _Context, collector: _Collector) -> None:
    """Procura hosts, caminhos e nomes de persistência no texto do fonte.

    Comentários ficam de fora de propósito: a ideia é ver o que o programa
    carrega, não o que o autor escreveu sobre ele.

    Args:
        ctx: Dados derivados da análise.
        collector: Coletor onde as evidências entram.
    """
    for linha in ctx.analysis.program.lines:
        code = _code_text(linha)
        if not code:
            continue
        _scan_text_network(code, linha.n, collector)
        _scan_text_paths(code, linha.n, collector)
        _scan_text_persistence(code, linha.n, collector)


def _scan_problems(ctx: _Context, problems: Sequence[Problem], collector: _Collector) -> None:
    """Usa avisos do validador como indício fraco de evasão de análise.

    Args:
        ctx: Dados derivados da análise.
        problems: Problemas devolvidos por :func:`asmx.linter.validate`.
        collector: Coletor onde as evidências entram.
    """
    for problem in problems:
        code = str(getattr(problem, "code", "") or "")
        if code not in _WEAK_PROBLEMS:
            continue
        line = int(getattr(problem, "line", 0) or 0)
        sample = _instruction_at(ctx.analysis, line)
        quoted = _instruction_text(sample) if sample is not None else str(problem.message)[:60]
        collector.add(
            "anti-analysis",
            line,
            "linha %d: %s — aviso %s do validador (indício fraco)" % (line, quoted, code),
            "aviso " + code,
            weak=True,
        )


def _apply_combinations(collector: _Collector) -> None:
    """Acrescenta as técnicas que só aparecem na combinação de categorias.

    Args:
        collector: Coletor já preenchido pelas detecções.
    """
    network = collector.first("network")
    files = collector.first("filesystem")
    crypto = collector.first("crypto")
    if network is not None and files is not None:
        collector.mark(
            "network",
            "T1041",
            "linha %d: %s junto de %s (linha %d) — indício de envio de dados locais para fora"
            % (network.line, network.signal, files.signal, files.line),
            "rede + arquivos",
        )
    if crypto is not None and files is not None:
        collector.mark(
            "crypto",
            "T1486",
            "linha %d: %s junto de %s (linha %d) — indício de cifra de dados locais"
            % (crypto.line, crypto.signal, files.signal, files.line),
            "cifra + arquivos",
        )


def _safe_problems(analysis: Analysis) -> List[Problem]:
    """Roda o validador para completar os indícios fracos.

    Args:
        analysis: Análise do fonte.

    Returns:
        Os problemas encontrados; lista vazia quando a validação falha.
    """
    try:
        return validate(analysis)
    except Exception:  # noqa: BLE001 - o indício é opcional, o relatório não
        logger.debug("validação falhou dentro da classificação", exc_info=True)
        return []


# -------------------------------------------------------------- interface --
def classify(analysis: Analysis, problems: Optional[Sequence[Problem]] = None) -> List[Behavior]:
    """Transforma a análise em comportamentos legíveis.

    Nunca levanta exceção: uma falha inesperada devolve o que já foi coletado
    (ou lista vazia) para que o relatório continue sendo gerado.

    Args:
        analysis: Análise devolvida por :func:`asmx.analyzer.analyze`.
        problems: Problemas do validador, quando o chamador já os tem. Quando
            ``None``, o próprio módulo roda :func:`asmx.linter.validate`, porque
            é de lá que vem o indício fraco de ``anti-analysis``.

    Returns:
        Lista de :class:`Behavior` ordenada por gravidade, confiança e chave da
        categoria; vazia para um programa vazio.

    Example:
        >>> from asmx.analyzer import analyze
        >>> nomes = [b.category for b in classify(analyze("mov rax, 60\\nsyscall"))]
        >>> nomes
        []
    """
    collector = _Collector()
    try:
        if analysis is None or not getattr(analysis, "program", None):
            return []
        if not analysis.program.lines:
            return []
        ctx = _context(analysis)
        _scan_instructions(ctx, collector)
        _scan_loops(ctx, collector)
        _scan_text(ctx, collector)
        _scan_problems(
            ctx, problems if problems is not None else _safe_problems(analysis), collector
        )
        _apply_combinations(collector)
    except Exception:  # noqa: BLE001 - a classificação não pode derrubar o relatório
        logger.debug("falha ao classificar comportamentos", exc_info=True)
    return collector.behaviors()


def to_dicts(behaviors: Sequence[Behavior]) -> List[Dict[str, Any]]:
    """Converte uma lista de comportamentos em dicionários prontos para JSON.

    Args:
        behaviors: Comportamentos classificados.

    Returns:
        Lista de dicionários, na mesma ordem de entrada.
    """
    return [behavior.to_dict() for behavior in behaviors]


def techniques(behaviors: Sequence[Behavior]) -> List[Dict[str, Any]]:
    """Lista as técnicas do ATT&CK citadas pelos comportamentos.

    Args:
        behaviors: Comportamentos classificados.

    Returns:
        Lista de dicionários com ``id``, ``name``, ``tactic``, ``url``,
        ``description`` e ``behaviors`` (as categorias que citaram a técnica),
        em ordem alfabética de identificador.
    """
    found: Dict[str, List[str]] = {}
    for behavior in behaviors or []:
        for technique in behavior.mitre:
            if technique not in MITRE_TECHNIQUES:
                continue
            categories = found.setdefault(technique, [])
            if behavior.category not in categories:
                categories.append(behavior.category)
    out: List[Dict[str, Any]] = []
    for technique in sorted(found):
        info = MITRE_TECHNIQUES[technique]
        out.append(
            {
                "id": technique,
                "name": info["name"],
                "tactic": info["tactic"],
                "url": info["url"],
                "description": info["description"],
                "behaviors": sorted(found[technique]),
            }
        )
    return out


def by_tactic(behaviors: Sequence[Behavior]) -> Dict[str, List[Dict[str, Any]]]:
    """Agrupa as técnicas por tática, na ordem em que o relatório as mostra.

    Args:
        behaviors: Comportamentos classificados.

    Returns:
        Dicionário ``tática -> técnicas``; táticas fora da ordem conhecida vão
        para o fim, em ordem alfabética.
    """
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for technique in techniques(behaviors):
        groups.setdefault(technique["tactic"], []).append(technique)
    out: Dict[str, List[Dict[str, Any]]] = {}
    for tactic in _TACTIC_ORDER:
        if tactic in groups:
            out[tactic] = groups[tactic]
    for tactic in sorted(groups):
        if tactic not in out:
            out[tactic] = groups[tactic]
    return out


def summary(behaviors: Sequence[Behavior]) -> str:
    """Resume os comportamentos numa linha.

    Args:
        behaviors: Comportamentos classificados.

    Returns:
        Texto como ``3 comportamento(s): rede (alto), console (baixo)``.

    Example:
        >>> summary([])
        '0 comportamento(s)'
    """
    items = list(behaviors or [])
    if not items:
        return "0 comportamento(s)"
    parts = ["%s (%s)" % (_SHORT_LABELS.get(b.category, b.category), b.severity) for b in items]
    return "%d comportamento(s): %s" % (len(items), ", ".join(parts))


def severity_rank(severity: str) -> int:
    """Ordena gravidades: ``alto`` vem antes de ``medio`` e de ``baixo``.

    Args:
        severity: ``alto``, ``medio``, ``baixo`` ou qualquer outro texto
            (acentos e caixa não importam).

    Returns:
        ``0`` para alto, ``1`` para medio, ``2`` para baixo e ``3`` para valor
        desconhecido.

    Example:
        >>> severity_rank("alto"), severity_rank("MÉDIO"), severity_rank("?")
        (0, 1, 3)
    """
    normalized = str(severity or "").strip().lower().translate(_ACCENTS)
    return _SEVERITY_RANK.get(normalized, 3)
