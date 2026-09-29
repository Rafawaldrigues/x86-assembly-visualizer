"""Behaviors: what the program does, with honest mapping to ATT&CK.

This is the layer that answers "what does this program do?" from the
:class:`~asmx.analyzer.Analysis`: each :class:`Behavior` gathers concrete
evidence (line + mnemonic, syscall or API) and, when there is a real signal,
one or more MITRE ATT&CK identifiers.

**This is a hint, not a verdict.** Every detection comes from static patterns in
the source — syscall names, called APIs, the text of the strings and the shape
of the loops — and none of them proves malicious behavior: a didactic program
that opens a file and a data collector use exactly the same call. The mapping to
ATT&CK is a clue for the analyst, with the same caveat, and that is why every
technique description says it is a hint derived from static patterns, not proof.

Honesty rules applied here:

* every behavior has at least one piece of evidence citing the line and the
  mnemonic, the syscall or the API observed;
* confidence comes from the number of evidence items (1-2 -> 60, 3-5 -> 80,
  6+ -> 95) and weak hints (home-made cipher, waiting or measuring time in a
  loop, validator warnings) are capped at 50;
* a category with no signal at all does not appear: an empty list is better
  than an invented suspicion;
* :func:`classify` never raises — an empty program returns ``[]``.

Known limitations, so that nobody reads the output as something it is not:

* ``process`` requires real execution, creation or manipulation of a process;
  ending the program itself (``ExitProcess``, ``exit``, ``exit_group``) does not
  count, because every program ends — an external call only enters the category
  when the external function is one of execution (``system``, ``execve``...);
* syscall detection only sees the services present in
  :data:`asmx.isa.LINUX_SYSCALLS`; names such as ``chmod``, ``clone``,
  ``mremap`` or ``clock_gettime`` are not in that table and therefore never
  fire (the list of each category stays there, for the day the table grows);
* ``string-handling`` also marks loops that load and store memory through an
  indexed register, because that is how a block of bytes is copied without the
  ``rep movs*`` instructions — it is a weak hint and the text says so;
* ``self-modifying`` only recognizes a write whose address is a declared code
  label; the same access made through a pointer computed earlier is not
  statically traceable;
* nothing is executed: whoever wants real behavior needs the virtual machine.

Example:
    >>> from asmx.analyzer import analyze
    >>> from asmx.behavior import classify, summary
    >>> source = "section .text\\n_start:\\n mov rax, 1\\n syscall"
    >>> summary(classify(analyze(source)))
    '1 behavior(s): console (low)'
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

# ----------------------------------------------------------------- catalog --

#: Behavior categories: key -> label, description and severity.
BEHAVIOR_CATEGORIES: Dict[str, Dict[str, str]] = {
    "console-io": {
        "label": "Console input and output",
        "description": "Reads or writes text on the console: write/read on "
        "Linux, GetStdHandle/WriteConsoleA/ReadConsoleA/MessageBoxA on Windows.",
        "severity": "low",
    },
    "network": {
        "label": "Network communication",
        "description": "Opens sockets, connects, listens or uses network APIs "
        "(WinINet/WinHTTP) and loads strings that look like a host, IP or URL.",
        "severity": "high",
    },
    "filesystem": {
        "label": "File access",
        "description": "Opens, creates, deletes or renames files and mentions "
        "system paths (/etc/, /tmp/, C:\\).",
        "severity": "medium",
    },
    "process": {
        "label": "Process manipulation",
        "description": "Runs or creates processes, sends signals, debugs with "
        "ptrace or calls an execution function (system, execve, CreateProcessA).",
        "severity": "high",
    },
    "memory": {
        "label": "Memory manipulation",
        "description": "Maps or protects memory regions (mmap, mprotect, "
        "VirtualAlloc) and writes to an address computed at run time.",
        "severity": "medium",
    },
    "anti-analysis": {
        "label": "Analysis evasion",
        "description": "Breakpoint (int 3), machine identification "
        "(cpuid/rdtsc), ptrace and waiting or measuring time inside a loop.",
        "severity": "high",
    },
    "crypto": {
        "label": "Cryptography or obfuscation",
        "description": "Asks the kernel for random bytes and loops with many "
        "bit operations — a hint of a home-made cipher or of obfuscation.",
        "severity": "medium",
    },
    "persistence": {
        "label": "Persistence",
        "description": "Mentions autostart (Run, RunOnce, cron, systemd, "
        ".bashrc) or repeats a file operation inside a loop.",
        "severity": "high",
    },
    "environment": {
        "label": "System information",
        "description": "Queries the PID, the user, the system version, a "
        "loaded module or the last API error.",
        "severity": "low",
    },
    "data-processing": {
        "label": "Data processing",
        "description": "Loops that only touch registers and memory, with no "
        "external call: it is the algorithm of the program (sum, sorting, "
        "conversion).",
        "severity": "low",
    },
    "string-handling": {
        "label": "Byte block handling",
        "description": "Copies, fills or compares memory regions "
        "(rep movs*/stos*/lods*/scas*) or moves indexed bytes in a loop.",
        "severity": "low",
    },
    "self-modifying": {
        "label": "Self-modifying code",
        "description": "Writes to an address that belongs to a code label: "
        "the program changes its own instructions.",
        "severity": "high",
    },
}

#: MITRE ATT&CK techniques used by the module: id -> technique record.
MITRE_TECHNIQUES: Dict[str, Dict[str, str]] = {
    "T1005": {
        "name": "Data from Local System",
        "tactic": "Collection",
        "url": "https://attack.mitre.org/techniques/T1005/",
        "description": "Collection of data stored on the local machine. A hint "
        "derived from static patterns, not proof of malicious behavior.",
    },
    "T1012": {
        "name": "Query Registry",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1012/",
        "description": "Query to the Windows Registry to discover settings. A "
        "hint derived from static patterns, not proof of malicious behavior.",
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1027/",
        "description": "Makes the code itself or the data harder to read. A "
        "hint derived from static patterns, not proof of malicious behavior.",
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "url": "https://attack.mitre.org/techniques/T1041/",
        "description": "Sending data out through the command and control "
        "channel. A hint derived from static patterns, not proof of malicious "
        "behavior.",
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1055/",
        "description": "Injection of code into another process, typical of "
        "whoever allocates and protects executable memory. A hint derived from "
        "static patterns, not proof of malicious behavior.",
    },
    "T1057": {
        "name": "Process Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1057/",
        "description": "Discovery of running processes and identifiers. A hint "
        "derived from static patterns, not proof of malicious behavior.",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/",
        "description": "Execution of commands or of another program. A hint "
        "derived from static patterns, not proof of malicious behavior.",
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1071/",
        "description": "Communication over an application protocol (HTTP and "
        "the like). A hint derived from static patterns, not proof of "
        "malicious behavior.",
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1082/",
        "description": "Survey of the version, architecture and configuration "
        "of the system. A hint derived from static patterns, not proof of "
        "malicious behavior.",
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1083/",
        "description": "Scan of files and directories of interest. A hint "
        "derived from static patterns, not proof of malicious behavior.",
    },
    "T1095": {
        "name": "Non-Application Layer Protocol",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1095/",
        "description": "Communication over a raw protocol, with no application "
        "layer. A hint derived from static patterns, not proof of malicious "
        "behavior.",
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1105/",
        "description": "Transfer of a file from outside into the analyzed "
        "machine. A hint derived from static patterns, not proof of malicious "
        "behavior.",
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "url": "https://attack.mitre.org/techniques/T1486/",
        "description": "Encryption of local data to harm the owner. A hint "
        "derived from static patterns, not proof of malicious behavior.",
    },
    "T1497": {
        "name": "Virtualization/Sandbox Evasion",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1497/",
        "description": "Detection of a virtual machine, sandbox or analysis "
        "environment. A hint derived from static patterns, not proof of "
        "malicious behavior.",
    },
    "T1543": {
        "name": "Create or Modify System Process",
        "tactic": "Persistence",
        "url": "https://attack.mitre.org/techniques/T1543/",
        "description": "Creation or change of a system service to survive a "
        "reboot. A hint derived from static patterns, not proof of malicious "
        "behavior.",
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence",
        "url": "https://attack.mitre.org/techniques/T1547/",
        "description": "Configuration of automatic execution at boot or logon. "
        "A hint derived from static patterns, not proof of malicious behavior.",
    },
    "T1622": {
        "name": "Debugger Evasion",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1622/",
        "description": "Detection of or interference with a debugger. A hint "
        "derived from static patterns, not proof of malicious behavior.",
    },
}

#: Short label of each category, used by :func:`summary`.
_SHORT_LABELS: Dict[str, str] = {
    "console-io": "console",
    "network": "network",
    "filesystem": "files",
    "process": "processes",
    "memory": "memory",
    "anti-analysis": "anti-analysis",
    "crypto": "crypto",
    "persistence": "persistence",
    "environment": "environment",
    "data-processing": "data processing",
    "string-handling": "byte blocks",
    "self-modifying": "self-modifying code",
}

#: Severity -> position in the ordering (the smallest comes first).
_SEVERITY_RANK: Dict[str, int] = {"high": 0, "medium": 1, "low": 2}

#: Tactics in the order the report must show them.
_TACTIC_ORDER: Tuple[str, ...] = (
    "Execution",
    "Command and Control",
    "Discovery",
    "Defense Evasion",
    "Persistence",
    "Collection",
    "Exfiltration",
    "Impact",
)

#: Maximum confidence of a behavior supported only by a weak hint.
_WEAK_CONFIDENCE = 50

#: Sections whose labels count as code.
_CODE_SECTIONS = frozenset({"text", "code"})

#: Registers that anchor local variables, not memory blocks.
_FRAME_REGS = frozenset({"rbp", "rsp", "rip"})

#: Bit operations that count towards the home-made cipher hint.
_BIT_OPS: Tuple[str, ...] = ("xor", "shl", "sal", "shr", "sar", "rol", "ror")

#: How many bit operations in the same loop already suggest cipher or obfuscation.
_BIT_OPS_MIN = 3

#: Stems of the mnemonics that move memory blocks (movsb, stosq, lodsb...).
_STRING_STEMS: Tuple[str, ...] = ("movs", "stos", "lods", "scas", "cmps")

#: Validator warnings that enter as a weak hint of analysis evasion.
_WEAK_PROBLEMS = frozenset({"INT001", "FLOW002"})

#: Syscall names (according to :data:`asmx.isa.LINUX_SYSCALLS`) per category.
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
    # In anti-analysis, only ptrace counts outside a loop; the time syscalls and
    # the mnemonics (int 3, cpuid, rdtsc) have rules of their own.
    "anti-analysis": ("ptrace",),
    "memory": ("brk", "mmap", "mprotect", "mremap"),
    "crypto": ("getrandom", "getentropy"),
    "environment": ("getpid", "getuid", "uname", "sysinfo", "time"),
}

#: Windows APIs (lowercase) that characterize each category.
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

#: Short text of some syscalls, more specific than the collection description.
_SYSCALL_HINTS: Dict[str, str] = {
    "write": "output to console or file",
    "read": "input from console or file",
}

#: Techniques suggested by each syscall, when there is a real signal.
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

#: Short description of the APIs that are not in the :data:`asmx.isa.WIN_APIS` collection.
_API_HINTS: Dict[str, str] = {
    "writeconsolew": "writes to the console (Unicode)",
    "readconsolew": "reads from the console (Unicode)",
    "wsastartup": "initializes the Windows socket library",
    "wsasocketa": "creates a socket through Winsock",
    "internetopena": "opens a WinINet session",
    "internetopenw": "opens a WinINet session",
    "internetopenurla": "opens a URL through WinINet",
    "internetopenurlw": "opens a URL through WinINet",
    "winhttpopen": "opens a WinHTTP session",
    "urldownloadtofilea": "downloads a file from a URL",
    "urldownloadtofilew": "downloads a file from a URL",
    "createfilew": "opens or creates a file (Unicode)",
    "deletefilea": "deletes a file",
    "deletefilew": "deletes a file (Unicode)",
    "gettemppatha": "finds the temporary folder",
    "gettempathw": "finds the temporary folder (Unicode)",
    "createprocessw": "creates a process (Unicode)",
    "shellexecutea": "opens a program or document through the shell",
    "shellexecutew": "opens a program or document through the shell (Unicode)",
    "winexec": "runs a program",
    "getmodulehandlew": "handle of the loaded module (Unicode)",
    "getversion": "Windows version",
    "heapalloc": "reserves memory in the process heap",
    "rtlmovememory": "copies bytes in the process memory",
    "regopenkeyexa": "opens a registry key",
    "regqueryvalueexa": "reads a registry value",
    "regsetvalueexa": "writes a registry value",
    "regcreatekeyexa": "creates a registry key",
    "regcreatekeyw": "creates a registry key (Unicode)",
}

#: Techniques suggested by each API, when there is a real signal.
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

#: Time or wait syscalls: they only become a hint inside a loop.
_LOOP_TIME_SYSCALLS: Tuple[str, ...] = ("nanosleep", "clock_gettime", "time", "gettimeofday")

#: External execution functions (libc), which count as ``process``.
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

#: IP in decimal format, as it appears in configuration strings.
_RE_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

#: Full URL with the HTTP or HTTPS scheme.
_RE_URL = re.compile(r"https?://[^\s\"']+", re.I)

#: Domain with a known TLD (avoids matching ``.text`` or ``name.asm``).
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

#: Typical Unix directory path, written in the source.
_RE_UNIX_PATH = re.compile(r"/(?:etc|tmp|var|usr|home|root|proc|dev|opt|bin|sbin|boot|srv|sys)/")

#: Windows-style path (``C:\``) or UNC path (``\\server\``).
_RE_WIN_PATH = re.compile(r"[A-Za-z]:\\|\\\\[A-Za-z0-9_.-]+\\")

#: Autostart strings for logon or boot.
_RE_AUTOSTART = re.compile(r"runonce|currentversion\\run|\brun\\|\.bashrc", re.I)

#: Service, scheduled task or system startup strings.
_RE_SERVICE = re.compile(r"\bcron|systemd|\bservices\b", re.I)

#: System configuration directory: possible persistence, with no technique of
#: its own, because ``/etc/passwd`` and ``/etc/cron.d`` are not the same thing.
_RE_SYSCONF = re.compile(r"/etc/", re.I)


def _invert(table: Dict[str, Tuple[str, ...]]) -> Dict[str, Tuple[str, ...]]:
    """Inverts a ``key -> names`` map into a ``name -> keys`` map.

    Args:
        table: Map whose values are sequences of names.

    Returns:
        Map from each name to the keys where it appears, in the original order.
    """
    out: Dict[str, List[str]] = {}
    for key, names in table.items():
        for name in names:
            out.setdefault(name, []).append(key)
    return {name: tuple(keys) for name, keys in out.items()}


#: Syscall -> categories it belongs to.
_SYSCALL_CATEGORIES: Dict[str, Tuple[str, ...]] = _invert(_SYSCALLS_BY_CATEGORY)

#: API -> categories it belongs to.
_API_CATEGORIES: Dict[str, Tuple[str, ...]] = _invert(_APIS_BY_CATEGORY)

#: Syscall number -> name, built from the collection (nothing hand-written).
_SYSCALL_NAMES_BY_NUMBER: Dict[int, str] = {
    number: data[0] for number, data in LINUX_SYSCALLS.items() if data
}

#: Syscall name -> collection description.
_SYSCALL_DOC: Dict[str, str] = {
    data[0]: data[1] for data in LINUX_SYSCALLS.values() if len(data) > 1
}


# ------------------------------------------------------------------- model --
@dataclass(frozen=True)
class Behavior:
    """A behavior observed in the program, with the evidence that supports it.

    Attributes:
        category: Key of :data:`BEHAVIOR_CATEGORIES`.
        label: Readable label of the category.
        description: What the category means in one sentence.
        severity: ``high``, ``medium`` or ``low``.
        confidence: Confidence from 0 to 100, derived from the number of evidence
            items.
        lines: Evidence lines, in increasing order and without repetition.
        evidence: Short sentences, each one citing line and signal.
        mitre: Identifiers present in :data:`MITRE_TECHNIQUES`.
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
        """Converts the behavior into a dictionary ready for JSON.

        Returns:
            Dictionary with ``category``, ``label``, ``description``,
            ``severity``, ``confidence``, ``lines``, ``evidence`` and ``mitre``,
            with the sequences already converted into lists.
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
    """One isolated piece of evidence, with the signal that produced it.

    Attributes:
        line: Source line where the pattern was seen.
        text: Ready sentence, already starting with ``line N:``.
        signal: Short name of the signal (``syscall socket``, ``API WriteFile``),
            used in the combination evidence.
        weak: Whether it is a weak hint (caps the behavior confidence at 50).
        mitre: Techniques suggested by this evidence.
    """

    line: int
    text: str
    signal: str
    weak: bool = False
    mitre: Tuple[str, ...] = ()


class _Collector:
    """Gathers evidence per category and builds the behaviors.

    Attributes:
        items: Category -> evidence, in the order they were found.
    """

    def __init__(self) -> None:
        """Creates an empty collector."""
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
        """Records a piece of evidence, ignoring an invalid category or text.

        Args:
            category: Key of :data:`BEHAVIOR_CATEGORIES`.
            line: Source line of the evidence.
            text: Ready sentence, starting with ``line N:``.
            signal: Short name of the signal, for the combinations.
            weak: Marks the evidence as a weak hint.
            mitre: Techniques suggested by this evidence.
        """
        if category not in BEHAVIOR_CATEGORIES or not text:
            return
        self.items.setdefault(category, []).append(
            _Evidence(line=line, text=text, signal=signal, weak=weak, mitre=tuple(mitre))
        )

    def mark(self, category: str, mitre: str, text: str, signal: str) -> None:
        """Adds a combination evidence to a category that already exists.

        Args:
            category: Category that already has at least one evidence item.
            mitre: Technique added by the combination.
            text: Sentence of the combination evidence.
            signal: Short name of the combined signal.
        """
        found = self.items.get(category)
        if not found:
            return
        found.append(_Evidence(line=found[0].line, text=text, signal=signal, mitre=(mitre,)))

    def first(self, category: str) -> Optional[_Evidence]:
        """Returns the evidence with the smallest line of a category.

        Args:
            category: Category key.

        Returns:
            The evidence, or ``None`` when the category has none.
        """
        found = self.items.get(category) or []
        return min(found, key=lambda item: item.line) if found else None

    def behaviors(self) -> List[Behavior]:
        """Builds the final list of behaviors.

        Returns:
            Behaviors without repeated evidence, ordered by severity, confidence
            (highest first) and category key.
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
    """Data derived from the analysis that every detection consults.

    Attributes:
        analysis: Source analysis.
        syscalls: Instruction index -> syscall name, when resolved.
        loops: Loops of the program; each loop is the list of its blocks.
        code_labels: Labels that point to code (``.text``/``code``).
    """

    analysis: Analysis
    syscalls: Dict[int, str]
    loops: List[List[Block]]
    code_labels: Set[str]


# -------------------------------------------------------------- utilities --
def _confidence(count: int) -> int:
    """Translates the number of evidence items into confidence from 0 to 100.

    Args:
        count: Number of evidence items of the behavior.

    Returns:
        ``60`` for 1 or 2 evidence items, ``80`` for 3 to 5, ``95`` for 6 or
        more and ``0`` when there is none.
    """
    if count <= 0:
        return 0
    if count <= 2:
        return 60
    if count <= 5:
        return 80
    return 95


def _mitre_of(items: Sequence[_Evidence]) -> Tuple[str, ...]:
    """Gathers the techniques cited by the evidence, without repetition.

    Args:
        items: Evidence items of one behavior.

    Returns:
        Identifiers in alphabetical order, restricted to
        :data:`MITRE_TECHNIQUES`.
    """
    ids: Set[str] = set()
    for item in items:
        for technique in item.mitre:
            if technique in MITRE_TECHNIQUES:
                ids.add(technique)
    return tuple(sorted(ids))


def _instruction_text(ins: Line) -> str:
    """Builds the short text of an instruction, with prefix and operands.

    Args:
        ins: Instruction to describe.

    Returns:
        Text like ``rep movsb`` or ``mov [array + rsi], bl``.
    """
    parts = [ins.mnemonic or "?"]
    parts.extend(operand.text for operand in ins.operands)
    prefix = (ins.prefix + " ") if ins.prefix else ""
    return prefix + " ".join(parts)


def _tag_of(ins: Line) -> str:
    """Returns the semantic tag of an instruction.

    Args:
        ins: Instruction to examine.

    Returns:
        The ``tag`` of the :class:`~asmx.analyzer.Semantic` (``arith``,
        ``load``...) or an empty string when the semantics was not filled in.
    """
    sem = ins.sem
    return str(getattr(sem, "tag", "") or "") if sem is not None else ""


def _clean_name(raw: str) -> str:
    """Cleans a function name to compare it with the module tables.

    Removes the AT&T ``%``, the MASM ``_``/``__imp_`` prefix, the ``@N`` suffix
    of decorated functions and the GAS ``@plt``/``@got``, and switches to
    lowercase.

    Args:
        raw: Symbol text as it appeared in the source.

    Returns:
        The normalized name in lowercase.
    """
    name = str(raw or "").strip().lstrip("%")
    name = re.sub(r"^_+", "", name)
    name = re.sub(r"@(plt|got[a-z.]*)$", "", name, flags=re.I)
    name = re.sub(r"@\d+$", "", name)
    return name.lower()


def _api_label(clean: str, raw: str) -> str:
    """Chooses how to display the name of an API.

    Args:
        clean: Normalized name (lowercase, without decoration).
        raw: Symbol as it appeared in the source.

    Returns:
        The official name coming from :data:`asmx.isa.WIN_APIS` when it exists;
        otherwise, the original symbol without decoration.
    """
    data = WIN_APIS.get(clean)
    if data:
        return data[0]
    return re.sub(r"^_+|@\d+$", "", str(raw or "").strip())


def _api_hint(clean: str) -> str:
    """Describes in a few words what the API does.

    Args:
        clean: Normalized name of the API.

    Returns:
        The description from the :data:`asmx.isa.WIN_APIS` collection, a text of
        the module itself, or ``"external API"``.
    """
    if clean in _API_HINTS:
        return _API_HINTS[clean]
    data = WIN_APIS.get(clean)
    if data and len(data) > 1:
        return data[1]
    return "external API"


def _call_api(ins: Line) -> Optional[Tuple[str, str]]:
    """Recognizes a call to an API that interests the report.

    Args:
        ins: Instruction to examine.

    Returns:
        The tuple ``(normalized name, label)``, or ``None`` when it is not a
        call or the target is not in :data:`_APIS_BY_CATEGORY`.
    """
    if ins.mnemonic != "call" or not ins.operands:
        return None
    raw = ins.operands[0].symbol or ins.operands[0].text
    clean = _clean_name(raw)
    if clean not in _API_CATEGORIES:
        return None
    return clean, _api_label(clean, raw)


def _syscall_hint(name: str) -> str:
    """Describes in a few words what the syscall does.

    Args:
        name: Syscall name, as it is in :data:`asmx.isa.LINUX_SYSCALLS`.

    Returns:
        The text of the module itself, the collection description, or
        ``"system call"``.
    """
    if name in _SYSCALL_HINTS:
        return _SYSCALL_HINTS[name]
    return _SYSCALL_DOC.get(name, "system call")


def _pending_number(ins: Line) -> Optional[int]:
    """Interprets ``mov rax, N`` or ``xor rax, rax`` as a service number.

    Args:
        ins: Instruction that writes to RAX or EAX.

    Returns:
        The service number, or ``None`` when the value is not known.
    """
    ops = ins.operands
    if len(ops) > 1 and ops[1].type == "imm":
        return ops[1].value
    if ins.mnemonic == "xor" and len(ops) > 1 and ops[0].text == ops[1].text:
        return 0
    return None


def _resolve_syscalls(analysis: Analysis) -> Dict[int, str]:
    """Resolves the syscall name of each instruction from the number in RAX.

    The analyzer already does this in most cases; this pass repeats the work so
    that the classification keeps working even when the semantics was not filled
    in. The numbers come from :data:`asmx.isa.LINUX_SYSCALLS`, never from
    hand-written constants.

    Args:
        analysis: Source analysis.

    Returns:
        Dictionary ``instruction index -> syscall name``.
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
    """Finds the syscall name of an instruction.

    Uses the name resolved by the analyzer and, when it does not exist, the map
    built by :func:`_resolve_syscalls`.

    Args:
        ctx: Data derived from the analysis.
        ins: Instruction to examine.

    Returns:
        The service name, or ``None`` when the instruction is not a recognized
        system call.
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
    """Groups the blocks of each loop of the program.

    A loop exists when an edge goes back to a block with a smaller or equal
    index; the loop gathers every block between the target and the origin of the
    edge. Looking at the whole loop, and not at a single block, is what allows
    recognizing the byte swap that a decision in the middle splits into two
    blocks.

    Args:
        analysis: Source analysis.

    Returns:
        List of loops; each loop is the list of its blocks, in code order.
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
    """Looks for the instruction that is on a source line.

    Args:
        analysis: Source analysis.
        line: Line number.

    Returns:
        The instruction of that line, or ``None``.
    """
    for ins in analysis.instrs:
        if ins.n == line:
            return ins
    return None


def _context(analysis: Analysis) -> _Context:
    """Builds the derived data used by the detections.

    Args:
        analysis: Source analysis.

    Returns:
        The :class:`_Context` with resolved syscalls, loops and code labels.
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
    """Tells whether the instruction is an ``int 3`` breakpoint.

    Args:
        ins: Instruction to examine.

    Returns:
        ``True`` for ``int 3`` and ``int3``.
    """
    if ins.mnemonic == "int3":
        return True
    if ins.mnemonic != "int" or not ins.operands:
        return False
    return ins.operands[0].value == 3


def _is_bit_op(ins: Line) -> bool:
    """Tells whether the instruction is a bit operation that counts for a cipher.

    ``xor r, r`` stays out: it is the idiomatic way to zero a register and has
    nothing to do with a cipher.

    Args:
        ins: Instruction to examine.

    Returns:
        ``True`` for shift, rotate and XOR between different operands.
    """
    mnemonic = ins.mnemonic or ""
    if mnemonic not in _BIT_OPS:
        return False
    ops = ins.operands
    if mnemonic == "xor" and len(ops) > 1 and ops[0].text == ops[1].text:
        return False
    return True


def _indexed_memory(instrs: Sequence[Line], tag: str) -> Optional[Line]:
    """Finds the first memory access through an indexed register.

    Addresses anchored in RBP/RSP are local variables, not a memory block; only
    bases such as RSI, RDI, RBX or R12 count.

    Args:
        instrs: Instructions of the loop.
        tag: Tag being searched for (``load`` or ``store``).

    Returns:
        The instruction found, or ``None`` when none qualifies.
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
    """Returns the source line without the comment.

    Args:
        linha: Source line.

    Returns:
        The code stretch, already trimmed; an empty string when nothing is left.
    """
    raw = linha.raw or ""
    comment = linha.comment or ""
    code = raw[: len(raw) - len(comment)] if comment else raw
    return code.strip()


def _host_token(code: str) -> str:
    """Extracts the first stretch that looks like a host, IP or URL.

    Args:
        code: Line already without the comment.

    Returns:
        The stretch found (up to 60 characters), or an empty string.
    """
    for pattern in (_RE_URL, _RE_IPV4, _RE_DOMAIN):
        found = pattern.search(code)
        if found:
            return found.group(0)[:60]
    return ""


# -------------------------------------------------------------- detections --
def _scan_syscall(ctx: _Context, ins: Line, collector: _Collector) -> None:
    """Marks the syscall of the instruction in the categories it belongs to.

    Args:
        ctx: Data derived from the analysis.
        ins: Instruction to examine.
        collector: Collector where the evidence enters.
    """
    name = _syscall_name(ctx, ins)
    if not name:
        return
    text = "line %d: syscall %s (%s)" % (ins.n, name, _syscall_hint(name))
    for category in _SYSCALL_CATEGORIES.get(name, ()):
        collector.add(category, ins.n, text, "syscall " + name, mitre=_SYSCALL_MITRE.get(name, ()))


def _scan_api(ins: Line, collector: _Collector) -> None:
    """Marks calls to the Windows APIs that interest the report.

    Args:
        ins: Instruction to examine.
        collector: Collector where the evidence enters.
    """
    found = _call_api(ins)
    if found is None:
        return
    clean, label = found
    text = "line %d: call to API %s (%s)" % (ins.n, label, _api_hint(clean))
    for category in _API_CATEGORIES.get(clean, ()):
        collector.add(category, ins.n, text, "API " + label, mitre=_API_MITRE.get(clean, ()))


def _scan_mnemonic(ins: Line, collector: _Collector) -> None:
    """Recognizes instructions that are neither a syscall nor an API, but say a lot.

    They are: ``int 3`` (debugger breakpoint), ``cpuid``/``rdtsc``/``rdtscp``
    (machine identification or timing) and ``rep movs*`` with company (byte
    block movement).

    Args:
        ins: Instruction to examine.
        collector: Collector where the evidence enters.
    """
    mnemonic = ins.mnemonic or ""
    if _is_int3(ins):
        collector.add(
            "anti-analysis",
            ins.n,
            "line %d: int 3 (debugger breakpoint)" % ins.n,
            "int 3",
            mitre=("T1622",),
        )
        return
    if mnemonic in ("cpuid", "rdtsc", "rdtscp"):
        collector.add(
            "anti-analysis",
            ins.n,
            "line %d: %s (identifies or times the machine — a hint of evasion)" % (ins.n, mnemonic),
            mnemonic,
            mitre=("T1497",),
        )
        return
    if ins.prefix and ins.prefix.startswith("rep") and mnemonic.startswith(_STRING_STEMS):
        text = _instruction_text(ins)
        collector.add(
            "string-handling",
            ins.n,
            "line %d: %s (copy, fill or scan of a byte block)" % (ins.n, text),
            text,
        )


def _scan_memory_write(ctx: _Context, ins: Line, collector: _Collector) -> None:
    """Marks a memory write through a pointer or to an undeclared symbol.

    Args:
        ctx: Data derived from the analysis.
        ins: Instruction to examine.
        collector: Collector where the evidence enters.
    """
    sem = ins.sem
    if sem is None or getattr(sem, "tag", None) != "store" or not ins.operands:
        return
    operand = ins.operands[0]
    if operand.type != "mem":
        return
    detail = str(getattr(sem, "detail", "") or "")
    if "address pointed to" in detail:
        collector.add(
            "memory",
            ins.n,
            "line %d: %s (write to an address pointed to, computed at run time)"
            % (ins.n, _instruction_text(ins)),
            "write through pointer",
        )
        return
    symbol = operand.symbol
    if symbol and symbol not in ctx.analysis.symbols:
        collector.add(
            "memory",
            ins.n,
            "line %d: %s (write to %s, a symbol the source does not declare)"
            % (ins.n, _instruction_text(ins), symbol),
            "write to unknown symbol",
        )


def _scan_self_modifying(ctx: _Context, ins: Line, collector: _Collector) -> None:
    """Marks a write to an address that belongs to a code label.

    Args:
        ctx: Data derived from the analysis.
        ins: Instruction to examine.
        collector: Collector where the evidence enters.
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
        "line %d: %s (writes to %s, a code label in .%s)"
        % (ins.n, _instruction_text(ins), operand.symbol, section),
        "write to code",
        mitre=("T1027",),
    )


def _scan_external_call(ctx: _Context, ins: Line, collector: _Collector) -> None:
    """Marks calls to external execution functions.

    Ending the program itself (``ExitProcess``, ``exit``, ``exit_group``) does
    not enter here: every program ends, and counting that as process
    manipulation would be a false alarm. External functions that execute nothing
    are also left out — what matters is the effect, not the link.

    Args:
        ctx: Data derived from the analysis.
        ins: Instruction to examine.
        collector: Collector where the evidence enters.
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
        "line %d: call %s (external execution function, resolved at link time)" % (ins.n, name),
        "call " + name,
        mitre=("T1059",),
    )


def _scan_instructions(ctx: _Context, collector: _Collector) -> None:
    """Walks the instructions applying the rules per syscall, API and mnemonic.

    Args:
        ctx: Data derived from the analysis.
        collector: Collector where the evidence enters.
    """
    for ins in ctx.analysis.instrs:
        _scan_syscall(ctx, ins, collector)
        _scan_api(ins, collector)
        _scan_mnemonic(ins, collector)
        _scan_memory_write(ctx, ins, collector)
        _scan_self_modifying(ctx, ins, collector)
        _scan_external_call(ctx, ins, collector)


def _scan_loop_memory(instrs: Sequence[Line], collector: _Collector) -> None:
    """Looks for indexed load and store inside the same loop.

    That is how a block of bytes is moved without the ``rep movs*``
    instructions; because it is a broader reading, the evidence enters as a weak
    hint. The whole loop is considered because a decision in the middle usually
    separates the load from the store into two blocks.

    Args:
        instrs: Instructions of every block of the loop.
        collector: Collector where the evidence enters.
    """
    if not instrs:
        return
    store = _indexed_memory(instrs, "store")
    if store is None or _indexed_memory(instrs, "load") is None:
        return
    collector.add(
        "string-handling",
        store.n,
        "line %d: %s — indexed load and store in the loop of lines %d-%d "
        "(byte by byte movement)" % (store.n, _instruction_text(store), instrs[0].n, instrs[-1].n),
        "loop over memory",
        weak=True,
    )


def _scan_loop_time(ctx: _Context, instrs: Sequence[Line], collector: _Collector) -> None:
    """Marks waiting or measuring time inside a loop.

    Args:
        ctx: Data derived from the analysis.
        instrs: Instructions of every block of the loop.
        collector: Collector where the evidence enters.
    """
    for ins in instrs:
        name = _syscall_name(ctx, ins)
        if name not in _LOOP_TIME_SYSCALLS:
            continue
        collector.add(
            "anti-analysis",
            ins.n,
            "line %d: syscall %s in the loop of lines %d-%d "
            "(waiting or measuring time — a hint)" % (ins.n, name, instrs[0].n, instrs[-1].n),
            "syscall " + name,
            weak=True,
            mitre=("T1497",),
        )
        return


def _scan_loop_bits(block: Block, collector: _Collector) -> None:
    """Counts bit operations in the block; many of them suggest a home-made cipher.

    Args:
        block: Block that is part of a loop.
        collector: Collector where the evidence enters.
    """
    instrs = list(getattr(block, "instrs", None) or [])
    ops = [ins for ins in instrs if _is_bit_op(ins)]
    if len(ops) < _BIT_OPS_MIN:
        return
    sample = ops[0]
    collector.add(
        "crypto",
        sample.n,
        "line %d: %s — %d bit operations in the same loop block "
        "(a hint of a home-made cipher or of obfuscation)"
        % (sample.n, _instruction_text(sample), len(ops)),
        "bit loop",
        weak=True,
        mitre=("T1027",),
    )


def _scan_loop_files(ctx: _Context, instrs: Sequence[Line], collector: _Collector) -> None:
    """Marks a file operation repeated inside a loop.

    Args:
        ctx: Data derived from the analysis.
        instrs: Instructions of every block of the loop.
        collector: Collector where the evidence enters.
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
            "line %d: %s in the loop of lines %d-%d (repeated file operation)"
            % (ins.n, signal, instrs[0].n, instrs[-1].n),
            signal,
        )
        return


def _scan_loop(group: Sequence[Block], ctx: _Context, collector: _Collector) -> None:
    """Applies every rule that depends on a whole loop.

    A loop can yield four different readings: pure algorithm
    (``data-processing``, block by block), byte by byte movement
    (``string-handling``), waiting or measuring time (``anti-analysis``) and
    home-made cipher (``crypto``).

    Args:
        group: Blocks that form the loop, in code order.
        ctx: Data derived from the analysis.
        collector: Collector where the evidence enters.
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
    """Marks the loop block that only manipulates registers and memory.

    Args:
        block: Block that is part of a loop.
        collector: Collector where the evidence enters.
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
        "line %d: %s — loop of lines %d-%d with no external call "
        "(only registers and memory)"
        % (sample.n, _instruction_text(sample), instrs[0].n, instrs[-1].n),
        "calculation loop",
    )


def _scan_loops(ctx: _Context, collector: _Collector) -> None:
    """Examines each loop of the program.

    Args:
        ctx: Data derived from the analysis.
        collector: Collector where the evidence enters.
    """
    for group in ctx.loops:
        _scan_loop(group, ctx, collector)


def _scan_text_network(code: str, line: int, collector: _Collector) -> None:
    """Marks strings that look like a host, IP or URL.

    Args:
        code: Source line without the comment.
        line: Line number.
        collector: Collector where the evidence enters.
    """
    token = _host_token(code)
    if not token:
        return
    collector.add(
        "network",
        line,
        "line %d: string with a possible host/URL: %s" % (line, token),
        "string " + token,
        mitre=("T1071",),
    )


def _scan_text_paths(code: str, line: int, collector: _Collector) -> None:
    """Marks system paths mentioned in the source.

    Args:
        code: Source line without the comment.
        line: Line number.
        collector: Collector where the evidence enters.
    """
    found = _RE_UNIX_PATH.search(code) or _RE_WIN_PATH.search(code)
    if found is None:
        return
    token = found.group(0)[:60]
    collector.add(
        "filesystem",
        line,
        "line %d: system path in the source: %s" % (line, token),
        "path " + token,
        mitre=("T1083",),
    )


def _scan_text_persistence(code: str, line: int, collector: _Collector) -> None:
    """Marks strings typical of autostart or of a service.

    Args:
        code: Source line without the comment.
        line: Line number.
        collector: Collector where the evidence enters.
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
            "line %d: persistence string in the source: %s" % (line, token),
            "string " + token,
            mitre=mitre,
        )


def _scan_text(ctx: _Context, collector: _Collector) -> None:
    """Looks for hosts, paths and persistence names in the source text.

    Comments stay out on purpose: the idea is to see what the program loads, not
    what the author wrote about it.

    Args:
        ctx: Data derived from the analysis.
        collector: Collector where the evidence enters.
    """
    for linha in ctx.analysis.program.lines:
        code = _code_text(linha)
        if not code:
            continue
        _scan_text_network(code, linha.n, collector)
        _scan_text_paths(code, linha.n, collector)
        _scan_text_persistence(code, linha.n, collector)


def _scan_problems(ctx: _Context, problems: Sequence[Problem], collector: _Collector) -> None:
    """Uses validator warnings as a weak hint of analysis evasion.

    Args:
        ctx: Data derived from the analysis.
        problems: Issues returned by :func:`asmx.linter.validate`.
        collector: Collector where the evidence enters.
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
            "line %d: %s — %s warning from the validator (weak hint)" % (line, quoted, code),
            "warning " + code,
            weak=True,
        )


def _apply_combinations(collector: _Collector) -> None:
    """Adds the techniques that only appear in the combination of categories.

    Args:
        collector: Collector already filled in by the detections.
    """
    network = collector.first("network")
    files = collector.first("filesystem")
    crypto = collector.first("crypto")
    if network is not None and files is not None:
        collector.mark(
            "network",
            "T1041",
            "line %d: %s together with %s (line %d) — a hint of sending local data out"
            % (network.line, network.signal, files.signal, files.line),
            "network + files",
        )
    if crypto is not None and files is not None:
        collector.mark(
            "crypto",
            "T1486",
            "line %d: %s together with %s (line %d) — a hint of encryption of local data"
            % (crypto.line, crypto.signal, files.signal, files.line),
            "cipher + files",
        )


def _safe_problems(analysis: Analysis) -> List[Problem]:
    """Runs the validator to complete the weak hints.

    Args:
        analysis: Source analysis.

    Returns:
        The issues found; an empty list when the validation fails.
    """
    try:
        return validate(analysis)
    except Exception:  # noqa: BLE001 - the hint is optional, the report is not
        logger.debug("validation failed inside the classification", exc_info=True)
        return []


# -------------------------------------------------------------- interface --
def classify(analysis: Analysis, problems: Optional[Sequence[Problem]] = None) -> List[Behavior]:
    """Turns the analysis into readable behaviors.

    Never raises: an unexpected failure returns what was already collected (or an
    empty list) so that the report keeps being generated.

    Args:
        analysis: Analysis returned by :func:`asmx.analyzer.analyze`.
        problems: Validator issues, when the caller already has them. When
            ``None``, the module itself runs :func:`asmx.linter.validate`,
            because that is where the weak ``anti-analysis`` hint comes from.

    Returns:
        List of :class:`Behavior` ordered by severity, confidence and category
        key; empty for an empty program.

    Example:
        >>> from asmx.analyzer import analyze
        >>> categories = [b.category for b in classify(analyze("mov rax, 60\\nsyscall"))]
        >>> categories
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
    except Exception:  # noqa: BLE001 - the classification cannot take the report down
        logger.debug("failed to classify behaviors", exc_info=True)
    return collector.behaviors()


def to_dicts(behaviors: Sequence[Behavior]) -> List[Dict[str, Any]]:
    """Converts a list of behaviors into dictionaries ready for JSON.

    Args:
        behaviors: Classified behaviors.

    Returns:
        List of dictionaries, in the same input order.
    """
    return [behavior.to_dict() for behavior in behaviors]


def techniques(behaviors: Sequence[Behavior]) -> List[Dict[str, Any]]:
    """Lists the ATT&CK techniques cited by the behaviors.

    Args:
        behaviors: Classified behaviors.

    Returns:
        List of dictionaries with ``id``, ``name``, ``tactic``, ``url``,
        ``description`` and ``behaviors`` (the categories that cited the
        technique), in alphabetical order of identifier.
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
    """Groups the techniques by tactic, in the order the report shows them.

    Args:
        behaviors: Classified behaviors.

    Returns:
        Dictionary ``tactic -> techniques``; tactics outside the known order go
        to the end, in alphabetical order.
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
    """Summarizes the behaviors in one line.

    Args:
        behaviors: Classified behaviors.

    Returns:
        Text like ``3 behavior(s): network (high), console (low)``.

    Example:
        >>> summary([])
        '0 behavior(s)'
    """
    items = list(behaviors or [])
    if not items:
        return "0 behavior(s)"
    parts = ["%s (%s)" % (_SHORT_LABELS.get(b.category, b.category), b.severity) for b in items]
    return "%d behavior(s): %s" % (len(items), ", ".join(parts))


def severity_rank(severity: str) -> int:
    """Orders severities: ``high`` comes before ``medium`` and ``low``.

    Args:
        severity: ``high``, ``medium``, ``low`` or any other text (case does not
            matter).

    Returns:
        ``0`` for high, ``1`` for medium, ``2`` for low and ``3`` for an unknown
        value.

    Example:
        >>> severity_rank("high"), severity_rank("MEDIUM"), severity_rank("?")
        (0, 1, 3)
    """
    normalized = str(severity or "").strip().lower()
    return _SEVERITY_RANK.get(normalized, 3)
