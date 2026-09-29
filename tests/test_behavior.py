"""Tests of the behaviors: categories, confidence, ATT&CK and honesty.

Every category has a hand-written piece of assembly, the ready examples are
checked against the result the report expects and the confidence, serialization,
technique and summary rules enter as cases of their own. No test writes a
syscall number by hand: everything comes from :data:`asmx.isa.LINUX_SYSCALLS`.
"""

import types
import unittest
from dataclasses import FrozenInstanceError
from typing import Dict, List, Optional, Sequence, Set
from unittest import mock

from asmx.analyzer import analyze
from asmx.behavior import (
    BEHAVIOR_CATEGORIES,
    MITRE_TECHNIQUES,
    Behavior,
    by_tactic,
    classify,
    severity_rank,
    summary,
    techniques,
    to_dicts,
)
from asmx.examples import EXAMPLES
from asmx.isa import LINUX_SYSCALLS
from asmx.linter import Problem, validate

#: Syscall name -> number, read from the collection.
SYSCALL_NUMBER: Dict[str, int] = {
    data[0]: number for number, data in LINUX_SYSCALLS.items() if data
}

#: Required categories and the severity of each one.
EXPECTED_CATEGORIES: Dict[str, str] = {
    "console-io": "low",
    "network": "high",
    "filesystem": "medium",
    "process": "high",
    "memory": "medium",
    "anti-analysis": "high",
    "crypto": "medium",
    "persistence": "high",
    "environment": "low",
    "data-processing": "low",
    "string-handling": "low",
    "self-modifying": "high",
}

#: Ready examples the report shows and that must stay predictable.
CHECKED_EXAMPLES: Sequence[str] = (
    "linux-hello",
    "linux-loop",
    "linux-function",
    "windows-hello",
    "gcc-att",
    "bubble",
    "broken",
    "overflow",
    "suspicious",
)

#: Tactics accepted in the ATT&CK records.
TACTICS: Set[str] = {
    "Execution",
    "Command and Control",
    "Discovery",
    "Defense Evasion",
    "Persistence",
    "Impact",
    "Collection",
    "Exfiltration",
}


def syscall_source(*names: str) -> str:
    """Builds a source with one syscall per name, using the collection numbers.

    Args:
        *names: Syscall names, as they are in ``LINUX_SYSCALLS``.

    Returns:
        The assembly code ready for :func:`asmx.analyzer.analyze`.
    """
    lines = ["section .text", "_start:"]
    for name in names:
        lines.append("    mov rax, %d" % SYSCALL_NUMBER[name])
        lines.append("    syscall")
    lines.append("    ret")
    return "\n".join(lines)


def behaviors_of(code: str, with_problems: bool = True) -> List[Behavior]:
    """Classifies a source and returns the behaviors found.

    Args:
        code: Assembly source.
        with_problems: Whether to pass the validator issues (``False`` passes an
            empty list, to measure only the signals of the source itself).

    Returns:
        The list returned by :func:`asmx.behavior.classify`.
    """
    analysis = analyze(code)
    problems = validate(analysis) if with_problems else []
    return classify(analysis, problems)


def categories_of(code: str, with_problems: bool = True) -> Set[str]:
    """Returns the set of categories triggered by a source.

    Args:
        code: Assembly source.
        with_problems: Forwarded to :func:`behaviors_of`.

    Returns:
        Set with the keys of the categories found.
    """
    return {b.category for b in behaviors_of(code, with_problems)}


def find_behavior(code: str, category: str) -> Optional[Behavior]:
    """Looks for the behavior of one category in a source.

    Args:
        code: Assembly source.
        category: Key being searched for.

    Returns:
        The matching :class:`~asmx.behavior.Behavior`, or ``None``.
    """
    for found in behaviors_of(code):
        if found.category == category:
            return found
    return None


def make_behavior(mitre: Sequence[str] = ()) -> Behavior:
    """Builds a behavior by hand, to test serialization and techniques.

    Args:
        mitre: Technique identifiers the behavior cites.

    Returns:
        A network :class:`~asmx.behavior.Behavior`, with one evidence item.
    """
    return Behavior(
        category="network",
        label="Network communication",
        description="test",
        severity="high",
        confidence=60,
        lines=(1,),
        evidence=("line 1: syscall socket (creates a socket)",),
        mitre=tuple(mitre),
    )


class TestCatalog(unittest.TestCase):
    """The public tables must match what the report expects."""

    def test_required_categories(self) -> None:
        self.assertEqual(set(BEHAVIOR_CATEGORIES), set(EXPECTED_CATEGORIES))

    def test_severity_of_each_category(self) -> None:
        for key, severity in EXPECTED_CATEGORIES.items():
            with self.subTest(category=key):
                self.assertEqual(BEHAVIOR_CATEGORIES[key]["severity"], severity)

    def test_categories_have_label_and_description(self) -> None:
        for key, entry in BEHAVIOR_CATEGORIES.items():
            with self.subTest(category=key):
                self.assertEqual(set(entry), {"label", "description", "severity"})
                self.assertTrue(entry["label"].strip())
                self.assertTrue(entry["description"].strip())

    def test_mitre_has_the_project_techniques(self) -> None:
        expected = {
            "T1005",
            "T1012",
            "T1027",
            "T1041",
            "T1055",
            "T1057",
            "T1059",
            "T1071",
            "T1082",
            "T1083",
            "T1095",
            "T1105",
            "T1486",
            "T1497",
            "T1543",
            "T1547",
            "T1622",
        }
        self.assertEqual(set(MITRE_TECHNIQUES), expected)

    def test_mitre_has_valid_url_and_tactic(self) -> None:
        for technique, entry in MITRE_TECHNIQUES.items():
            with self.subTest(technique=technique):
                self.assertEqual(
                    entry["url"], "https://attack.mitre.org/techniques/%s/" % technique
                )
                self.assertIn(entry["tactic"], TACTICS)
                self.assertTrue(entry["name"].strip())

    def test_every_technique_description_mentions_a_hint(self) -> None:
        for technique, entry in MITRE_TECHNIQUES.items():
            with self.subTest(technique=technique):
                self.assertIn("A hint", entry["description"])
                self.assertIn("not proof", entry["description"])

    def test_behavior_mitre_exists_in_the_catalog(self) -> None:
        for name in CHECKED_EXAMPLES:
            with self.subTest(example=name):
                for found in behaviors_of(EXAMPLES[name]["code"]):
                    self.assertTrue(set(found.mitre) <= set(MITRE_TECHNIQUES))

    def test_all_categories_are_reachable(self) -> None:
        cases = {
            "console-io": syscall_source("write"),
            "network": syscall_source("socket"),
            "filesystem": syscall_source("open"),
            "process": syscall_source("execve"),
            "memory": "section .text\nmain:\n    mov rax, rdi\n    mov [rax], rbx\n    ret\n",
            "anti-analysis": "section .text\nmain:\n    int 3\n    ret\n",
            "crypto": syscall_source("getrandom"),
            "persistence": 'section .data\n    c db "RunOnce", 0\nsection .text\nmain:\n    ret\n',
            "environment": syscall_source("getpid"),
            "data-processing": "section .text\nmain:\n.loop:\n    add rax, 1\n    jmp .loop\n",
            "string-handling": "section .text\nmain:\n    rep movsb\n    ret\n",
            "self-modifying": (
                "section .text\ntarget:\n    nop\n_start:\n    mov byte [target], 1\n    ret\n"
            ),
        }
        self.assertEqual(set(cases), set(BEHAVIOR_CATEGORIES))
        for category, code in cases.items():
            with self.subTest(category=category):
                self.assertIn(category, categories_of(code))


class TestConsoleAndNetwork(unittest.TestCase):
    """Console and network: the most common signals in a sample program."""

    def test_console_by_write_syscall(self) -> None:
        found = find_behavior(syscall_source("write"), "console-io")
        assert found is not None
        self.assertEqual(found.severity, "low")
        self.assertIn("syscall write", found.evidence[0])

    def test_console_by_read_syscall(self) -> None:
        found = find_behavior(syscall_source("read"), "console-io")
        assert found is not None
        self.assertIn("syscall read", found.evidence[0])

    def test_console_by_windows_apis(self) -> None:
        code = (
            "extern GetStdHandle\n"
            "extern WriteConsoleA\n"
            "section .text\n"
            "main:\n"
            "    sub rsp, 40\n"
            "    mov rcx, -11\n"
            "    call GetStdHandle\n"
            "    mov rcx, rax\n"
            "    mov rdx, msg\n"
            "    mov r8, 5\n"
            "    mov r9, written\n"
            "    call WriteConsoleA\n"
            "    ret\n"
        )
        found = find_behavior(code, "console-io")
        assert found is not None
        self.assertEqual(len(found.evidence), 2)
        self.assertIn("GetStdHandle", found.evidence[0])

    def test_network_by_socket(self) -> None:
        found = find_behavior(syscall_source("socket"), "network")
        assert found is not None
        self.assertEqual(found.severity, "high")
        self.assertIn("T1095", found.mitre)

    def test_network_by_url_in_string(self) -> None:
        code = (
            "section .data\n"
            '    url db "https://collect.example.com/beacon", 0\n'
            "section .text\n"
            "main:\n"
            "    ret\n"
        )
        found = find_behavior(code, "network")
        assert found is not None
        self.assertIn("https://collect.example.com/beacon", found.evidence[0])
        self.assertIn("T1071", found.mitre)

    def test_network_by_ip_in_string(self) -> None:
        code = "section .data\n" '    ip db "10.0.0.7", 0\n' "section .text\n" "main:\n" "    ret\n"
        self.assertIn("network", categories_of(code))

    def test_network_by_wsastartup(self) -> None:
        code = "extern WSAStartup\nsection .text\nmain:\n    call WSAStartup\n    ret\n"
        found = find_behavior(code, "network")
        assert found is not None
        self.assertIn("WSAStartup", found.evidence[0])
        self.assertIn("T1095", found.mitre)

    def test_network_by_url_download(self) -> None:
        code = (
            "extern URLDownloadToFileA\n"
            "section .text\n"
            "main:\n"
            "    call URLDownloadToFileA\n"
            "    ret\n"
        )
        found = find_behavior(code, "network")
        assert found is not None
        self.assertIn("T1105", found.mitre)

    def test_linux_hello_has_no_network(self) -> None:
        self.assertNotIn("network", categories_of(EXAMPLES["linux-hello"]["code"]))

    def test_files_by_open_syscall(self) -> None:
        found = find_behavior(syscall_source("open"), "filesystem")
        assert found is not None
        self.assertEqual(found.severity, "medium")
        self.assertIn("T1005", found.mitre)

    def test_files_by_unix_path(self) -> None:
        code = (
            "section .data\n"
            '    path db "/etc/passwd", 0\n'
            "section .text\n"
            "main:\n"
            "    ret\n"
        )
        found = find_behavior(code, "filesystem")
        assert found is not None
        self.assertIn("/etc/", found.evidence[0])
        self.assertIn("T1083", found.mitre)

    def test_files_by_windows_path(self) -> None:
        code = (
            "section .data\n"
            '    path db "C:\\Users\\Public\\data.txt", 0\n'
            "section .text\n"
            "main:\n"
            "    ret\n"
        )
        self.assertIn("filesystem", categories_of(code))

    def test_files_by_createfile_api(self) -> None:
        code = "extern CreateFileA\nsection .text\nmain:\n    call CreateFileA\n    ret\n"
        found = find_behavior(code, "filesystem")
        assert found is not None
        self.assertIn("CreateFileA", found.evidence[0])


class TestProcessAndMemory(unittest.TestCase):
    """Process and memory, including the false alarm that was fixed."""

    def test_process_by_execve(self) -> None:
        found = find_behavior(syscall_source("execve"), "process")
        assert found is not None
        self.assertEqual(found.severity, "high")
        self.assertIn("T1059", found.mitre)

    def test_process_by_createprocess(self) -> None:
        code = "extern CreateProcessA\nsection .text\nmain:\n    call CreateProcessA\n    ret\n"
        found = find_behavior(code, "process")
        assert found is not None
        self.assertIn("CreateProcessA", found.evidence[0])

    def test_process_by_external_execution_function(self) -> None:
        code = "extern system\nsection .text\nmain:\n    call system\n    ret\n"
        found = find_behavior(code, "process")
        assert found is not None
        self.assertIn("call system", found.evidence[0])

    def test_ending_the_program_is_not_process(self) -> None:
        exitprocess = (
            "extern ExitProcess\nsection .text\nmain:\n    xor rcx, rcx\n    call ExitProcess\n"
        )
        self.assertNotIn("process", categories_of(exitprocess))
        self.assertEqual(categories_of(exitprocess), set())
        self.assertNotIn("process", categories_of(syscall_source("exit")))

    def test_indirect_call_is_not_an_external_function(self) -> None:
        code = "section .text\nmain:\n    call [rbx]\n    ret\n"
        self.assertEqual(categories_of(code), set())

    def test_memory_by_write_through_pointer(self) -> None:
        code = "section .text\nmain:\n    mov rax, rdi\n    mov [rax], rbx\n    ret\n"
        found = find_behavior(code, "memory")
        assert found is not None
        self.assertIn("address pointed to", found.evidence[0])

    def test_memory_by_undeclared_symbol(self) -> None:
        code = "section .text\nmain:\n    mov [counter], 1\n    ret\n"
        found = find_behavior(code, "memory")
        assert found is not None
        self.assertIn("counter", found.evidence[0])

    def test_memory_by_mmap_and_mprotect(self) -> None:
        found = find_behavior(syscall_source("mmap", "mprotect"), "memory")
        assert found is not None
        self.assertIn("T1055", found.mitre)

    def test_memory_by_virtualalloc(self) -> None:
        code = "extern VirtualAlloc\nsection .text\nmain:\n    call VirtualAlloc\n    ret\n"
        found = find_behavior(code, "memory")
        assert found is not None
        self.assertIn("VirtualAlloc", found.evidence[0])

    def test_memory_does_not_fire_on_local_variable(self) -> None:
        code = "section .text\nmain:\n    mov [rbp-8], rax\n    mov rax, [rbp-8]\n    ret\n"
        self.assertNotIn("memory", categories_of(code))


class TestEvasionCryptoAndPersistence(unittest.TestCase):
    """The high severity signals and the weak hints."""

    def test_anti_analysis_by_int3(self) -> None:
        found = find_behavior("section .text\nmain:\n    int 3\n    ret\n", "anti-analysis")
        assert found is not None
        self.assertIn("int 3", found.evidence[0])
        self.assertIn("T1622", found.mitre)

    def test_anti_analysis_by_cpuid_and_rdtsc(self) -> None:
        found = find_behavior(
            "section .text\nmain:\n    cpuid\n    rdtsc\n    ret\n", "anti-analysis"
        )
        assert found is not None
        self.assertEqual(len(found.evidence), 2)
        self.assertIn("T1497", found.mitre)

    def test_anti_analysis_by_glued_int3(self) -> None:
        found = find_behavior("section .text\nmain:\n    int3\n    ret\n", "anti-analysis")
        assert found is not None
        self.assertIn("int 3", found.evidence[0])

    def test_anti_analysis_by_warning_without_instruction_on_the_line(self) -> None:
        code = "section .text\nmain:\n    nop\n"
        problems = [Problem(2, "info", "INT001", "internal failure in rule check_x")]
        found = classify(analyze(code), problems)
        found_categories = {b.category for b in found}
        self.assertIn("anti-analysis", found_categories)
        behavior = [b for b in found if b.category == "anti-analysis"][0]
        self.assertIn("check_x", behavior.evidence[0])
        self.assertLessEqual(behavior.confidence, 50)

    def test_anti_analysis_by_ptrace(self) -> None:
        found = find_behavior(syscall_source("ptrace"), "anti-analysis")
        assert found is not None
        self.assertIn("syscall ptrace", found.evidence[0])
        self.assertIn("T1622", found.mitre)

    def test_anti_analysis_by_time_in_loop_is_weak(self) -> None:
        code = "section .text\nmain:\n.loop:\n    mov rax, 201\n    syscall\n    jmp .loop\n"
        found = find_behavior(code, "anti-analysis")
        assert found is not None
        self.assertLessEqual(found.confidence, 50)
        self.assertIn("hint", found.evidence[0])

    def test_anti_analysis_with_validator_flow_warning(self) -> None:
        code = "section .text\nmain:\n.stuck:\n    jmp .stuck\n"
        with_warning = categories_of(code)
        without_warning = categories_of(code, with_problems=False)
        self.assertIn("anti-analysis", with_warning)
        self.assertNotIn("anti-analysis", without_warning)

    def test_anti_analysis_by_warning_is_always_weak(self) -> None:
        code = "section .text\nmain:\n.stuck:\n    jmp .stuck\n"
        found = find_behavior(code, "anti-analysis")
        assert found is not None
        self.assertLessEqual(found.confidence, 50)
        self.assertIn("FLOW002", found.evidence[0])

    def test_crypto_by_getrandom(self) -> None:
        found = find_behavior(syscall_source("getrandom"), "crypto")
        assert found is not None
        self.assertEqual(found.severity, "medium")
        self.assertIn("syscall getrandom", found.evidence[0])

    def test_crypto_by_bit_loop_is_weak(self) -> None:
        code = (
            "section .text\n"
            "main:\n"
            ".loop:\n"
            "    xor rbx, rcx\n"
            "    shl rbx, 3\n"
            "    shr rbx, 1\n"
            "    rol rbx, 2\n"
            "    ror rbx, 5\n"
            "    jmp .loop\n"
        )
        found = find_behavior(code, "crypto")
        assert found is not None
        self.assertLessEqual(found.confidence, 50)
        self.assertIn("hint", found.evidence[0])
        self.assertIn("T1027", found.mitre)

    def test_zeroing_xor_does_not_count_as_cipher(self) -> None:
        code = (
            "section .text\n"
            "main:\n"
            ".loop:\n"
            "    xor rax, rax\n"
            "    xor rbx, rbx\n"
            "    xor rcx, rcx\n"
            "    xor rdx, rdx\n"
            "    jmp .loop\n"
        )
        self.assertNotIn("crypto", categories_of(code))

    def test_persistence_by_run_key(self) -> None:
        code = (
            "section .data\n"
            '    key db "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0\n'
            "section .text\n"
            "main:\n"
            "    ret\n"
        )
        found = find_behavior(code, "persistence")
        assert found is not None
        self.assertEqual(found.severity, "high")
        self.assertIn("T1547", found.mitre)

    def test_persistence_by_cron(self) -> None:
        code = (
            "section .data\n"
            '    target db "/etc/cron.d/backdoor", 0\n'
            "section .text\n"
            "main:\n"
            "    ret\n"
        )
        found = find_behavior(code, "persistence")
        assert found is not None
        self.assertIn("T1543", found.mitre)

    def test_persistence_by_file_in_loop(self) -> None:
        code = (
            "section .data\n"
            '    text db "x", 0\n'
            "section .text\n"
            "main:\n"
            ".loop:\n"
            "    mov rax, 2\n"
            "    syscall\n"
            "    jmp .loop\n"
        )
        found = find_behavior(code, "persistence")
        assert found is not None
        self.assertIn("syscall open", found.evidence[0])
        self.assertIn("filesystem", categories_of(code))

    def test_persistence_by_file_api_in_loop(self) -> None:
        code = (
            "extern CreateFileA\n"
            "section .text\n"
            "main:\n"
            ".loop:\n"
            "    call CreateFileA\n"
            "    jmp .loop\n"
        )
        found = find_behavior(code, "persistence")
        assert found is not None
        self.assertIn("API CreateFileA", found.evidence[0])


class TestEnvironmentAndAlgorithm(unittest.TestCase):
    """The low severity categories and the self-modifying code."""

    def test_environment_by_getpid_and_time(self) -> None:
        found = find_behavior(syscall_source("getpid", "time"), "environment")
        assert found is not None
        self.assertIn("T1057", found.mitre)
        self.assertIn("T1082", found.mitre)

    def test_environment_by_windows_apis(self) -> None:
        code = (
            "extern GetLastError\n"
            "extern GetVersion\n"
            "section .text\n"
            "main:\n"
            "    call GetLastError\n"
            "    call GetVersion\n"
            "    ret\n"
        )
        found = find_behavior(code, "environment")
        assert found is not None
        self.assertEqual(len(found.evidence), 2)

    def test_data_processing_by_loop(self) -> None:
        code = (
            "section .text\n"
            "main:\n"
            "    mov rcx, 5\n"
            ".loop:\n"
            "    add rax, rcx\n"
            "    dec rcx\n"
            "    jnz .loop\n"
            "    ret\n"
        )
        found = find_behavior(code, "data-processing")
        assert found is not None
        self.assertIn("add rax rcx", found.evidence[0])
        self.assertEqual(found.mitre, ())

    def test_comparison_only_loop_is_not_an_algorithm(self) -> None:
        code = (
            "section .text\n" "main:\n" ".loop:\n" "    cmp rcx, 0\n" "    jne .loop\n" "    ret\n"
        )
        self.assertNotIn("data-processing", categories_of(code))

    def test_string_handling_by_rep_movsb(self) -> None:
        code = "section .text\nmain:\n    cld\n    rep movsb\n    ret\n"
        found = find_behavior(code, "string-handling")
        assert found is not None
        self.assertIn("rep movsb", found.evidence[0])

    def test_string_handling_by_indexed_loop(self) -> None:
        code = (
            "section .data\n"
            "    array db 1, 2, 3, 4\n"
            "section .text\n"
            "main:\n"
            "    mov rsi, 0\n"
            ".loop:\n"
            "    mov al, [array + rsi]\n"
            "    mov [array + rsi], al\n"
            "    inc rsi\n"
            "    cmp rsi, 4\n"
            "    jb .loop\n"
            "    ret\n"
        )
        found = find_behavior(code, "string-handling")
        assert found is not None
        self.assertLessEqual(found.confidence, 50)

    def test_self_modifying_by_write_to_code_label(self) -> None:
        code = (
            "section .text\n"
            "target:\n"
            "    nop\n"
            "_start:\n"
            "    mov byte [target], 0x90\n"
            "    ret\n"
        )
        found = find_behavior(code, "self-modifying")
        assert found is not None
        self.assertEqual(found.severity, "high")
        self.assertIn("target", found.evidence[0])
        self.assertIn("T1027", found.mitre)

    def test_write_to_data_variable_is_not_self_modifying(self) -> None:
        code = (
            "section .data\n"
            "    target db 0\n"
            "section .text\n"
            "main:\n"
            "    mov byte [target], 1\n"
            "    ret\n"
        )
        self.assertNotIn("self-modifying", categories_of(code))

    def test_self_modifying_without_section_directive(self) -> None:
        code = "target:\n    nop\n_start:\n    mov byte [target], 0x90\n    ret\n"
        self.assertIn("self-modifying", categories_of(code))

    def test_memory_by_rtlmovememory(self) -> None:
        code = "extern RtlMoveMemory\nsection .text\nmain:\n    call RtlMoveMemory\n    ret\n"
        found = find_behavior(code, "memory")
        assert found is not None
        self.assertIn("RtlMoveMemory", found.evidence[0])
        self.assertIn("process memory", found.evidence[0])


class TestExamples(unittest.TestCase):
    """The ready examples must keep the reading the report promises."""

    def test_linux_hello(self) -> None:
        found = behaviors_of(EXAMPLES["linux-hello"]["code"])
        self.assertEqual([b.category for b in found], ["console-io"])
        self.assertEqual(found[0].severity, "low")

    def test_linux_loop(self) -> None:
        self.assertEqual(categories_of(EXAMPLES["linux-loop"]["code"]), {"console-io"})

    def test_linux_function(self) -> None:
        found = categories_of(EXAMPLES["linux-function"]["code"])
        self.assertIn("console-io", found)
        self.assertIn("memory", found)
        self.assertNotIn("network", found)

    def test_windows_hello_only_console(self) -> None:
        found = behaviors_of(EXAMPLES["windows-hello"]["code"])
        self.assertEqual([b.category for b in found], ["console-io"])
        self.assertEqual(found[0].severity, "low")

    def test_windows_hello_has_no_high_behavior(self) -> None:
        for found in behaviors_of(EXAMPLES["windows-hello"]["code"]):
            self.assertNotEqual(found.severity, "high")

    def test_gcc_att_raises_nothing_and_invents_nothing(self) -> None:
        found = behaviors_of(EXAMPLES["gcc-att"]["code"])
        self.assertEqual([b.category for b in found], [])

    def test_bubble_is_algorithm_and_byte_block(self) -> None:
        found = categories_of(EXAMPLES["bubble"]["code"])
        self.assertIn("data-processing", found)
        self.assertIn("string-handling", found)

    def test_broken_has_at_least_two_categories(self) -> None:
        found = categories_of(EXAMPLES["broken"]["code"])
        self.assertGreaterEqual(len(found), 2)
        self.assertIn("anti-analysis", found)

    def test_overflow_is_data_processing(self) -> None:
        found = categories_of(EXAMPLES["overflow"]["code"])
        self.assertIn("data-processing", found)
        self.assertNotIn("network", found)

    def test_suspicious_has_network_file_and_crypto(self) -> None:
        found = {b.category: b for b in behaviors_of(EXAMPLES["suspicious"]["code"])}
        self.assertEqual(found["network"].severity, "high")
        self.assertEqual(found["crypto"].severity, "medium")
        self.assertEqual(found["filesystem"].severity, "medium")
        self.assertIn("console-io", found)
        self.assertIn("environment", found)

    def test_suspicious_does_not_invent_process(self) -> None:
        self.assertNotIn("process", categories_of(EXAMPLES["suspicious"]["code"]))

    def test_every_example_has_evidence_with_line(self) -> None:
        for name in CHECKED_EXAMPLES:
            with self.subTest(example=name):
                for found in behaviors_of(EXAMPLES[name]["code"]):
                    self.assertTrue(found.evidence)
                    for evidence in found.evidence:
                        self.assertRegex(evidence, r"^line \d+: \S")

    def test_every_example_returns_a_list(self) -> None:
        for name in CHECKED_EXAMPLES:
            with self.subTest(example=name):
                self.assertIsInstance(behaviors_of(EXAMPLES[name]["code"]), list)


class TestRules(unittest.TestCase):
    """Confidence, ordering and evidence format."""

    def test_confidence_60_with_few_evidence_items(self) -> None:
        one = find_behavior(syscall_source("write"), "console-io")
        two = find_behavior(syscall_source("write", "read"), "console-io")
        assert one is not None and two is not None
        self.assertEqual(one.confidence, 60)
        self.assertEqual(two.confidence, 60)

    def test_confidence_80_with_three_to_five_evidence_items(self) -> None:
        found = find_behavior(syscall_source("socket", "connect", "bind"), "network")
        assert found is not None
        self.assertEqual(len(found.evidence), 3)
        self.assertEqual(found.confidence, 80)

    def test_confidence_95_with_six_evidence_items(self) -> None:
        code = syscall_source("socket", "connect", "bind", "listen", "accept", "sendto")
        found = find_behavior(code, "network")
        assert found is not None
        self.assertEqual(len(found.evidence), 6)
        self.assertEqual(found.confidence, 95)

    def test_confidence_always_between_zero_and_one_hundred(self) -> None:
        for name in CHECKED_EXAMPLES:
            for found in behaviors_of(EXAMPLES[name]["code"]):
                self.assertGreaterEqual(found.confidence, 0)
                self.assertLessEqual(found.confidence, 100)

    def test_ordering_by_severity(self) -> None:
        found = behaviors_of(syscall_source("socket", "write"))
        ranks = [severity_rank(b.severity) for b in found]
        self.assertEqual(ranks, sorted(ranks))
        self.assertEqual(found[0].category, "network")

    def test_lines_sorted_and_without_repetition(self) -> None:
        for name in CHECKED_EXAMPLES:
            for found in behaviors_of(EXAMPLES[name]["code"]):
                self.assertEqual(list(found.lines), sorted(set(found.lines)))

    def test_evidence_cites_line_and_signal(self) -> None:
        found = find_behavior(syscall_source("socket", "connect"), "network")
        assert found is not None
        for evidence in found.evidence:
            self.assertRegex(evidence, r"^line \d+: ")
        self.assertTrue(any("syscall socket" in e for e in found.evidence))
        self.assertTrue(any("syscall connect" in e for e in found.evidence))

    def test_category_without_signal_does_not_appear(self) -> None:
        code = "section .text\nmain:\n    mov rax, 1\n    add rax, 2\n    ret\n"
        self.assertEqual(categories_of(code), set())

    def test_unknown_syscall_number_invents_no_category(self) -> None:
        code = "section .text\n_start:\n    mov rax, 999\n    syscall\n    ret\n"
        self.assertEqual(categories_of(code), set())

    def test_behavior_severity_comes_from_the_catalog(self) -> None:
        for name in CHECKED_EXAMPLES:
            for found in behaviors_of(EXAMPLES[name]["code"]):
                self.assertEqual(found.severity, BEHAVIOR_CATEGORIES[found.category]["severity"])


class TestSerialization(unittest.TestCase):
    """``to_dicts``, ``techniques``, ``by_tactic``, ``summary`` and the ordering."""

    def test_to_dicts_returns_dictionaries(self) -> None:
        found = behaviors_of(EXAMPLES["suspicious"]["code"])
        dictionaries = to_dicts(found)
        self.assertEqual(len(dictionaries), len(found))
        for dictionary in dictionaries:
            self.assertEqual(
                set(dictionary),
                {
                    "category",
                    "label",
                    "description",
                    "severity",
                    "confidence",
                    "lines",
                    "evidence",
                    "mitre",
                },
            )

    def test_to_dicts_uses_lists(self) -> None:
        dictionary = to_dicts([make_behavior(["T1095"])])[0]
        self.assertEqual(dictionary["lines"], [1])
        self.assertEqual(dictionary["evidence"], ["line 1: syscall socket (creates a socket)"])
        self.assertEqual(dictionary["mitre"], ["T1095"])

    def test_to_dicts_of_an_empty_list(self) -> None:
        self.assertEqual(to_dicts([]), [])

    def test_behavior_is_immutable(self) -> None:
        found = make_behavior()
        with self.assertRaises(FrozenInstanceError):
            setattr(found, "category", "other")

    def test_techniques_groups_by_technique(self) -> None:
        found = behaviors_of(EXAMPLES["suspicious"]["code"])
        items = techniques(found)
        ids = [technique["id"] for technique in items]
        self.assertEqual(ids, sorted(ids))
        self.assertIn("T1095", ids)
        self.assertIn("T1071", ids)
        self.assertIn("T1486", ids)
        for technique in items:
            self.assertTrue(technique["behaviors"])
            self.assertEqual(
                technique["url"], "https://attack.mitre.org/techniques/%s/" % technique["id"]
            )

    def test_techniques_without_behavior(self) -> None:
        self.assertEqual(techniques([]), [])

    def test_techniques_ignores_unknown_identifier(self) -> None:
        self.assertEqual(techniques([make_behavior(["T9999"])]), [])

    def test_techniques_does_not_repeat_category(self) -> None:
        items = techniques([make_behavior(["T1095"]), make_behavior(["T1095"])])
        self.assertEqual(items[0]["behaviors"], ["network"])

    def test_by_tactic_with_tactic_outside_the_order(self) -> None:
        entry = {
            "name": "Test technique",
            "tactic": "Curiosity",
            "url": "https://attack.mitre.org/techniques/T9999/",
            "description": "A hint derived from static patterns.",
        }
        with mock.patch.dict(MITRE_TECHNIQUES, {"T9999": entry}):
            groups = by_tactic([make_behavior(["T9999"])])
        self.assertEqual(list(groups), ["Curiosity"])

    def test_by_tactic_orders_the_tactics(self) -> None:
        found = behaviors_of(EXAMPLES["suspicious"]["code"])
        groups = by_tactic(found)
        self.assertEqual(
            list(groups),
            ["Command and Control", "Discovery", "Collection", "Exfiltration", "Impact"],
        )
        for tactic, items in groups.items():
            for technique in items:
                self.assertEqual(technique["tactic"], tactic)

    def test_by_tactic_without_behavior(self) -> None:
        self.assertEqual(by_tactic([]), {})

    def test_summary_empty(self) -> None:
        self.assertEqual(summary([]), "0 behavior(s)")

    def test_summary_with_several(self) -> None:
        found = behaviors_of(EXAMPLES["suspicious"]["code"])
        self.assertEqual(
            summary(found),
            "5 behavior(s): network (high), crypto (medium), files (medium), "
            "console (low), environment (low)",
        )

    def test_summary_with_one(self) -> None:
        self.assertEqual(
            summary(behaviors_of(EXAMPLES["linux-hello"]["code"])),
            "1 behavior(s): console (low)",
        )

    def test_severity_rank_orders(self) -> None:
        self.assertEqual(severity_rank("high"), 0)
        self.assertEqual(severity_rank("medium"), 1)
        self.assertEqual(severity_rank("low"), 2)

    def test_severity_rank_accepts_case(self) -> None:
        self.assertEqual(severity_rank("HIGH"), 0)
        self.assertEqual(severity_rank(" Medium "), 1)

    def test_severity_rank_unknown(self) -> None:
        self.assertEqual(severity_rank("urgent"), 3)
        self.assertEqual(severity_rank(""), 3)


class TestEdges(unittest.TestCase):
    """Empty program, data only, garbage and the seam with the validator."""

    def test_empty_program(self) -> None:
        self.assertEqual(classify(analyze("")), [])

    def test_whitespace_only_program(self) -> None:
        self.assertEqual(classify(analyze("\n\n   \n\t\n")), [])

    def test_data_only_program(self) -> None:
        code = 'section .data\n    msg db "simple text", 10\n    size equ $ - msg\n'
        self.assertEqual(categories_of(code), set())

    def test_data_only_program_with_url(self) -> None:
        code = 'section .data\n    u db "http://x.example.com", 0\n'
        self.assertIn("network", categories_of(code))

    def test_windows_masm_program(self) -> None:
        code = (
            ".386\n"
            ".model flat, stdcall\n"
            "includelib kernel32.lib\n"
            ".data\n"
            '    msg db "hi", 0\n'
            ".code\n"
            "main PROC\n"
            "    sub rsp, 40\n"
            "    mov rcx, -11\n"
            "    call GetStdHandle\n"
            "    mov rcx, rax\n"
            "    mov rdx, msg\n"
            "    mov r8, 5\n"
            "    mov r9, written\n"
            "    call WriteConsoleA\n"
            "    ret\n"
            "main ENDP\n"
            "end main\n"
        )
        self.assertEqual(categories_of(code), {"console-io"})

    def test_classify_does_not_raise_on_garbage(self) -> None:
        for code in ("\x00\x01 ??? @@\n", "a" * 500, "ПРИВЕТ\n mov ,,\n"):
            with self.subTest(code=code[:12]):
                self.assertIsInstance(classify(analyze(code)), list)

    def test_classify_accepts_none_problems(self) -> None:
        code = "section .text\nmain:\n.stuck:\n    jmp .stuck\n"
        analysis = analyze(code)
        automatic = [b.category for b in classify(analysis)]
        explicit = [b.category for b in classify(analysis, validate(analysis))]
        self.assertEqual(automatic, explicit)

    def test_classify_without_problems_does_not_use_the_validator(self) -> None:
        code = "section .text\nmain:\n.stuck:\n    jmp .stuck\n"
        self.assertEqual(classify(analyze(code), []), [])

    def test_classify_with_null_analysis(self) -> None:
        self.assertEqual(classify(None), [])  # type: ignore[arg-type]

    def test_classify_with_program_without_lines(self) -> None:
        empty = types.SimpleNamespace(program=types.SimpleNamespace(lines=[]))
        self.assertEqual(classify(empty), [])  # type: ignore[arg-type]

    def test_validator_failure_does_not_take_the_report_down(self) -> None:
        code = EXAMPLES["linux-hello"]["code"]
        with mock.patch("asmx.behavior.validate", side_effect=RuntimeError("blew up")):
            found = classify(analyze(code))
        self.assertEqual([b.category for b in found], ["console-io"])

    def test_internal_failure_returns_a_list(self) -> None:
        code = "section .text\nmain:\n    mov rax, 1\n    syscall\n    ret\n"
        with mock.patch("asmx.behavior._context", side_effect=RuntimeError("blew up")):
            self.assertEqual(classify(analyze(code)), [])


if __name__ == "__main__":
    unittest.main()
