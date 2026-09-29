"""Tests of file reading: encoding, hash, limits and errors."""

import os
import tempfile
import unittest
import unittest.mock

from asmx.errors import ParseError, SourceNotFoundError, SourceReadError, UnsupportedSourceError
from asmx.source import (
    PROJECT_SUFFIXES,
    SOURCE_SUFFIXES,
    decode_text,
    fingerprint,
    read_source,
    sha256_of,
)


class TestDecoding(unittest.TestCase):
    """Accepting a file that is not UTF-8 is part of the job."""

    def test_plain_utf8(self) -> None:
        self.assertEqual(decode_text(b"mov rax, 1"), ("mov rax, 1", "utf-8"))

    def test_utf8_with_bom(self) -> None:
        text, encoding = decode_text("mov rax, 1".encode("utf-8-sig"))
        self.assertEqual(text, "mov rax, 1")
        self.assertEqual(encoding, "utf-8-sig")

    def test_latin1_as_fallback(self) -> None:
        text, encoding = decode_text(b"; temp: 20\xb0C\n")
        self.assertEqual(encoding, "latin-1")
        self.assertIn("20\u00b0C", text)

    def test_never_raises(self) -> None:
        text, encoding = decode_text(bytes(range(256)))
        self.assertEqual(encoding, "latin-1")
        self.assertEqual(len(text), 256)


class TestHashes(unittest.TestCase):
    """Hash and fingerprint identify the content."""

    def test_known_sha256(self) -> None:
        self.assertTrue(sha256_of(b"").startswith("e3b0c44298fc1c14"))

    def test_fingerprint_has_the_requested_size(self) -> None:
        self.assertEqual(len(fingerprint("mov rax, 1", 8)), 8)
        self.assertEqual(len(fingerprint("mov rax, 1")), 12)

    def test_fingerprint_ignores_line_endings_and_trailing_spaces(self) -> None:
        self.assertEqual(
            fingerprint("mov rax, 1\nmov rbx, 2"), fingerprint("mov rax, 1  \r\nmov rbx, 2\r\n")
        )

    def test_fingerprint_changes_when_the_code_changes(self) -> None:
        self.assertNotEqual(fingerprint("mov rax, 1"), fingerprint("mov rax, 2"))


class TestReadSource(unittest.TestCase):
    """Reading a real file, in a temporary directory."""

    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "prog.asm")
        with open(self.path, "w", encoding="utf-8") as file:
            file.write("mov rax, 1\nsyscall\n")

    def tearDown(self) -> None:
        self.dir.cleanup()

    def test_metadata(self) -> None:
        source = read_source(self.path)
        self.assertEqual(source.name, "prog.asm")
        self.assertEqual(source.suffix, ".asm")
        self.assertEqual(source.lines, 2)
        self.assertEqual(source.size, 19)
        self.assertEqual(source.encoding, "utf-8")
        with open(self.path, "rb") as file:
            self.assertEqual(source.sha256, sha256_of(file.read()))

    def test_to_dict(self) -> None:
        data = read_source(self.path).to_dict()
        self.assertEqual(data["name"], "prog.asm")
        self.assertEqual(
            set(data), {"name", "path", "size", "lines", "encoding", "sha256", "fingerprint"}
        )

    def test_accepted_extension(self) -> None:
        source = read_source(self.path, suffixes=SOURCE_SUFFIXES)
        self.assertEqual(source.suffix, ".asm")

    def test_file_without_extension_is_accepted(self) -> None:
        path = os.path.join(self.dir.name, "no_extension")
        with open(path, "w", encoding="utf-8") as file:
            file.write("nop\n")
        self.assertEqual(read_source(path, suffixes=SOURCE_SUFFIXES).lines, 1)

    def test_refused_extension(self) -> None:
        path = os.path.join(self.dir.name, "malware.bin")
        with open(path, "wb") as file:
            file.write(b"\x7fELF")
        with self.assertRaises(UnsupportedSourceError):
            read_source(path, suffixes=SOURCE_SUFFIXES)

    def test_project_extensions(self) -> None:
        self.assertIn(".asmproj", PROJECT_SUFFIXES)

    def test_binary_file_is_refused(self) -> None:
        path = os.path.join(self.dir.name, "binary.asm")
        with open(path, "wb") as file:
            file.write(b"\x7fELF\x00\x01\x02mov rax, 1")
        with self.assertRaises(ParseError) as context:
            read_source(path)
        self.assertIn("null bytes", str(context.exception))

    def test_missing_file(self) -> None:
        with self.assertRaises(SourceNotFoundError):
            read_source(os.path.join(self.dir.name, "does_not_exist.asm"))

    def test_directory_is_a_read_error(self) -> None:
        with self.assertRaises(SourceReadError):
            read_source(self.dir.name)

    def test_size_limit(self) -> None:
        with self.assertRaises(SourceReadError):
            read_source(self.path, max_bytes=4)

    def test_latin1_file_is_read(self) -> None:
        path = os.path.join(self.dir.name, "latin1.asm")
        with open(path, "wb") as file:
            file.write(b"; temp: 20\xb0C\nnop\n")
        source = read_source(path)
        self.assertEqual(source.encoding, "latin-1")
        self.assertIn("20\u00b0C", source.text)

    def test_tilde_is_expanded(self) -> None:
        with unittest.mock.patch.dict(os.environ, {"HOME": self.dir.name}):
            source = read_source("~/prog.asm")
        self.assertEqual(source.path, os.path.join(self.dir.name, "prog.asm"))


if __name__ == "__main__":
    unittest.main()
