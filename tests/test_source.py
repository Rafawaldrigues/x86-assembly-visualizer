"""Testes de leitura de arquivos: codificação, hash, limites e erros."""

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


class TestDecodificacao(unittest.TestCase):
    """Aceitar arquivo que não está em UTF-8 faz parte do trabalho."""

    def test_utf8_simples(self) -> None:
        self.assertEqual(decode_text(b"mov rax, 1"), ("mov rax, 1", "utf-8"))

    def test_utf8_com_bom(self) -> None:
        texto, encoding = decode_text("mov rax, 1".encode("utf-8-sig"))
        self.assertEqual(texto, "mov rax, 1")
        self.assertEqual(encoding, "utf-8-sig")

    def test_latin1_como_rede(self) -> None:
        texto, encoding = decode_text("; ação".encode("latin-1"))
        self.assertEqual(encoding, "latin-1")
        self.assertIn("ação", texto)

    def test_nunca_levanta_excecao(self) -> None:
        texto, encoding = decode_text(bytes(range(256)))
        self.assertEqual(encoding, "latin-1")
        self.assertEqual(len(texto), 256)


class TestHashes(unittest.TestCase):
    """Hash e impressão digital identificam o conteúdo."""

    def test_sha256_conhecido(self) -> None:
        self.assertTrue(sha256_of(b"").startswith("e3b0c44298fc1c14"))

    def test_fingerprint_tem_o_tamanho_pedido(self) -> None:
        self.assertEqual(len(fingerprint("mov rax, 1", 8)), 8)
        self.assertEqual(len(fingerprint("mov rax, 1")), 12)

    def test_fingerprint_ignora_fim_de_linha_e_espaco_final(self) -> None:
        self.assertEqual(
            fingerprint("mov rax, 1\nmov rbx, 2"), fingerprint("mov rax, 1  \r\nmov rbx, 2\r\n")
        )

    def test_fingerprint_muda_quando_o_codigo_muda(self) -> None:
        self.assertNotEqual(fingerprint("mov rax, 1"), fingerprint("mov rax, 2"))


class TestReadSource(unittest.TestCase):
    """Leitura de arquivo de verdade, em diretório temporário."""

    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.caminho = os.path.join(self.dir.name, "prog.asm")
        with open(self.caminho, "w", encoding="utf-8") as arquivo:
            arquivo.write("mov rax, 1\nsyscall\n")

    def tearDown(self) -> None:
        self.dir.cleanup()

    def test_metadados(self) -> None:
        fonte = read_source(self.caminho)
        self.assertEqual(fonte.name, "prog.asm")
        self.assertEqual(fonte.suffix, ".asm")
        self.assertEqual(fonte.lines, 2)
        self.assertEqual(fonte.size, 19)
        self.assertEqual(fonte.encoding, "utf-8")
        with open(self.caminho, "rb") as arquivo:
            self.assertEqual(fonte.sha256, sha256_of(arquivo.read()))

    def test_to_dict(self) -> None:
        dados = read_source(self.caminho).to_dict()
        self.assertEqual(dados["name"], "prog.asm")
        self.assertEqual(
            set(dados), {"name", "path", "size", "lines", "encoding", "sha256", "fingerprint"}
        )

    def test_extensao_aceita(self) -> None:
        fonte = read_source(self.caminho, suffixes=SOURCE_SUFFIXES)
        self.assertEqual(fonte.suffix, ".asm")

    def test_arquivo_sem_extensao_e_aceito(self) -> None:
        caminho = os.path.join(self.dir.name, "sem_extensao")
        with open(caminho, "w", encoding="utf-8") as arquivo:
            arquivo.write("nop\n")
        self.assertEqual(read_source(caminho, suffixes=SOURCE_SUFFIXES).lines, 1)

    def test_extensao_recusada(self) -> None:
        caminho = os.path.join(self.dir.name, "malware.bin")
        with open(caminho, "wb") as arquivo:
            arquivo.write(b"\x7fELF")
        with self.assertRaises(UnsupportedSourceError):
            read_source(caminho, suffixes=SOURCE_SUFFIXES)

    def test_extensoes_de_projeto(self) -> None:
        self.assertIn(".asmproj", PROJECT_SUFFIXES)

    def test_arquivo_binario_e_recusado(self) -> None:
        caminho = os.path.join(self.dir.name, "binario.asm")
        with open(caminho, "wb") as arquivo:
            arquivo.write(b"\x7fELF\x00\x01\x02mov rax, 1")
        with self.assertRaises(ParseError) as contexto:
            read_source(caminho)
        self.assertIn("bytes nulos", str(contexto.exception))

    def test_arquivo_ausente(self) -> None:
        with self.assertRaises(SourceNotFoundError):
            read_source(os.path.join(self.dir.name, "nao_existe.asm"))

    def test_diretorio_e_erro_de_leitura(self) -> None:
        with self.assertRaises(SourceReadError):
            read_source(self.dir.name)

    def test_limite_de_tamanho(self) -> None:
        with self.assertRaises(SourceReadError):
            read_source(self.caminho, max_bytes=4)

    def test_arquivo_latin1_e_lido(self) -> None:
        caminho = os.path.join(self.dir.name, "acentos.asm")
        with open(caminho, "wb") as arquivo:
            arquivo.write("; ação\nnop\n".encode("latin-1"))
        fonte = read_source(caminho)
        self.assertEqual(fonte.encoding, "latin-1")
        self.assertIn("ação", fonte.text)

    def test_til_e_expandido(self) -> None:
        with unittest.mock.patch.dict(os.environ, {"HOME": self.dir.name}):
            fonte = read_source("~/prog.asm")
        self.assertEqual(fonte.path, os.path.join(self.dir.name, "prog.asm"))


if __name__ == "__main__":
    unittest.main()
