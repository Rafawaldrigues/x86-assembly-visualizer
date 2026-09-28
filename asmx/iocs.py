"""Indicadores de compromisso e strings interessantes escondidos no fonte.

A análise de comportamento diz o que o programa *faz*; este módulo responde a
outra pergunta: o que está *escrito* dentro dele. URLs, endereços IP, domínios,
caminhos, chaves de registro, comandos e palavras-chave são procurados nos
literais de dados (``db``, ``dq``...) e nos comentários do fonte — e também na
memória, depois que o programa roda, com :func:`from_memory`.

O ponto de partida é :func:`strings_of`, que devolve as strings de cada linha;
:func:`extract` classifica cada uma e devolve a lista de :class:`Ioc`, já sem
repetições. Nada aqui levanta exceção: fonte vazia, binária ou absurda devolve
lista vazia.

Example:
    >>> from asmx.iocs import extract, summary
    >>> iocs = extract('msg db "http://exemplo.com/x", 0')
    >>> [(i.kind, i.value) for i in iocs]
    [('url', 'http://exemplo.com/x')]
    >>> summary(iocs)
    '1 indicador(es): 1 URL'
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import partial
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

from .parser import strip_comment

__all__ = [
    "IOC_KINDS",
    "Ioc",
    "strings_of",
    "extract",
    "group",
    "to_dicts",
    "summary",
    "from_memory",
]

#: Rótulo em português de cada categoria de indicador.
IOC_KINDS: Dict[str, str] = {
    "url": "URL",
    "ipv4": "Endereço IPv4",
    "domain": "Domínio",
    "email": "Endereço de e-mail",
    "path_unix": "Caminho Unix",
    "path_windows": "Caminho Windows",
    "registry": "Chave de registro",
    "command": "Comando",
    "extension": "Extensão sensível",
    "keyword": "Palavra-chave",
    "string": "String",
}

#: Nomes curtos usados só no resumo de uma linha (veja :func:`summary`).
_RESUMO: Dict[str, str] = {
    "url": "URL",
    "ipv4": "IPv4",
    "domain": "domínio",
    "email": "e-mail",
    "path_unix": "caminho",
    "path_windows": "caminho Windows",
    "registry": "registro",
    "command": "comando",
    "extension": "extensão",
    "keyword": "palavra-chave",
    "string": "string",
}

#: Categorias reconhecidas por padrão (tudo menos a string genérica).
_PATTERN_KINDS: Tuple[str, ...] = (
    "url",
    "ipv4",
    "domain",
    "email",
    "path_unix",
    "path_windows",
    "registry",
    "command",
    "extension",
    "keyword",
)

#: Posição de cada categoria, para a saída ficar sempre na mesma ordem.
_KIND_ORDER: Dict[str, int] = {kind: indice for indice, kind in enumerate(IOC_KINDS)}

#: Tamanho máximo do trecho de linha guardado em :attr:`Ioc.context`.
_MAX_CONTEXT = 160

#: Extensões que merecem atenção quando aparecem citadas no fonte.
_EXTENSOES: Tuple[str, ...] = (
    ".exe",
    ".dll",
    ".bat",
    ".ps1",
    ".sh",
    ".so",
    ".zip",
    ".enc",
    ".locked",
    ".key",
)

#: Comandos e executáveis que o relatório destaca quando são citados.
_COMANDOS: Tuple[str, ...] = (
    "cmd.exe",
    "powershell.exe",
    "powershell",
    "pwsh",
    "cmd",
    "bash.exe",
    "bash",
    "sh.exe",
    "sh",
    "nc.exe",
    "nc",
    "ncat",
    "netcat",
    "curl.exe",
    "curl",
    "wget.exe",
    "wget",
    "chmod",
    "chown",
    "iptables",
    "systemctl",
    "crontab",
)

#: Palavras de interesse (comparadas sem diferenciar maiúsculas).
_PALAVRAS: Tuple[str, ...] = (
    "password",
    "senha",
    "token",
    "secret",
    "admin",
    "root",
    "login",
    "bot",
    "keylog",
    "ransom",
    "bitcoin",
    "wallet",
)

#: TLDs considerados plausíveis. Ficam de fora, de propósito, os que também são
#: extensão de arquivo (``md``, ``pl``, ``rs``, ``py``, ``sh``, ``so``, ``zip``,
#: ``in``, ``it``, ``is``, ``id``): sem isso ``README.md`` e ``script.sh``
#: apareceriam como domínio.
_TLDS = frozenset("""
    com org net edu gov mil int info biz name pro aero coop museum travel
    io ai app dev xyz online site store tech cloud blog page live news media
    shop club space world today life zone link click email group digital
    top icu monster quest wiki me
    br pt us uk de fr es nl ca au jp cn ru ua se ch be dk no fi gr tr
    mx ar cl co pe ve ec uy bo cr pa gt hn sv ni
    kr tw hk sg th vn ph pk lk np
    za eg ma ng ke il sa ae qa ir cz sk hu ro bg hr si lt lv ee by
    kz uz az ge am tn dz gh ci sn cm ug tz zm zw mu mg ao mz cv na bw
    """.split())

#: Marca os limites de uma palavra: aceita ``_``, ``.`` e ``/`` dos lados, mas
#: não letra ou dígito. É o que impede ``bot`` de casar dentro de ``botão``.
_LIM_ESQ = r"(?<![^\W_])"
_LIM_DIR = r"(?![^\W_])"

#: Limite dos comandos: um nome de arquivo como ``script.sh`` não é o comando
#: ``sh``, então o ponto à esquerda também barra a captura.
_LIM_ESQ_CMD = r"(?<![\w.])"

_URL_RE = re.compile(r"https?://[^\s\"',;<>()\[\]{}]+", re.I)
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_DOMAIN_RE = re.compile(
    r"(?<![\w.@/-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+([A-Za-z]{2,24})"
)
_EMAIL_RE = re.compile(
    r"(?<![\w.%+-])[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}(?![^\W_])"
)
_PATH_UNIX_RE = re.compile(r"(?<![\w./-])/(?:[A-Za-z0-9._-]+/)+[A-Za-z0-9._-]*")
_WIN_COMP = r"[A-Za-z0-9_.$-]+(?: [A-Za-z0-9_.$-]+)*"
_WIN_LAST = r"[A-Za-z0-9_.$-]+"
_PATH_WIN_RE = re.compile(
    rf"(?<![A-Za-z0-9_])"
    rf"(?:[A-Za-z]:\\(?:{_WIN_COMP}\\)*{_WIN_LAST}"
    rf"|\\\\{_WIN_COMP}\\{_WIN_LAST}(?:\\{_WIN_COMP})*)"
)
_REGISTRY_RE = re.compile(
    rf"(?:(?:HKEY_[A-Za-z_]+|HKLM|HKCU|HKCR|HKU|HKCC)(?:\\{_WIN_COMP})+"
    rf"|(?:Software|System)(?:\\{_WIN_COMP})+"
    rf"|(?:[A-Za-z0-9_.$-]+)?CurrentVersion\\Run(?:\\{_WIN_COMP})*)",
    re.I,
)
_COMMAND_RE = re.compile(
    _LIM_ESQ_CMD
    + r"(?:"
    + "|".join(re.escape(c) for c in sorted(_COMANDOS, key=len, reverse=True))
    + r")"
    + _LIM_DIR,
    re.I,
)
_EXTENSION_RE = re.compile(r"\.[A-Za-z][A-Za-z0-9]{0,5}" + _LIM_DIR)
_KEYWORD_RE = re.compile(
    _LIM_ESQ
    + r"(?:"
    + "|".join(re.escape(p) for p in sorted(_PALAVRAS, key=len, reverse=True))
    + r")"
    + r"(?![^\W_\d])",
    re.I,
)
_LITERAL_RE = re.compile(r"\"((?:[^\"\\]|\\.)*)\"|'((?:[^'\\]|\\.)*)'")
_DATA_HEAD_RE = re.compile(
    r"(?:[A-Za-z_.$][\w.$@]*\s+)?(?:db|dw|dd|dq|dt|resb|resw|resd|resq)\b", re.I
)
_SO_SEPARADORES = re.compile(r"[,;:.\-_/\\|*+=~^\s]+")

#: Escapes que o NASM entende dentro de um literal e o que cada um vira.
_ESCAPES: Dict[str, str] = {
    "n": "\n",
    "t": "\t",
    "r": "\r",
    "\\": "\\",
    '"': '"',
    "'": "'",
}


@dataclass(frozen=True)
class Ioc:
    """Um indicador encontrado no fonte ou na memória.

    Attributes:
        kind: Chave da categoria, uma de :data:`IOC_KINDS`.
        value: O texto do indicador, como apareceu (extensões em minúsculas).
        line: Linha do fonte (1-based) ou ``0`` quando veio da memória.
        context: Trecho da linha onde apareceu, sem espaços duplicados.
    """

    kind: str
    value: str
    line: int
    context: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Converte o indicador em dicionário pronto para o relatório.

        Returns:
            Dicionário com ``kind``, ``value``, ``line``, ``context`` e o
            ``label`` em português vindo de :data:`IOC_KINDS`.
        """
        return {
            "kind": self.kind,
            "value": self.value,
            "line": self.line,
            "context": self.context,
            "label": IOC_KINDS.get(self.kind, self.kind),
        }


@dataclass(frozen=True)
class _Linha:
    """Uma linha do fonte já dividida em código e comentário.

    Attributes:
        n: Número da linha (1-based).
        raw: Linha original, sem alterações.
        body: Parte antes do comentário, sem espaços nas pontas.
        comment: Comentário da linha (com o marcador), vazio quando não existe.
    """

    n: int
    raw: str
    body: str
    comment: str


# --------------------------------------------------------------------- linhas -


def _scan_lines(text: str) -> List[_Linha]:
    """Divide o texto em linhas já com código e comentário separados.

    Args:
        text: Fonte completo.

    Returns:
        Uma :class:`_Linha` por linha do texto, na ordem do arquivo.
    """
    linhas: List[_Linha] = []
    normalizado = text.replace("\r\n", "\n").replace("\r", "\n")
    for indice, raw in enumerate(normalizado.split("\n")):
        try:
            body, comment = strip_comment(raw)
        except Exception:
            body, comment = raw, ""
        linhas.append(_Linha(n=indice + 1, raw=raw, body=body.strip(), comment=comment))
    return linhas


def _unescape(fragmento: str) -> str:
    """Traduz os escapes usuais do NASM dentro de um literal.

    ``\\n``, ``\\t``, ``\\r``, ``\\\\``, ``\\"`` e ``\\'`` viram um caractere;
    escape desconhecido fica como está, com a contrabarra.

    Args:
        fragmento: Conteúdo do literal, ainda com os escapes.

    Returns:
        O texto já decodificado.
    """
    if "\\" not in fragmento:
        return fragmento
    saida: List[str] = []
    i = 0
    while i < len(fragmento):
        char = fragmento[i]
        if char == "\\" and i + 1 < len(fragmento) and fragmento[i + 1] in _ESCAPES:
            saida.append(_ESCAPES[fragmento[i + 1]])
            i += 2
            continue
        saida.append(char)
        i += 1
    return "".join(saida)


def _literals_of(body: str) -> List[str]:
    """Extrai os literais de um trecho de código.

    Literais vizinhos separados só por vírgula são concatenados, como o
    montador faria com ``db "a", "b"``; um número ou símbolo no meio quebra a
    concatenação.

    Args:
        body: Trecho de código da linha, já sem o comentário.

    Returns:
        Os textos encontrados, na ordem em que aparecem.
    """
    valores: List[str] = []
    pendente: Optional[str] = None
    fim_anterior = -1
    for casado in _LITERAL_RE.finditer(body):
        grupo = casado.group(1)
        texto = _unescape(grupo if grupo is not None else casado.group(2) or "")
        entre = body[fim_anterior : casado.start()] if fim_anterior >= 0 else ""
        if pendente is not None and entre.strip(" \t,") == "":
            pendente += texto
        else:
            if pendente is not None:
                valores.append(pendente)
            pendente = texto
        fim_anterior = casado.end()
    if pendente is not None:
        valores.append(pendente)
    return valores


def _comment_text(comment: str) -> str:
    """Limpa um comentário: tira o marcador e junta os espaços.

    Args:
        comment: Comentário como saiu do parser, com ``;``, ``#`` ou ``//``.

    Returns:
        O texto do comentário sem o marcador e sem espaços duplicados.
    """
    return " ".join(comment.lstrip(";#/").split())


def _aceita(valor: str, min_length: int) -> bool:
    """Diz se um texto merece virar indicador.

    Args:
        valor: Texto candidato.
        min_length: Tamanho mínimo, medido sem os espaços das pontas.

    Returns:
        ``True`` quando o texto não é vazio, nem só separadores, e alcança o
        tamanho mínimo.
    """
    texto = valor.strip()
    if len(texto) < max(1, int(min_length)):
        return False
    return _SO_SEPARADORES.fullmatch(texto) is None


def _context(raw: str) -> str:
    """Monta o trecho de linha que acompanha o indicador.

    Args:
        raw: Linha original do fonte.

    Returns:
        A linha sem espaços duplicados, cortada em :data:`_MAX_CONTEXT`.
    """
    return " ".join(raw.split())[:_MAX_CONTEXT]


# ----------------------------------------------------------------- detectores -


def _urls(texto: str) -> List[str]:
    """Procura URLs ``http``/``https``.

    A captura para no primeiro espaço, aspas, vírgula ou fechamento, e a
    pontuação final da frase não entra.

    Args:
        texto: Texto a varrer.

    Returns:
        As URLs encontradas.
    """
    achados: List[str] = []
    for casado in _URL_RE.finditer(texto):
        valor = casado.group(0).rstrip(".,;:")
        if len(valor) > len("https://"):
            achados.append(valor)
    return achados


def _ips(texto: str) -> List[str]:
    """Procura endereços IPv4 válidos.

    Cada octeto precisa caber em 0-255 e o endereço não pode fazer parte de uma
    sequência maior de números: ``1.2.3.4.5`` e a versão ``1.2`` ficam de fora.

    Args:
        texto: Texto a varrer.

    Returns:
        Os endereços encontrados.
    """
    achados: List[str] = []
    for casado in _IPV4_RE.finditer(texto):
        valor = casado.group(0)
        octetos = valor.split(".")
        if all(octeto.isdigit() and int(octeto) <= 255 for octeto in octetos):
            achados.append(valor)
    return achados


def _domains(texto: str) -> List[str]:
    """Procura domínios com TLD plausível.

    Domínio dentro de URL (depois de ``/``) ou de e-mail (depois de ``@``) não
    conta: a URL e o e-mail já carregam o nome, e repetir só faria barulho.
    Nomes de arquivo (``arquivo.asm``) e de seção (``.text``) também ficam de
    fora, porque a extensão deles não é um TLD.

    Args:
        texto: Texto a varrer.

    Returns:
        Os domínios encontrados.
    """
    achados: List[str] = []
    for casado in _DOMAIN_RE.finditer(texto):
        if casado.group(1).lower() in _TLDS:
            achados.append(casado.group(0))
    return achados


def _emails(texto: str) -> List[str]:
    """Procura endereços de e-mail.

    Args:
        texto: Texto a varrer.

    Returns:
        Os e-mails encontrados.
    """
    return [casado.group(0) for casado in _EMAIL_RE.finditer(texto)]


def _unix_paths(texto: str) -> List[str]:
    """Procura caminhos Unix com pelo menos um diretório.

    Args:
        texto: Texto a varrer.

    Returns:
        Os caminhos encontrados, como ``/etc/passwd``.
    """
    return [casado.group(0) for casado in _PATH_UNIX_RE.finditer(texto)]


def _windows_paths(texto: str) -> List[str]:
    """Procura caminhos do Windows e nomes UNC.

    Aceita barras escapadas (``C:\\\\Windows``) e simples (``C:\\Windows``),
    porque o texto varrido já vem normalizado. O último componente não aceita
    espaço, o que faz a captura parar antes da prosa seguinte.

    Args:
        texto: Texto a varrer.

    Returns:
        Os caminhos encontrados.
    """
    return [casado.group(0) for casado in _PATH_WIN_RE.finditer(texto)]


def _registry_keys(texto: str) -> List[str]:
    """Procura chaves de registro do Windows.

    Args:
        texto: Texto a varrer.

    Returns:
        As chaves encontradas, como ``HKLM\\Software\\Microsoft``.
    """
    return [casado.group(0) for casado in _REGISTRY_RE.finditer(texto)]


def _commands(texto: str) -> List[str]:
    """Procura nomes de comandos e executáveis citados.

    Args:
        texto: Texto a varrer.

    Returns:
        Os comandos encontrados, preservando maiúsculas e minúsculas.
    """
    return [casado.group(0) for casado in _COMMAND_RE.finditer(texto)]


def _extensions(texto: str) -> List[str]:
    """Procura extensões de arquivo que merecem atenção.

    Args:
        texto: Texto a varrer.

    Returns:
        As extensões encontradas, sempre em minúsculas.
    """
    achados: List[str] = []
    for casado in _EXTENSION_RE.finditer(texto):
        valor = casado.group(0).lower()
        if valor in _EXTENSOES:
            achados.append(valor)
    return achados


def _keywords(texto: str) -> List[str]:
    """Procura palavras de interesse, sem diferenciar maiúsculas.

    Args:
        texto: Texto a varrer.

    Returns:
        As palavras encontradas, guardadas como apareceram no texto.
    """
    return [casado.group(0) for casado in _KEYWORD_RE.finditer(texto)]


#: Um detector por categoria de padrão.
_DETECTORES: Dict[str, Callable[[str], List[str]]] = {
    "url": _urls,
    "ipv4": _ips,
    "domain": _domains,
    "email": _emails,
    "path_unix": _unix_paths,
    "path_windows": _windows_paths,
    "registry": _registry_keys,
    "command": _commands,
    "extension": _extensions,
    "keyword": _keywords,
}


def _classify(valor: str) -> List[Tuple[str, str]]:
    """Roda todos os detectores sobre um texto.

    Args:
        valor: Texto a classificar, vindo do fonte ou da memória.

    Returns:
        Pares ``(kind, valor)``; quando nenhum detector reconhece o texto, a
        resposta é ``[("string", valor)]``.
    """
    achados: List[Tuple[str, str]] = []
    for kind in _PATTERN_KINDS:
        for encontrado in _DETECTORES[kind](valor):
            achados.append((kind, encontrado))
    return achados if achados else [("string", valor)]


def _fallback_patterns(raw: str) -> List[Tuple[str, str]]:
    """Procura caminhos e chaves no texto cru de uma linha.

    É a rede de segurança para quando a string está quebrada em pedaços: as
    contrabarras dobradas do fonte viram simples antes da busca.

    Args:
        raw: Linha original do fonte.

    Returns:
        Pares ``(kind, valor)`` encontrados.
    """
    normalizado = raw.replace("\\\\", "\\")
    achados: List[Tuple[str, str]] = [("path_unix", v) for v in _unix_paths(normalizado)]
    achados += [("path_windows", v) for v in _windows_paths(normalizado)]
    achados += [("registry", v) for v in _registry_keys(normalizado)]
    return achados


def _precisa_fallback(linha: _Linha) -> bool:
    """Diz se a linha crua deve passar pela busca de caminhos e chaves.

    Args:
        linha: Linha já dividida em código e comentário.

    Returns:
        ``True`` para linhas de dados e para linhas com comentário.
    """
    if linha.comment:
        return True
    return _DATA_HEAD_RE.match(linha.body) is not None


def _add_iocs(
    destino: List[Ioc],
    vistos: Set[Tuple[str, str]],
    valor: str,
    line: int,
    context: str,
) -> None:
    """Classifica um texto e guarda os indicadores ainda inéditos.

    Args:
        destino: Lista onde os indicadores são acumulados.
        vistos: Conjunto de pares ``(kind, value)`` já registrados.
        valor: Texto a classificar.
        line: Linha onde o texto apareceu.
        context: Trecho da linha, para o relatório.
    """
    for kind, encontrado in _classify(valor):
        if (kind, encontrado) in vistos:
            continue
        vistos.add((kind, encontrado))
        destino.append(Ioc(kind=kind, value=encontrado, line=line, context=context))


def _order_key(ioc: Ioc) -> Tuple[int, int, str]:
    """Monta a chave de ordenação dos indicadores.

    Args:
        ioc: Indicador a ordenar.

    Returns:
        Tupla ``(linha, categoria, valor)``.
    """
    return (ioc.line, _KIND_ORDER.get(ioc.kind, len(_KIND_ORDER)), ioc.value)


def _sem_prefixos(iocs: List[Ioc]) -> List[Ioc]:
    """Descarta o caminho que é só um pedaço de outro caminho da mesma linha.

    Quando um literal perde as contrabarras para um escape (``db "C:\\Users"``
    escrito com uma contrabarra só), a leitura decodificada para no meio do
    caminho e o resto só aparece no texto cru da linha. Dos dois, fica o mais
    completo.

    Args:
        iocs: Indicadores já sem repetição.

    Returns:
        A lista sem os caminhos que são prefixo de outro da mesma linha.
    """
    completos = {"path_unix", "path_windows", "registry"}
    descartar: Set[Tuple[str, str]] = set()
    for ioc in iocs:
        if ioc.kind not in completos:
            continue
        for outro in iocs:
            if outro.kind != ioc.kind or outro.line != ioc.line:
                continue
            if len(outro.value) > len(ioc.value) and outro.value.startswith(ioc.value):
                descartar.add((ioc.kind, ioc.value))
                break
    return [ioc for ioc in iocs if (ioc.kind, ioc.value) not in descartar]


# ------------------------------------------------------------------- público -


def strings_of(
    text: str, *, min_length: int = 4, include_comments: bool = True
) -> List[Tuple[int, str]]:
    """Lista as strings escritas no fonte, com a linha de cada uma.

    Lê os literais de dados (``db "..."``, ``dq '...'``, inclusive listas
    separadas por vírgula, que são concatenadas) e, quando
    ``include_comments``, também o texto dos comentários. Escapes como ``\\n``,
    ``\\t``, ``\\\\`` e ``\\"`` são decodificados nos literais; em comentário o
    texto entra como está. Strings vazias, só de separadores ou menores que
    ``min_length`` ficam de fora.

    Args:
        text: Fonte completo.
        min_length: Tamanho mínimo de uma string para ela entrar na lista.
        include_comments: Se os comentários também contam como strings.

    Returns:
        Lista de ``(linha, texto)`` na ordem do arquivo; lista vazia para
        entrada vazia, binária ou absurda.

    Example:
        >>> strings_of('msg db "Ola", 0', min_length=2)
        [(1, 'Ola')]
    """
    if not isinstance(text, str):
        return []
    encontradas: List[Tuple[int, str]] = []
    try:
        for linha in _scan_lines(text):
            for valor in _literals_of(linha.body):
                if _aceita(valor, min_length):
                    encontradas.append((linha.n, valor))
            if include_comments and linha.comment:
                texto = _comment_text(linha.comment)
                if _aceita(texto, min_length):
                    encontradas.append((linha.n, texto))
    except Exception:
        return encontradas
    return encontradas


def extract(text: str, *, min_length: int = 4, include_comments: bool = True) -> List[Ioc]:
    """Extrai os indicadores de compromisso escritos no fonte.

    Roda todas as categorias sobre :func:`strings_of` e, como reforço, procura
    caminhos e chaves de registro no texto cru das linhas de dados e dos
    comentários — é o que salva o caso da string quebrada em pedaços. O mesmo
    par ``(kind, value)`` aparece uma vez só, na primeira linha onde surgiu, e
    uma string que já caiu em alguma categoria não volta como ``string``. Se um
    caminho da mesma linha for só um pedaço de outro, fica o mais completo.

    Args:
        text: Fonte completo.
        min_length: Tamanho mínimo de uma string para ela ser classificada.
        include_comments: Se os comentários também são vasculhados.

    Returns:
        Os indicadores em ordem de linha; lista vazia para entrada vazia,
        binária ou absurda.

    Example:
        >>> iocs = extract('msg db "senha do admin", 0')
        >>> [(i.kind, i.value) for i in iocs]
        [('keyword', 'admin'), ('keyword', 'senha')]
    """
    if not isinstance(text, str):
        return []
    achados: List[Ioc] = []
    vistos: Set[Tuple[str, str]] = set()
    try:
        linhas = _scan_lines(text)
        for linha in linhas:
            contexto = _context(linha.raw)
            for valor in _literals_of(linha.body):
                if _aceita(valor, min_length):
                    _add_iocs(achados, vistos, valor, linha.n, contexto)
            if include_comments and linha.comment:
                texto = _comment_text(linha.comment)
                if _aceita(texto, min_length):
                    _add_iocs(achados, vistos, texto, linha.n, contexto)
        for linha in linhas:
            if not _precisa_fallback(linha):
                continue
            for kind, valor in _fallback_patterns(linha.raw):
                if (kind, valor) in vistos:
                    continue
                vistos.add((kind, valor))
                achados.append(
                    Ioc(kind=kind, value=valor, line=linha.n, context=_context(linha.raw))
                )
    except Exception:
        return _sem_prefixos(sorted(achados, key=_order_key))
    return _sem_prefixos(sorted(achados, key=_order_key))


def group(iocs: Sequence[Ioc]) -> Dict[str, List[Ioc]]:
    """Agrupa os indicadores por categoria, sem repetir valor.

    Args:
        iocs: Indicadores a agrupar, em qualquer ordem.

    Returns:
        Dicionário ``kind -> lista``, com as categorias na ordem de
        :data:`IOC_KINDS`; de cada valor fica a primeira ocorrência.
    """
    agrupado: Dict[str, List[Ioc]] = {}
    for ioc in iocs:
        lista = agrupado.setdefault(ioc.kind, [])
        if any(existente.value == ioc.value for existente in lista):
            continue
        lista.append(ioc)
    ordem = sorted(agrupado, key=lambda kind: _KIND_ORDER.get(kind, len(_KIND_ORDER)))
    return {kind: agrupado[kind] for kind in ordem}


def to_dicts(iocs: Sequence[Ioc]) -> Dict[str, List[Dict[str, Any]]]:
    """Converte os indicadores agrupados em dicionários prontos para o relatório.

    Args:
        iocs: Indicadores a converter.

    Returns:
        Dicionário ``kind -> lista de dicionários``, no formato de
        :meth:`Ioc.to_dict`.
    """
    return {kind: [ioc.to_dict() for ioc in lista] for kind, lista in group(iocs).items()}


def summary(iocs: Sequence[Ioc]) -> str:
    """Resume os indicadores numa linha, por categoria.

    Args:
        iocs: Indicadores a resumir.

    Returns:
        Texto como ``"12 indicador(es): 3 URL, 2 IPv4, 1 caminho"``; quando não
        há nada, ``"0 indicador(es)"``.
    """
    contagem: Dict[str, int] = {}
    for ioc in iocs:
        contagem[ioc.kind] = contagem.get(ioc.kind, 0) + 1
    partes = ["%d %s" % (contagem[kind], _RESUMO[kind]) for kind in _KIND_ORDER if kind in contagem]
    if not partes:
        return "0 indicador(es)"
    return "%d indicador(es): %s" % (len(iocs), ", ".join(partes))


def _ler_com_rd8(rd8: Callable[[int], Any], addr: int) -> int:
    """Lê um byte usando ``rd8`` do leitor, tolerando falha de leitura.

    Args:
        rd8: Método ``rd8`` do leitor.
        addr: Endereço pedido.

    Returns:
        O byte lido, ou ``0`` quando a leitura não é possível.
    """
    try:
        valor = rd8(addr)
    except Exception:
        return 0
    return valor & 0xFF if isinstance(valor, int) else 0


def _ler_com_mem(read_mem: Callable[[int, int], Any], addr: int) -> int:
    """Lê um byte usando ``read_mem(addr, 1)``, tolerando falha de leitura.

    Args:
        read_mem: Método ``read_mem`` do leitor.
        addr: Endereço pedido.

    Returns:
        O byte lido, ou ``0`` quando a leitura não é possível.
    """
    try:
        valor = read_mem(addr, 1)
    except Exception:
        return 0
    return valor & 0xFF if isinstance(valor, int) else 0


def _byte_reader(reader: Any) -> Optional[Callable[[int], int]]:
    """Escolhe a melhor leitura de byte oferecida pelo leitor.

    Args:
        reader: Objeto com ``rd8`` ou, na falta dele, ``read_mem``.

    Returns:
        Função ``endereço -> byte``, ou ``None`` quando o leitor não tem
        nenhuma das duas.
    """
    rd8 = getattr(reader, "rd8", None)
    if callable(rd8):
        return partial(_ler_com_rd8, rd8)
    read_mem = getattr(reader, "read_mem", None)
    if callable(read_mem):
        return partial(_ler_com_mem, read_mem)
    return None


def _printable(byte: int) -> bool:
    """Diz se um byte faz parte de um trecho de texto.

    Args:
        byte: Valor de 0 a 255.

    Returns:
        ``True`` para os imprimíveis ASCII e para os bytes altos usados por
        UTF-8 e latin-1.
    """
    return 0x20 <= byte <= 0x7E or byte >= 0x80


def _printable_runs(
    ler: Callable[[int], int], inicio: int, fim: int, min_length: int
) -> List[Tuple[int, int]]:
    """Varre a memória procurando sequências de bytes imprimíveis.

    Args:
        ler: Função que devolve o byte de um endereço.
        inicio: Primeiro endereço da varredura.
        fim: Endereço seguinte ao último (exclusivo).
        min_length: Tamanho mínimo de uma sequência, em bytes.

    Returns:
        Pares ``(início, fim)`` de cada sequência aceita.
    """
    corridas: List[Tuple[int, int]] = []
    i = inicio
    while i < fim:
        try:
            if not _printable(ler(i)):
                i += 1
                continue
            j = i + 1
            while j < fim and _printable(ler(j)):
                j += 1
        except Exception:
            break
        if j - i >= min_length:
            corridas.append((i, j))
        i = j
    return corridas


def _memory_text(reader: Any, ler: Callable[[int], int], inicio: int, fim: int) -> str:
    """Lê o texto de uma sequência de bytes da memória.

    Usa ``read_cstring`` do leitor e, se ele não devolver nada, remonta o texto
    a partir dos bytes já lidos.

    Args:
        reader: Objeto com ``read_cstring``.
        ler: Função que devolve o byte de um endereço.
        inicio: Primeiro endereço da sequência.
        fim: Endereço seguinte ao último (exclusivo).

    Returns:
        O texto encontrado, sem espaços nas pontas.
    """
    read_cstring = getattr(reader, "read_cstring", None)
    texto = ""
    if callable(read_cstring):
        try:
            lido = read_cstring(inicio, fim - inicio)
        except Exception:
            lido = ""
        if isinstance(lido, str):
            texto = lido
    if not texto:
        pedacos: List[str] = []
        for addr in range(inicio, fim):
            pedacos.append(chr(ler(addr) & 0xFF))
        texto = "".join(pedacos)
    return texto.strip()


def _cstring_runs(
    read_cstring: Callable[..., Any], inicio: int, fim: int, min_length: int
) -> List[str]:
    """Varre a memória usando só ``read_cstring`` do leitor.

    É o caminho de quem sabe ler strings terminadas em zero, mas não sabe ler
    byte a byte.

    Args:
        read_cstring: Método ``read_cstring`` do leitor.
        inicio: Primeiro endereço da varredura.
        fim: Endereço seguinte ao último (exclusivo).
        min_length: Tamanho mínimo de uma string, em caracteres.

    Returns:
        As strings aceitas, na ordem dos endereços.
    """
    textos: List[str] = []
    addr = inicio
    while addr < fim:
        try:
            lido = read_cstring(addr, fim - addr)
        except Exception:
            break
        if not isinstance(lido, str):
            break
        if _aceita(lido, min_length):
            textos.append(lido.strip())
        addr += len(lido) + 1
    return textos


def from_memory(
    reader: Any, *, base: int = 0x00400000, size: int = 0x40000, min_length: int = 4
) -> List[Ioc]:
    """Extrai indicadores das strings que só existem na memória em execução.

    Varre ``size`` bytes a partir de ``base`` procurando sequências de bytes
    imprimíveis de pelo menos ``min_length`` e classifica cada uma com as
    mesmas categorias de :func:`extract`. Os indicadores saem com ``line``
    igual a ``0``, porque não vêm de nenhuma linha do fonte.

    Args:
        reader: Leitor de memória com ``read_cstring`` (o ``Machine`` do ASM X);
            ``rd8`` ou ``read_mem`` aceleram a varredura.
        base: Primeiro endereço varrido.
        size: Quantidade de bytes varridos.
        min_length: Tamanho mínimo de uma sequência, em bytes.

    Returns:
        Os indicadores encontrados, na ordem dos endereços; lista vazia quando
        o leitor não sabe ler strings ou quando não há nada legível na região.
    """
    read_cstring = getattr(reader, "read_cstring", None)
    if not callable(read_cstring):
        return []
    try:
        inicio = int(base)
        fim = inicio + max(0, int(size))
        minimo = max(1, int(min_length))
    except Exception:
        return []
    achados: List[Ioc] = []
    vistos: Set[Tuple[str, str]] = set()
    try:
        ler = _byte_reader(reader)
        textos: List[str] = []
        if ler is not None:
            for comeco, termino in _printable_runs(ler, inicio, fim, minimo):
                textos.append(_memory_text(reader, ler, comeco, termino))
        else:
            textos = _cstring_runs(read_cstring, inicio, fim, minimo)
        for texto in textos:
            if _aceita(texto, minimo):
                _add_iocs(achados, vistos, texto, 0, texto[:_MAX_CONTEXT])
    except Exception:
        return achados
    return achados
