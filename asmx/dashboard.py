"""A local, read-only web dashboard for a folder of analysis reports.

The command line is enough to analyse one sample, but a folder with three
hundred of them needs something you can sort, filter and click through. This
module serves exactly that, using only :mod:`http.server` from the standard
library — no Flask, no template engine, no CDN, no telemetry.

What it does:

* reads the manifest written by ``asmx analyze`` (``index.json``, schema
  ``asmx-analyze/1``) and, when it is not there, falls back to scanning the
  directory for ``*.report.json`` / ``*.report.html``;
* renders one self-contained HTML page with the sample table, the risk of each
  sample, quick filters and links to the full reports;
* exposes the same data as JSON (``/api/samples``, ``/api/summary``) so another
  tool can consume it;
* refuses to write anything and refuses to serve a path outside the directory it
  was pointed at.

Security posture: it binds to ``127.0.0.1`` unless you explicitly ask for
another interface, it only answers ``GET``/``HEAD``, and when it is exposed
beyond the loopback it can require a token (``--token``). There is no login, no
cookie and no session: the dashboard is a viewer for files that are already on
your disk.

Example:
    >>> from asmx.dashboard import build_index, render_page
    >>> pagina = render_page(build_index([]), title="ASM X")
    >>> "no samples" in pagina
    True
"""

from __future__ import annotations

import html
import json
import os
import secrets
import socket
import threading
import webbrowser
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import unquote, urlparse

from .errors import ProjectError, SourceReadError
from .logging_setup import get_logger, log_event

__all__ = [
    "DASHBOARD_SCHEMA",
    "Sample",
    "build_index",
    "find_manifest",
    "load_samples",
    "render_page",
    "serve",
]

logger = get_logger(__name__)

#: Schema of the manifest the dashboard reads and writes.
DASHBOARD_SCHEMA = "asmx-dashboard/1"

#: Risk levels, most serious first, used for sorting and colouring.
RISK_ORDER: Tuple[str, ...] = ("critical", "high", "medium", "low")

#: How many bytes of a report we are willing to read while scanning a folder.
MAX_REPORT_BYTES = 20 * 1024 * 1024


@dataclass
class Sample:
    """One analysed sample, as the dashboard sees it.

    Attributes:
        name: File name, used as the link target and the display name.
        risk: Risk level (``low``..``critical``); empty when unknown.
        score: Risk score from 0 to 100.
        instructions: Instruction count.
        behaviors: Number of behaviours observed.
        indicators: Number of indicators found.
        problems: Number of validation problems.
        platform: Short platform string (``linux · 64-bit``).
        report: Relative path of the full report, when one exists.
        reason: One-line reason for the risk, when available.
        extra: Anything else the manifest carried for this sample.
    """

    name: str
    risk: str = ""
    score: int = 0
    instructions: int = 0
    behaviors: int = 0
    indicators: int = 0
    problems: int = 0
    platform: str = ""
    report: str = ""
    reason: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialises the sample for the JSON API.

        Returns:
            Dictionary with the summary fields and the extras.
        """
        dados = {
            "name": self.name,
            "risk": self.risk,
            "score": self.score,
            "instructions": self.instructions,
            "behaviors": self.behaviors,
            "indicators": self.indicators,
            "problems": self.problems,
            "platform": self.platform,
            "report": self.report,
            "reason": self.reason,
        }
        dados.update(self.extra)
        return dados

    @property
    def rank(self) -> int:
        """Sort key that puts the most serious samples first.

        Returns:
            ``0`` for critical, up to ``4`` for an unknown level, then the score
            in reverse so that within the same level the highest score leads.
        """
        nivel = RISK_ORDER.index(self.risk) if self.risk in RISK_ORDER else len(RISK_ORDER)
        return nivel * 1000 - self.score


def _risk_of(dados: Dict[str, Any]) -> Tuple[str, int, str]:
    """Extracts the risk level, the score and a one-line reason from a report.

    The report schema (``asmx-report/1``) carries ``risk`` as a mapping with
    ``score``, ``level``, ``description`` and ``reasons``; the summary written by
    ``asmx analyze`` flattens those three fields per sample. Both shapes are
    accepted here, plus the degenerate one where an old report has neither.

    Args:
        dados: Report dictionary (``asmx-report/1``) or manifest entry.

    Returns:
        Tuple ``(level, score, reason)``, with empty values when the payload has
        no risk assessment at all.
    """
    risco = dados.get("risk")
    if isinstance(risco, dict):
        motivos = risco.get("reasons") or []
        primeiro = ""
        if isinstance(motivos, (list, tuple)) and motivos:
            primeiro = str(motivos[0])
        elif isinstance(motivos, str):
            primeiro = motivos
        return (
            str(risco.get("level") or ""),
            int(risco.get("score") or 0),
            primeiro or str(risco.get("description") or ""),
        )
    if isinstance(risco, str):
        return risco, int(dados.get("score") or 0), str(dados.get("reason") or "")
    return (
        str(dados.get("level") or ""),
        int(dados.get("score") or 0),
        str(dados.get("reason") or ""),
    )


def _sample_from_report(nome: str, dados: Dict[str, Any], caminho: str) -> Sample:
    """Builds a :class:`Sample` from a report payload.

    Args:
        nome: File name to show.
        dados: Report dictionary (``asmx-report/1``).
        caminho: Relative path of the report file.

    Returns:
        The sample, with whatever the report had to offer. Counts come from
        ``stats`` and from the length of the ``problems``/``behaviors`` lists,
        which is how the report schema exposes them.
    """
    nivel, pontos, motivo = _risk_of(dados)
    estatisticas = dados.get("stats") or {}
    fonte = dados.get("source") or {}
    plataforma = dados.get("platform") or {}
    indicadores = dados.get("iocs") or {}
    total_indicadores = (
        sum(len(valor) for valor in indicadores.values()) if isinstance(indicadores, dict) else 0
    )
    bits = plataforma.get("bits")
    rotulo_plataforma = " ".join(
        parte
        for parte in (str(plataforma.get("os") or ""), "%s-bit" % bits if bits else "")
        if parte
    )
    return Sample(
        name=nome,
        risk=nivel,
        score=pontos,
        instructions=int(estatisticas.get("instructions") or 0),
        behaviors=len(dados.get("behaviors") or []),
        indicators=total_indicadores,
        problems=len(dados.get("problems") or []),
        platform=rotulo_plataforma,
        report=caminho,
        reason=motivo,
        extra={"size": int(fonte.get("size") or 0), "lines": int(fonte.get("lines") or 0)},
    )


def find_manifest(directory: str) -> Optional[str]:
    """Finds the manifest written by ``asmx analyze``.

    Args:
        directory: Folder to inspect.

    Returns:
        Path of ``index.json`` when it exists, otherwise ``None``.
    """
    candidato = os.path.join(directory, "index.json")
    return candidato if os.path.isfile(candidato) else None


def _load_json(path: str) -> Dict[str, Any]:
    """Reads a JSON file with a size ceiling.

    Args:
        path: File to read.

    Returns:
        The parsed object; an empty dictionary when the file is not a JSON
        object.

    Raises:
        SourceReadError: File missing, too big, unreadable or malformed.
    """
    if not os.path.isfile(path):
        raise SourceReadError(path, "file not found")
    tamanho = os.path.getsize(path)
    if tamanho > MAX_REPORT_BYTES:
        raise SourceReadError(path, "is larger than the limit of %d bytes" % MAX_REPORT_BYTES)
    try:
        with open(path, encoding="utf-8") as arquivo:
            dados = json.load(arquivo)
    except OSError as erro:
        raise SourceReadError(path, str(erro)) from erro
    except ValueError as erro:
        raise SourceReadError(path, "invalid JSON: %s" % erro) from erro
    return dados if isinstance(dados, dict) else {}


def load_samples(directory: str) -> List[Sample]:
    """Collects the samples of a folder, from the manifest or from the files.

    The manifest (``index.json``) is the fast path and carries everything. When
    it is missing, every ``*.report.json`` is read and, as a last resort, the
    ``*.report.html`` files are listed by name so the dashboard still has
    something to link to.

    Args:
        directory: Folder with reports.

    Returns:
        Samples sorted by severity (most serious first), then by score.

    Raises:
        ProjectError: The directory does not exist or is not a directory.
    """
    if not os.path.isdir(directory):
        raise ProjectError("dashboard directory not found: %s" % directory, path=directory)
    amostras: List[Sample] = []
    manifesto = find_manifest(directory)
    if manifesto:
        dados = _load_json(manifesto)
        for item in dados.get("files") or []:
            if not isinstance(item, dict):
                continue
            nome = str(item.get("name") or item.get("source") or "?")
            relatorio = str(item.get("report") or "")
            amostras.append(
                Sample(
                    name=nome,
                    risk=str(item.get("risk") or ""),
                    score=int(item.get("score") or 0),
                    instructions=int(item.get("instructions") or 0),
                    behaviors=int(item.get("behaviors") or 0),
                    indicators=int(item.get("indicators") or 0),
                    problems=int(item.get("problems") or 0),
                    platform=str(item.get("platform") or ""),
                    report=relatorio,
                    reason=str(item.get("reason") or ""),
                )
            )
        log_event(logger, "dashboard_manifest", level=10, path=manifesto, samples=len(amostras))
        return sorted(amostras, key=lambda s: (s.rank, s.name))

    for nome in sorted(os.listdir(directory)):
        caminho = os.path.join(directory, nome)
        if not os.path.isfile(caminho):
            continue
        if nome.endswith(".report.json"):
            try:
                dados = _load_json(caminho)
            except SourceReadError as erro:
                logger.warning("skipping %s: %s", nome, erro)
                continue
            amostras.append(_sample_from_report(nome[: -len(".report.json")], dados, nome))
        elif nome.endswith(".report.html"):
            amostras.append(Sample(name=nome[: -len(".report.html")], report=nome))
    log_event(logger, "dashboard_scan", level=10, path=directory, samples=len(amostras))
    return sorted(amostras, key=lambda s: (s.rank, s.name))


def build_index(samples: Sequence[Sample], *, title: str = "ASM X") -> Dict[str, Any]:
    """Builds the machine-readable index served by the dashboard.

    Args:
        samples: Samples to summarise.
        title: Dashboard title.

    Returns:
        Dictionary with the schema, the title, the totals and the sample list.

    Example:
        >>> build_index([])["total"]
        0
    """
    por_nivel = {nivel: sum(1 for s in samples if s.risk == nivel) for nivel in RISK_ORDER}
    return {
        "schema": DASHBOARD_SCHEMA,
        "title": title,
        "total": len(samples),
        "by_risk": por_nivel,
        "worst": max((s.score for s in samples), default=0),
        "samples": [s.to_dict() for s in samples],
    }


_CSS = """
:root{--bg:#0f1115;--panel:#161a21;--line:#262c36;--fg:#e6e9ef;--dim:#98a2b3;
--low:#3fb950;--medium:#d29922;--high:#db6d28;--critical:#f85149;--accent:#58a6ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,
BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
header{padding:22px 28px;border-bottom:1px solid var(--line);display:flex;
flex-wrap:wrap;gap:16px;align-items:baseline}
h1{margin:0;font-size:20px;letter-spacing:.2px}
.sub{color:var(--dim);font-size:13px}
main{padding:20px 28px 60px}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:20px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;
padding:12px 16px;min-width:120px}
.card b{display:block;font-size:22px}
.card span{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.6px}
input[type=search]{background:var(--panel);border:1px solid var(--line);color:var(--fg);
padding:9px 12px;border-radius:8px;min-width:260px;font-size:14px}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);
border-radius:10px;overflow:hidden}
th,td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line);font-size:14px}
th{background:#1b2029;color:var(--dim);font-weight:600;cursor:pointer;user-select:none;
white-space:nowrap}
th:hover{color:var(--fg)}
tr:last-child td{border-bottom:0}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.chip{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;
font-weight:600;border:1px solid transparent}
.low{color:var(--low);border-color:var(--low)}
.medium{color:var(--medium);border-color:var(--medium)}
.high{color:var(--high);border-color:var(--high)}
.critical{color:var(--critical);border-color:var(--critical)}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.empty{color:var(--dim);padding:24px;text-align:center}
footer{color:var(--dim);font-size:12px;padding:18px 28px;border-top:1px solid var(--line)}
"""

_JS = """
function filtro(){var q=document.getElementById('busca').value.toLowerCase();
var linhas=document.querySelectorAll('tbody tr');var vistos=0;
linhas.forEach(function(tr){var ok=tr.dataset.name.indexOf(q)>=0;
tr.style.display=ok?'':'none';if(ok)vistos++;});
document.getElementById('vazio').style.display=vistos?'none':'';}
function ordenar(coluna){var tb=document.querySelector('tbody');
var linhas=Array.prototype.slice.call(tb.querySelectorAll('tr'));
var desc=tb.dataset.col===coluna&&tb.dataset.dir!=='desc';
linhas.sort(function(a,b){var x=a.children[coluna].dataset.val||a.children[coluna].innerText;
var y=b.children[coluna].dataset.val||b.children[coluna].innerText;
var nx=parseFloat(x),ny=parseFloat(y);
if(!isNaN(nx)&&!isNaN(ny)){return desc?ny-nx:nx-ny;}
return desc?String(y).localeCompare(String(x)):String(x).localeCompare(String(y));});
linhas.forEach(function(tr){tb.appendChild(tr);});
tb.dataset.col=coluna;tb.dataset.dir=desc?'desc':'asc';}
"""


def render_page(index: Dict[str, Any], *, title: str = "ASM X", live: bool = True) -> str:
    """Renders the dashboard page as one self-contained HTML document.

    Args:
        index: Index built by :func:`build_index`.
        title: Page title.
        live: When ``True`` the search box and the sortable headers are wired to
            the inline JavaScript; ``False`` renders a static table (useful for
            tests and for saving the page to disk).

    Returns:
        The whole HTML document, with no external resource.
    """
    amostras = list(index.get("samples") or [])
    por_nivel = index.get("by_risk") or {}
    total = int(index.get("total") or 0)
    pior = int(index.get("worst") or 0)
    linhas = []
    for amostra in amostras:
        nome = html.escape(str(amostra.get("name") or "?"))
        risco = str(amostra.get("risk") or "")
        chip = (
            '<span class="chip %s">%s</span>' % (html.escape(risco), html.escape(risco.upper()))
            if risco
            else '<span class="sub">-</span>'
        )
        relatorio = str(amostra.get("report") or "")
        celula_nome = (
            '<a href="report/%s">%s</a>' % (html.escape(relatorio), nome) if relatorio else nome
        )
        linhas.append(
            '<tr data-name="%s">'
            "<td>%s</td>"
            '<td data-val="%d">%s</td>'
            '<td class="num" data-val="%d">%d</td>'
            '<td class="num" data-val="%d">%d</td>'
            '<td class="num" data-val="%d">%d</td>'
            '<td class="num" data-val="%d">%d</td>'
            '<td class="num" data-val="%d">%d</td>'
            '<td class="sub">%s</td>'
            "</tr>"
            % (
                html.escape(str(amostra.get("name") or "?").lower()),
                celula_nome,
                RISK_ORDER.index(risco) if risco in RISK_ORDER else len(RISK_ORDER),
                chip,
                int(amostra.get("score") or 0),
                int(amostra.get("score") or 0),
                int(amostra.get("instructions") or 0),
                int(amostra.get("instructions") or 0),
                int(amostra.get("behaviors") or 0),
                int(amostra.get("behaviors") or 0),
                int(amostra.get("indicators") or 0),
                int(amostra.get("indicators") or 0),
                int(amostra.get("problems") or 0),
                int(amostra.get("problems") or 0),
                html.escape(str(amostra.get("reason") or amostra.get("platform") or "")),
            )
        )
    cartoes = [
        ("samples", total),
        ("critical", int(por_nivel.get("critical") or 0)),
        ("high", int(por_nivel.get("high") or 0)),
        ("medium", int(por_nivel.get("medium") or 0)),
        ("low", int(por_nivel.get("low") or 0)),
        ("worst score", pior),
    ]
    html_cartoes = "".join(
        '<div class="card"><b>%s</b><span>%s</span></div>' % (valor, rotulo)
        for rotulo, valor in cartoes
    )
    corpo = (
        "".join(linhas)
        if linhas
        else '<tr><td colspan="8" class="empty">no samples in this folder</td></tr>'
    )
    ferramentas = (
        '<input type="search" id="busca" placeholder="filter by file name…" ' 'oninput="filtro()">'
        if live
        else ""
    )
    script = "<script>%s</script>" % _JS if live else ""
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%(titulo)s — dashboard</title>
<style>%(css)s</style>
</head>
<body>
<header>
<h1>%(titulo)s</h1>
<span class="sub">%(total)d sample(s) · generated by <code>asmx dashboard</code> ·
read-only, served from this machine</span>
%(ferramentas)s
</header>
<main>
<div class="cards">%(cartoes)s</div>
<table>
<thead><tr>
<th onclick="ordenar(0)">sample</th>
<th onclick="ordenar(1)">risk</th>
<th onclick="ordenar(2)">score</th>
<th onclick="ordenar(3)">instructions</th>
<th onclick="ordenar(4)">behaviors</th>
<th onclick="ordenar(5)">indicators</th>
<th onclick="ordenar(6)">problems</th>
<th>note</th>
</tr></thead>
<tbody>%(corpo)s</tbody>
</table>
<div id="vazio" class="empty" style="display:none">nothing matches that filter</div>
</main>
<footer>ASM X · this page is generated locally and needs no network ·
<code>asmx analyze DIR --out DIR</code> to produce the reports</footer>
%(script)s
</body>
</html>
""" % {
        "titulo": html.escape(title),
        "css": _CSS,
        "total": total,
        "ferramentas": ferramentas,
        "cartoes": html_cartoes,
        "corpo": corpo,
        "script": script,
    }


class _Handler(BaseHTTPRequestHandler):
    """Serves the dashboard page, the reports and the JSON API."""

    server_version = "ASMX-Dashboard/1"
    directory = "."
    title = "ASM X"
    token: Optional[str] = None

    def log_message(self, formato: str, *args: Any) -> None:
        """Routes the HTTP log through the project logger instead of stderr.

        Args:
            formato: printf-style format used by :mod:`http.server`.
            *args: Values for the format.
        """
        logger.debug("dashboard %s - %s", self.address_string(), formato % args)

    # -- helpers ------------------------------------------------------------
    def _autorizado(self) -> bool:
        """Checks the optional token.

        Returns:
            ``True`` when no token is configured or the request carries it in
            the ``token`` query parameter or the ``X-ASMX-Token`` header.
        """
        if not self.token:
            return True
        enviado = self.headers.get("X-ASMX-Token")
        if enviado == self.token:
            return True
        consulta = urlparse(self.path).query
        for parte in consulta.split("&"):
            chave, _, valor = parte.partition("=")
            if chave == "token" and unquote(valor) == self.token:
                return True
        return False

    def _responder(
        self, corpo: bytes, tipo: str = "text/html; charset=utf-8", codigo: int = 200
    ) -> None:
        """Sends a complete response.

        Args:
            corpo: Body bytes.
            tipo: Content type.
            codigo: HTTP status code.
        """
        self.send_response(codigo)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(corpo)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(corpo)

    def _json(self, dados: Dict[str, Any], codigo: int = 200) -> None:
        """Sends a JSON response.

        Args:
            dados: Payload to serialise.
            codigo: HTTP status code.
        """
        self._responder(
            json.dumps(dados, ensure_ascii=False, indent=2).encode("utf-8"),
            "application/json; charset=utf-8",
            codigo,
        )

    def _erro(self, codigo: int, mensagem: str) -> None:
        """Sends a plain text error.

        Args:
            codigo: HTTP status code.
            mensagem: Text shown to the user.
        """
        self._responder((mensagem + "\n").encode("utf-8"), "text/plain; charset=utf-8", codigo)

    def _caminho_seguro(self, relativo: str) -> Optional[str]:
        """Resolves a request path inside the served directory.

        Args:
            relativo: Path taken from the URL, already unquoted.

        Returns:
            Absolute path when it stays inside the directory and points at a
            file, otherwise ``None``.
        """
        base = os.path.abspath(self.directory)
        alvo = os.path.abspath(os.path.join(base, relativo))
        if alvo != base and not alvo.startswith(base + os.sep):
            return None
        return alvo if os.path.isfile(alvo) else None

    # -- routes -------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 - inherited naming
        """Handles a GET request."""
        self._rota()

    def do_HEAD(self) -> None:  # noqa: N802 - inherited naming
        """Handles a HEAD request (same routes, no body)."""
        self._rota()

    def _rota(self) -> None:
        """Dispatches the request to the right view."""
        if not self._autorizado():
            self._erro(403, "missing or wrong token")
            return
        caminho = unquote(urlparse(self.path).path)
        try:
            amostras = load_samples(self.directory)
        except ProjectError as erro:
            self._erro(500, str(erro))
            return
        indice = build_index(amostras, title=self.title)
        if caminho in ("/", "/index.html"):
            self._responder(render_page(indice, title=self.title).encode("utf-8"))
        elif caminho == "/api/samples":
            self._json(indice)
        elif caminho == "/api/summary":
            self._json(
                {
                    "schema": indice["schema"],
                    "title": indice["title"],
                    "total": indice["total"],
                    "by_risk": indice["by_risk"],
                    "worst": indice["worst"],
                }
            )
        elif caminho.startswith("/report/"):
            self._relatorio(caminho[len("/report/") :])
        else:
            self._erro(404, "not found: %s" % caminho)

    def _relatorio(self, relativo: str) -> None:
        """Serves one report file from inside the directory.

        Args:
            relativo: File name requested under ``/report/``.
        """
        alvo = self._caminho_seguro(relativo)
        if alvo is None:
            self._erro(404, "report not found: %s" % relativo)
            return
        try:
            with open(alvo, "rb") as arquivo:
                corpo = arquivo.read()
        except OSError as erro:
            self._erro(500, "could not read %s: %s" % (relativo, erro))
            return
        tipo = (
            "application/json; charset=utf-8"
            if alvo.endswith(".json")
            else "text/html; charset=utf-8"
        )
        self._responder(corpo, tipo)


def _free_port(host: str) -> int:
    """Asks the operating system for a free TCP port.

    Args:
        host: Interface the port must be free on.

    Returns:
        A port number that can be bound right away.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as soquete:
        soquete.bind((host, 0))
        return int(soquete.getsockname()[1])


def serve(
    directory: str,
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    title: str = "ASM X",
    token: Optional[str] = None,
    open_browser: bool = False,
    background: bool = False,
) -> Tuple[ThreadingHTTPServer, str]:
    """Starts the dashboard.

    Args:
        directory: Folder with the reports to show.
        host: Interface to bind; the default only accepts local connections.
        port: TCP port; ``0`` picks a free one.
        title: Title shown on the page.
        token: Optional shared secret; generated when ``None`` and the host is
            not a loopback address.
        open_browser: Whether to open the page in the default browser.
        background: When ``True`` the server runs in a daemon thread and the
            caller must call ``shutdown()`` on the returned server.

    Returns:
        Tuple ``(server, url)`` with the running server and the URL to open.

    Raises:
        ProjectError: The directory does not exist.
        OSError: The port is taken or the interface cannot be bound.
    """
    if not os.path.isdir(directory):
        raise ProjectError("dashboard directory not found: %s" % directory, path=directory)
    local = host in ("127.0.0.1", "localhost", "::1")
    segredo = token
    if not local and not segredo:
        segredo = secrets.token_urlsafe(12)
        logger.warning("dashboard exposed on %s: a token was generated (%s)", host, segredo)
    porta = int(port) or _free_port(host)
    handler = type(
        "_AsmxDashboard",
        (_Handler,),
        {
            "directory": os.path.abspath(directory),
            "title": title,
            "token": segredo,
        },
    )
    servidor = ThreadingHTTPServer((host, porta), handler)
    url = "http://%s:%d/" % ("127.0.0.1" if local else host, porta)
    if segredo:
        url += "?token=%s" % segredo
    log_event(
        logger,
        "dashboard_started",
        host=host,
        port=porta,
        directory=directory,
        samples=len(load_samples(directory)),
    )
    if background:
        thread = threading.Thread(target=servidor.serve_forever, name="asmx-dashboard", daemon=True)
        thread.start()
    if open_browser:
        webbrowser.open(url)
    return servidor, url
