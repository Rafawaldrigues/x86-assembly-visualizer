"""Similarity and clustering for a pile of samples.

Analysing one file answers "what does this do?". Analysing three hundred answers
nothing unless you can group them: which samples are near-duplicates, which ones
share a technique, which one is the odd one out. This module turns each analysis
into a small numeric vector and groups the vectors.

What this is, precisely: **algorithmic similarity**, not a trained model. There
is no machine learning here — no weights, no training set, no inference. The
vector is built from what the other layers already extracted (instruction mix,
syscalls, behaviour categories, indicator kinds, size and shape), the comparison
is cosine similarity, and the grouping is single or complete linkage
agglomerative clustering over a threshold you choose. That is honest, fast,
deterministic, needs no dependency, and — unlike an opaque model — you can read
exactly why two samples landed in the same group.

Example:
    >>> from asmx.similarity import cosine
    >>> round(cosine({"a": 1.0}, {"a": 1.0}), 3)
    1.0
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .analyzer import Analysis
from .behavior import classify
from .logging_setup import get_logger, log_event
from .linter import Problem, validate

__all__ = [
    "FEATURE_WEIGHTS",
    "Cluster",
    "cluster",
    "cosine",
    "feature_names",
    "feature_vector",
    "groups",
    "jaccard",
    "similar_to",
    "similarity_matrix",
]

logger = get_logger(__name__)

#: How much each family of signals weighs in the vector. Instructions dominate
#: because they are the code; the counters only separate samples that are
#: otherwise alike.
FEATURE_WEIGHTS: Dict[str, float] = {
    "instruction": 1.0,
    "syscall": 1.4,
    "behavior": 1.6,
    "indicator": 0.8,
    "api": 1.4,
    "shape": 0.6,
}

#: Signal used for the "shape" features (counts that are not instructions).
SHAPE_KEYS: Tuple[str, ...] = ("instructions", "blocks", "calls", "sections", "strings")


def feature_names() -> List[str]:
    """Lists the families of signals used by the vector.

    Returns:
        The keys of :data:`FEATURE_WEIGHTS`, in order.

    Example:
        >>> "syscall" in feature_names()
        True
    """
    return list(FEATURE_WEIGHTS)


def _add(alvo: Dict[str, float], chave: str, peso: float) -> None:
    """Adds weight to one feature, creating it when needed.

    Args:
        alvo: Vector being built.
        chave: Feature name.
        peso: Value to add.
    """
    alvo[chave] = alvo.get(chave, 0.0) + peso


def feature_vector(
    analysis: Analysis,
    *,
    problems: Optional[Sequence[Problem]] = None,
    behaviors: Optional[Sequence[Any]] = None,
    text: Optional[str] = None,
) -> Dict[str, float]:
    """Builds the feature vector of one program.

    Args:
        analysis: Program analysis.
        problems: Validator problems; computed when omitted.
        behaviors: Behaviour classification; computed when omitted.
        text: Source text; taken from the analysis when omitted.

    Returns:
        Sparse vector mapping ``family:name`` to a weight. Counts are damped
        with ``log1p`` so a program with 400 ``mov`` does not drown out
        everything else.

    Raises:
        ConfigError: Propagated from the behaviour classifier when a rule is
            malformed (never for well-formed analysis).
    """
    fonte = analysis.program.source if text is None else text
    vetor: Dict[str, float] = {}

    historico: Dict[str, int] = {}
    for ins in analysis.instrs:
        if not ins.mnemonic:
            continue
        historico[ins.mnemonic] = historico.get(ins.mnemonic, 0) + 1
    for mnemonic, contagem in historico.items():
        _add(
            vetor,
            "instruction:%s" % mnemonic,
            FEATURE_WEIGHTS["instruction"] * math.log1p(contagem),
        )

    for ins in analysis.instrs:
        if ins.mnemonic == "syscall" and ins.sem and ins.sem.syscall_name:
            _add(vetor, "syscall:%s" % ins.sem.syscall_name, FEATURE_WEIGHTS["syscall"])
        if ins.mnemonic == "call" and ins.operands:
            alvo = ins.operands[0].symbol or ins.operands[0].text
            if alvo and alvo not in analysis.label_at:
                _add(vetor, "api:%s" % alvo, FEATURE_WEIGHTS["api"])

    lista_problemas = list(problems) if problems is not None else validate(analysis)
    lista_comportamentos = (
        list(behaviors) if behaviors is not None else classify(analysis, lista_problemas)
    )
    for comportamento in lista_comportamentos:
        _add(vetor, "behavior:%s" % comportamento.category, FEATURE_WEIGHTS["behavior"])
    for problema in lista_problemas:
        _add(vetor, "problem:%s" % problema.code, FEATURE_WEIGHTS["indicator"] * 0.5)

    contagens = {
        "instructions": len(analysis.instrs),
        "blocks": len(analysis.blocks),
        "calls": sum(1 for ins in analysis.instrs if ins.mnemonic == "call"),
        "sections": len(
            {linha.new_section for linha in analysis.program.lines if linha.new_section}
        ),
        "strings": sum(
            1 for linha in analysis.program.lines if linha.kind == "data" and not linha.reserve
        ),
    }
    for chave in SHAPE_KEYS:
        if contagens[chave]:
            _add(vetor, "shape:%s" % chave, FEATURE_WEIGHTS["shape"] * math.log1p(contagens[chave]))

    escalar = math.sqrt(sum(valor * valor for valor in vetor.values()))
    if escalar:
        vetor = {chave: valor / escalar for chave, valor in vetor.items()}
    log_event(logger, "vector_built", level=10, features=len(vetor), characters=len(fonte))
    return vetor


def cosine(primeiro: Dict[str, float], segundo: Dict[str, float]) -> float:
    """Cosine similarity between two vectors.

    Args:
        primeiro: First vector.
        segundo: Second vector.

    Returns:
        ``0.0`` when either vector is empty (nothing in common, or nothing to
        compare) up to ``1.0`` for vectors pointing the same way.

    Example:
        >>> cosine({}, {"a": 1.0})
        0.0
    """
    if not primeiro or not segundo:
        return 0.0
    if len(segundo) < len(primeiro):
        primeiro, segundo = segundo, primeiro
    produto = sum(valor * segundo.get(chave, 0.0) for chave, valor in primeiro.items())
    norma_a = math.sqrt(sum(valor * valor for valor in primeiro.values()))
    norma_b = math.sqrt(sum(valor * valor for valor in segundo.values()))
    if norma_a == 0.0 or norma_b == 0.0:
        return 0.0
    return max(0.0, min(1.0, produto / (norma_a * norma_b)))


def jaccard(primeiro: Iterable[str], segundo: Iterable[str]) -> float:
    """Jaccard similarity between two sets of names.

    Args:
        primeiro: First collection of names.
        segundo: Second collection of names.

    Returns:
        Intersection over union, from ``0.0`` to ``1.0``; two empty sets are
        considered identical (``1.0``).

    Example:
        >>> jaccard({"a", "b"}, {"b", "c"})
        0.3333333333333333
    """
    conjunto_a = set(primeiro)
    conjunto_b = set(segundo)
    if not conjunto_a and not conjunto_b:
        return 1.0
    return len(conjunto_a & conjunto_b) / len(conjunto_a | conjunto_b)


def similarity_matrix(vectors: Sequence[Dict[str, float]]) -> List[List[float]]:
    """Builds the full similarity matrix.

    Args:
        vectors: Vectors to compare.

    Returns:
        Square matrix of cosine similarities, symmetric, with ``1.0`` on the
        diagonal.

    Example:
        >>> similarity_matrix([{"a": 1.0}])
        [[1.0]]
    """
    total = len(vectors)
    matriz = [[1.0] * total for _ in range(total)]
    for i in range(total):
        for j in range(i + 1, total):
            valor = cosine(vectors[i], vectors[j])
            matriz[i][j] = valor
            matriz[j][i] = valor
    return matriz


@dataclass
class Cluster:
    """A group of samples that look alike.

    Attributes:
        members: Indexes of the members inside the input list.
        cohesion: Lowest similarity between any two members (``1.0`` when the
            group has a single member).
        label: Name of the most frequent feature inside the group, when the
            vectors were passed along.
    """

    members: List[int] = field(default_factory=list)
    cohesion: float = 1.0
    label: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialises the cluster for JSON output.

        Returns:
            Dictionary with the members, the cohesion and the label.
        """
        return {
            "members": list(self.members),
            "size": len(self.members),
            "cohesion": round(self.cohesion, 4),
            "label": self.label,
        }


def cluster(
    vectors: Sequence[Dict[str, float]], *, threshold: float = 0.8, linkage: str = "single"
) -> List[Cluster]:
    """Groups vectors that are similar enough to belong together.

    Args:
        vectors: Vectors to group.
        threshold: Minimum similarity for two samples to share a group.
        linkage: ``single`` joins groups when their closest members are similar;
            ``complete`` requires the most distant members to be similar too,
            which produces tighter groups.

    Returns:
        Clusters with at least one member, ordered by size (largest first) and
        then by the smallest member index, so the output is deterministic.

    Raises:
        ValueError: ``linkage`` is neither ``single`` nor ``complete``.

    Example:
        >>> [c.members for c in cluster([{"a": 1.0}, {"a": 1.0}, {"b": 1.0}])]
        [[0, 1], [2]]
    """
    if linkage not in ("single", "complete"):
        raise ValueError("linkage must be 'single' or 'complete', got %r" % linkage)
    total = len(vectors)
    if total == 0:
        return []
    pai = list(range(total))

    def raiz(indice: int) -> int:
        """Finds the representative of a group, compressing the path.

        Args:
            indice: Index whose group representative is wanted.

        Returns:
            Index of the representative of the group.
        """
        while pai[indice] != indice:
            pai[indice] = pai[pai[indice]]
            indice = pai[indice]
        return indice

    matriz = similarity_matrix(vectors)
    membros: Dict[int, List[int]] = {i: [i] for i in range(total)}
    for i in range(total):
        for j in range(i + 1, total):
            if matriz[i][j] < threshold:
                continue
            if linkage == "complete":
                raiz_i, raiz_j = raiz(i), raiz(j)
                if raiz_i == raiz_j:
                    continue
                if min(matriz[a][b] for a in membros[raiz_i] for b in membros[raiz_j]) < threshold:
                    continue
            raiz_i, raiz_j = raiz(i), raiz(j)
            if raiz_i == raiz_j:
                continue
            pai[raiz_j] = raiz_i
            membros[raiz_i] = sorted(membros[raiz_i] + membros.pop(raiz_j))

    grupos: Dict[int, List[int]] = {}
    for indice in range(total):
        grupos.setdefault(raiz(indice), []).append(indice)
    resultado = []
    for indices in grupos.values():
        coesao = min(
            (matriz[a][b] for posicao, a in enumerate(indices) for b in indices[posicao + 1 :]),
            default=1.0,
        )
        resultado.append(Cluster(members=indices, cohesion=coesao))
    resultado.sort(key=lambda c: (-len(c.members), c.members[0]))
    log_event(
        logger,
        "clusters_built",
        level=10,
        samples=total,
        clusters=len(resultado),
        threshold=threshold,
        linkage=linkage,
    )
    return resultado


def similar_to(
    reference: Dict[str, float], vectors: Sequence[Dict[str, float]], *, top: int = 5
) -> List[Tuple[int, float]]:
    """Ranks the vectors closest to a reference.

    Args:
        reference: Vector to compare against.
        vectors: Candidates.
        top: How many results to return.

    Returns:
        List of ``(index, similarity)`` sorted by similarity, most similar
        first; ties keep the original order.

    Example:
        >>> similar_to({"a": 1.0}, [{"b": 1.0}, {"a": 1.0}], top=1)
        [(1, 1.0)]
    """
    pares = [(indice, cosine(reference, vetor)) for indice, vetor in enumerate(vectors)]
    pares.sort(key=lambda par: (-par[1], par[0]))
    return pares[: max(0, top)]


def groups(
    samples: Sequence[Dict[str, Any]], *, threshold: float = 0.8, linkage: str = "single"
) -> List[Dict[str, Any]]:
    """Groups analysed programs by similarity, keeping their names.

    Args:
        samples: Sequence of ``{"name": str, "analysis": Analysis}`` mappings —
            the shape the batch command builds.
        threshold: Minimum similarity to share a group.
        linkage: ``single`` or ``complete``.

    Returns:
        List of ``{"size", "cohesion", "label", "members": [names]}``, largest
        group first.
    """
    vetores = [feature_vector(item["analysis"]) for item in samples]
    nomes = [str(item.get("name") or "?") for item in samples]
    saida = []
    for grupo in cluster(vetores, threshold=threshold, linkage=linkage):
        saida.append(
            {
                "size": len(grupo.members),
                "cohesion": round(grupo.cohesion, 4),
                "label": _group_label(vetores, grupo.members),
                "members": [nomes[i] for i in grupo.members],
            }
        )
    return saida


def _group_label(vectors: Sequence[Dict[str, float]], membros: Sequence[int]) -> str:
    """Picks the most characteristic feature of a group.

    Args:
        vectors: All vectors.
        membros: Indexes that belong to the group.

    Returns:
        Human-readable label like ``"syscall:connect"``; empty when there is
        nothing to show.
    """
    if len(membros) < 2:
        return ""
    frequencia: Dict[str, int] = {}
    for indice in membros:
        for chave in vectors[indice]:
            frequencia[chave] = frequencia.get(chave, 0) + 1
    candidatos = [
        (chave, contagem)
        for chave, contagem in frequencia.items()
        if contagem == len(membros) and not chave.startswith("shape:")
    ]
    if not candidatos:
        candidatos = [
            (chave, contagem) for chave, contagem in frequencia.items() if contagem == len(membros)
        ]
    if not candidatos:
        return ""
    candidatos.sort(key=lambda par: (-par[1], par[0]))
    return candidatos[0][0]
