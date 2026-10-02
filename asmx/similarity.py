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


def _add(target_name: Dict[str, float], key: str, feature_weight: float) -> None:
    """Adds weight to one feature, creating it when needed.

    Args:
        target_name: Vector being built.
        key: Feature name.
        feature_weight: Value to add.
    """
    target_name[key] = target_name.get(key, 0.0) + feature_weight


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
    source_text = analysis.program.source if text is None else text
    vector: Dict[str, float] = {}

    history: Dict[str, int] = {}
    for ins in analysis.instrs:
        if not ins.mnemonic:
            continue
        history[ins.mnemonic] = history.get(ins.mnemonic, 0) + 1
    for mnemonic, item_count in history.items():
        _add(
            vector,
            "instruction:%s" % mnemonic,
            FEATURE_WEIGHTS["instruction"] * math.log1p(item_count),
        )

    for ins in analysis.instrs:
        if ins.mnemonic == "syscall" and ins.sem and ins.sem.syscall_name:
            _add(vector, "syscall:%s" % ins.sem.syscall_name, FEATURE_WEIGHTS["syscall"])
        if ins.mnemonic == "call" and ins.operands:
            target_name = ins.operands[0].symbol or ins.operands[0].text
            if target_name and target_name not in analysis.label_at:
                _add(vector, "api:%s" % target_name, FEATURE_WEIGHTS["api"])

    problem_list = list(problems) if problems is not None else validate(analysis)
    behavior_list = list(behaviors) if behaviors is not None else classify(analysis, problem_list)
    for behavior_item in behavior_list:
        _add(vector, "behavior:%s" % behavior_item.category, FEATURE_WEIGHTS["behavior"])
    for problem_item in problem_list:
        _add(vector, "problem:%s" % problem_item.code, FEATURE_WEIGHTS["indicator"] * 0.5)

    feature_counts = {
        "instructions": len(analysis.instrs),
        "blocks": len(analysis.blocks),
        "calls": sum(1 for ins in analysis.instrs if ins.mnemonic == "call"),
        "sections": len(
            {
                source_line.new_section
                for source_line in analysis.program.lines
                if source_line.new_section
            }
        ),
        "strings": sum(
            1
            for source_line in analysis.program.lines
            if source_line.kind == "data" and not source_line.reserve
        ),
    }
    for key in SHAPE_KEYS:
        if feature_counts[key]:
            _add(
                vector, "shape:%s" % key, FEATURE_WEIGHTS["shape"] * math.log1p(feature_counts[key])
            )

    scalar = math.sqrt(sum(numeric_value * numeric_value for numeric_value in vector.values()))
    if scalar:
        vector = {key: numeric_value / scalar for key, numeric_value in vector.items()}
    log_event(logger, "vector_built", level=10, features=len(vector), characters=len(source_text))
    return vector


def cosine(first_item: Dict[str, float], second_item: Dict[str, float]) -> float:
    """Cosine similarity between two vectors.

    Args:
        first_item: First vector.
        second_item: Second vector.

    Returns:
        ``0.0`` when either vector is empty (nothing in common, or nothing to
        compare) up to ``1.0`` for vectors pointing the same way.

    Example:
        >>> cosine({}, {"a": 1.0})
        0.0
    """
    if not first_item or not second_item:
        return 0.0
    if len(second_item) < len(first_item):
        first_item, second_item = second_item, first_item
    product = sum(
        numeric_value * second_item.get(key, 0.0) for key, numeric_value in first_item.items()
    )
    norm_a = math.sqrt(sum(numeric_value * numeric_value for numeric_value in first_item.values()))
    norm_b = math.sqrt(sum(numeric_value * numeric_value for numeric_value in second_item.values()))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return max(0.0, min(1.0, product / (norm_a * norm_b)))


def jaccard(first_item: Iterable[str], second_item: Iterable[str]) -> float:
    """Jaccard similarity between two sets of names.

    Args:
        first_item: First collection of names.
        second_item: Second collection of names.

    Returns:
        Intersection over union, from ``0.0`` to ``1.0``; two empty sets are
        considered identical (``1.0``).

    Example:
        >>> jaccard({"a", "b"}, {"b", "c"})
        0.3333333333333333
    """
    set_a = set(first_item)
    set_b = set(second_item)
    if not set_a and not set_b:
        return 1.0
    return len(set_a & set_b) / len(set_a | set_b)


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
    matrix = [[1.0] * total for _ in range(total)]
    for i in range(total):
        for j in range(i + 1, total):
            numeric_value = cosine(vectors[i], vectors[j])
            matrix[i][j] = numeric_value
            matrix[j][i] = numeric_value
    return matrix


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

    def root_index(idx: int) -> int:
        """Finds the representative of a group, compressing the path.

        Args:
            idx: Index whose group representative is wanted.

        Returns:
            Index of the representative of the group.
        """
        while pai[idx] != idx:
            pai[idx] = pai[pai[idx]]
            idx = pai[idx]
        return idx

    matrix = similarity_matrix(vectors)
    member_indexes: Dict[int, List[int]] = {i: [i] for i in range(total)}
    for i in range(total):
        for j in range(i + 1, total):
            if matrix[i][j] < threshold:
                continue
            if linkage == "complete":
                root_i, root_j = root_index(i), root_index(j)
                if root_i == root_j:
                    continue
                if (
                    min(
                        matrix[a][b] for a in member_indexes[root_i] for b in member_indexes[root_j]
                    )
                    < threshold
                ):
                    continue
            root_i, root_j = root_index(i), root_index(j)
            if root_i == root_j:
                continue
            pai[root_j] = root_i
            member_indexes[root_i] = sorted(member_indexes[root_i] + member_indexes.pop(root_j))

    group_items: Dict[int, List[int]] = {}
    for idx in range(total):
        group_items.setdefault(root_index(idx), []).append(idx)
    result_value = []
    for indices in group_items.values():
        cohesion_value = min(
            (matrix[a][b] for position, a in enumerate(indices) for b in indices[position + 1 :]),
            default=1.0,
        )
        result_value.append(Cluster(members=indices, cohesion=cohesion_value))
    result_value.sort(key=lambda c: (-len(c.members), c.members[0]))
    log_event(
        logger,
        "clusters_built",
        level=10,
        samples=total,
        clusters=len(result_value),
        threshold=threshold,
        linkage=linkage,
    )
    return result_value


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
    pairs = [(idx, cosine(reference, vector)) for idx, vector in enumerate(vectors)]
    pairs.sort(key=lambda par: (-par[1], par[0]))
    return pairs[: max(0, top)]


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
    feature_vectors = [feature_vector(item["analysis"]) for item in samples]
    item_names = [str(item.get("name") or "?") for item in samples]
    output_value = []
    for group_item in cluster(feature_vectors, threshold=threshold, linkage=linkage):
        output_value.append(
            {
                "size": len(group_item.members),
                "cohesion": round(group_item.cohesion, 4),
                "label": _group_label(feature_vectors, group_item.members),
                "members": [item_names[i] for i in group_item.members],
            }
        )
    return output_value


def _group_label(vectors: Sequence[Dict[str, float]], member_indexes: Sequence[int]) -> str:
    """Picks the most characteristic feature of a group.

    Args:
        vectors: All vectors.
        member_indexes: Indexes that belong to the group.

    Returns:
        Human-readable label like ``"syscall:connect"``; empty when there is
        nothing to show.
    """
    if len(member_indexes) < 2:
        return ""
    frequency: Dict[str, int] = {}
    for idx in member_indexes:
        for key in vectors[idx]:
            frequency[key] = frequency.get(key, 0) + 1
    candidates = [
        (key, item_count)
        for key, item_count in frequency.items()
        if item_count == len(member_indexes) and not key.startswith("shape:")
    ]
    if not candidates:
        candidates = [
            (key, item_count)
            for key, item_count in frequency.items()
            if item_count == len(member_indexes)
        ]
    if not candidates:
        return ""
    candidates.sort(key=lambda par: (-par[1], par[0]))
    return candidates[0][0]
