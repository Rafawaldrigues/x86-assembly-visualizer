"""Tests for the similarity and clustering module (:mod:`asmx.similarity`).

The point of the module is grouping, so the tests use sources that are alike,
sources that differ in exactly one dimension, and sources that share nothing —
plus the degenerate cases (empty vector, single sample, impossible threshold)
that would otherwise divide by zero or loop forever.
"""

from __future__ import annotations

import unittest

from asmx.analyzer import analyze
from asmx.examples import EXAMPLES
from asmx.similarity import (
    FEATURE_WEIGHTS,
    Cluster,
    _group_label,
    cluster,
    cosine,
    feature_names,
    feature_vector,
    groups,
    jaccard,
    similar_to,
    similarity_matrix,
)

LOOP = """
section .text
global _start
_start:
    mov rcx, 10
.loop:
    dec rcx
    jnz .loop
    mov rax, 60
    xor rdi, rdi
    syscall
"""

SIMILAR_LOOP = """
section .text
global _start
_start:
    mov rcx, 10
.loop:
    dec rcx
    jnz .loop
    mov rax, 60
    xor rdi, rdi
    syscall
"""

CONSOLE = """
section .text
global _start
_start:
    mov rax, 1
    mov rdi, 1
    mov rsi, msg
    mov rdx, 4
    syscall
    mov rax, 60
    syscall
section .data
msg db "hi", 0
"""


class TestVector(unittest.TestCase):
    """The vector must be normalised, deterministic and comparable."""

    def test_vector_is_nonempty(self) -> None:
        vector = feature_vector(analyze(LOOP))
        self.assertTrue(vector)
        self.assertTrue(all(key.count(":") == 1 for key in vector))

    def test_vector_is_normalized(self) -> None:
        vector = feature_vector(analyze(LOOP))
        norm = sum(numeric_value * numeric_value for numeric_value in vector.values()) ** 0.5
        self.assertAlmostEqual(norm, 1.0, places=9)

    def test_expected_feature_families(self) -> None:
        vector = feature_vector(analyze(CONSOLE))
        families = {key.split(":")[0] for key in vector}
        self.assertIn("instruction", families)
        self.assertIn("syscall", families)
        self.assertIn("shape", families)

    def test_empty_program(self) -> None:
        self.assertEqual(feature_vector(analyze("")), {})

    def test_deterministic(self) -> None:
        self.assertEqual(feature_vector(analyze(LOOP)), feature_vector(analyze(LOOP)))

    def test_high_count_does_not_dominate(self) -> None:
        """log1p damping: 100 instructions must not outweigh a distinct signal."""
        many_instructions = "section .text\n_start:\n" + "nop\n" * 100
        vector = feature_vector(analyze(many_instructions))
        self.assertLess(max(vector.values()), 1.0)

    def test_reuses_problems_and_behaviors(self) -> None:
        analysis_result = analyze(EXAMPLES["suspicious"]["code"])
        vector = feature_vector(analysis_result)
        self.assertTrue(any(key.startswith("behavior:") for key in vector))

    def test_feature_names(self) -> None:
        self.assertEqual(feature_names(), list(FEATURE_WEIGHTS))


class TestComparison(unittest.TestCase):
    """Cosine and Jaccard, including the empty cases."""

    def test_identical_vectors(self) -> None:
        vector = feature_vector(analyze(LOOP))
        self.assertAlmostEqual(cosine(vector, vector), 1.0, places=9)

    def test_empty_vector_comparison(self) -> None:
        self.assertEqual(cosine({}, {"a": 1.0}), 0.0)
        self.assertEqual(cosine({"a": 1.0}, {}), 0.0)

    def test_no_intersection(self) -> None:
        self.assertEqual(cosine({"a": 1.0}, {"b": 1.0}), 0.0)

    def test_symmetric_similarity(self) -> None:
        a = feature_vector(analyze(LOOP))
        b = feature_vector(analyze(CONSOLE))
        self.assertAlmostEqual(cosine(a, b), cosine(b, a), places=12)

    def test_similarity_in_unit_interval(self) -> None:
        a = feature_vector(analyze(LOOP))
        b = feature_vector(analyze(CONSOLE))
        self.assertGreaterEqual(cosine(a, b), 0.0)
        self.assertLessEqual(cosine(a, b), 1.0)

    def test_similar_ranks_above_different(self) -> None:
        similar = cosine(feature_vector(analyze(LOOP)), feature_vector(analyze(SIMILAR_LOOP)))
        different = cosine(feature_vector(analyze(LOOP)), feature_vector(analyze(CONSOLE)))
        self.assertGreater(similar, different)
        self.assertGreater(similar, 0.99)

    def test_jaccard(self) -> None:
        self.assertEqual(jaccard({"a", "b"}, {"a", "b"}), 1.0)
        self.assertEqual(jaccard({"a"}, {"b"}), 0.0)
        self.assertAlmostEqual(jaccard({"a", "b"}, {"b", "c"}), 1 / 3, places=9)
        self.assertEqual(jaccard(set(), set()), 1.0)
        self.assertEqual(jaccard(set(), {"a"}), 0.0)

    def test_matrix_is_symmetric_with_unit_diagonal(self) -> None:
        feature_vectors = [
            feature_vector(analyze(source_text)) for source_text in (LOOP, CONSOLE, SIMILAR_LOOP)
        ]
        matrix = similarity_matrix(feature_vectors)
        for i, source_line in enumerate(matrix):
            self.assertEqual(source_line[i], 1.0)
            for j, numeric_value in enumerate(source_line):
                self.assertAlmostEqual(numeric_value, matrix[j][i], places=12)
        self.assertEqual(similarity_matrix([{"a": 1.0}]), [[1.0]])
        self.assertEqual(similarity_matrix([]), [])


class TestClustering(unittest.TestCase):
    """Clustering: grouping, ordering, threshold and linkage."""

    def feature_vectors(self) -> list:
        return [
            feature_vector(analyze(source_text)) for source_text in (LOOP, SIMILAR_LOOP, CONSOLE)
        ]

    def test_groups_identical_vectors(self) -> None:
        group_items = cluster(self.feature_vectors())
        self.assertEqual(group_items[0].members, [0, 1])
        self.assertEqual(group_items[1].members, [2])

    def test_sorts_by_size(self) -> None:
        group_items = cluster([{"a": 1.0}, {"a": 1.0}, {"a": 1.0}, {"b": 1.0}])
        self.assertEqual(group_items[0].members, [0, 1, 2])
        self.assertEqual(group_items[1].members, [3])

    def test_high_threshold_separates_different_vectors(self) -> None:
        """Identical vectors always stay together: the threshold is a floor."""
        group_items = cluster(self.feature_vectors(), threshold=0.999)
        self.assertEqual([g.members for g in group_items], [[0, 1], [2]])

    def test_threshold_controls_groups(self) -> None:
        # cos(0, 1) ~= 0.90 and cos(0, 2) = cos(1, 2) = 0
        feature_vectors = [{"a": 1.0}, {"a": 0.9, "b": 0.44}, {"c": 1.0}]
        self.assertEqual(
            [g.members for g in cluster(feature_vectors, threshold=0.95)], [[0], [1], [2]]
        )
        self.assertEqual(
            [g.members for g in cluster(feature_vectors, threshold=0.85)], [[0, 1], [2]]
        )
        self.assertEqual([g.members for g in cluster(feature_vectors, threshold=0.0)], [[0, 1, 2]])

    def test_zero_threshold_groups_all(self) -> None:
        group_items = cluster([{"a": 1.0}, {"b": 1.0}], threshold=0.0)
        self.assertEqual(len(group_items), 1)
        self.assertEqual(group_items[0].members, [0, 1])

    def test_cohesion(self) -> None:
        group_items = cluster([{"a": 1.0}, {"a": 1.0}])
        self.assertAlmostEqual(group_items[0].cohesion, 1.0, places=9)
        singleton = cluster([{"a": 1.0}])
        self.assertEqual(singleton[0].cohesion, 1.0)

    def test_complete_linkage_is_stricter(self) -> None:
        # 0 and 2 are similar to 1 but not to each other
        feature_vectors = [{"a": 1.0, "b": 0.55}, {"a": 1.0, "b": 0.9}, {"a": 1.0, "b": 1.25}]
        simple = cluster(feature_vectors, threshold=0.95, linkage="single")
        complete_result = cluster(feature_vectors, threshold=0.95, linkage="complete")
        self.assertGreaterEqual(len(complete_result), len(simple))

    def test_invalid_linkage(self) -> None:
        with self.assertRaises(ValueError):
            cluster([{"a": 1.0}], linkage="average")

    def test_empty_list(self) -> None:
        self.assertEqual(cluster([]), [])

    def test_deterministic(self) -> None:
        first_item = [g.members for g in cluster(self.feature_vectors())]
        second_result = [g.members for g in cluster(self.feature_vectors())]
        self.assertEqual(first_item, second_result)

    def test_to_dict(self) -> None:
        values_data = Cluster([0, 1], cohesion=0.98765, label="syscall:socket").to_dict()
        self.assertEqual(values_data["members"], [0, 1])
        self.assertEqual(values_data["size"], 2)
        self.assertEqual(values_data["cohesion"], 0.9877)
        self.assertEqual(values_data["label"], "syscall:socket")

    def test_similar_to(self) -> None:
        feature_vectors = self.feature_vectors()
        ranking = similar_to(feature_vectors[0], feature_vectors, top=2)
        self.assertEqual(ranking[0][0], 0)
        self.assertAlmostEqual(ranking[0][1], 1.0, places=9)
        self.assertEqual(ranking[1][0], 1)

    def test_similar_to_with_zero_top(self) -> None:
        self.assertEqual(similar_to({"a": 1.0}, [{"a": 1.0}], top=0), [])


class TestGroups(unittest.TestCase):
    """The name-aware facade used by the batch command."""

    def sample_list(self) -> list:
        return [
            {"name": "loop-a.asm", "analysis": analyze(LOOP)},
            {"name": "loop-b.asm", "analysis": analyze(SIMILAR_LOOP)},
            {"name": "console.asm", "analysis": analyze(CONSOLE)},
        ]

    def test_groups_by_name(self) -> None:
        group_items = groups(self.sample_list())
        self.assertEqual(group_items[0]["size"], 2)
        self.assertEqual(group_items[0]["members"], ["loop-a.asm", "loop-b.asm"])
        self.assertRegex(group_items[0]["label"], r"^(behavior|instruction|syscall):")
        self.assertEqual(group_items[1]["members"], ["console.asm"])

    def test_label_is_shared_feature(self) -> None:
        feature_vectors = [
            {"instruction:dec": 0.7, "shape:blocks": 0.7},
            {"instruction:dec": 0.7, "syscall:exit": 0.7},
        ]
        self.assertEqual(_group_label(feature_vectors, [0, 1]), "instruction:dec")
        self.assertEqual(_group_label([{"a": 1.0}], [0]), "")

    def test_singleton_has_empty_label(self) -> None:
        group_items = groups([{"name": "a.asm", "analysis": analyze(CONSOLE)}])
        self.assertEqual(group_items[0]["label"], "")

    def test_threshold_changes_result(self) -> None:
        sample_list = self.sample_list()
        self.assertEqual(len(groups(sample_list, threshold=0.9)), 2)
        self.assertEqual(len(groups(sample_list, threshold=0.4)), 1)

    def test_complete_linkage(self) -> None:
        group_items = groups(self.sample_list(), threshold=0.5, linkage="complete")
        self.assertTrue(all(g["size"] >= 1 for g in group_items))

    def test_project_examples_form_separate_groups(self) -> None:
        sample_list = [
            {"name": item_name, "analysis": analyze(EXAMPLES[item_name]["code"])}
            for item_name in ("linux-hello", "windows-hello", "bubble")
        ]
        group_items = groups(sample_list, threshold=0.9)
        self.assertGreaterEqual(len(group_items), 2)


if __name__ == "__main__":
    unittest.main()
