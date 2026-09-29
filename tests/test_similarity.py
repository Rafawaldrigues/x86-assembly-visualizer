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

LOOP_PARECIDO = """
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


class TestVetor(unittest.TestCase):
    """The vector must be normalised, deterministic and comparable."""

    def test_vetor_nao_e_vazio(self) -> None:
        vetor = feature_vector(analyze(LOOP))
        self.assertTrue(vetor)
        self.assertTrue(all(chave.count(":") == 1 for chave in vetor))

    def test_vetor_e_normalizado(self) -> None:
        vetor = feature_vector(analyze(LOOP))
        norma = sum(valor * valor for valor in vetor.values()) ** 0.5
        self.assertAlmostEqual(norma, 1.0, places=9)

    def test_familias_esperadas(self) -> None:
        vetor = feature_vector(analyze(CONSOLE))
        familias = {chave.split(":")[0] for chave in vetor}
        self.assertIn("instruction", familias)
        self.assertIn("syscall", familias)
        self.assertIn("shape", familias)

    def test_programa_vazio(self) -> None:
        self.assertEqual(feature_vector(analyze("")), {})

    def test_deterministico(self) -> None:
        self.assertEqual(feature_vector(analyze(LOOP)), feature_vector(analyze(LOOP)))

    def test_contagem_alta_nao_domina(self) -> None:
        """log1p damping: 100 instructions must not outweigh a distinct signal."""
        muitos = "section .text\n_start:\n" + "nop\n" * 100
        vetor = feature_vector(analyze(muitos))
        self.assertLess(max(vetor.values()), 1.0)

    def test_problemas_e_comportamentos_reaproveitados(self) -> None:
        analise = analyze(EXAMPLES["suspicious"]["code"])
        vetor = feature_vector(analise)
        self.assertTrue(any(chave.startswith("behavior:") for chave in vetor))

    def test_feature_names(self) -> None:
        self.assertEqual(feature_names(), list(FEATURE_WEIGHTS))


class TestComparacao(unittest.TestCase):
    """Cosine and Jaccard, including the empty cases."""

    def test_identicos(self) -> None:
        vetor = feature_vector(analyze(LOOP))
        self.assertAlmostEqual(cosine(vetor, vetor), 1.0, places=9)

    def test_vazio_com_qualquer_coisa(self) -> None:
        self.assertEqual(cosine({}, {"a": 1.0}), 0.0)
        self.assertEqual(cosine({"a": 1.0}, {}), 0.0)

    def test_sem_interseccao(self) -> None:
        self.assertEqual(cosine({"a": 1.0}, {"b": 1.0}), 0.0)

    def test_simetrico(self) -> None:
        a = feature_vector(analyze(LOOP))
        b = feature_vector(analyze(CONSOLE))
        self.assertAlmostEqual(cosine(a, b), cosine(b, a), places=12)

    def test_entre_zero_e_um(self) -> None:
        a = feature_vector(analyze(LOOP))
        b = feature_vector(analyze(CONSOLE))
        self.assertGreaterEqual(cosine(a, b), 0.0)
        self.assertLessEqual(cosine(a, b), 1.0)

    def test_parecidos_acima_de_diferentes(self) -> None:
        parecido = cosine(feature_vector(analyze(LOOP)), feature_vector(analyze(LOOP_PARECIDO)))
        diferente = cosine(feature_vector(analyze(LOOP)), feature_vector(analyze(CONSOLE)))
        self.assertGreater(parecido, diferente)
        self.assertGreater(parecido, 0.99)

    def test_jaccard(self) -> None:
        self.assertEqual(jaccard({"a", "b"}, {"a", "b"}), 1.0)
        self.assertEqual(jaccard({"a"}, {"b"}), 0.0)
        self.assertAlmostEqual(jaccard({"a", "b"}, {"b", "c"}), 1 / 3, places=9)
        self.assertEqual(jaccard(set(), set()), 1.0)
        self.assertEqual(jaccard(set(), {"a"}), 0.0)

    def test_matriz_simetrica_com_diagonal_um(self) -> None:
        vetores = [feature_vector(analyze(fonte)) for fonte in (LOOP, CONSOLE, LOOP_PARECIDO)]
        matriz = similarity_matrix(vetores)
        for i, linha in enumerate(matriz):
            self.assertEqual(linha[i], 1.0)
            for j, valor in enumerate(linha):
                self.assertAlmostEqual(valor, matriz[j][i], places=12)
        self.assertEqual(similarity_matrix([{"a": 1.0}]), [[1.0]])
        self.assertEqual(similarity_matrix([]), [])


class TestAgrupamento(unittest.TestCase):
    """Clustering: grouping, ordering, threshold and linkage."""

    def vetores(self) -> list:
        return [feature_vector(analyze(fonte)) for fonte in (LOOP, LOOP_PARECIDO, CONSOLE)]

    def test_agrupa_iguais(self) -> None:
        grupos = cluster(self.vetores())
        self.assertEqual(grupos[0].members, [0, 1])
        self.assertEqual(grupos[1].members, [2])

    def test_ordena_por_tamanho(self) -> None:
        grupos = cluster([{"a": 1.0}, {"a": 1.0}, {"a": 1.0}, {"b": 1.0}])
        self.assertEqual(grupos[0].members, [0, 1, 2])
        self.assertEqual(grupos[1].members, [3])

    def test_limiar_alto_separa_o_que_e_so_parecido(self) -> None:
        """Identical vectors always stay together: the threshold is a floor."""
        grupos = cluster(self.vetores(), threshold=0.999)
        self.assertEqual([g.members for g in grupos], [[0, 1], [2]])

    def test_limiar_controla_o_agrupamento(self) -> None:
        # cos(0, 1) ~= 0.90 and cos(0, 2) = cos(1, 2) = 0
        vetores = [{"a": 1.0}, {"a": 0.9, "b": 0.44}, {"c": 1.0}]
        self.assertEqual([g.members for g in cluster(vetores, threshold=0.95)], [[0], [1], [2]])
        self.assertEqual([g.members for g in cluster(vetores, threshold=0.85)], [[0, 1], [2]])
        self.assertEqual([g.members for g in cluster(vetores, threshold=0.0)], [[0, 1, 2]])

    def test_limiar_zero_junta_tudo(self) -> None:
        grupos = cluster([{"a": 1.0}, {"b": 1.0}], threshold=0.0)
        self.assertEqual(len(grupos), 1)
        self.assertEqual(grupos[0].members, [0, 1])

    def test_coesao(self) -> None:
        grupos = cluster([{"a": 1.0}, {"a": 1.0}])
        self.assertAlmostEqual(grupos[0].cohesion, 1.0, places=9)
        solitario = cluster([{"a": 1.0}])
        self.assertEqual(solitario[0].cohesion, 1.0)

    def test_complete_linkage_e_mais_estreito(self) -> None:
        # 0 and 2 are similar to 1 but not to each other
        vetores = [{"a": 1.0, "b": 0.55}, {"a": 1.0, "b": 0.9}, {"a": 1.0, "b": 1.25}]
        simples = cluster(vetores, threshold=0.95, linkage="single")
        completo = cluster(vetores, threshold=0.95, linkage="complete")
        self.assertGreaterEqual(len(completo), len(simples))

    def test_linkage_invalido(self) -> None:
        with self.assertRaises(ValueError):
            cluster([{"a": 1.0}], linkage="average")

    def test_lista_vazia(self) -> None:
        self.assertEqual(cluster([]), [])

    def test_deterministico(self) -> None:
        primeira = [g.members for g in cluster(self.vetores())]
        segunda = [g.members for g in cluster(self.vetores())]
        self.assertEqual(primeira, segunda)

    def test_to_dict(self) -> None:
        dados = Cluster([0, 1], cohesion=0.98765, label="syscall:socket").to_dict()
        self.assertEqual(dados["members"], [0, 1])
        self.assertEqual(dados["size"], 2)
        self.assertEqual(dados["cohesion"], 0.9877)
        self.assertEqual(dados["label"], "syscall:socket")

    def test_similar_to(self) -> None:
        vetores = self.vetores()
        ranking = similar_to(vetores[0], vetores, top=2)
        self.assertEqual(ranking[0][0], 0)
        self.assertAlmostEqual(ranking[0][1], 1.0, places=9)
        self.assertEqual(ranking[1][0], 1)

    def test_similar_to_com_top_zero(self) -> None:
        self.assertEqual(similar_to({"a": 1.0}, [{"a": 1.0}], top=0), [])


class TestGroups(unittest.TestCase):
    """The name-aware facade used by the batch command."""

    def amostras(self) -> list:
        return [
            {"name": "loop-a.asm", "analysis": analyze(LOOP)},
            {"name": "loop-b.asm", "analysis": analyze(LOOP_PARECIDO)},
            {"name": "console.asm", "analysis": analyze(CONSOLE)},
        ]

    def test_agrupa_por_nome(self) -> None:
        grupos = groups(self.amostras())
        self.assertEqual(grupos[0]["size"], 2)
        self.assertEqual(grupos[0]["members"], ["loop-a.asm", "loop-b.asm"])
        self.assertRegex(grupos[0]["label"], r"^(behavior|instruction|syscall):")
        self.assertEqual(grupos[1]["members"], ["console.asm"])

    def test_rotulo_e_uma_caracteristica_comum_a_todos(self) -> None:
        vetores = [
            {"instruction:dec": 0.7, "shape:blocks": 0.7},
            {"instruction:dec": 0.7, "syscall:exit": 0.7},
        ]
        self.assertEqual(_group_label(vetores, [0, 1]), "instruction:dec")
        self.assertEqual(_group_label([{"a": 1.0}], [0]), "")

    def test_rotulo_vazio_para_solitario(self) -> None:
        grupos = groups([{"name": "a.asm", "analysis": analyze(CONSOLE)}])
        self.assertEqual(grupos[0]["label"], "")

    def test_limiar_afeta_o_resultado(self) -> None:
        amostras = self.amostras()
        self.assertEqual(len(groups(amostras, threshold=0.9)), 2)
        self.assertEqual(len(groups(amostras, threshold=0.4)), 1)

    def test_complete_linkage(self) -> None:
        grupos = groups(self.amostras(), threshold=0.5, linkage="complete")
        self.assertTrue(all(g["size"] >= 1 for g in grupos))

    def test_exemplos_do_projeto_separam(self) -> None:
        amostras = [
            {"name": nome, "analysis": analyze(EXAMPLES[nome]["code"])}
            for nome in ("linux-hello", "windows-hello", "bubble")
        ]
        grupos = groups(amostras, threshold=0.9)
        self.assertGreaterEqual(len(grupos), 2)


if __name__ == "__main__":
    unittest.main()
