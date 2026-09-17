import os
import tempfile
import unittest

from asmx.examples import EXAMPLES
from asmx.workspace import (Project, Scenario, parse_reg_values,
                            run_all_scenarios, run_scenario)

HELLO = EXAMPLES["linux-hello"]["code"]


class TestProjeto(unittest.TestCase):

    def setUp(self):
        self.p = Project.new(code=HELLO, name="teste")

    def test_projeto_novo_tem_branch_principal(self):
        self.assertEqual(self.p.active, "principal")
        self.assertEqual(self.p.code, HELLO)

    def test_fork_copia_o_codigo(self):
        b = self.p.fork("experimento")
        self.assertEqual(b.code, HELLO)
        self.assertEqual(b.parent, "principal")
        self.assertIn("experimento", self.p.branches)

    def test_branches_sao_independentes(self):
        self.p.fork("experimento")
        self.p.switch("experimento")
        self.p.set_code("mov rax, 1")
        self.assertEqual(self.p.code, "mov rax, 1")
        self.p.switch("principal")
        self.assertEqual(self.p.code, HELLO)

    def test_fork_com_nome_repetido_falha(self):
        self.p.fork("x")
        with self.assertRaises(ValueError):
            self.p.fork("x")

    def test_fork_sem_nome_falha(self):
        with self.assertRaises(ValueError):
            self.p.fork("   ")

    def test_nao_apaga_a_ultima_branch(self):
        with self.assertRaises(ValueError):
            self.p.delete_branch("principal")

    def test_apagar_branch_ativa_troca_para_outra(self):
        self.p.fork("b2")
        self.p.switch("b2")
        self.p.delete_branch("b2")
        self.assertEqual(self.p.active, "principal")

    def test_renomear_branch_mantem_filhos(self):
        self.p.fork("filha")
        self.p.rename_branch("principal", "base")
        self.assertEqual(self.p.branches["filha"].parent, "base")
        self.assertEqual(self.p.active, "base")

    def test_diff_entre_branches(self):
        self.p.fork("alt")
        self.p.switch("alt")
        self.p.set_code(HELLO.replace("Ola, mundo!", "Outro texto"))
        d = self.p.diff("principal", "alt")
        self.assertIn("Outro texto", d)
        self.assertIn("-", d)

    def test_anotacoes_por_linha(self):
        self.p.set_note(3, "aqui começa o texto")
        self.assertEqual(self.p.note(3), "aqui começa o texto")
        self.p.set_note(3, "")
        self.assertEqual(self.p.note(3), "")

    def test_anotacao_nao_vaza_para_nova_branch_depois_do_fork(self):
        self.p.set_note(1, "nota da principal")
        self.p.fork("b")
        self.p.switch("b")
        self.assertEqual(self.p.note(1), "nota da principal")
        self.p.set_note(1, "só da b")
        self.p.switch("principal")
        self.assertEqual(self.p.note(1), "nota da principal")

    def test_breakpoints(self):
        self.assertTrue(self.p.toggle_breakpoint(10))
        self.assertIn(10, self.p.branch.breakpoints)
        self.assertFalse(self.p.toggle_breakpoint(10))
        self.assertNotIn(10, self.p.branch.breakpoints)

    def test_salvar_e_carregar(self):
        self.p.set_note(2, "olha isto")
        self.p.fork("outra")
        self.p.toggle_breakpoint(4)
        self.p.add_scenario(Scenario(name="básico", expect_exit=0))
        with tempfile.TemporaryDirectory() as d:
            caminho = os.path.join(d, "proj.asmproj")
            self.p.save(caminho)
            self.assertTrue(os.path.exists(caminho))
            q = Project.load(caminho)
        self.assertEqual(set(q.branches), {"principal", "outra"})
        self.assertEqual(q.code, HELLO)
        self.assertEqual(q.note(2), "olha isto")
        self.assertIn(4, q.branch.breakpoints)
        self.assertEqual(q.branch.scenarios[0].name, "básico")
        self.assertFalse(q.dirty)

    def test_importar_asm_e_exportar(self):
        with tempfile.TemporaryDirectory() as d:
            origem = os.path.join(d, "a.asm")
            with open(origem, "w", encoding="utf-8") as f:
                f.write(HELLO)
            p = Project.from_asm_file(origem)
            self.assertEqual(p.code, HELLO)
            destino = os.path.join(d, "b.asm")
            p.export_asm(destino)
            with open(destino, encoding="utf-8") as f:
                self.assertEqual(f.read(), HELLO)

    def test_marca_de_alteracao(self):
        self.assertFalse(self.p.dirty)
        self.p.set_code("mov rax, 1")
        self.assertTrue(self.p.dirty)


class TestCenarios(unittest.TestCase):

    def test_parse_reg_values(self):
        d = parse_reg_values("rax=10, rbx=0x20; rcx = 5")
        self.assertEqual(d, {"rax": 10, "rbx": 32, "rcx": 5})
        self.assertEqual(parse_reg_values("naoexiste=1"), {})

    def test_cenario_aprovado(self):
        r = run_scenario(HELLO, Scenario(name="saida", expect_output="Ola, mundo!\n", expect_exit=0))
        self.assertTrue(r.passed, r.reason)
        self.assertEqual(r.exit_code, 0)

    def test_cenario_reprovado_mostra_motivo(self):
        r = run_scenario(HELLO, Scenario(name="errado", expect_output="outra coisa"))
        self.assertFalse(r.passed)
        self.assertIn("saída diferente", r.reason)

    def test_cenario_com_entrada_em_funcao_e_registradores(self):
        code = EXAMPLES["escala"]["code"]
        r = run_scenario(code, Scenario(name="soma ate 10", entry="soma_ate",
                                        regs={"rdi": 10}))
        self.assertTrue(r.passed, r.reason)
        r2 = run_scenario(code, Scenario(name="soma ate 100", entry="soma_ate",
                                         regs={"rdi": 100}))
        self.assertTrue(r2.passed, r2.reason)
        self.assertGreater(r2.steps, r.steps)

    def test_cenario_de_valor_absurdo_detecta_problema(self):
        """É o caso 'e se eu colocar um número muito alto?'."""
        code = EXAMPLES["escala"]["code"]
        r = run_scenario(code, Scenario(name="N gigante", entry="soma_ate",
                                        regs={"rdi": "0xFFFFFFFFFFFFFFFF"},
                                        max_steps=5000, expect_issue=True))
        self.assertTrue(r.passed, r.reason)
        self.assertTrue(r.issues)

    def test_cenario_espera_problema_mas_nao_ha(self):
        r = run_scenario(HELLO, Scenario(name="falso alarme", expect_issue=True))
        self.assertFalse(r.passed)
        self.assertIn("esperava", r.reason)

    def test_rodar_todos_os_cenarios(self):
        cenarios = [Scenario(name="a", expect_exit=0), Scenario(name="b", expect_exit=99)]
        rs = run_all_scenarios(HELLO, cenarios)
        self.assertEqual([r.passed for r in rs], [True, False])

    def test_cenario_serializa(self):
        s = Scenario(name="x", regs={"rax": 1}, expect_exit=0)
        d = s.to_dict()
        s2 = Scenario.from_dict(d)
        self.assertEqual(s2.name, "x")
        self.assertEqual(s2.regs, {"rax": 1})


if __name__ == "__main__":
    unittest.main()
