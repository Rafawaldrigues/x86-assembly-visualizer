# Contribuindo com o ASM X

Obrigado pelo interesse. O ASM X é um ambiente de desktop para estudar, validar,
testar e depurar assembly x86-64 — Python + Tkinter, biblioteca padrão e mais
nada. Toda contribuição é bem-vinda: código, documentação de instruções,
exemplos, tradução de mensagens ou apenas um relato de defeito bem descrito.

Antes de escrever código, vale ler `docs/GUIA.md` (como a ferramenta funciona) e
`docs/REFERENCIA.md` (o acervo de mnemônicos). E vale saber o que o projeto **não**
faz: ele não monta, não liga e não executa binário de verdade — a máquina virtual
simula instruções de inteiros em Python. Contribuições que empurram o projeto
para "montador caseiro" ou "debugger de processo real" fogem do escopo.

## Preparando o ambiente

```bash
git clone https://github.com/<usuario>/asmx
cd asmx
python3 -m venv .venv
source .venv/bin/activate         # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
```

No Linux a interface precisa do Tkinter, que não vem no `pip`:

| Sistema | Como instalar |
|---|---|
| Debian/Ubuntu | `sudo apt install python3-tk` |
| Fedora | `sudo dnf install python3-tkinter` |
| Arch | `sudo pacman -S tk` |
| Windows/macOS | já vem no instalador oficial do Python |

Para rodar a interface durante o desenvolvimento:

```bash
python3 asmx.py
```

O executável não tem dependência nenhuma: se `python3 asmx.py` abre a janela, o
ambiente está pronto. O `requirements-dev.txt` existe só para as ferramentas de
qualidade (formatação, lint, tipagem e cobertura).

## Estilo de código

O projeto é Python puro e segue estas regras sem exceção:

- **PEP 8**, formatado com **black `--line-length 100`**:

  ```bash
  black --line-length 100 asmx/ tests/
  flake8 asmx/ tests/ tools/ asmx.py --max-line-length 100
  ```

- **100% de anotações de tipo** em funções, métodos e atributos. O `mypy` não
  pode reclamar:

  ```bash
  mypy asmx/
  ```

- **Docstrings no estilo Google** para todo módulo, classe e função pública,
  explicando o que entra, o que sai e o que pode dar errado.
- **Comentários e mensagens em português do Brasil.** O código-fonte fala
  português: nomes de módulos e funções em inglês quando já são o vocabulário
  da área (`parse`, `analyze`, `validate`), mas comentários, docstrings, rótulos
  e mensagens de erro em pt-BR, direto, sem jargão de marketing e sem emoji.

Exemplo do tom esperado:

```python
def check_division(analysis: Analysis) -> List[Problem]:
    """Confere se a divisão está segura antes de rodar.

    `div` e `idiv` usam RDX:RAX como dividendo. Se RDX não for zerado antes, o
    quociente estoura e o processador levanta #DE — no Linux isso é SIGFPE.

    Args:
        analysis: Análise já produzida pelo `analyzer`.

    Returns:
        Lista de problemas encontrados (vazia quando está tudo certo).
    """
```

Sem dependência nova. O ASM X é biblioteca padrão por princípio: qualquer
contribuição que precise de `pip install` para rodar a ferramenta em si será
recusada. Ferramentas de desenvolvimento ficam no `requirements-dev.txt`.

## Rodando os testes

O núcleo roda sem tela:

```bash
python3 -m unittest discover -s tests
```

Os testes de interface precisam de um display. Em Linux headless (servidor, CI,
container), use o X virtual:

```bash
xvfb-run -a python3 -m unittest discover -s tests
```

Sem display, `tests/test_gui.py` se pula sozinho — é o comportamento esperado,
não um defeito. Um teste só é considerado pronto quando passa nos dois modos.

Um teste isolado, enquanto você trabalha:

```bash
python3 -m unittest tests.test_linter -v
```

### Cobertura

O piso é **94%** de cobertura de `asmx/`. Medida com o `coverage`:

```bash
coverage run --branch --source=asmx -m unittest discover -s tests
coverage report --fail-under=94 --show-missing
```

A cobertura é medida com ramos (`--branch`), que é mais rígida que a contagem
por linha. Os números atuais aparecem no `README.md`.

Código novo entra com teste. Não existe contribuição "só de código": se a
mudança mexe em parser, analisador, máquina virtual, validador ou projeto,
o teste correspondente faz parte do mesmo commit.

## Mensagens de commit

Conventional Commits, em português, com escopo quando fizer sentido:

```
feat(linter): nova regra para shadow space
fix(emulator): corrige sinal em IDIV
docs(referencia): documenta JRCXZ
test(parser): cobre sintaxe GAS com sufixo de tamanho
refactor(analyzer): separa detecção de plataforma
perf(isa): indexa mnemônicos por dicionário
chore(ci): fixa Python 3.11 no workflow
```

Tipos usados: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`.
Escopos mais comuns: `parser`, `analyzer`, `emulator`, `linter`, `workspace`,
`isa`, `ui`, `docs`, `ci`.

Escreva o assunto no imperativo e em uma linha só. Se a mudança precisa de
explicação, use o corpo do commit — explicando **por que**, não o quê (o diff já
mostra o quê).

## Processo de pull request

1. Abra uma issue antes, para mudanças grandes (regra nova, mudança de formato
   do `.asmproj`, alteração de escopo).
2. Faça um fork e crie um branch com nome descritivo:
   `feat/regra-shadow-space`, `fix/idiv-sinal`.
3. Commits pequenos, cada um fazendo sentido sozinho.
4. Antes de abrir o PR, rode localmente:

   ```bash
   black --line-length 100 asmx/ tests/
   flake8 asmx/ tests/ tools/ asmx.py --max-line-length 100
   mypy asmx/
   xvfb-run -a python3 -m unittest discover -s tests
   coverage run --source=asmx -m unittest discover -s tests && coverage report --fail-under=94
   ```

5. Abra o PR preenchendo o template. Descreva **o que muda para quem usa** — não
   apenas o que mudou no código.
6. Um mantenedor revisa. Comentários de revisão são sobre o código, nunca sobre
   a pessoa.
7. O merge é feito por squash, mantendo a mensagem no padrão acima.

PR que quebra teste existente, derruba a cobertura abaixo de 94% ou adiciona
dependência de runtime não é aceito — sem drama, é só ajustar.

## Como adicionar uma regra de validação

As regras ficam em `asmx/linter.py`. Cada uma é uma função que recebe a análise
pronta e devolve uma lista de `Problem`:

```python
def check_minha_regra(analysis: Analysis) -> List[Problem]:
    """Uma frase dizendo o que a regra procura."""
    out: List[Problem] = []
    for ins in analysis.instrs:
        if <condição suspeita>:
            out.append(Problem(
                ins.n, ALERTA, "XXX001",
                "o que está errado, em uma frase",
                "como corrigir, em uma frase"))
    return out
```

Passos:

1. Escolha um código de quatro letras + três dígitos, seguindo a família já
   usada: `STR` (strings), `STK` (pilha), `DIV` (divisão), `ABI` (convenção de
   chamada), `REG` (registrador), `MEM` (memória), `FLOW` (fluxo), `SYS`
   (syscalls), `SYM` (símbolos), `SEC` (seções), `IMM` (imediatos), `SHF`
   (deslocamento), `ENT`/`EXIT` (entrada e saída), `UNK` (instrução
   desconhecida). Não reaproveite código de outra regra.
2. Use a severidade certa: `ERRO` para o que quebra na execução, `ALERTA` para
   o que provavelmente é defeito, `INFO` para observação de estilo.
3. Registre a função em `ALL_CHECKS`, no fim do arquivo. Regra fora de
   `ALL_CHECKS` não roda — e o `validate()` engole exceção de regra, então
   regra quebrada vira `INT001` em vez de estourar a interface.
4. Toda mensagem tem **duas** partes: o que está errado e a dica de correção.
   Um `Problem` sem dica é uma regra pela metade.
5. Adicione os testes em `tests/test_linter.py`: um caso que **dispara** a regra
   (com o código esperado) e um que **não dispara** em código correto. Teste de
   regra que só cobre o caso positivo não é teste.
6. Se a regra depende de plataforma (shadow space é do Windows, alinhamento de
   pilha é do SysV), verifique `analysis.platform` antes de acusar — regra de
   Windows disparando em código Linux é falso positivo e vira issue.
7. Atualize a contagem de regras no `README.md` e no `docs/GUIA.md` se ela
   mudou, e registre a regra nova no `CHANGELOG.md`, em `[Não publicado]`.

## Como adicionar documentação de instrução

O acervo fica em `asmx/data/isa.json` e é carregado por `asmx/isa.py`. Não é
preciso mexer em Python para documentar uma instrução — só no JSON.

Estrutura de uma entrada (as chaves são exatamente estas — `note` é opcional):

```json
"loop": {
  "cat": "branch",
  "name": "Loop — repete usando RCX como contador",
  "syntax": "LOOP rótulo",
  "desc": "Decrementa RCX e desvia se RCX != 0. Equivale a DEC RCX / JNZ, mas costuma ser mais lento que escrever os dois.",
  "ex": ["MOV RCX, 5", "corpo:", "  LOOP corpo"],
  "flags": "Não altera flags."
}
```

Regras do acervo:

- Uma entrada por mnemônico, em minúsculas, na chave `ISA`.
- `cat` precisa ser uma das categorias de `CATEGORIES` (`data`, `stack`,
  `arith`, `logic`, `cmp`, `branch`, `call`, `sys`, `string`, `fpu`, `misc`).
- `name` é o título curto que aparece na interface. `syntax` mostra a forma de
  uso. `desc` explica a armadilha, o efeito nas flags e o que costuma dar errado
  — é o texto que o estudante lê. `flags` diz o que a instrução mexe, usando os
  nomes de `FLAG_DOC` (`ZF`, `SF`, `CF`, `OF`, `PF`, `DF`) ou a frase
  "Não altera flags.".
- `ex` é uma lista com um exemplo de assembly válido em NASM/Intel. Use `note`
  quando houver uma observação que não cabe em `desc`.
- Depois de editar, confira que o JSON continua válido e que o acervo carrega:

  ```bash
  python3 -c "import json;d=json.load(open('asmx/data/isa.json',encoding='utf-8'));print(len(d['ISA']),'mnemonicos')"
  python3 -m unittest discover -s tests
  ```

- Se a contagem de mnemônicos mudar, atualize `README.md` e `docs/GUIA.md`.
- Mnemônico sem entrada no acervo não é erro: o analisador apenas não explica a
  instrução. Mas a lista buraco é justamente o que a gente quer fechar.

Syscalls do Linux ficam em `LINUX_SYSCALLS` (número, nome, argumentos e o que
faz) e as APIs do Windows em `WIN_APIS`, no mesmo arquivo. Mesmo espírito:
explicar em português, com o detalhe que o manual oficial não dá de graça.

## Código de conduta

Este projeto adota o [Contributor Covenant 2.1](./CODE_OF_CONDUCT.md). Ao
participar — issue, PR, discussão ou comentário de revisão — você concorda em
seguir esse texto. Relatos de conduta vão para `conduta@example.com`, em
privado.

## Licença

Ao contribuir, você concorda que sua contribuição é licenciada sob a MIT, os
mesmos termos do [LICENSE](./LICENSE).
