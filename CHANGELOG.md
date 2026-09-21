# Changelog

Todas as mudanças relevantes do ASM X ficam registradas aqui.

O formato segue o [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e o
projeto usa [Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [Não publicado]

### Added

- Nada por enquanto. Toda contribuição nova entra aqui antes da próxima versão.

### Changed

- Nada por enquanto.

### Fixed

- Nada por enquanto.

## [1.0.0] - 2026-09-21

Primeira versão estável. O ASM X nasce como ambiente de desktop para estudar,
validar, testar e depurar assembly x86-64 — Python + Tkinter, biblioteca padrão e
nenhuma dependência externa.

### Added

- **Leitura de três sintaxes**: o parser reconhece NASM/Intel (`mov rax, 1`),
  MASM (diretivas e `PTR`) e GAS/AT&T (`movq $1, %rax`), incluindo rótulos,
  seções, diretivas de dados e os comentários de cada dialeto. O AT&T é
  normalizado para a ordem Intel, então todo o resto da ferramenta trabalha com
  uma única forma.
- **Explicação semântica por instrução**: cada linha recebe uma etiqueta de
  efeito ("Escreve na memória", "Desvia se for igual", "Chamada de sistema") e
  uma frase em português dizendo o que ela faz, incluindo o efeito nas flags e o
  papel do operando (variável local, parâmetro, ponteiro, constante).
- **Detecção de plataforma e ABI**: identifica Linux ou Windows pelas pistas do
  próprio fonte (syscall, `kernel32`, diretivas, convenção de chamada), mostra a
  confiança da conclusão, as evidências e as regras de chamada de cada sistema.
- **Mapa de fluxo de controle**: funções e blocos básicos com "vem de" e
  "vai para", o motivo de cada desvio condicional, o caminho de cada salto e o
  motivo de cada saída de bloco.
- **Validação estática**: 15 checagens que produzem 34 códigos de problema em
  três severidades (erro, alerta, informação), cada um com dica de correção —
  string com acento, string sem terminador, `div` sem preparar RDX, `push` sem
  `pop`, imediato que não cabe, tamanho de operando ambíguo, shadow space do
  Windows, rótulo inexistente, escrita em `.rodata`, registrador lido antes de
  receber valor, laço infinito, código inalcançável e por aí.
- **Máquina virtual didática**: executa o assembly direto, sem montar nem ligar
  nada, com registradores, flags, pilha e memória à vista, breakpoints,
  histórico de execução e detecção de estouro, divisão por zero, pilha
  desbalanceada e leitura de memória nunca escrita.
- **Projeto em arquivo único** (`.asmproj`, JSON) com branches do mesmo programa,
  diff entre elas, anotações por linha, breakpoints e cenários de teste — tudo
  versionável junto com o código e fora do `.asm`.
- **Cenários de teste**: estado inicial (onde começar, quais registradores,
  entrada simulada) mais a expectativa (saída, código de saída ou "deve acusar
  problema"), com limite de instruções e de tempo.
- **Interface Tkinter**: editor com realce e calha de breakpoints, árvore de
  estrutura do código, painel da máquina, painel de documentação, painel de
  testes, tema escuro e atalhos de teclado.
- **Linha de comando completa**: `check`, `run`, `explain`, `info`, `examples` e
  `version`, com saída em JSON, códigos de saída estáveis (0/1/2/3/4), `--trace`,
  `--timeout`, `--entry` e `--stdin`.
- **Referência de 148 mnemônicos** em português, agrupados por finalidade, com
  sintaxe, descrição, efeito nas flags e exemplo de uso — disponível na interface
  e no terminal (`asmx explain prog.asm --mnemonic div`).
- **43 syscalls do Linux** documentadas (número, nome, argumentos e o que fazem)
  e as principais funções `kernel32`/`user32` do Windows.
- **8 programas de exemplo** prontos, do "olá mundo" com syscall à ordenação
  bolha, incluindo um com defeitos de propósito e outro que estoura com valor
  alto — gravados também em `examples/*.asm`.
- **Logging estruturado**: eventos com nome e campos próprios, em texto legível
  ou JSON de uma linha por evento, sem depender de biblioteca externa.
- **Códigos de erro padronizados** em `asmx.errors`, com código estável,
  contexto estruturado e compatibilidade com `ValueError`, `KeyError` e
  `FileNotFoundError`.
- **Configuração por arquivo e ambiente** (`asmx.yaml`, `asmx.json`,
  `ASMX_TIMEOUT`, `--config`), com validação e mensagens que dizem qual campo
  está errado.
- **Anotações de tipo em 100% do código**, docstrings no padrão Google com
  exemplos executáveis e comentários em português em todos os módulos.
- **Portões de qualidade automatizados** (`tools/quality_gates.py`): reprovam
  qualquer função sem anotação, sem docstring ou com parâmetro não documentado.
- **Suíte de testes** cobrindo parser, analisador, validador, máquina virtual,
  projeto, configuração, erros, CLI e interface (esta última sob `xvfb`).
- **Integração contínua** com GitHub Actions em Python 3.9 a 3.13: flake8, mypy,
  portões de qualidade, testes com cobertura e verificação de que o pacote
  instala e roda numa `venv` vazia.
- **Varredura de segurança** com bandit e pip-audit, mais a política de
  segurança em `.github/SECURITY.md`.
- **Docker**: imagem enxuta com usuário sem privilégio, `HEALTHCHECK` e alvos
  `check`, `run`, `test`, `quality` e `gui`.
- **Documentação**: `README.md`, `docs/GUIA.md` (manual de uso, CLI,
  configuração, logging e erros) e `docs/REFERENCIA.md` (acervo completo).

### Changed

- **Divisão de trabalho entre passo a passo e modo contínuo**: "Passo" mostra o
  efeito de uma instrução e para; "Rodar" vai até o fim, até um breakpoint ou
  até um problema detectado.
- **Detecção de plataforma passou a explicar a conclusão**: além de dizer
  "Linux" ou "Windows", lista as pistas que levaram a isso.
- **Anotações saíram do `.asm` para o projeto**, para não sujar o fonte que
  seria montado de verdade depois.
- **Erros da biblioteca ganharam código estável** (`ERR_*`) sem deixar de ser
  `ValueError`, `KeyError` ou `FileNotFoundError` para quem já tratava assim.
- **A linha de comando virou cidadã de primeira classe**: a interface gráfica é
  um dos front-ends, não o único.

### Fixed

Problemas reais encontrados pelos testes e pela revisão, cada um com caso de
teste que reproduz:

- **`times` com valor** gravava zeros em vez de repetir o valor: `times 3 db 7`
  agora produz três bytes `07`.
- **`INT 0x80` usava a tabela de syscalls de 64 bits**, então o exemplo clássico
  de 32 bits (`eax=4` para `write`) chamava a syscall errada; agora os números do
  i386 são traduzidos e o que não tem equivalente é avisado.
- **Arquivo com BOM UTF-8** deixava o caractere `\ufeff` grudado no primeiro
  mnemônico; a leitura reconhece e remove o BOM.
- **Deslocamento negativo em AT&T** (`-8(%rbp)`) era convertido para `[rbp+-8]`;
  agora sai `[rbp-8]`.
- **`SourceReadError` não estava importado** em `workspace.py`, o que transformava
  um erro de leitura de projeto em `NameError`.
- **Projeto `.asmproj` corrompido** deixou de vazar `JSONDecodeError` cru: agora
  vira `ProjectFormatError` com o arquivo e a linha do problema.
- **Divisão por zero e estouro de quociente** não derrubam mais a simulação:
  viram problema detectado, explicado na linha, com a execução parando em paz.
- **`movsx`/`movzx`/`cdq`/`cqo`** preenchem os bits superiores como o processador
  faz, em vez de deixar lixo.
- **Exemplos e arquivos `examples/*.asm`** não podem divergir: um teste compara os
  dois e `tools/export_examples.py` regrava a partir da fonte única.

### Performance

- **Acervo de instruções carregado uma única vez por processo**, na importação.
- **Uma leitura de disco por arquivo**, com hash e impressão digital calculados
  sobre os mesmos bytes.
- **Parser, análise e validação trabalham sobre a mesma estrutura em memória** —
  nada é reparseado a cada consulta da interface.
- **Realce do editor agendado com atraso e cancelamento do trabalho anterior**,
  em vez de redesenhar a cada tecla digitada.
- **Log só formata o que o nível pedido exige**; sem handler configurado, uma
  biblioteca embutida em outro programa não imprime nada.

[1.0.0]: https://github.com/usuario/asmx/releases/tag/v1.0.0
