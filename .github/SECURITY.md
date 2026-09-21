# Política de Segurança

## Como relatar uma vulnerabilidade

Encontrou um problema de segurança? **Não abra issue pública.**

Mande um e-mail para **seguranca@example.com** com:

- descrição do problema e o impacto que ele permite;
- passos para reproduzir (arquivo `.asm` ou `.asmproj` de exemplo, se houver);
- versão do ASM X (`python3 -c "import asmx; print(asmx.__version__)"`), sistema
  operacional e versão do Python;
- se quiser, a correção sugerida.

Você recebe uma confirmação em até **72 horas** e uma posição sobre o relato em
até **7 dias**. Se o problema for confirmado, combinamos o prazo de correção e o
crédito pelo achado — a menos que você prefira ficar anônimo. Pedimos apenas que
o problema não seja divulgado antes de existir versão corrigida.

## Versões suportadas

| Versão | Situação | Até |
|--------|----------|-----|
| 1.0.x  | Suportada, recebe correção de segurança | 2027-09 |
| < 1.0  | Fim de vida, não recebe correção | — |

## O que o ASM X faz e o que ele não faz

Esta é a parte que importa para julgar qualquer relato de segurança neste
projeto.

**O ASM X nunca monta, nunca liga e nunca executa binário de verdade.** Ele lê
arquivos de texto (`.asm`, `.s`, `.asmproj`), interpreta e explica o que cada
instrução faz. Não existe `nasm`, `ld`, `gcc`, `subprocess` ou `exec` no caminho
de execução da ferramenta.

**A máquina virtual é uma simulação em Python.** Ela modela registradores,
flags, pilha e memória como estruturas de dados do próprio interpretador, e cobre
apenas o essencial das instruções de inteiros. Não há tradução para código de
máquina, não há `mmap` com permissão de execução, não há `ctypes`, não há
chamada de sistema real: uma `syscall` no programa analisado é apenas registrada
e, quando simulada, tem efeito dentro do modelo — nunca no sistema operacional.
O que roda na sua máquina é o Python do ASM X; o código assembly analisado é
dado, não programa.

**Consequência prática:** analisar um fonte `.asm` não confiável é seguro. O
pior que um arquivo hostil pode fazer é travar a simulação, consumir memória,
entrar em laço infinito ou explorar um defeito do próprio ASM X — por isso os
relatos de estouro, laço sem fim e consumo de memória são tratados como
problemas de segurança e valem e-mail privado.

### O que continua sendo responsabilidade sua

O ASM X é uma ferramenta de estudo: ele ajuda a entender e achar defeito
**antes** de rodar. Ele não substitui o ciclo real de montagem e execução.

Se você pegar o `.asm` que estudou aqui e rodar com `nasm`, `ld`, `gcc` ou
qualquer outro montador de verdade, o resultado é um **binário real, executando
de verdade na sua máquina**, com os privilégios do seu usuário. A partir desse
momento quem responde é você:

- rode código de origem desconhecida ou não confiável **somente** dentro de uma
  máquina virtual ou container isolado, sem rede, sem acesso à sua pasta pessoal
  e com o mínimo de privilégios;
- nunca rode como root e nunca no seu ambiente de trabalho;
- trate qualquer fonte que você não escreveu como hostil, mesmo que ele passe
  limpo pelas regras de validação — as regras pegam defeito comum de
  programação, não código malicioso.

O ASM X não assina, não verifica e não garante nada sobre o que você monta fora
dele.

## Práticas recomendadas ao usar a ferramenta

- Mantenha o Python atualizado. O ASM X não tem dependências para atualizar.
- Rode a interface com o seu usuário comum, nunca como administrador.
- Projetos `.asmproj` são JSON: vêm de terceiros, são dados — trate como
  qualquer arquivo recebido de fora.
- Ao abrir um projeto ou fonte que não é seu, prefira uma máquina virtual
  descartável e deixe a rede desligada.
- Se você mantém um fork: `git tag -s v1.0.0 -m "Release v1.0.0"` e
  `git push origin v1.0.0` para publicar releases assinadas.

## Fora do escopo

Não são consideradas vulnerabilidades do ASM X:

- falha de segurança no binário que **você** gerou com `nasm`/`ld` e executou;
- instrução, syscall ou recurso de hardware que a simulação não cobre (SSE,
  macros do NASM, a maior parte das syscalls) — isso é limite documentado em
  `docs/GUIA.md`, não defeito de segurança;
- alerta de antivírus sobre um `.asm` que você mesmo escreveu para estudar
  técnicas de baixo nível;
- execução lenta ou consumo de memória em programa com laço infinito
  **intencional** no fonte analisado. Laço infinito acidental, que trava a
  interface sem escape, é defeito e deve ser relatado.
