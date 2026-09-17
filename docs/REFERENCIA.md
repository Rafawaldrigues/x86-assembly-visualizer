# Referência de instruções x86-64

Gerado a partir do mesmo acervo que a aba **Docs** do ASM X usa.
Todos os 148 mnemônicos reconhecidos, agrupados por finalidade.

> Convenção usada aqui: o **destino** vem primeiro (sintaxe Intel/NASM).
> No GAS/AT&T a ordem é invertida e os registradores levam `%`.

## Índice

1. [Movimentação de dados](#1-movimentacao-de-dados)
2. [Pilha](#2-pilha)
3. [Aritmética](#3-aritmetica)
4. [Lógica e bits](#4-logica-e-bits)
5. [Comparação](#5-comparacao)
6. [Desvio](#6-desvio)
7. [Chamada / retorno](#7-chamada-retorno)
8. [Sistema](#8-sistema)
9. [Blocos de memória](#9-blocos-de-memoria)
10. [SSE / ponto flutuante](#10-sse-ponto-flutuante)
11. [Diversos](#11-diversos)

---

## 1. Movimentação de dados

Copia valores entre registradores, memória e imediatos.

### 1.1 MOV — copia um valor

**Sintaxe:** `MOV destino, origem`

Copia o conteúdo da origem para o destino. A origem não muda. Não existe MOV de memória para memória: um dos dois lados precisa ser registrador (ou a origem um imediato).

```asm
MOV RAX, 10        ; coloca o número 10 em RAX
MOV RBX, RAX       ; copia RAX para RBX
MOV [contador], EAX ; escreve EAX na variável contador
```

**Flags:** Não altera flags.

### 1.2 MOVZX — copia preenchendo com zeros

**Sintaxe:** `MOVZX destino_maior, origem_menor`

Copia um valor pequeno (8 ou 16 bits) para um registrador maior preenchendo o resto com zeros. Use para valores sem sinal (unsigned).

```asm
MOVZX EAX, BYTE [buf]  ; 1 byte -> 32 bits, resto zerado
```

**Flags:** Não altera flags.

### 1.3 MOVSX — copia preservando o sinal

**Sintaxe:** `MOVSX destino_maior, origem_menor`

Igual ao MOVZX, mas replica o bit de sinal. Use para valores com sinal (signed), senão -1 em 8 bits vira 255 em 32 bits.

```asm
MOVSX RAX, AL      ; -1 continua sendo -1
```

**Flags:** Não altera flags.

### 1.4 MOVSXD — 32 para 64 bits com sinal

**Sintaxe:** `MOVSXD destino64, origem32`

Estende um valor de 32 bits com sinal para 64 bits. Muito comum ao usar um índice int como offset de ponteiro.

```asm
MOVSXD RCX, EDI
```

**Flags:** Não altera flags.

### 1.5 LEA — calcula um endereço

**Sintaxe:** `LEA destino, [expressão]`

Calcula o endereço da expressão entre colchetes e guarda o número no destino, SEM ler a memória. É a forma normal de pegar o endereço de uma string, e também um jeito rápido de fazer contas (multiplicar por 2/4/8 e somar).

```asm
LEA RSI, [msg]            ; RSI = endereço da string
LEA RAX, [RBX+RCX*4+8]    ; RAX = RBX + RCX*4 + 8, sem acessar memória
```

**Flags:** Não altera flags.

> MOV RSI, [msg] leria o conteúdo. LEA pega o endereço.

### 1.6 XCHG — troca dois valores

**Sintaxe:** `XCHG a, b`

Troca o conteúdo dos dois operandos. Quando um deles é memória, a operação é atômica (trava o barramento).

```asm
XCHG RAX, RBX
```

**Flags:** Não altera flags.

### 1.7 CMOV — copia só se a condição for verdadeira

**Sintaxe:** `CMOVcc destino, origem`

Copia a origem para o destino apenas se a condição (a mesma família de sufixos dos jumps: E, NE, G, L, A, B...) estiver satisfeita. Evita um desvio, o que ajuda o processador a não errar previsão.

```asm
CMP RAX, RBX
CMOVL RAX, RBX   ; RAX = min(RAX, RBX)
```

**Flags:** Lê as flags, não altera.

### 1.8 CMOVE — Conditional Move if E

**Sintaxe:** `CMOVE destino, origem`

Copia a origem para o destino apenas se igual (ZF = 1). Sem desvio, sem risco de erro de previsão.

```asm
CMP RAX, RBX
CMOVE RAX, RBX
```

**Flags:** Lê as flags, não altera.

### 1.9 CMOVZ — Conditional Move if Z

**Sintaxe:** `CMOVZ destino, origem`

Copia a origem para o destino apenas se zero (ZF = 1). Sem desvio, sem risco de erro de previsão.

```asm
CMP RAX, RBX
CMOVZ RAX, RBX
```

**Flags:** Lê as flags, não altera.

### 1.10 CMOVNE — Conditional Move if NE

**Sintaxe:** `CMOVNE destino, origem`

Copia a origem para o destino apenas se diferente (ZF = 0). Sem desvio, sem risco de erro de previsão.

```asm
CMP RAX, RBX
CMOVNE RAX, RBX
```

**Flags:** Lê as flags, não altera.

### 1.11 CMOVNZ — Conditional Move if NZ

**Sintaxe:** `CMOVNZ destino, origem`

Copia a origem para o destino apenas se não zero (ZF = 0). Sem desvio, sem risco de erro de previsão.

```asm
CMP RAX, RBX
CMOVNZ RAX, RBX
```

**Flags:** Lê as flags, não altera.

### 1.12 CMOVG — Conditional Move if G

**Sintaxe:** `CMOVG destino, origem`

Copia a origem para o destino apenas se maior (com sinal) (ZF = 0 e SF = OF). Sem desvio, sem risco de erro de previsão.

```asm
CMP RAX, RBX
CMOVG RAX, RBX
```

**Flags:** Lê as flags, não altera.

### 1.13 CMOVGE — Conditional Move if GE

**Sintaxe:** `CMOVGE destino, origem`

Copia a origem para o destino apenas se maior ou igual (com sinal) (SF = OF). Sem desvio, sem risco de erro de previsão.

```asm
CMP RAX, RBX
CMOVGE RAX, RBX
```

**Flags:** Lê as flags, não altera.

### 1.14 CMOVL — Conditional Move if L

**Sintaxe:** `CMOVL destino, origem`

Copia a origem para o destino apenas se menor (com sinal) (SF ≠ OF). Sem desvio, sem risco de erro de previsão.

```asm
CMP RAX, RBX
CMOVL RAX, RBX
```

**Flags:** Lê as flags, não altera.

### 1.15 CMOVLE — Conditional Move if LE

**Sintaxe:** `CMOVLE destino, origem`

Copia a origem para o destino apenas se menor ou igual (com sinal) (ZF = 1 ou SF ≠ OF). Sem desvio, sem risco de erro de previsão.

```asm
CMP RAX, RBX
CMOVLE RAX, RBX
```

**Flags:** Lê as flags, não altera.

### 1.16 CMOVA — Conditional Move if A

**Sintaxe:** `CMOVA destino, origem`

Copia a origem para o destino apenas se acima (sem sinal) (CF = 0 e ZF = 0). Sem desvio, sem risco de erro de previsão.

```asm
CMP RAX, RBX
CMOVA RAX, RBX
```

**Flags:** Lê as flags, não altera.

### 1.17 CMOVAE — Conditional Move if AE

**Sintaxe:** `CMOVAE destino, origem`

Copia a origem para o destino apenas se acima ou igual (sem sinal) (CF = 0). Sem desvio, sem risco de erro de previsão.

```asm
CMP RAX, RBX
CMOVAE RAX, RBX
```

**Flags:** Lê as flags, não altera.

### 1.18 CMOVB — Conditional Move if B

**Sintaxe:** `CMOVB destino, origem`

Copia a origem para o destino apenas se abaixo (sem sinal) (CF = 1). Sem desvio, sem risco de erro de previsão.

```asm
CMP RAX, RBX
CMOVB RAX, RBX
```

**Flags:** Lê as flags, não altera.

### 1.19 CMOVBE — Conditional Move if BE

**Sintaxe:** `CMOVBE destino, origem`

Copia a origem para o destino apenas se abaixo ou igual (sem sinal) (CF = 1 ou ZF = 1). Sem desvio, sem risco de erro de previsão.

```asm
CMP RAX, RBX
CMOVBE RAX, RBX
```

**Flags:** Lê as flags, não altera.

### 1.20 CMOVS — Conditional Move if S

**Sintaxe:** `CMOVS destino, origem`

Copia a origem para o destino apenas se negativo (SF = 1). Sem desvio, sem risco de erro de previsão.

```asm
CMP RAX, RBX
CMOVS RAX, RBX
```

**Flags:** Lê as flags, não altera.

### 1.21 CMOVNS — Conditional Move if NS

**Sintaxe:** `CMOVNS destino, origem`

Copia a origem para o destino apenas se não negativo (SF = 0). Sem desvio, sem risco de erro de previsão.

```asm
CMP RAX, RBX
CMOVNS RAX, RBX
```

**Flags:** Lê as flags, não altera.

### 1.22 CMOVC — Conditional Move if C

**Sintaxe:** `CMOVC destino, origem`

Copia a origem para o destino apenas se houve carry (CF = 1). Sem desvio, sem risco de erro de previsão.

```asm
CMP RAX, RBX
CMOVC RAX, RBX
```

**Flags:** Lê as flags, não altera.

### 1.23 CMOVNC — Conditional Move if NC

**Sintaxe:** `CMOVNC destino, origem`

Copia a origem para o destino apenas se não houve carry (CF = 0). Sem desvio, sem risco de erro de previsão.

```asm
CMP RAX, RBX
CMOVNC RAX, RBX
```

**Flags:** Lê as flags, não altera.

### 1.24 CMOVO — Conditional Move if O

**Sintaxe:** `CMOVO destino, origem`

Copia a origem para o destino apenas se houve overflow (OF = 1). Sem desvio, sem risco de erro de previsão.

```asm
CMP RAX, RBX
CMOVO RAX, RBX
```

**Flags:** Lê as flags, não altera.

### 1.25 CMOVNO — Conditional Move if NO

**Sintaxe:** `CMOVNO destino, origem`

Copia a origem para o destino apenas se não houve overflow (OF = 0). Sem desvio, sem risco de erro de previsão.

```asm
CMP RAX, RBX
CMOVNO RAX, RBX
```

**Flags:** Lê as flags, não altera.

### 1.26 CMOVP — Conditional Move if P

**Sintaxe:** `CMOVP destino, origem`

Copia a origem para o destino apenas se paridade par (PF = 1). Sem desvio, sem risco de erro de previsão.

```asm
CMP RAX, RBX
CMOVP RAX, RBX
```

**Flags:** Lê as flags, não altera.

### 1.27 CMOVNP — Conditional Move if NP

**Sintaxe:** `CMOVNP destino, origem`

Copia a origem para o destino apenas se paridade ímpar (PF = 0). Sem desvio, sem risco de erro de previsão.

```asm
CMP RAX, RBX
CMOVNP RAX, RBX
```

**Flags:** Lê as flags, não altera.

## 2. Pilha

Empilha/desempilha e mantém o quadro de função.

### 2.1 PUSH — empilha um valor

**Sintaxe:** `PUSH origem`

Subtrai 8 de RSP e grava o valor de 64 bits nesse endereço. A pilha cresce para endereços MENORES.

```asm
PUSH RAX        ; salva RAX na pilha
PUSH QWORD 42
```

**Flags:** Não altera flags.

### 2.2 POP — desempilha um valor

**Sintaxe:** `POP destino`

Lê 8 bytes do topo da pilha para o destino e soma 8 em RSP. Todo PUSH precisa de um POP correspondente (ou de um ajuste em RSP) antes do RET.

```asm
POP RBX
```

**Flags:** Não altera flags.

### 2.3 ENTER — monta o quadro de pilha

**Sintaxe:** `ENTER tamanho, nível`

Equivale a PUSH RBP / MOV RBP, RSP / SUB RSP, tamanho. Pouco usado hoje: a sequência manual é mais rápida.

```asm
ENTER 32, 0
```

**Flags:** Não altera flags.

### 2.4 LEAVE — desmonta o quadro de pilha

**Sintaxe:** `LEAVE`

Equivale a MOV RSP, RBP / POP RBP. É o epílogo padrão de uma função que usou RBP.

```asm
LEAVE
RET
```

**Flags:** Não altera flags.

## 3. Aritmética

Soma, subtrai, multiplica, divide.

### 3.1 ADD — soma

**Sintaxe:** `ADD destino, origem`

destino = destino + origem.

```asm
ADD RAX, 1
ADD RAX, RBX
```

**Flags:** Altera CF, OF, SF, ZF, AF, PF.

### 3.2 ADC — soma com o vai-um

**Sintaxe:** `ADC destino, origem`

destino = destino + origem + CF. Serve para somar números maiores que 64 bits em partes.

```asm
ADD RAX, RCX
ADC RDX, RBX
```

**Flags:** Altera CF, OF, SF, ZF, AF, PF.

### 3.3 SUB — subtrai

**Sintaxe:** `SUB destino, origem`

destino = destino - origem. Também é como se reserva espaço na pilha: SUB RSP, 32.

```asm
SUB RAX, 5
SUB RSP, 32   ; abre 32 bytes de espaço local
```

**Flags:** Altera CF, OF, SF, ZF, AF, PF.

### 3.4 SBB — subtrai com empréstimo

**Sintaxe:** `SBB destino, origem`

destino = destino - origem - CF. Par do ADC para números longos.

```asm
SBB RDX, RBX
```

**Flags:** Altera CF, OF, SF, ZF, AF, PF.

### 3.5 INC — soma 1

**Sintaxe:** `INC destino`

destino = destino + 1. Não mexe em CF (diferente de ADD x, 1).

```asm
INC RCX
```

**Flags:** Altera OF, SF, ZF, AF, PF. Preserva CF.

### 3.6 DEC — subtrai 1

**Sintaxe:** `DEC destino`

destino = destino - 1. Muito usado em contadores de laço junto com JNZ.

```asm
DEC RCX
JNZ loop
```

**Flags:** Altera OF, SF, ZF, AF, PF. Preserva CF.

### 3.7 NEG — troca o sinal

**Sintaxe:** `NEG destino`

destino = 0 - destino (complemento de dois).

```asm
NEG RAX
```

**Flags:** Altera CF, OF, SF, ZF, AF, PF.

### 3.8 MUL — Multiply (sem sinal)

**Sintaxe:** `MUL origem`

Multiplica RAX pela origem. O resultado de 128 bits fica em RDX:RAX. O operando implícito RAX é obrigatório.

```asm
MOV RAX, 6
MOV RBX, 7
MUL RBX      ; RAX = 42
```

**Flags:** Altera CF e OF (indicam se a parte alta é diferente de zero).

### 3.9 IMUL — Integer Multiply (com sinal)

**Sintaxe:** `IMUL origem  |  IMUL dest, origem  |  IMUL dest, origem, imediato`

Multiplicação com sinal. A forma de dois ou três operandos é a usada no dia a dia porque o destino é explícito.

```asm
IMUL RAX, RBX
IMUL RAX, RBX, 4
```

**Flags:** Altera CF e OF.

### 3.10 DIV — Divide (sem sinal)

**Sintaxe:** `DIV divisor`

Divide RDX:RAX pelo divisor. Quociente vai para RAX, resto para RDX. ATENÇÃO: zere RDX antes (XOR RDX, RDX), senão o resultado é lixo ou a CPU dispara exceção.

```asm
XOR RDX, RDX
MOV RAX, 100
MOV RBX, 7
DIV RBX      ; RAX=14, RDX=2
```

**Flags:** Flags ficam indefinidas.

### 3.11 IDIV — Integer Divide (com sinal)

**Sintaxe:** `IDIV divisor`

Igual ao DIV, mas com sinal. Antes dele use CQO (64 bits) ou CDQ (32 bits) para estender o sinal em RDX/EDX.

```asm
MOV RAX, -100
CQO
IDIV RBX
```

**Flags:** Flags ficam indefinidas.

## 4. Lógica e bits

AND/OR/XOR/NOT e deslocamentos.

### 4.1 AND — E bit a bit

**Sintaxe:** `AND destino, origem`

Mantém apenas os bits que estão ligados nos dois operandos. Usado para mascarar (ficar só com parte do valor).

```asm
AND RAX, 0x0F     ; fica só com os 4 bits baixos
```

**Flags:** Zera CF e OF; altera SF, ZF, PF.

### 4.2 OR — OU bit a bit

**Sintaxe:** `OR destino, origem`

Liga no destino todo bit que esteja ligado na origem. Usado para ativar flags.

```asm
OR RAX, 1         ; liga o bit 0
```

**Flags:** Zera CF e OF; altera SF, ZF, PF.

### 4.3 XOR — OU exclusivo

**Sintaxe:** `XOR destino, origem`

Bit fica 1 quando os dois são diferentes. XOR de um registrador com ele mesmo é a forma idiomática (e mais curta) de zerar.

```asm
XOR RAX, RAX      ; RAX = 0
```

**Flags:** Zera CF e OF; altera SF, ZF, PF.

### 4.4 NOT — inverte todos os bits

**Sintaxe:** `NOT destino`

Complemento de um: cada 0 vira 1 e vice-versa.

```asm
NOT RAX
```

**Flags:** Não altera flags.

### 4.5 SHL — desloca bits para a esquerda

**Sintaxe:** `SHL destino, contagem`

Cada deslocamento de 1 multiplica por 2. Entram zeros pela direita.

```asm
SHL RAX, 3        ; RAX = RAX * 8
```

**Flags:** Altera CF (último bit que saiu), OF, SF, ZF, PF.

### 4.6 SAL — idêntico ao SHL

**Sintaxe:** `SAL destino, contagem`

Mesma instrução do SHL; existe só por simetria com o SAR.

```asm
SAL RAX, 1
```

**Flags:** Igual ao SHL.

### 4.7 SHR — Shift Right (sem sinal)

**Sintaxe:** `SHR destino, contagem`

Desloca para a direita entrando zeros. Equivale a dividir por 2^n valores sem sinal.

```asm
SHR RAX, 1        ; RAX = RAX / 2 (unsigned)
```

**Flags:** Altera CF, OF, SF, ZF, PF.

### 4.8 SAR — Shift Arithmetic Right (com sinal)

**Sintaxe:** `SAR destino, contagem`

Desloca para a direita repetindo o bit de sinal, então números negativos continuam negativos.

```asm
SAR RAX, 2
```

**Flags:** Altera CF, OF, SF, ZF, PF.

### 4.9 ROL — rotaciona à esquerda

**Sintaxe:** `ROL destino, contagem`

Os bits que saem de um lado entram do outro. Nada é perdido.

```asm
ROL AL, 4
```

**Flags:** Altera CF e OF.

### 4.10 ROR — rotaciona à direita

**Sintaxe:** `ROR destino, contagem`

Rotação no sentido contrário ao ROL.

```asm
ROR AL, 4
```

**Flags:** Altera CF e OF.

### 4.11 BT — testa um bit

**Sintaxe:** `BT valor, índice`

Copia o bit indicado para CF, sem alterar o valor.

```asm
BT RAX, 5
JC ligado
```

**Flags:** Altera CF.

## 5. Comparação

Calcula e descarta o resultado, guardando só as flags.

### 5.1 CMP — compara dois valores

**Sintaxe:** `CMP a, b`

Faz a - b, joga o resultado fora e guarda só as flags. É sempre lido junto com o desvio seguinte: CMP RAX, 10 + JG significa "se RAX > 10".

```asm
CMP RAX, 10
JG maior
```

**Flags:** Altera CF, OF, SF, ZF, AF, PF.

### 5.2 TEST — AND que só produz flags

**Sintaxe:** `TEST a, b`

Faz a AND b e guarda só as flags. TEST RAX, RAX é o jeito idiomático de perguntar "RAX é zero?" — mais curto que CMP RAX, 0.

```asm
TEST RAX, RAX
JZ era_zero
```

**Flags:** Zera CF e OF; altera SF, ZF, PF.

### 5.3 SET — vira 0 ou 1 conforme a condição

**Sintaxe:** `SETcc destino8`

Grava 1 no byte de destino se a condição for verdadeira, senão 0. É como compiladores geram um bool.

```asm
CMP RAX, RBX
SETE AL     ; AL = (RAX == RBX)
```

**Flags:** Lê as flags, não altera.

### 5.4 SETE — 1 se igual

**Sintaxe:** `SETE destino8`

Coloca 1 no byte de destino se igual (ZF = 1), senão 0.

```asm
CMP RAX, RBX
SETE AL
```

**Flags:** Lê as flags, não altera.

### 5.5 SETZ — 1 se zero

**Sintaxe:** `SETZ destino8`

Coloca 1 no byte de destino se zero (ZF = 1), senão 0.

```asm
CMP RAX, RBX
SETZ AL
```

**Flags:** Lê as flags, não altera.

### 5.6 SETNE — 1 se diferente

**Sintaxe:** `SETNE destino8`

Coloca 1 no byte de destino se diferente (ZF = 0), senão 0.

```asm
CMP RAX, RBX
SETNE AL
```

**Flags:** Lê as flags, não altera.

### 5.7 SETNZ — 1 se não zero

**Sintaxe:** `SETNZ destino8`

Coloca 1 no byte de destino se não zero (ZF = 0), senão 0.

```asm
CMP RAX, RBX
SETNZ AL
```

**Flags:** Lê as flags, não altera.

### 5.8 SETG — 1 se maior (com sinal)

**Sintaxe:** `SETG destino8`

Coloca 1 no byte de destino se maior (com sinal) (ZF = 0 e SF = OF), senão 0.

```asm
CMP RAX, RBX
SETG AL
```

**Flags:** Lê as flags, não altera.

### 5.9 SETGE — 1 se maior ou igual (com sinal)

**Sintaxe:** `SETGE destino8`

Coloca 1 no byte de destino se maior ou igual (com sinal) (SF = OF), senão 0.

```asm
CMP RAX, RBX
SETGE AL
```

**Flags:** Lê as flags, não altera.

### 5.10 SETL — 1 se menor (com sinal)

**Sintaxe:** `SETL destino8`

Coloca 1 no byte de destino se menor (com sinal) (SF ≠ OF), senão 0.

```asm
CMP RAX, RBX
SETL AL
```

**Flags:** Lê as flags, não altera.

### 5.11 SETLE — 1 se menor ou igual (com sinal)

**Sintaxe:** `SETLE destino8`

Coloca 1 no byte de destino se menor ou igual (com sinal) (ZF = 1 ou SF ≠ OF), senão 0.

```asm
CMP RAX, RBX
SETLE AL
```

**Flags:** Lê as flags, não altera.

### 5.12 SETA — 1 se acima (sem sinal)

**Sintaxe:** `SETA destino8`

Coloca 1 no byte de destino se acima (sem sinal) (CF = 0 e ZF = 0), senão 0.

```asm
CMP RAX, RBX
SETA AL
```

**Flags:** Lê as flags, não altera.

### 5.13 SETAE — 1 se acima ou igual (sem sinal)

**Sintaxe:** `SETAE destino8`

Coloca 1 no byte de destino se acima ou igual (sem sinal) (CF = 0), senão 0.

```asm
CMP RAX, RBX
SETAE AL
```

**Flags:** Lê as flags, não altera.

### 5.14 SETB — 1 se abaixo (sem sinal)

**Sintaxe:** `SETB destino8`

Coloca 1 no byte de destino se abaixo (sem sinal) (CF = 1), senão 0.

```asm
CMP RAX, RBX
SETB AL
```

**Flags:** Lê as flags, não altera.

### 5.15 SETBE — 1 se abaixo ou igual (sem sinal)

**Sintaxe:** `SETBE destino8`

Coloca 1 no byte de destino se abaixo ou igual (sem sinal) (CF = 1 ou ZF = 1), senão 0.

```asm
CMP RAX, RBX
SETBE AL
```

**Flags:** Lê as flags, não altera.

### 5.16 SETS — 1 se negativo

**Sintaxe:** `SETS destino8`

Coloca 1 no byte de destino se negativo (SF = 1), senão 0.

```asm
CMP RAX, RBX
SETS AL
```

**Flags:** Lê as flags, não altera.

### 5.17 SETNS — 1 se não negativo

**Sintaxe:** `SETNS destino8`

Coloca 1 no byte de destino se não negativo (SF = 0), senão 0.

```asm
CMP RAX, RBX
SETNS AL
```

**Flags:** Lê as flags, não altera.

### 5.18 SETC — 1 se houve carry

**Sintaxe:** `SETC destino8`

Coloca 1 no byte de destino se houve carry (CF = 1), senão 0.

```asm
CMP RAX, RBX
SETC AL
```

**Flags:** Lê as flags, não altera.

### 5.19 SETNC — 1 se não houve carry

**Sintaxe:** `SETNC destino8`

Coloca 1 no byte de destino se não houve carry (CF = 0), senão 0.

```asm
CMP RAX, RBX
SETNC AL
```

**Flags:** Lê as flags, não altera.

### 5.20 SETO — 1 se houve overflow

**Sintaxe:** `SETO destino8`

Coloca 1 no byte de destino se houve overflow (OF = 1), senão 0.

```asm
CMP RAX, RBX
SETO AL
```

**Flags:** Lê as flags, não altera.

### 5.21 SETNO — 1 se não houve overflow

**Sintaxe:** `SETNO destino8`

Coloca 1 no byte de destino se não houve overflow (OF = 0), senão 0.

```asm
CMP RAX, RBX
SETNO AL
```

**Flags:** Lê as flags, não altera.

### 5.22 SETP — 1 se paridade par

**Sintaxe:** `SETP destino8`

Coloca 1 no byte de destino se paridade par (PF = 1), senão 0.

```asm
CMP RAX, RBX
SETP AL
```

**Flags:** Lê as flags, não altera.

### 5.23 SETNP — 1 se paridade ímpar

**Sintaxe:** `SETNP destino8`

Coloca 1 no byte de destino se paridade ímpar (PF = 0), senão 0.

```asm
CMP RAX, RBX
SETNP AL
```

**Flags:** Lê as flags, não altera.

## 6. Desvio

Muda o fluxo de execução.

### 6.1 JMP — desvio incondicional

**Sintaxe:** `JMP destino`

Continua a execução no rótulo (ou endereço) indicado, sem condição e sem guardar volta.

```asm
JMP fim
```

**Flags:** Não altera flags.

### 6.2 LOOP — repete usando RCX como contador

**Sintaxe:** `LOOP rótulo`

Decrementa RCX e desvia se RCX != 0. Equivale a DEC RCX / JNZ, mas costuma ser mais lento que escrever os dois.

```asm
MOV RCX, 5
corpo:
  LOOP corpo
```

**Flags:** Não altera flags.

### 6.3 JE — desvia se igual

**Sintaxe:** `JE rótulo`

Desvia para o rótulo quando a última comparação indicou igual. Condição nas flags: ZF = 1. Se a condição for falsa, a execução simplesmente segue para a linha de baixo.

```asm
CMP RAX, RBX
JE destino
```

**Flags:** Lê as flags, não altera.

### 6.4 JZ — desvia se zero

**Sintaxe:** `JZ rótulo`

Desvia para o rótulo quando a última comparação indicou zero. Condição nas flags: ZF = 1. Se a condição for falsa, a execução simplesmente segue para a linha de baixo.

```asm
CMP RAX, RBX
JZ destino
```

**Flags:** Lê as flags, não altera.

### 6.5 JNE — desvia se diferente

**Sintaxe:** `JNE rótulo`

Desvia para o rótulo quando a última comparação indicou diferente. Condição nas flags: ZF = 0. Se a condição for falsa, a execução simplesmente segue para a linha de baixo.

```asm
CMP RAX, RBX
JNE destino
```

**Flags:** Lê as flags, não altera.

### 6.6 JNZ — desvia se não zero

**Sintaxe:** `JNZ rótulo`

Desvia para o rótulo quando a última comparação indicou não zero. Condição nas flags: ZF = 0. Se a condição for falsa, a execução simplesmente segue para a linha de baixo.

```asm
CMP RAX, RBX
JNZ destino
```

**Flags:** Lê as flags, não altera.

### 6.7 JG — desvia se maior (com sinal)

**Sintaxe:** `JG rótulo`

Desvia para o rótulo quando a última comparação indicou maior (com sinal). Condição nas flags: ZF = 0 e SF = OF. Se a condição for falsa, a execução simplesmente segue para a linha de baixo.

```asm
CMP RAX, RBX
JG destino
```

**Flags:** Lê as flags, não altera.

### 6.8 JGE — desvia se maior ou igual (com sinal)

**Sintaxe:** `JGE rótulo`

Desvia para o rótulo quando a última comparação indicou maior ou igual (com sinal). Condição nas flags: SF = OF. Se a condição for falsa, a execução simplesmente segue para a linha de baixo.

```asm
CMP RAX, RBX
JGE destino
```

**Flags:** Lê as flags, não altera.

### 6.9 JL — desvia se menor (com sinal)

**Sintaxe:** `JL rótulo`

Desvia para o rótulo quando a última comparação indicou menor (com sinal). Condição nas flags: SF ≠ OF. Se a condição for falsa, a execução simplesmente segue para a linha de baixo.

```asm
CMP RAX, RBX
JL destino
```

**Flags:** Lê as flags, não altera.

### 6.10 JLE — desvia se menor ou igual (com sinal)

**Sintaxe:** `JLE rótulo`

Desvia para o rótulo quando a última comparação indicou menor ou igual (com sinal). Condição nas flags: ZF = 1 ou SF ≠ OF. Se a condição for falsa, a execução simplesmente segue para a linha de baixo.

```asm
CMP RAX, RBX
JLE destino
```

**Flags:** Lê as flags, não altera.

### 6.11 JA — desvia se acima (sem sinal)

**Sintaxe:** `JA rótulo`

Desvia para o rótulo quando a última comparação indicou acima (sem sinal). Condição nas flags: CF = 0 e ZF = 0. Se a condição for falsa, a execução simplesmente segue para a linha de baixo.

```asm
CMP RAX, RBX
JA destino
```

**Flags:** Lê as flags, não altera.

### 6.12 JAE — desvia se acima ou igual (sem sinal)

**Sintaxe:** `JAE rótulo`

Desvia para o rótulo quando a última comparação indicou acima ou igual (sem sinal). Condição nas flags: CF = 0. Se a condição for falsa, a execução simplesmente segue para a linha de baixo.

```asm
CMP RAX, RBX
JAE destino
```

**Flags:** Lê as flags, não altera.

### 6.13 JB — desvia se abaixo (sem sinal)

**Sintaxe:** `JB rótulo`

Desvia para o rótulo quando a última comparação indicou abaixo (sem sinal). Condição nas flags: CF = 1. Se a condição for falsa, a execução simplesmente segue para a linha de baixo.

```asm
CMP RAX, RBX
JB destino
```

**Flags:** Lê as flags, não altera.

### 6.14 JBE — desvia se abaixo ou igual (sem sinal)

**Sintaxe:** `JBE rótulo`

Desvia para o rótulo quando a última comparação indicou abaixo ou igual (sem sinal). Condição nas flags: CF = 1 ou ZF = 1. Se a condição for falsa, a execução simplesmente segue para a linha de baixo.

```asm
CMP RAX, RBX
JBE destino
```

**Flags:** Lê as flags, não altera.

### 6.15 JS — desvia se negativo

**Sintaxe:** `JS rótulo`

Desvia para o rótulo quando a última comparação indicou negativo. Condição nas flags: SF = 1. Se a condição for falsa, a execução simplesmente segue para a linha de baixo.

```asm
CMP RAX, RBX
JS destino
```

**Flags:** Lê as flags, não altera.

### 6.16 JNS — desvia se não negativo

**Sintaxe:** `JNS rótulo`

Desvia para o rótulo quando a última comparação indicou não negativo. Condição nas flags: SF = 0. Se a condição for falsa, a execução simplesmente segue para a linha de baixo.

```asm
CMP RAX, RBX
JNS destino
```

**Flags:** Lê as flags, não altera.

### 6.17 JC — desvia se houve carry

**Sintaxe:** `JC rótulo`

Desvia para o rótulo quando a última comparação indicou houve carry. Condição nas flags: CF = 1. Se a condição for falsa, a execução simplesmente segue para a linha de baixo.

```asm
CMP RAX, RBX
JC destino
```

**Flags:** Lê as flags, não altera.

### 6.18 JNC — desvia se não houve carry

**Sintaxe:** `JNC rótulo`

Desvia para o rótulo quando a última comparação indicou não houve carry. Condição nas flags: CF = 0. Se a condição for falsa, a execução simplesmente segue para a linha de baixo.

```asm
CMP RAX, RBX
JNC destino
```

**Flags:** Lê as flags, não altera.

### 6.19 JO — desvia se houve overflow

**Sintaxe:** `JO rótulo`

Desvia para o rótulo quando a última comparação indicou houve overflow. Condição nas flags: OF = 1. Se a condição for falsa, a execução simplesmente segue para a linha de baixo.

```asm
CMP RAX, RBX
JO destino
```

**Flags:** Lê as flags, não altera.

### 6.20 JNO — desvia se não houve overflow

**Sintaxe:** `JNO rótulo`

Desvia para o rótulo quando a última comparação indicou não houve overflow. Condição nas flags: OF = 0. Se a condição for falsa, a execução simplesmente segue para a linha de baixo.

```asm
CMP RAX, RBX
JNO destino
```

**Flags:** Lê as flags, não altera.

### 6.21 JP — desvia se paridade par

**Sintaxe:** `JP rótulo`

Desvia para o rótulo quando a última comparação indicou paridade par. Condição nas flags: PF = 1. Se a condição for falsa, a execução simplesmente segue para a linha de baixo.

```asm
CMP RAX, RBX
JP destino
```

**Flags:** Lê as flags, não altera.

### 6.22 JNP — desvia se paridade ímpar

**Sintaxe:** `JNP rótulo`

Desvia para o rótulo quando a última comparação indicou paridade ímpar. Condição nas flags: PF = 0. Se a condição for falsa, a execução simplesmente segue para a linha de baixo.

```asm
CMP RAX, RBX
JNP destino
```

**Flags:** Lê as flags, não altera.

## 7. Chamada / retorno

Entra e sai de funções.

### 7.1 CALL — chama uma função

**Sintaxe:** `CALL destino`

Empilha o endereço da instrução seguinte (endereço de retorno) e desvia para a função. O RET depois usa esse valor para voltar.

```asm
CALL soma
CALL printf
```

**Flags:** Não altera flags.

### 7.2 RET — volta da função

**Sintaxe:** `RET  |  RET n`

Desempilha o endereço de retorno e continua dali. A pilha precisa estar exatamente como estava na entrada, ou o retorno vai para um endereço errado.

```asm
RET
```

**Flags:** Não altera flags.

## 8. Sistema

Fala com o kernel ou com o hardware.

### 8.1 SYSCALL — chama o kernel (Linux x86-64)

**Sintaxe:** `SYSCALL`

Entrega o controle ao kernel. O número do serviço vai em RAX e os argumentos em RDI, RSI, RDX, R10, R8, R9. O retorno vem em RAX. RCX e R11 são destruídos.

```asm
MOV RAX, 1   ; write
MOV RDI, 1   ; stdout
MOV RSI, msg
MOV RDX, 13
SYSCALL
```

**Flags:** Não altera flags (RCX e R11 são sobrescritos).

### 8.2 INT — dispara uma interrupção de software

**Sintaxe:** `INT número`

INT 0x80 é a chamada de sistema antiga de 32 bits do Linux — em código 64 bits o normal é SYSCALL. INT 3 é o breakpoint usado por depuradores.

```asm
INT 0x80
INT 3
```

**Flags:** Depende do handler.

### 8.3 SYSENTER — entrada rápida em modo kernel (32 bits)

**Sintaxe:** `SYSENTER`

Mecanismo de entrada no kernel em sistemas 32 bits. Em x86-64 foi substituído por SYSCALL.

```asm
SYSENTER
```

**Flags:** —

### 8.4 CPUID — identifica o processador

**Sintaxe:** `CPUID`

Retorna informações da CPU em EAX/EBX/ECX/EDX conforme o valor colocado antes em EAX.

```asm
XOR EAX, EAX
CPUID
```

**Flags:** Não altera flags.

### 8.5 RDTSC — lê o contador de ciclos

**Sintaxe:** `RDTSC`

Coloca em EDX:EAX o número de ciclos desde a inicialização. Usado para medir tempo com alta resolução.

```asm
RDTSC
```

**Flags:** Não altera flags.

### 8.6 HLT — para o processador

**Sintaxe:** `HLT`

Só faz sentido em código de kernel/bare metal. Em programa de usuário causa falha de proteção.

```asm
HLT
```

**Flags:** —

## 9. Blocos de memória

Copia/compara/preenche regiões inteiras.

### 9.1 MOVSB — copia bytes de RSI para RDI _(também: MOVSW, MOVSD, MOVSQ)_

**Sintaxe:** `MOVSB  (normalmente REP MOVSB)`

Copia um byte de [RSI] para [RDI] e avança os dois. Com REP e RCX, é um memcpy em uma linha.

```asm
MOV RCX, 100
REP MOVSB
```

**Flags:** Não altera flags. Direção controlada por DF (CLD/STD).

### 9.2 STOSB — preenche memória com AL _(também: STOSW, STOSD, STOSQ)_

**Sintaxe:** `STOSB  (normalmente REP STOSB)`

Grava AL em [RDI] e avança RDI. Com REP vira um memset.

```asm
XOR AL, AL
MOV RCX, 64
REP STOSB
```

**Flags:** Não altera flags.

### 9.3 LODSB — lê byte de [RSI] para AL _(também: LODSW, LODSD, LODSQ)_

**Sintaxe:** `LODSB`

Carrega um byte de [RSI] em AL e avança RSI. Base para percorrer strings.

```asm
LODSB
TEST AL, AL
JZ fim
```

**Flags:** Não altera flags.

### 9.4 SCASB — procura um byte _(também: SCASW, SCASD, SCASQ)_

**Sintaxe:** `SCASB  (normalmente REPNE SCASB)`

Compara AL com [RDI] e avança. Com REPNE, encontra um byte dentro de um buffer (base do strlen).

```asm
REPNE SCASB
```

**Flags:** Altera as flags da comparação.

### 9.5 CMPSB — compara duas regiões _(também: CMPSW, CMPSD, CMPSQ)_

**Sintaxe:** `CMPSB  (normalmente REPE CMPSB)`

Compara [RSI] com [RDI] e avança os dois. Com REPE, é um memcmp.

```asm
REPE CMPSB
```

**Flags:** Altera as flags da comparação.

### 9.6 REP — prefixo de repetição _(também: REPNZ, REPZ, REPNE, REPE)_

**Sintaxe:** `REP / REPE / REPNE instrução`

Repete a instrução de string RCX vezes. REPE para quando ZF=0; REPNE para quando ZF=1.

```asm
REP MOVSB
```

**Flags:** Depende da instrução repetida.

### 9.7 CLD — percorrer para frente

**Sintaxe:** `CLD`

Zera DF: as instruções de string avançam (RSI/RDI crescem). É o estado esperado pela ABI.

```asm
CLD
```

**Flags:** Zera DF.

### 9.8 STD — percorrer para trás

**Sintaxe:** `STD`

Liga DF: as instruções de string andam para trás. Sempre restaure com CLD depois.

```asm
STD
```

**Flags:** Liga DF.

## 10. SSE / ponto flutuante

Números reais e registradores XMM.

### 10.1 MOVSS — float de 32 bits

**Sintaxe:** `MOVSS xmm, origem`

Move um float de precisão simples entre registradores XMM e memória.

```asm
MOVSS XMM0, [valor]
```

**Flags:** Não altera flags.

### 10.2 MOVSD_SSE — double de 64 bits

**Sintaxe:** `MOVSD xmm, origem`

Move um double. Cuidado: o mesmo mnemônico MOVSD também existe como instrução de string — o assembler decide pelo operando.

```asm
MOVSD XMM0, [valor]
```

**Flags:** Não altera flags.

### 10.3 ADDSD — soma de doubles

**Sintaxe:** `ADDSD xmm, origem`

Soma dois doubles em registradores XMM.

```asm
ADDSD XMM0, XMM1
```

**Flags:** Não altera as flags inteiras.

### 10.4 MULSD — Multiply Scalar Double

**Sintaxe:** `MULSD xmm, origem`

Multiplica dois doubles.

```asm
MULSD XMM0, XMM1
```

**Flags:** —

### 10.5 CVTSI2SD — Convert Integer to Double

**Sintaxe:** `CVTSI2SD xmm, reg/mem`

Converte inteiro para double.

```asm
CVTSI2SD XMM0, RAX
```

**Flags:** —

## 11. Diversos

Conversões, sincronização, nada-a-fazer.

### 11.1 NOP — não faz nada

**Sintaxe:** `NOP`

Gasta um ciclo. Serve para alinhar código na memória e como espaço reservado para patches.

```asm
NOP
```

**Flags:** Não altera flags.

### 11.2 CDQ — estende EAX em EDX

**Sintaxe:** `CDQ`

Replica o bit de sinal de EAX em todo o EDX. Obrigatório antes de IDIV em 32 bits.

```asm
CDQ
IDIV EBX
```

**Flags:** Não altera flags.

### 11.3 CQO — estende RAX em RDX

**Sintaxe:** `CQO`

Versão 64 bits do CDQ. Use antes de IDIV com operandos de 64 bits.

```asm
CQO
IDIV RBX
```

**Flags:** Não altera flags.

### 11.4 CWDE — Convert Word to Doubleword

**Sintaxe:** `CWDE`

Estende AX com sinal para EAX.

```asm
CWDE
```

**Flags:** Não altera flags.

### 11.5 BSWAP — inverte a ordem dos bytes

**Sintaxe:** `BSWAP registrador`

Converte entre little-endian e big-endian (ordem de rede).

```asm
BSWAP EAX
```

**Flags:** Não altera flags.

### 11.6 XADD — troca e soma (atômico com LOCK)

**Sintaxe:** `XADD destino, origem`

Troca os operandos e guarda a soma no destino. Base de contadores atômicos.

```asm
LOCK XADD [contador], RAX
```

**Flags:** Altera as flags aritméticas.

### 11.7 CMPXCHG — o CAS do x86

**Sintaxe:** `CMPXCHG destino, origem`

Se destino == RAX, grava origem no destino; senão carrega destino em RAX. Base de locks e estruturas sem travas.

```asm
LOCK CMPXCHG [ptr], RBX
```

**Flags:** Altera ZF e as demais flags aritméticas.

### 11.8 LOCK — prefixo de atomicidade

**Sintaxe:** `LOCK instrução`

Garante que a operação de memória seja atômica entre núcleos.

```asm
LOCK INC [contador]
```

**Flags:** Depende da instrução.

### 11.9 ENDBR64 — marca alvo válido de desvio indireto

**Sintaxe:** `ENDBR64`

Parte da proteção CET/IBT. Marca que aquele endereço pode ser alvo de um call/jmp indireto. Compiladores modernos colocam no início de cada função.

```asm
ENDBR64
```

**Flags:** Não altera flags.

### 11.10 UD2 — instrução inválida proposital

**Sintaxe:** `UD2`

Gera exceção de opcode inválido. Compiladores usam para marcar código inalcançável.

```asm
UD2
```

**Flags:** —

---

## Registradores de uso geral

| Registrador | Papel |
|---|---|
| `RAX` | Acumulador. Valor de retorno das funções e número da syscall no Linux. |
| `RBX` | Base. Preservado entre chamadas (callee-saved). |
| `RCX` | Contador de laços; 1º argumento no Windows, 4º no Linux. Destruído pelo SYSCALL. |
| `RDX` | 3º argumento (Linux) / 2º (Windows). Parte alta em MUL e DIV. |
| `RSI` | Origem em operações de string; 2º argumento no Linux. |
| `RDI` | Destino em operações de string; 1º argumento no Linux. |
| `RSP` | Ponteiro do topo da pilha. Nunca mexa nele sem saber o que está fazendo. |
| `RBP` | Base do quadro de pilha atual; ancora as variáveis locais. |
| `R8` | 5º argumento (Linux) / 3º (Windows). |
| `R9` | 6º argumento (Linux) / 4º (Windows). |
| `R10` | 4º argumento das syscalls do Linux (no lugar de RCX). |
| `R11` | Registrador temporário. Destruído pelo SYSCALL. |
| `R12` | Temporário preservado entre chamadas. |
| `R13` | Temporário preservado entre chamadas. |
| `R14` | Temporário preservado entre chamadas. |
| `R15` | Temporário preservado entre chamadas. |
| `RIP` | Ponteiro da próxima instrução. Só é alterado por desvios; endereçamento [rel x] é relativo a ele. |

Cada um dos 16 registradores tem versões menores que compartilham os mesmos bits:

```
RAX  64 bits  ┌────────────────────────────────────────────────┐
EAX  32 bits                  ┌────────────────────────────────┐   (escrever em EAX zera a parte alta)
 AX  16 bits                                  ┌────────────────┐
 AH   8 bits                                  ┌───────┐
 AL   8 bits                                          ┌────────┐
```

Nos registradores R8–R15 os apelidos são `R8D` (32), `R8W` (16) e `R8B` (8).

## Flags do registrador RFLAGS

| Flag | Significado |
|---|---|
| `ZF` | Zero — o resultado deu exatamente zero (ou os valores comparados eram iguais). |
| `SF` | Sign — o bit mais alto do resultado é 1 (número negativo com sinal). |
| `CF` | Carry — houve vai-um/empréstimo. É a flag dos desvios sem sinal (JA/JB). |
| `OF` | Overflow — o resultado estourou a faixa com sinal. É a flag dos desvios com sinal (JG/JL). |
| `PF` | Parity — o byte baixo do resultado tem quantidade par de bits 1. |
| `DF` | Direction — define se as instruções de string andam para frente (0) ou para trás (1). |

## Chamadas de sistema do Linux x86-64

Número em `RAX`, argumentos em `RDI, RSI, RDX, R10, R8, R9`, resultado em `RAX`.

| Nº | Nome | O que faz | Argumentos |
|---|---|---|---|
| 0 | `read` | lê de um descritor | fd, buf, count |
| 1 | `write` | escreve em um descritor | fd, buf, count |
| 2 | `open` | abre arquivo | path, flags, mode |
| 3 | `close` | fecha descritor | fd |
| 4 | `stat` | informações do arquivo | path, statbuf |
| 5 | `fstat` | informações pelo descritor | fd, statbuf |
| 8 | `lseek` | posiciona no arquivo | fd, offset, whence |
| 9 | `mmap` | mapeia memória | addr, len, prot, flags, fd, off |
| 10 | `mprotect` | muda permissões de memória | addr, len, prot |
| 11 | `munmap` | desfaz o mapeamento | addr, len |
| 12 | `brk` | ajusta o fim do heap | addr |
| 13 | `rt_sigaction` | instala tratador de sinal | sig, act, oldact |
| 16 | `ioctl` | controle de dispositivo | fd, request, arg |
| 22 | `pipe` | cria um par de descritores | pipefd |
| 32 | `dup` | duplica descritor | fd |
| 33 | `dup2` | duplica em um número específico | old, new |
| 34 | `pause` | espera por sinal | — |
| 35 | `nanosleep` | dorme | req, rem |
| 39 | `getpid` | PID do processo | — |
| 41 | `socket` | cria socket | domain, type, protocol |
| 42 | `connect` | conecta socket | fd, addr, addrlen |
| 43 | `accept` | aceita conexão | fd, addr, addrlen |
| 44 | `sendto` | envia dados | fd, buf, len, flags, addr, alen |
| 45 | `recvfrom` | recebe dados | fd, buf, len, flags, addr, alen |
| 49 | `bind` | associa endereço ao socket | fd, addr, addrlen |
| 50 | `listen` | coloca o socket em escuta | fd, backlog |
| 57 | `fork` | duplica o processo | — |
| 59 | `execve` | substitui o programa atual | path, argv, envp |
| 60 | `exit` | encerra a thread | código |
| 61 | `wait4` | espera processo filho | pid, status, options, rusage |
| 62 | `kill` | envia sinal | pid, sig |
| 79 | `getcwd` | diretório atual | buf, size |
| 83 | `mkdir` | cria diretório | path, mode |
| 87 | `unlink` | apaga arquivo | path |
| 89 | `readlink` | lê link simbólico | path, buf, size |
| 96 | `gettimeofday` | hora atual | tv, tz |
| 101 | `ptrace` | depuração de processo | request, pid, addr, data |
| 186 | `gettid` | ID da thread | — |
| 201 | `time` | hora em segundos | tloc |
| 202 | `futex` | espera/acorda thread | uaddr, op, val, ... |
| 231 | `exit_group` | encerra o processo inteiro | código |
| 257 | `openat` | abre relativo a um diretório | dirfd, path, flags, mode |
| 318 | `getrandom` | bytes aleatórios | buf, buflen, flags |

## Funções do Windows que mais aparecem em assembly

Argumentos em `RCX, RDX, R8, R9` e 32 bytes de shadow space reservados pelo chamador.

| Função | O que faz | Argumentos |
|---|---|---|
| `ExitProcess` | encerra o processo | uExitCode (RCX) |
| `MessageBoxA` | abre uma caixa de mensagem | hWnd, texto, título, tipo |
| `MessageBoxW` | caixa de mensagem (Unicode) | hWnd, texto, título, tipo |
| `GetStdHandle` | pega o handle de stdin/stdout/stderr | nStdHandle (-11 = stdout) |
| `WriteConsoleA` | escreve no console | handle, buffer, tamanho, escritos, reservado |
| `ReadConsoleA` | lê do console | handle, buffer, tamanho, lidos, reservado |
| `WriteFile` | escreve em arquivo/handle | handle, buffer, tamanho, escritos, overlapped |
| `ReadFile` | lê de arquivo/handle | handle, buffer, tamanho, lidos, overlapped |
| `CreateFileA` | abre ou cria arquivo | nome, acesso, compartilhamento, ... |
| `CloseHandle` | libera um handle | handle |
| `GetProcAddress` | endereço de uma função da DLL | hModule, nome |
| `LoadLibraryA` | carrega uma DLL | nome |
| `VirtualAlloc` | reserva memória | addr, tamanho, tipo, proteção |
| `VirtualProtect` | muda proteção de memória | addr, tamanho, nova, antiga |
| `GetLastError` | código do último erro | — |
| `Sleep` | pausa a thread | milissegundos |
| `CreateProcessA` | cria um processo | ... |
| `GetModuleHandleA` | handle do módulo carregado | nome |
