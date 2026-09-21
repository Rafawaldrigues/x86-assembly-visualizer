---
name: Pedido de recurso
about: Uma ideia para o ASM X — instrução, regra, tela ou fluxo de trabalho
title: "[feat] "
labels: enhancement
---

## Que problema isso resolve

<!-- Descreva a dificuldade concreta ao estudar, validar ou depurar assembly. -->

## O que você propõe

<!-- O comportamento que você gostaria de ver na ferramenta. -->

## Onde isso entra

- **Instrução ou documentação** (mnemônico fora do acervo, syscall, função do
  Windows)
- **Regra de validação** (ver "Como adicionar uma regra" no CONTRIBUTING.md)
- **Análise** (plataforma, semântica, mapa de fluxo)
- **Máquina virtual** (instrução que a simulação não cobre)
- **Interface** (tela, atalho, tema)
- **Projeto** (branch, cenário, anotação)

## Alternativas que você considerou

<!-- Como você resolve isso hoje: gdb, olhar o manual, papel e caneta... -->

## Exemplo de uso

<!-- Um trecho de assembly e o que a ferramenta deveria dizer sobre ele. -->

```asm

```

## Isso cabe no escopo?

O ASM X não monta, não liga e não executa binário real: a máquina virtual
simula instruções de inteiros em Python, sem dependência externa. A ideia
cabe nesse limite?

- [ ] Sim, é análise, explicação, validação ou simulação
- [ ] Não tenho certeza
