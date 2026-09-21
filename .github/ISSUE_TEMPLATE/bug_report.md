---
name: Relato de defeito
about: Alguma coisa no ASM X não fez o que devia
title: "[bug] "
labels: bug
---

<!--
Antes de abrir: rode `python3 -m asmx info --json`.
Problema de segurança NÃO vai aqui — veja .github/SECURITY.md.
-->

## O que aconteceu

<!-- O que você esperava e o que a ferramenta fez. Uma ou duas frases. -->

## Como reproduzir

1.
2.
3.

**Onde acontece:** análise / validação / execução passo a passo / cenários /
interface / documentação

**Modo de execução:** passo a passo (`Passo`) · contínuo (`Rodar`) · não executo

## Trecho de assembly que reproduz

<!-- Cole o menor programa possível que mostra o problema. -->

```asm

```

**Sintaxe do arquivo:** NASM/Intel · MASM · GAS/AT&T
**Plataforma detectada pela ferramenta:** Linux · Windows · nenhuma

## O que a validação diz

<!-- Saída do painel de problemas, se houver. -->

```
```

## O que o histórico de execução mostra

<!-- Últimas linhas do painel da máquina, se o defeito aparece ao executar. -->

```
```

## Ambiente

Saída de `python3 -m asmx info --json` (o log vai para o stderr; o JSON é o
resultado):

```json

```

- Sistema operacional:
- Como a ferramenta foi aberta: `python3 asmx.py` · `python3 -m asmx` (interface)
  · `python3 -m asmx check arquivo.asm` (linha de comando)
- Já funcionou em outra versão? Se sim, qual:

## Contexto extra

<!-- Projeto .asmproj anexado, captura de tela, qualquer coisa que ajude. -->
