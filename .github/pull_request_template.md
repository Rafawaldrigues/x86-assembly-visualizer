<!--
Obrigado pela contribuição. Preencha o que se aplica e apague o resto.
Contribuição grande sem issue aberta antes pode ser recusada — combine primeiro.
-->

## O que muda para quem usa

<!-- Em uma ou duas frases, sem jargão. -->

## Tipo de mudança

- [ ] Correção de defeito (`fix`)
- [ ] Recurso novo (`feat`)
- [ ] Documentação (`docs`)
- [ ] Teste (`test`)
- [ ] Refatoração (`refactor`)
- [ ] Desempenho (`perf`)
- [ ] Manutenção, CI, empacotamento (`chore`)
- [ ] Mudança que quebra compatibilidade (formato do `.asmproj`, API do pacote)

## Issue relacionada

<!-- Closes #000 -->

## Como foi testado

```bash
python3 -m unittest discover -s tests      # núcleo
xvfb-run -a python3 -m unittest discover -s tests   # inclui a GUI, em Linux sem tela
make quality                               # lint + typecheck + cobertura (94%)
```

- [ ] `python3 -m unittest discover -s tests` passa
- [ ] `xvfb-run -a python3 -m unittest discover -s tests` passa (testes de GUI)
- [ ] Cobertura de `asmx/` continua em 94% ou mais (`make coverage`)
- [ ] Adicionei teste para o que mudei (caso positivo e caso negativo)
- [ ] Conferi que a ferramenta roda sem dependência externa
- [ ] Nada de `README.md`, `docs/` ou dados ficou desatualizado com a mudança

## Checklist de estilo

- [ ] PEP 8, `black --line-length 100`, `flake8` limpo (`make format`, `make lint`)
- [ ] 100% de anotações de tipo e docstring no estilo Google no que criei
- [ ] Comentários e mensagens em português do Brasil
- [ ] `CHANGELOG.md` atualizado em `[Não publicado]`
- [ ] Dependência de desenvolvimento nova declarada em `requirements-dev.txt`
      (e em `pyproject.toml`, se for o caso) — o pacote `asmx` continua sem
      dependência de execução

## Observações para quem revisa

<!-- Dúvida, decisão que você tomou, ponto que merece atenção especial. -->
