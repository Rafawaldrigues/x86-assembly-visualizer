; Este exemplo é proposital: cada bloco tem um erro clássico.
section .data
    msg     db  "Ação inválida", 10     ; acento = mais bytes do que letras
    tam     equ $ - msg
    nome    db  "rafael"                ; falta o terminador 0

section .text
    global _start

divide:
    push rbx
    mov  rax, 100
    mov  rbx, 7
    div  rbx                 ; RDX não foi zerado
    ret                      ; e o RBX empilhado nunca volta

_start:
    mov  al, 300             ; 300 não cabe em 8 bits
    mov  [contador], 1       ; tamanho ambíguo e símbolo inexistente
    call divide
    jmp  .parado

.parado:
    jmp  .parado             ; laço infinito sem nada que mude
