; Soma os N primeiros inteiros em RAX. Bom para testar limites:
; com N pequeno funciona; com N gigante o resultado estoura 64 bits.
section .text
    global _start

soma_ate:                    ; entrada: RDI = N, saída: RAX = soma
    xor  rax, rax
    mov  rcx, rdi
.laco:
    test rcx, rcx
    jz   .fim
    add  rax, rcx
    dec  rcx
    jmp  .laco
.fim:
    ret

_start:
    mov  rdi, 10
    call soma_ate            ; RAX = 55
    mov  rdi, rax
    mov  rax, 60
    syscall
