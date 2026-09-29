; Sums the first N integers in RAX. Good for testing limits:
; with a small N it works; with a giant N the result overflows 64 bits.
section .text
    global _start

sum_until:                   ; input: RDI = N, output: RAX = sum
    xor  rax, rax
    mov  rcx, rdi
.loop_body:
    test rcx, rcx
    jz   .done
    add  rax, rcx
    dec  rcx
    jmp  .loop_body
.done:
    ret

_start:
    mov  rdi, 10
    call sum_until           ; RAX = 55
    mov  rdi, rax
    mov  rax, 60
    syscall
