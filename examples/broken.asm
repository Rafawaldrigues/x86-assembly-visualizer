; This example is on purpose: every block has a classic error.
section .data
    msg     db  "Invalid action", 10    ; plain ASCII: one byte per letter
    size    equ $ - msg
    user    db  "rafael"                ; missing the 0 terminator

section .text
    global _start

divide:
    push rbx
    mov  rax, 100
    mov  rbx, 7
    div  rbx                 ; RDX was not zeroed
    ret                      ; and the pushed RBX never comes back

_start:
    mov  al, 300             ; 300 does not fit in 8 bits
    mov  [counter], 1        ; ambiguous size and nonexistent symbol
    call divide
    jmp  .stuck

.stuck:
    jmp  .stuck              ; infinite loop with nothing that changes
