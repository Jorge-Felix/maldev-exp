default rel

;size_t strlen(const char *str);
section .text

global optistrlen

optistrlen:
    push rdi

    mov rdi, rcx
    mov r9, rcx

    xor eax, eax
    mov rcx, -1

    repne scasb

    sub rdi, r9
    lea rax, [rdi - 1]

    pop rdi
    ret
