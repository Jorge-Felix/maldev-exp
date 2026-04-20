;nasm -f win64 memcpy.asm
;void* memcpy(void *dest_str, const void * src_str, size_t n)

section .text
global memcpy

memcpy:
    mov rax, rcx
    test r8, r8
    jz .done

.loop_64:
    cmp r8, 64
    jb .loop_16
    movdqu xmm0, [rdx]
    movdqu xmm1, [rdx + 16]
    movdqu xmm2, [rdx + 32]
    movdqu xmm3, [rdx + 48]
    movdqu [rcx], xmm0
    movdqu [rcx + 16], xmm1
    movdqu [rcx + 32], xmm2
    movdqu [rcx + 48], xmm3
    add rcx, 64
    add rdx, 64
    sub r8, 64
    jmp .loop_64

.loop_16:
    cmp r8, 16
    jb .loop_1
    movdqu xmm0, [rdx]
    movdqu [rcx], xmm0
    add rcx, 16
    add rdx, 16
    sub r8, 16
    jmp .loop_16

.loop_1:
    test r8, r8
    jz .done
    mov r9b, [rdx]
    mov [rcx], r9b
    inc rcx
    inc rdx
    dec r8
    jnz .loop_1

.done:
    ret
