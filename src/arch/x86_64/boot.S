.global start
.extern long_mode_start

.section .text
.code32
start:
    mov $stack_top, %esp
    mov %ebx, %edi /* Move Multiboot info pointer to edi */

    call check_multiboot
    call check_cpuid
    call check_long_mode

    call set_up_page_tables
    call enable_paging

    /* load the 64-bit GDT */
    lgdt gdt64_pointer

    ljmp $8, $long_mode_start

error:
    movl $0x4f524f45, 0xb8000
    movl $0x4f3a4f52, 0xb8004
    movl $0x4f204f20, 0xb8008
    movb %al, 0xb800a
    hlt

check_multiboot:
    cmpl $0x36d76289, %eax
    jne .no_multiboot
    ret
.no_multiboot:
    movb $'0', %al
    jmp error

check_cpuid:
    pushfl
    popl %eax
    movl %eax, %ecx
    xorl $(1 << 21), %eax
    pushl %eax
    popfl
    pushfl
    popl %eax
    pushl %ecx
    popfl
    cmpl %ecx, %eax
    je .no_cpuid
    ret
.no_cpuid:
    movb $'1', %al
    jmp error

check_long_mode:
    movl $0x80000000, %eax
    cpuid
    cmpl $0x80000001, %eax
    jb .no_long_mode

    movl $0x80000001, %eax
    cpuid
    testl $(1 << 29), %edx
    jz .no_long_mode
    ret
.no_long_mode:
    movb $'2', %al
    jmp error

set_up_page_tables:
    movl $p3_table, %eax
    orl $3, %eax /* present + writable */
    movl %eax, p4_table

    movl $p2_table, %eax
    orl $3, %eax /* present + writable */
    movl %eax, p3_table

    movl $0, %ecx /* counter variable */

.map_p2_table:
    movl $0x200000, %eax /* 2MiB */
    mull %ecx
    orl $0x83, %eax /* present + writable + huge */
    movl %eax, p2_table(,%ecx,8)

    incl %ecx
    cmpl $512, %ecx
    jne .map_p2_table

    ret

enable_paging:
    movl $p4_table, %eax
    movl %eax, %cr3

    movl %cr4, %eax
    orl $(1 << 5), %eax
    movl %eax, %cr4

    movl $0xC0000080, %ecx
    rdmsr
    orl $(1 << 8), %eax
    wrmsr

    movl %cr0, %eax
    orl $(1 << 31), %eax
    movl %eax, %cr0

    ret

.section .bss
.align 4096
p4_table:
    .skip 4096
p3_table:
    .skip 4096
p2_table:
    .skip 4096
stack_bottom:
    .skip 65536
stack_top:

.section .rodata
gdt64:
    .quad 0 /* zero entry */
.code:
    .equ code_seg, .code - gdt64
    .quad (1<<43) | (1<<44) | (1<<47) | (1<<53) /* code segment */
gdt64_pointer:
    .short . - gdt64 - 1
    .quad gdt64
