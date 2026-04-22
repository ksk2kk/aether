.code16
.global _start
_start:
    /* 1. 执行测试调用 (0x42) */
    mov $0x42, %ecx
    mov $0x1, %edx
    mov $0x2, %esi
    mov $0x3, %edi
    .byte 0x0f, 0x01, 0xc1 /* VMCALL */

    /* 2. 执行 Yield 调用 (0x04) */
    /* 这将触发 Hypercore 的调度器切换到 ID 2 (Macro-Realm) */
    mov $0x04, %ecx
    .byte 0x0f, 0x01, 0xc1 /* VMCALL */

.halt_loop:
    hlt
    jmp .halt_loop