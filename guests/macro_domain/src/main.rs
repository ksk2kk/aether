#![no_std]
#![no_main]

use core::arch::asm;
use core::arch::global_asm;
use core::panic::PanicInfo;

const MSR_EFER: u32 = 0xC0000080;
const MSR_STAR: u32 = 0xC0000081;
const MSR_LSTAR: u32 = 0xC0000082;
const MSR_FMASK: u32 = 0xC0000084;

const SYS_WRITE: u64 = 1;
const SYS_EXIT: u64 = 60;
const HC_YIELD: u64 = 0x04;
const HC_DEBUG: u64 = 0xFF;

/* 预定义的 GDT 布局 */
static mut GDT: [u64; 5] = [
    0,
    0x00209A0000000000, /* 0x08: Kernel Code */
    0x0000920000000000, /* 0x10: Kernel Data */
    0x0000F20000000000, /* 0x18: User Data */
    0x0020FA0000000000, /* 0x20: User Code */
];

static mut GDTR: [u16; 5] = [0; 5];

global_asm!(
    ".intel_syntax noprefix",
    ".section .text.entry",
    ".code16",
    ".global _start",
    "_start:",
    "cli",
    /* 1. 设置最简分页用于切换 */
    "mov eax, cr4",
    "or eax, 0x20",
    "mov cr4, eax",
    "lea eax, [p4_table]",
    "mov cr3, eax",
    "mov ecx, 0xC0000080",
    "rdmsr",
    "or eax, 0x100",
    "wrmsr",
    "mov eax, cr0",
    "or eax, 0x80000001",
    "mov cr0, eax",
    /* 2. 加载 32 位临时 GDT 并跳入长模式 */
    "lea eax, [gdtr32]",
    "lgdt [eax]",
    "push 0x08",
    "lea eax, [long_mode_init]",
    "push eax",
    "retf",

    ".align 4096",
    "p4_table:",
    "   .long p3_table + 7, 0",
    "   .space 4088",
    "p3_table:",
    "   .long p2_table + 7, 0",
    "   .space 4088",
    "p2_table:",
    "   .long 0x87, 0", /* 2MB 恒等映射 */
    "   .space 4088",

    "gdtr32:",
    "   .word 23",
    "   .long gdt32",
    "gdt32:",
    "   .quad 0",
    "   .quad 0x00209A0000000000",
    "   .quad 0x0000920000000000",

    ".code64",
    "long_mode_init:",
    "   mov ax, 0x10",
    "   mov ds, ax",
    "   mov es, ax",
    "   mov ss, ax",
    "   mov rsp, 0x200000", /* 设置内核栈 */
    "   call setup_posix_shim",
    "   call execute_linux_elf_stub",
    "6:",
    "   hlt",
    "   jmp 6b",

    ".global syscall_entry",
    "syscall_entry:",
    "   swapgs",
    "   mov gs:[0x0], rsp", /* 保存用户栈，这里假设 GS 已设置，简化处理 */
    "   mov rsp, 0x200000", /* 切换到内核栈 */
    "   push rcx",
    "   push r11",
    "   push rbp",
    "   mov rbp, rsp",
    "   sub rsp, 8", /* 栈对齐 */
    "   mov r9, r8",
    "   mov r8, r10",
    "   mov rcx, rdx",
    "   mov rdx, rsi",
    "   mov rsi, rdi",
    "   mov rdi, rax",
    "   call handle_linux_syscall",
    "   add rsp, 8",
    "   pop rbp",
    "   pop r11",
    "   pop rcx",
    "   mov rsp, gs:[0x0]",
    "   swapgs",
    "   sysretq",
    ".att_syntax"
);

extern "C" {
    fn syscall_entry();
}

#[no_mangle]
pub extern "C" fn setup_posix_shim() {
    let msg = b"POSIX Shim: Init GDT/MSRs...\n";
    hypercall(HC_DEBUG, msg.as_ptr() as u64, msg.len() as u64, 0, 0, 0);

    unsafe {
        let gdt_base = core::ptr::addr_of!(GDT) as u64;
        let gdt_limit = (core::mem::size_of::<[u64; 5]>() - 1) as u16;
        let gdtr_ptr = core::ptr::addr_of_mut!(GDTR);
        (*gdtr_ptr)[0] = gdt_limit;
        (*gdtr_ptr)[1] = (gdt_base & 0xFFFF) as u16;
        (*gdtr_ptr)[2] = ((gdt_base >> 16) & 0xFFFF) as u16;
        (*gdtr_ptr)[3] = ((gdt_base >> 32) & 0xFFFF) as u16;
        (*gdtr_ptr)[4] = ((gdt_base >> 48) & 0xFFFF) as u16;
        asm!("lgdt [{}]", in(reg) gdtr_ptr);

        let mut efer_low: u32;
        let mut efer_high: u32;
        asm!("rdmsr", in("ecx") MSR_EFER, out("eax") efer_low, out("edx") efer_high);
        efer_low |= 1;
        asm!("wrmsr", in("ecx") MSR_EFER, in("eax") efer_low, in("edx") efer_high);

        let star: u64 = (0x10u64 << 48) | (0x08u64 << 32);
        asm!("wrmsr", in("ecx") MSR_STAR, in("eax") (star as u32), in("edx") (star >> 32) as u32);
        let lstar: u64 = (syscall_entry as *const ()) as usize as u64;
        asm!("wrmsr", in("ecx") MSR_LSTAR, in("eax") (lstar as u32), in("edx") (lstar >> 32) as u32);
        let fmask: u64 = 0x200;
        asm!("wrmsr", in("ecx") MSR_FMASK, in("eax") (fmask as u32), in("edx") (fmask >> 32) as u32);
    }
}

#[no_mangle]
pub extern "C" fn execute_linux_elf_stub() {
    let msg = b"POSIX Shim: Dropping to Ring 3...\n";
    hypercall(HC_DEBUG, msg.as_ptr() as u64, msg.len() as u64, 0, 0, 0);

    let linux_app_msg = b"Linux Macro-Realm ABI OK!\n";

    unsafe {
        asm!(
            "mov rcx, 0x1B",
            "push rcx",
            "lea rcx, [rip + 5f]",
            "push rcx",
            "pushfq",
            "mov rcx, 0x23",
            "push rcx",
            "lea rcx, [rip + 3f]",
            "push rcx",
            "iretq",
            "3:",
            "mov rax, 1",
            "mov rdi, 1",
            "mov rsi, r8",
            "mov rdx, 26",
            "syscall",
            "mov rax, 60",
            "mov rdi, 0",
            "syscall",
            "4:",
            "jmp 4b",
            ".align 16",
            "5:",
            ".space 1024",
            in("r8") linux_app_msg.as_ptr(),
            out("rcx") _,
            out("rax") _,
        );
    }
}

#[no_mangle]
pub extern "C" fn handle_linux_syscall(sys_nr: u64, a1: u64, a2: u64, a3: u64, _a4: u64, _a5: u64, _a6: u64) -> u64 {
    match sys_nr {
        SYS_WRITE => {
            hypercall(HC_DEBUG, a2, a3, 0, 0, 0);
            a3
        }
        SYS_EXIT => {
            hypercall(HC_YIELD, a1, 0, 0, 0, 0);
            0
        }
        _ => 0,
    }
}

fn hypercall(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    let mut ret: u64;
    unsafe {
        asm!(
            "vmcall",
            in("rcx") nr,
            in("rdx") a1,
            in("rsi") a2,
            in("rdi") a3,
            in("r8") a4,
            in("r9") a5,
            lateout("rax") ret,
            options(nostack)
        );
    }
    ret
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}