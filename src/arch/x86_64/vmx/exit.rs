// src/arch/x86_64/vmx/exit.rs
use super::instructions::{vmread, vmwrite};
use super::vmcs::VmcsField;
use super::GuestRegisters;

core::arch::global_asm!(
    ".global vmx_exit_handler",
    "vmx_exit_handler:",
    "push r15",
    "push r14",
    "push r13",
    "push r12",
    "push r11",
    "push r10",
    "push r9",
    "push r8",
    "push rdi",
    "push rsi",
    "push rbp",
    "push rbx",
    "push rdx",
    "push rcx",
    "push rax",
    
    "lfence",
    
    "mov rdi, rsp",
    
    "call rust_vmx_exit_handler",
    
    "pop rax",
    "pop rcx",
    "pop rdx",
    "pop rbx",
    "pop rbp",
    "pop rsi",
    "pop rdi",
    "pop r8",
    "pop r9",
    "pop r10",
    "pop r11",
    "pop r12",
    "pop r13",
    "pop r14",
    "pop r15",
    
    "vmresume",
    
    "hlt",
    "jmp vmx_exit_handler"
);

fn mitigate_side_channels() {
    unsafe {
        // 使用 {0:x} 明确指定 16 位寄存器格式，解决 asm_sub_register 警告
        core::arch::asm!("verw {0:x}", in(reg) 0u16, options(nostack));
    }
}

#[no_mangle]
pub extern "C" fn rust_vmx_exit_handler(regs: *mut GuestRegisters) {
    mitigate_side_channels();
    
    let exit_reason = unsafe { vmread(VmcsField::ExitReason as u64) };
    let true_reason = exit_reason & 0xFFFF;
    let regs_ref = unsafe { &mut *regs };
    
    if exit_reason & (1 << 31) != 0 {
        crate::log_error!("严重错误: VM-Entry 硬件失败，目标执行体销毁动作启动");
        crate::enclave::terminate_current_and_yield(regs_ref);
        return;
    }

    let guest_rip = unsafe { vmread(VmcsField::GuestRip as u64) };
    let exit_qual = unsafe { vmread(VmcsField::ExitQualification as u64) };
    
    let reason_enum = crate::vm::exit::ExitReason::from_u32(true_reason as u32);
    
    let resume = crate::vm::exit::dispatch_exit(reason_enum, regs_ref, exit_qual, guest_rip);
    
    if resume {
        let mut inst_len = unsafe { vmread(VmcsField::VmExitInstructionLen as u64) };
        if inst_len == 0 {
            inst_len = match true_reason {
                18 => 3, // VMCALL length
                12 => 1, // HLT length
                13 => 1, // INVD length
                16 => 2, // RDTSC length
                15 => 2, // RDPMC length
                53 => 1, // WBINVD length
                54 => 2, // XSETBV length
                _ => 0,
            };
        }
        unsafe { vmwrite(VmcsField::GuestRip as u64, guest_rip + inst_len) };
    } else {
        crate::enclave::terminate_current_and_yield(regs_ref);
    }
}

extern "C" {
    pub fn vmx_exit_handler();
}