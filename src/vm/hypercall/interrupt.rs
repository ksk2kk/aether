// src/vm/hypercall/interrupt.rs
use crate::arch::x86_64::vmx::GuestRegisters;
use super::types::{HypercallArgs, HypercallHandler, HC_SUCCESS, HC_NOT_IMPLEMENTED};

pub struct InterruptHandler;
impl HypercallHandler for InterruptHandler {
    fn handle(&self, args: HypercallArgs, _regs: &mut GuestRegisters) -> u64 {
        crate::log_debug!("系统级中断发生，引导向目标投递，向量={}", args.arg2);
        let apic_guard = crate::arch::x86_64::apic::get_manager();
        if let Some(apic) = apic_guard.as_ref() {
            apic.inject_interrupt_to_guest(args.arg2 as u8, args.arg1 as u32);
            HC_SUCCESS
        } else {
            HC_NOT_IMPLEMENTED
        }
    }
}