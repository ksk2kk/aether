/* src/coherence.rs */
use crate::arch::x86_64::vmx::instructions::{invept_all, invept_single_context, invvpid_single_context};

#[inline]
pub fn memory_fence() {
    unsafe {
        core::arch::asm!("mfence", options(nostack, preserves_flags));
    }
}

#[inline]
pub fn fence_and_invalidate_all_epts() {
    memory_fence();
    invept_all();
    memory_fence();
}

#[inline]
pub fn fence_and_invalidate_ept_context(eptp: u64) {
    memory_fence();
    unsafe { invept_single_context(eptp) };
    memory_fence();
}

#[inline]
pub fn fence_and_invalidate_vpid(vpid: u16) {
    memory_fence();
    unsafe { invvpid_single_context(vpid) };
    memory_fence();
}

pub fn broadcast_tlb_flush() {
    let guard = crate::arch::x86_64::apic::get_manager();
    if let Some(apic) = guard.as_ref() {
        let self_id = crate::arch::x86_64::apic::local_apic_id();
        
        apic.send_ipi_all_excluding_self(
            self_id,
            crate::arch::x86_64::apic::DOORBELL_FLUSH_VECTOR,
        );
        
        fence_and_invalidate_all_epts();
    }
}

pub fn broadcast_vpid_flush(vpid: u16) {
    let guard = crate::arch::x86_64::apic::get_manager();
    if let Some(apic) = guard.as_ref() {
        let self_id = crate::arch::x86_64::apic::local_apic_id();
        
        apic.send_ipi_all_excluding_self(
            self_id,
            crate::arch::x86_64::apic::DOORBELL_FLUSH_VECTOR,
        );
        
        fence_and_invalidate_vpid(vpid);
    }
}