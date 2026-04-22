// src/enclave/state.rs
use crate::memory::ept::EptManager;
use crate::memory::{GuestImageSpec, RealmKind};
use x86_64::PhysAddr;
use crate::arch::x86_64::vmx::GuestRegisters;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnclaveState {
    Uninitialized,
    Ready,
    Running,
    Paused,
    Terminated,
}

pub struct Enclave {
    pub id: u32,
    pub state: EnclaveState,
    pub realm_kind: RealmKind,
    pub ept: EptManager,
    pub vmcs_phys_addr: PhysAddr,
    pub pml_buffer_phys_addr: PhysAddr,
    pub module_phys: u64,
    pub module_size: usize,
    pub guest_entry_gpa: u64,
    pub entry_rip: u64,
    pub entry_rsp: u64,
    pub regs: GuestRegisters,
    pub launched: bool,
    pub core_affinity: Option<u32>,
}

impl Enclave {
    pub fn new(id: u32, ept: EptManager, vmcs_phys_addr: PhysAddr, pml_buffer_phys_addr: PhysAddr, spec: GuestImageSpec) -> Self {
        Self {
            id,
            state: EnclaveState::Ready,
            realm_kind: spec.realm_kind,
            ept,
            vmcs_phys_addr,
            pml_buffer_phys_addr,
            module_phys: spec.module_start,
            module_size: spec.module_size,
            guest_entry_gpa: spec.load_gpa,
            entry_rip: spec.load_gpa,
            entry_rsp: spec.load_gpa + 4096,
            regs: GuestRegisters {
                rax: 0, rcx: 0, rdx: 0, rbx: 0, rbp: 0, rsi: 0, rdi: 0,
                r8: 0, r9: 0, r10: 0, r11: 0, r12: 0, r13: 0, r14: 0, r15: 0,
            },
            launched: false,
            core_affinity: None,
        }
    }
}