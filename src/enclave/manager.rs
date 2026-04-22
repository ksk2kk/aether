/* src/enclave/manager.rs */
use crate::arch::x86_64::vmx::GuestRegisters;
use crate::memory::ept::EptManager;
use crate::memory::GuestImageSpec;
use crate::percpu;
use x86_64::PhysAddr;
use super::state::{Enclave, EnclaveState};

pub struct EnclaveManager {
    enclaves: [Option<Enclave>; 16],
    next_id: u32,
}

impl EnclaveManager {
    pub const fn new() -> Self {
        const INIT: Option<Enclave> = None;
        Self {
            enclaves: [INIT; 16],
            next_id: 1,
        }
    }

    pub fn current_id(&self) -> Option<u32> {
        percpu::get_current_enclave_id()
    }

    pub fn register_enclave(&mut self, ept: EptManager, vmcs_phys_addr: PhysAddr, pml_buffer_phys_addr: PhysAddr, spec: GuestImageSpec) -> Option<u32> {
        let id = self.next_id;
        for slot in self.enclaves.iter_mut() {
            if slot.is_none() {
                *slot = Some(Enclave::new(id, ept, vmcs_phys_addr, pml_buffer_phys_addr, spec));
                self.next_id += 1;
                crate::log_info!("挂载执行矩阵条目: 域ID={}, 类型={:?}", id, spec.realm_kind);
                return Some(id);
            }
        }
        crate::log_error!("域注册限制: 分配槽位已耗尽");
        None
    }

    pub fn get_enclave_mut(&mut self, id: u32) -> Option<&mut Enclave> {
        self.enclaves.iter_mut().find_map(|slot| {
            slot.as_mut().filter(|enclave| enclave.id == id)
        })
    }
    
    pub fn get_enclave(&self, id: u32) -> Option<&Enclave> {
        self.enclaves.iter().find_map(|slot| {
            slot.as_ref().filter(|enclave| enclave.id == id)
        })
    }

    pub fn schedule_next(&mut self, current_regs: &mut GuestRegisters) {
        let current_core_id = percpu::get_core_id() as u32;
        let current_id = match self.current_id() {
            Some(id) => id,
            None => {
                crate::log_debug!("调度器空载: 未发现当前活动域");
                return;
            }
        };

        if let Some(current) = self.get_enclave_mut(current_id) {
            current.regs = *current_regs;
            current.state = EnclaveState::Paused;
            unsafe { crate::arch::x86_64::vmx::instructions::vmclear(current.vmcs_phys_addr) };
        }

        let next_id = self.find_next_ready_enclave(current_id);

        if let Some(id) = next_id {
            let affinity = self.get_enclave(id).and_then(|e| e.core_affinity);
            if affinity.is_some() && affinity != Some(current_core_id) {
                 if let Some(apic) = crate::arch::x86_64::apic::get_manager().as_ref() {
                     apic.send_ipi(affinity.unwrap(), crate::arch::x86_64::apic::DOORBELL_SCHEDULE_VECTOR);
                 }
            } else {
                percpu::set_current_enclave_id(Some(id));
                if let Some(next) = self.get_enclave_mut(id) {
                    next.state = EnclaveState::Running;
                    *current_regs = next.regs; 
                    percpu::set_active_vmcs(next.vmcs_phys_addr.as_u64());
                    unsafe { crate::arch::x86_64::vmx::instructions::vmptrld(next.vmcs_phys_addr) };
                    crate::log_debug!("轮转机制生效: 挂起域 {} -> 激活域 {}", current_id, id);
                    return;
                }
            }
        }

        if let Some(current) = self.get_enclave_mut(current_id) {
            current.state = EnclaveState::Running;
            percpu::set_active_vmcs(current.vmcs_phys_addr.as_u64());
            unsafe { crate::arch::x86_64::vmx::instructions::vmptrld(current.vmcs_phys_addr) };
        }
    }

    pub fn find_next_ready_enclave(&self, current_id: u32) -> Option<u32> {
        let start_idx = self
            .enclaves
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|e| e.id == current_id))
            .unwrap_or(0);

        for off in 1..=16 {
            let idx = (start_idx + off) % 16;
            if let Some(enclave) = &self.enclaves[idx] {
                if enclave.id != current_id
                    && (enclave.state == EnclaveState::Ready || enclave.state == EnclaveState::Paused)
                {
                    return Some(enclave.id);
                }
            }
        }
        None
    }
}