// src/vm/hypercall/enclave.rs
use crate::arch::x86_64::vmx::GuestRegisters;
use super::types::{HypercallArgs, HypercallHandler, HC_SUCCESS, HC_INVALID_ENCLAVE, HC_NOT_IMPLEMENTED};

const REALM_CAP_MSB: u64 = 1 << 0;
const REALM_CAP_MMDL: u64 = 1 << 1;
const REALM_CAP_FUSION: u64 = 1 << 2;
const REALM_CAP_IOMMU: u64 = 1 << 3;
const REALM_CAP_POSIX_SHIM: u64 = 1 << 4;

pub struct QueryEnclaveHandler;
impl HypercallHandler for QueryEnclaveHandler {
    fn handle(&self, args: HypercallArgs, regs: &mut GuestRegisters) -> u64 {
        let mut enclave_mgr_guard = crate::enclave::get_manager();
        if let Some(manager) = enclave_mgr_guard.as_mut() {
            let target_id = if args.arg1 == 0 {
                match manager.current_id() {
                    Some(id) => id,
                    None => return HC_INVALID_ENCLAVE,
                }
            } else {
                args.arg1 as u32
            };

            crate::log_debug!("隔离域状态探测：目标 ID={}", target_id);
            if let Some(enclave) = manager.get_enclave(target_id) {
                regs.rbx = enclave.state as u64;
                return HC_SUCCESS;
            }
            HC_INVALID_ENCLAVE
        } else {
            HC_NOT_IMPLEMENTED
        }
    }
}

pub struct YieldHandler;
impl HypercallHandler for YieldHandler {
    fn handle(&self, _args: HypercallArgs, regs: &mut GuestRegisters) -> u64 {
        crate::log_debug!("当前域主动放弃硬件核心使用权");
        let mut enclave_mgr_guard = crate::enclave::get_manager();
        if let Some(manager) = enclave_mgr_guard.as_mut() {
            manager.schedule_next(regs);
        }
        HC_SUCCESS
    }
}

pub struct QueryRealmCapsHandler;
impl HypercallHandler for QueryRealmCapsHandler {
    fn handle(&self, _args: HypercallArgs, regs: &mut GuestRegisters) -> u64 {
        let mut mgr = crate::enclave::get_manager();
        let manager = match mgr.as_mut() {
            Some(m) => m,
            None => return HC_NOT_IMPLEMENTED,
        };
        let cur = match manager.current_id() {
            Some(id) => id,
            None => return HC_INVALID_ENCLAVE,
        };
        let enclave = match manager.get_enclave(cur) {
            Some(e) => e,
            None => return HC_INVALID_ENCLAVE,
        };

        let base_caps = REALM_CAP_MSB | REALM_CAP_MMDL | REALM_CAP_FUSION | REALM_CAP_IOMMU;
        let (kind, caps) = match enclave.realm_kind {
            crate::memory::RealmKind::Micro => (0u64, base_caps),
            crate::memory::RealmKind::Macro => (1u64, base_caps | REALM_CAP_POSIX_SHIM),
        };

        regs.rbx = caps;
        regs.rcx = kind;
        HC_SUCCESS
    }
}