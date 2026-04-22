use x86_64::PhysAddr;
use crate::arch::x86_64::vmx::GuestRegisters;
use super::types::{HypercallArgs, HypercallHandler, HC_SUCCESS, HC_INVALID_CALL, HC_INVALID_ENCLAVE, HC_NOT_IMPLEMENTED, HC_RESOURCE_EXHAUSTED};

fn calculate_content_hash(hpa: PhysAddr) -> u64 {
    let virt = crate::memory::phys_to_virt(hpa);
    if virt.is_null() {
        return 0;
    }
    let data = unsafe { core::slice::from_raw_parts(virt.as_ptr::<u64>(), 512) };
    data.iter().fold(0, |acc, &x| acc.wrapping_add(x))
}

pub struct MmdlPublishHandler;
impl HypercallHandler for MmdlPublishHandler {
    fn handle(&self, args: HypercallArgs, _regs: &mut GuestRegisters) -> u64 {
        let slot = args.arg1 as usize;
        if slot >= crate::mmdl::SLOT_COUNT {
            return HC_INVALID_CALL;
        }
        
        let gpa = PhysAddr::new(args.arg3);
        let is_huge = args.arg4 != 0;

        let hpa = {
            let mut mgr = crate::enclave::get_manager();
            let manager = match mgr.as_mut() {
                Some(m) => m,
                None => return HC_NOT_IMPLEMENTED,
            };
            let cur = match manager.current_id() {
                Some(id) => id,
                None => return HC_INVALID_ENCLAVE,
            };
            let enclave = match manager.get_enclave_mut(cur) {
                Some(e) => e,
                None => return HC_INVALID_ENCLAVE,
            };
            match enclave.ept.translate_gpa(gpa) {
                Some(h) => h,
                None => return HC_INVALID_CALL,
            }
        };

        let tag = if args.arg2 == 0 {
            calculate_content_hash(hpa)
        } else {
            args.arg2
        };

        let mut ledger = crate::mmdl::ledger();
        match ledger.publish(slot, tag, hpa, is_huge) {
            Ok(()) => HC_SUCCESS,
            Err(()) => HC_RESOURCE_EXHAUSTED,
        }
    }
}

pub struct MmdlMapSharedHandler;
impl HypercallHandler for MmdlMapSharedHandler {
    fn handle(&self, args: HypercallArgs, _regs: &mut GuestRegisters) -> u64 {
        let slot = args.arg3 as usize;
        if slot >= crate::mmdl::SLOT_COUNT {
            return HC_INVALID_CALL;
        }
        let dst_id = args.arg1 as u32;
        let gpa = PhysAddr::new(args.arg2);

        let r = {
            let mut mgr = crate::enclave::get_manager();
            let manager = match mgr.as_mut() {
                Some(m) => m,
                None => return HC_NOT_IMPLEMENTED,
            };
            let dst = match manager.get_enclave_mut(dst_id) {
                Some(e) => e,
                None => return HC_INVALID_ENCLAVE,
            };
            let ledger = crate::mmdl::ledger();
            ledger.map_shared_readonly(&mut dst.ept, slot, gpa)
        };

        match r {
            Ok(()) => {
                crate::coherence::broadcast_vpid_flush(dst_id as u16);
                HC_SUCCESS
            }
            Err(()) => HC_INVALID_CALL,
        }
    }
}

pub struct FusionRegisterHandler;
impl HypercallHandler for FusionRegisterHandler {
    fn handle(&self, args: HypercallArgs, _regs: &mut GuestRegisters) -> u64 {
        use crate::fusion::FusionBackendKind;
        let kind = match args.arg1 {
            0 => FusionBackendKind::VirtioNet,
            1 => FusionBackendKind::VirtioBlock,
            _ => return HC_INVALID_CALL,
        };
        let service_id = if args.arg2 == 0 {
            let mgr = crate::enclave::get_manager();
            match mgr.as_ref().and_then(|m| m.current_id()) {
                Some(id) => id,
                None => return HC_INVALID_ENCLAVE,
            }
        } else {
            args.arg2 as u32
        };

        let mut hub = crate::fusion::hub();
        match hub.register(kind, service_id) {
            Ok(()) => HC_SUCCESS,
            Err(()) => HC_RESOURCE_EXHAUSTED,
        }
    }
}