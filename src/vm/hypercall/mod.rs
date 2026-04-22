// src/vm/hypercall/mod.rs
pub mod types;
pub mod utils;
pub mod memory;
pub mod enclave;
pub mod device;
pub mod interrupt;
pub mod system;
pub mod extensions;

pub use types::{HypercallArgs, HypercallType, HypercallHandler, HC_INVALID_CALL};

use crate::arch::x86_64::vmx::GuestRegisters;

pub fn dispatch(args: HypercallArgs, regs: &mut GuestRegisters, hypercall_nr: u8) -> u64 {
    let hc_type = match HypercallType::from_u8(hypercall_nr) {
        Some(t) => t,
        None => {
            if hypercall_nr == 0x42 {
                return system::TestHandler.handle(args, regs);
            }
            crate::log_warn!("调用抛弃: 截获非法或未注册的系统服务调用口令 {:#04x}", hypercall_nr);
            return HC_INVALID_CALL;
        }
    };

    match hc_type {
        HypercallType::PageTransfer => memory::PageTransferHandler.handle(args, regs),
        HypercallType::PageTransferBatch => memory::PageTransferBatchHandler.handle(args, regs),
        HypercallType::InjectInterrupt => interrupt::InterruptHandler.handle(args, regs),
        HypercallType::QueryEnclave => enclave::QueryEnclaveHandler.handle(args, regs),
        HypercallType::MapDevice => device::MapDeviceHandler.handle(args, regs),
        HypercallType::Yield => enclave::YieldHandler.handle(args, regs),
        HypercallType::GetHypervisorInfo => system::GetHypervisorInfoHandler.handle(args, regs),
        HypercallType::MmdlPublish => extensions::MmdlPublishHandler.handle(args, regs),
        HypercallType::MmdlMapShared => extensions::MmdlMapSharedHandler.handle(args, regs),
        HypercallType::Microbench => system::MicrobenchHandler.handle(args, regs),
        HypercallType::FusionRegister => extensions::FusionRegisterHandler.handle(args, regs),
        HypercallType::FenceStress => memory::FenceStressHandler.handle(args, regs),
        HypercallType::QueryRealmCaps => enclave::QueryRealmCapsHandler.handle(args, regs),
        HypercallType::MapSharedReadOnly => memory::MapSharedReadOnlyHandler.handle(args, regs),
        HypercallType::PageTransferAsync => memory::PageTransferAsyncHandler.handle(args, regs),
        HypercallType::GetDmaAuditLog => device::GetDmaAuditLogHandler.handle(args, regs),
        HypercallType::Debug => system::DebugHandler.handle(args, regs),
    }
}