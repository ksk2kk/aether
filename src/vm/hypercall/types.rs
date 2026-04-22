// src/vm/hypercall/types.rs
use crate::arch::x86_64::vmx::GuestRegisters;

pub const HC_SUCCESS: u64 = 0x00;
pub const HC_INVALID_CALL: u64 = 0x01;
pub const HC_INVALID_ENCLAVE: u64 = 0x02;
pub const HC_PERMISSION_DENIED: u64 = 0x03;
pub const HC_RESOURCE_EXHAUSTED: u64 = 0x04;
pub const HC_NOT_IMPLEMENTED: u64 = 0x05;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HypercallType {
    PageTransfer = 0x00,
    InjectInterrupt = 0x01,
    QueryEnclave = 0x02,
    MapDevice = 0x03,
    Yield = 0x04,
    GetHypervisorInfo = 0x06,
    PageTransferBatch = 0x07,
    MmdlPublish = 0x08,
    MmdlMapShared = 0x09,
    Microbench = 0x0A,
    FusionRegister = 0x0B,
    FenceStress = 0x0C,
    QueryRealmCaps = 0x0D,
    MapSharedReadOnly = 0x0E,
    PageTransferAsync = 0x0F,
    GetDmaAuditLog = 0x10,
    Debug = 0xFF,
}

impl HypercallType {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x00 => Some(HypercallType::PageTransfer),
            0x01 => Some(HypercallType::InjectInterrupt),
            0x02 => Some(HypercallType::QueryEnclave),
            0x03 => Some(HypercallType::MapDevice),
            0x04 => Some(HypercallType::Yield),
            0x06 => Some(HypercallType::GetHypervisorInfo),
            0x07 => Some(HypercallType::PageTransferBatch),
            0x08 => Some(HypercallType::MmdlPublish),
            0x09 => Some(HypercallType::MmdlMapShared),
            0x0A => Some(HypercallType::Microbench),
            0x0B => Some(HypercallType::FusionRegister),
            0x0C => Some(HypercallType::FenceStress),
            0x0D => Some(HypercallType::QueryRealmCaps),
            0x0E => Some(HypercallType::MapSharedReadOnly),
            0x0F => Some(HypercallType::PageTransferAsync),
            0x10 => Some(HypercallType::GetDmaAuditLog),
            0xFF => Some(HypercallType::Debug),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HypercallArgs {
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
    pub arg5: u64,
}

pub trait HypercallHandler {
    fn handle(&self, args: HypercallArgs, regs: &mut GuestRegisters) -> u64;
}