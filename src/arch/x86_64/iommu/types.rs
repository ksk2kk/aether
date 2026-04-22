// src/arch/x86_64/iommu/types.rs
use x86_64::PhysAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IommuType {
    IntelVtd,
    AmdVi,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterError {
    DomainConflict,
    Capacity,
    PolicyDenied,
}

#[derive(Debug, Clone, Copy)]
pub struct IommuPolicy {
    pub max_mmio_bytes_per_window: u64,
}

impl Default for IommuPolicy {
    fn default() -> Self {
        Self {
            max_mmio_bytes_per_window: 16 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DmaDeviceBinding {
    pub bdf: u16,
    pub domain_id: u32,
    pub mmio_gpa: PhysAddr,
    pub mmio_bytes: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct SlptRootBinding {
    pub bdf: u16,
    pub domain_id: u32,
    pub root_phys: PhysAddr,
}

#[inline]
pub fn pack_bdf(bus: u8, device: u8, function: u8) -> u16 {
    ((bus as u16) << 8) | ((device as u16) << 3) | (function as u16)
}