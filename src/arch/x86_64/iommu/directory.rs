// src/arch/x86_64/iommu/directory.rs
use super::types::{DmaDeviceBinding, SlptRootBinding};

pub const MAX_BINDINGS: usize = 32;
pub const MAX_SLPT_ROOTS: usize = 32;

pub struct DeviceDirectory {
    pub bindings:[Option<DmaDeviceBinding>; MAX_BINDINGS],
    pub slpt_roots:[Option<SlptRootBinding>; MAX_SLPT_ROOTS],
}

impl DeviceDirectory {
    pub const fn new() -> Self {
        Self {
            bindings: [None; MAX_BINDINGS],
            slpt_roots:[None; MAX_SLPT_ROOTS],
        }
    }

    pub fn lookup_binding_by_bdf(&self, bdf: u16) -> Option<DmaDeviceBinding> {
        self.bindings.iter().find_map(|s| match s {
            Some(b) if b.bdf == bdf => Some(*b),
            _ => None,
        })
    }

    pub fn slpt_root_slot_index(&self, bdf: u16, domain_id: u32) -> Option<usize> {
        self.slpt_roots.iter().position(|slot| {
            slot.is_some_and(|s| s.bdf == bdf && s.domain_id == domain_id)
        })
    }

    pub fn binding_slot_index(&self, bdf: u16, domain_id: u32) -> Option<usize> {
        self.bindings.iter().position(|slot| {
            slot.is_some_and(|b| b.bdf == bdf && b.domain_id == domain_id)
        })
    }

    pub fn dump_serial(&self) {
        crate::serial_println!("[IOMMU] --- DMA binding matrix ---");
        for slot in &self.bindings {
            if let Some(b) = slot {
                crate::serial_println!(
                    "[IOMMU]  BDF {:#06x} -> domain {} MMIO GPA {:#x} len {:#x}",
                    b.bdf, b.domain_id, b.mmio_gpa.as_u64(), b.mmio_bytes
                );
            }
        }
        crate::serial_println!("[IOMMU] --- end matrix ---");
    }
}