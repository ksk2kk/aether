// src/vm/hypercall/device.rs
use x86_64::PhysAddr;
use crate::arch::x86_64::vmx::GuestRegisters;
use crate::memory::ept::EptFlags;
use crate::arch::x86_64::iommu::DmaAuditRecord;
use crate::coherence::fence_and_invalidate_all_epts;
use super::types::{HypercallArgs, HypercallHandler, HC_SUCCESS, HC_INVALID_CALL, HC_INVALID_ENCLAVE, HC_PERMISSION_DENIED, HC_RESOURCE_EXHAUSTED, HC_NOT_IMPLEMENTED};
use super::utils::copy_bytes_to_guest_gpa;

const MAP_DEVICE_MAX_BYTES: u64 = 16 * 1024 * 1024;

fn decode_pci_bdf(packed: u64) -> (u8, u8, u8) {
    let bdf = packed as u16;
    let bus = (bdf >> 8) as u8;
    let device = ((bdf >> 3) & 0x1F) as u8;
    let function = (bdf & 7) as u8;
    (bus, device, function)
}

pub struct MapDeviceHandler;
impl HypercallHandler for MapDeviceHandler {
    fn handle(&self, args: HypercallArgs, _regs: &mut GuestRegisters) -> u64 {
        if args.arg3 == 0 {
            return HC_INVALID_CALL;
        }
        if args.arg3 > MAP_DEVICE_MAX_BYTES {
            return HC_RESOURCE_EXHAUSTED;
        }

        let mut enclave_mgr_guard = crate::enclave::get_manager();
        let manager = match enclave_mgr_guard.as_mut() {
            Some(m) => m,
            None => return HC_NOT_IMPLEMENTED,
        };
        let current_id = match manager.current_id() {
            Some(id) => id,
            None => return HC_INVALID_ENCLAVE,
        };
        let enclave = match manager.get_enclave_mut(current_id) {
            Some(e) => e,
            None => return HC_INVALID_ENCLAVE,
        };

        let (bus, device, function) = decode_pci_bdf(args.arg1);
        crate::log_debug!(
            "外部硬件穿透指令：向分配域投递设备权限 BDF={:02x}:{:02x}.{}",
            bus, device, function
        );

        let guest_base = PhysAddr::new(args.arg2);

        {
            let mut iommu_guard = crate::arch::x86_64::iommu::get_manager();
            if let Some(im) = iommu_guard.as_mut() {
                let old_binding = match im.register_device_dma(
                    bus,
                    device,
                    function,
                    current_id,
                    guest_base,
                    args.arg3,
                ) {
                    Ok(prev) => prev,
                    Err(e) => {
                        crate::log_warn!("映射被底层 IOMMU 仲裁器退回: {:?}", e);
                        return match e {
                        crate::arch::x86_64::iommu::RegisterError::DomainConflict => {
                            HC_PERMISSION_DENIED
                        }
                        crate::arch::x86_64::iommu::RegisterError::Capacity => {
                            HC_RESOURCE_EXHAUSTED
                        }
                        crate::arch::x86_64::iommu::RegisterError::PolicyDenied => {
                            HC_PERMISSION_DENIED
                        }
                    };
                    }
                };

                if let Some(prev) = old_binding {
                    let _ = im.teardown_device_dma_window(
                        bus,
                        device,
                        function,
                        current_id,
                        prev.mmio_gpa,
                        prev.mmio_bytes,
                        false,
                    );
                }
            }
        }

        let mmio_flags = EptFlags::READ | EptFlags::WRITE | EptFlags::MEMORY_TYPE_WB;
        enclave.ept.identity_map_range(guest_base, args.arg3, mmio_flags);

        drop(enclave_mgr_guard);
        fence_and_invalidate_all_epts();

        let mut iommu_guard = crate::arch::x86_64::iommu::get_manager();
        if let Some(im) = iommu_guard.as_mut() {
            let ok = im.setup_device_dma_remapping(
                bus,
                device,
                function,
                current_id,
                guest_base,
                guest_base,
            );
            if !ok {
                let _ = im.unregister_device_dma(bus, device, function, current_id);
                return HC_RESOURCE_EXHAUSTED;
            }
        }

        HC_SUCCESS
    }
}

pub struct GetDmaAuditLogHandler;
impl HypercallHandler for GetDmaAuditLogHandler {
    fn handle(&self, args: HypercallArgs, _regs: &mut GuestRegisters) -> u64 {
        let guest_buf_gpa = args.arg1;
        let guest_buf_len_bytes = args.arg2 as usize;
        let entry_size = core::mem::size_of::<DmaAuditRecord>();

        if guest_buf_len_bytes == 0 || guest_buf_len_bytes % entry_size != 0 {
            return HC_INVALID_CALL;
        }

        let mut iommu = crate::arch::x86_64::iommu::get_manager();
        let manager = match iommu.as_mut() {
            Some(m) => m,
            None => return HC_NOT_IMPLEMENTED,
        };
        let snapshot = manager.audit_snapshot();

        let mut mgr = crate::enclave::get_manager();
        let enclave_manager = mgr.as_mut().unwrap();
        let cur = enclave_manager.current_id().unwrap();
        let enclave = enclave_manager.get_enclave(cur).unwrap();

        let entries_to_copy = core::cmp::min(guest_buf_len_bytes / entry_size, snapshot.len());
        let bytes_to_copy = entries_to_copy * entry_size;

        let bytes_written = unsafe {
            let slice = core::slice::from_raw_parts(
                (&snapshot as *const DmaAuditRecord) as *const u8,
                bytes_to_copy,
            );
            copy_bytes_to_guest_gpa(&enclave.ept, guest_buf_gpa, slice)
        };
        
        (bytes_written / entry_size) as u64
    }
}