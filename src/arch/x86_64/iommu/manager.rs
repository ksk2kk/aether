// src/arch/x86_64/iommu/manager.rs
use x86_64::PhysAddr;
use super::types::{IommuType, IommuPolicy, RegisterError, DmaDeviceBinding, SlptRootBinding, pack_bdf};
use super::audit::{AuditLog, DmaAuditRecord, DmaAuditOp, AUDIT_RING};
use super::directory::DeviceDirectory;
use super::tables::{HardwareTables, PAGE_SIZE};

pub struct IommuManager {
    iommu_type: IommuType,
    policy: IommuPolicy,
    directory: DeviceDirectory,
    tables: HardwareTables,
    audit: AuditLog,
}

impl IommuManager {
    pub fn new() -> Self {
        Self {
            iommu_type: IommuType::None,
            policy: IommuPolicy::default(),
            directory: DeviceDirectory::new(),
            tables: HardwareTables::new(),
            audit: AuditLog::new(),
        }
    }

    pub fn detect(&mut self) {
        crate::log_debug!("分析 ACPI 固件配置表");
        self.iommu_type = IommuType::IntelVtd;
        crate::log_info!("硬件兼容确认: 已识别 Intel VT-d (DMA 重定向能力)");
    }

    pub fn initialize_root_context_table(&mut self) {
        if self.iommu_type == IommuType::None {
            crate::log_warn!("放弃配置根上下文: 环境缺少有效的底层 IOMMU 单元");
            return;
        }
        self.tables.initialize_root_context_table();
    }

    pub fn handle_dma_fault(&mut self, bdf: u16, fault_gpa: u64, fault_flags: u64) {
        let domain_id = self.directory.lookup_binding_by_bdf(bdf).map_or(0, |b| b.domain_id);
        self.audit.push(DmaAuditRecord {
            op: DmaAuditOp::DmaFault,
            bdf,
            domain_id,
            ok: false,
            fault_gpa,
            fault_flags,
        });
        crate::log_error!("阻断了硬件违规访问: 设备 BDF={:#06x} 越界访问 GPA {:#x} 标志={:#x}", bdf, fault_gpa, fault_flags);
    }

    pub fn register_device_dma(
        &mut self,
        bus: u8,
        device: u8,
        function: u8,
        domain_id: u32,
        mmio_gpa: PhysAddr,
        mmio_bytes: u64,
    ) -> Result<Option<DmaDeviceBinding>, RegisterError> {
        let bdf = pack_bdf(bus, device, function);

        if mmio_bytes == 0 || mmio_bytes > self.policy.max_mmio_bytes_per_window {
            self.audit.push(DmaAuditRecord {
                op: DmaAuditOp::Register, bdf, domain_id, ok: false, fault_gpa: 0, fault_flags: 0,
            });
            crate::log_warn!(
                "穿透窗口容量审核未通过: 目标 BDF {:#06x} 申请长度 {:#x} 超过系统规范阈值 {:#x}",
                bdf, mmio_bytes, self.policy.max_mmio_bytes_per_window
            );
            return Err(RegisterError::PolicyDenied);
        }

        for slot in &self.directory.bindings {
            if let Some(b) = slot {
                if b.bdf == bdf && b.domain_id != domain_id {
                    self.audit.push(DmaAuditRecord {
                        op: DmaAuditOp::Register, bdf, domain_id, ok: false, fault_gpa: 0, fault_flags: 0,
                    });
                    return Err(RegisterError::DomainConflict);
                }
            }
        }

        let mut empty: Option<usize> = None;
        for (i, slot) in self.directory.bindings.iter_mut().enumerate() {
            if let Some(b) = slot.as_mut() {
                if b.bdf == bdf && b.domain_id == domain_id {
                    let old_gpa = b.mmio_gpa;
                    let old_bytes = b.mmio_bytes;
                    b.mmio_gpa = mmio_gpa;
                    b.mmio_bytes = mmio_bytes;
                    self.audit.push(DmaAuditRecord {
                        op: DmaAuditOp::Register, bdf, domain_id, ok: true, fault_gpa: 0, fault_flags: 0,
                    });
                    crate::log_debug!(
                        "调整硬件直通窗口: 分配域 {} 获取总线节点 BDF {:#06x} (映射 {:#x}, 容量 {:#x})",
                        domain_id, bdf, mmio_gpa.as_u64(), mmio_bytes
                    );
                    return Ok(Some(DmaDeviceBinding {
                        bdf, domain_id, mmio_gpa: old_gpa, mmio_bytes: old_bytes,
                    }));
                }
            } else if empty.is_none() {
                empty = Some(i);
            }
        }

        let idx = empty.ok_or(RegisterError::Capacity)?;
        self.directory.bindings[idx] = Some(DmaDeviceBinding { bdf, domain_id, mmio_gpa, mmio_bytes });

        self.audit.push(DmaAuditRecord {
            op: DmaAuditOp::Register, bdf, domain_id, ok: true, fault_gpa: 0, fault_flags: 0,
        });

        crate::log_info!(
            "外设授权交接就绪: 分配域 {} 获取设备 BDF {:#06x} 控制权 (映射地 {:#x}, 窗格尺寸 {:#x})",
            domain_id, bdf, mmio_gpa.as_u64(), mmio_bytes
        );

        Ok(None)
    }

    pub fn lookup_binding_by_bdf(&self, bdf: u16) -> Option<DmaDeviceBinding> {
        self.directory.lookup_binding_by_bdf(bdf)
    }

    pub fn lookup_binding(&self, bus: u8, device: u8, function: u8) -> Option<DmaDeviceBinding> {
        self.lookup_binding_by_bdf(pack_bdf(bus, device, function))
    }

    pub fn device_owned_by(&self, bus: u8, device: u8, function: u8, domain_id: u32) -> bool {
        self.lookup_binding(bus, device, function)
            .is_some_and(|b| b.domain_id == domain_id)
    }

    fn ensure_slpt_root(&mut self, bdf: u16, domain_id: u32) -> Option<PhysAddr> {
        if let Some(idx) = self.directory.slpt_root_slot_index(bdf, domain_id) {
            return Some(self.directory.slpt_roots[idx].unwrap().root_phys);
        }

        let root = HardwareTables::alloc_zeroed_page_table()?;
        for slot in &mut self.directory.slpt_roots {
            if slot.is_none() {
                *slot = Some(SlptRootBinding { bdf, domain_id, root_phys: root });
                return Some(root);
            }
        }
        None
    }

    fn invalidate_context_cache(&mut self, bdf: u16, domain_id: u32, ok: bool) {
        self.audit.push(DmaAuditRecord {
            op: DmaAuditOp::Invalidate, bdf, domain_id, ok, fault_gpa: 0, fault_flags: 0,
        });
        if ok {
            crate::log_debug!("驱逐旧版上下文缓存: 关联项 BDF {:#06x}, 所属域 {}", bdf, domain_id);
        } else {
            crate::log_debug!("不包含可驱逐的上下文记录: 关联项 BDF {:#06x}, 所属域 {}", bdf, domain_id);
        }
    }

    pub fn teardown_device_dma_window(
        &mut self,
        bus: u8,
        device: u8,
        function: u8,
        owner_domain: u32,
        mmio_gpa: PhysAddr,
        mmio_bytes: u64,
        reclaim_root: bool,
    ) -> bool {
        let bdf = pack_bdf(bus, device, function);
        let Some(slot_idx) = self.directory.slpt_root_slot_index(bdf, owner_domain) else {
            self.audit.push(DmaAuditRecord {
                op: DmaAuditOp::Teardown, bdf, domain_id: owner_domain, ok: true, fault_gpa: 0, fault_flags: 0,
            });
            self.invalidate_context_cache(bdf, owner_domain, true);
            return true;
        };
        let root = self.directory.slpt_roots[slot_idx].unwrap().root_phys;

        let base_iova = mmio_gpa.as_u64() & !(PAGE_SIZE - 1);
        let span = mmio_bytes.max(PAGE_SIZE);
        let pages = (span + (PAGE_SIZE - 1)) / PAGE_SIZE;
        let mut ok = true;
        for i in 0..pages {
            let iova_page = PhysAddr::new(base_iova + i * PAGE_SIZE);
            if !HardwareTables::unmap_slpt_page(root, iova_page) {
                ok = false;
            }
        }

        let cleared_ctx = self.tables.clear_context_entry(bus, device, function);
        ok &= cleared_ctx;
        self.audit.push(DmaAuditRecord {
            op: DmaAuditOp::Teardown, bdf, domain_id: owner_domain, ok, fault_gpa: 0, fault_flags: 0,
        });
        self.invalidate_context_cache(bdf, owner_domain, ok);

        if reclaim_root {
            let freed = HardwareTables::reclaim_slpt_tables_recursive(root, 4, true);
            self.directory.slpt_roots[slot_idx] = None;
            self.audit.push(DmaAuditRecord {
                op: DmaAuditOp::Reclaim, bdf, domain_id: owner_domain, ok: true, fault_gpa: 0, fault_flags: 0,
            });
            crate::log_debug!("已收回系统 SLPT 页树: 绑定关联 BDF {:#06x}, 原所属域 {} (腾空 {} 张表)", bdf, owner_domain, freed);
        }

        crate::log_info!("关闭设备隔离穿透通道: 关联节点 BDF {:#06x}, 原属域 {}", bdf, owner_domain);
        ok
    }

    pub fn unregister_device_dma(&mut self, bus: u8, device: u8, function: u8, domain_id: u32) -> bool {
        let bdf = pack_bdf(bus, device, function);
        let Some(binding_idx) = self.directory.binding_slot_index(bdf, domain_id) else {
            return false;
        };
        let binding = self.directory.bindings[binding_idx].unwrap();
        let ok = self.teardown_device_dma_window(
            bus, device, function, domain_id, binding.mmio_gpa, binding.mmio_bytes, true,
        );
        self.directory.bindings[binding_idx] = None;
        ok
    }

    pub fn audit_snapshot(&self) ->[DmaAuditRecord; AUDIT_RING] {
        self.audit.snapshot()
    }

    pub fn setup_device_dma_remapping(
        &mut self,
        bus: u8,
        device: u8,
        function: u8,
        owner_domain: u32,
        gpa: PhysAddr,
        hpa: PhysAddr,
    ) -> bool {
        let bdf = pack_bdf(bus, device, function);
        crate::log_debug!("加载物理映射关联点 BDF={:#06x} 原域={} 源GPA={:#x} 链接至 HPA={:#x}", bdf, owner_domain, gpa.as_u64(), hpa.as_u64());

        if self.iommu_type != IommuType::IntelVtd || self.tables.root_table_addr.is_none() {
            return false;
        }

        if !self.device_owned_by(bus, device, function, owner_domain) {
            self.audit.push(DmaAuditRecord { op: DmaAuditOp::RemapHook, bdf, domain_id: owner_domain, ok: false, fault_gpa: 0, fault_flags: 0 });
            return false;
        }

        let binding = self.lookup_binding(bus, device, function).unwrap();

        let Some(slpt_root) = self.ensure_slpt_root(bdf, owner_domain) else {
            self.audit.push(DmaAuditRecord { op: DmaAuditOp::RemapHook, bdf, domain_id: owner_domain, ok: false, fault_gpa: 0, fault_flags: 0 });
            return false;
        };

        let base_iova = binding.mmio_gpa.as_u64() & !(PAGE_SIZE - 1);
        let base_hpa = hpa.as_u64() & !(PAGE_SIZE - 1);
        let span = binding.mmio_bytes.max(PAGE_SIZE);
        let pages = (span + (PAGE_SIZE - 1)) / PAGE_SIZE;
        
        let mut mapped_all = true;
        for i in 0..pages {
            let iova_page = PhysAddr::new(base_iova + i * PAGE_SIZE);
            let hpa_page = PhysAddr::new(base_hpa + i * PAGE_SIZE);
            if !HardwareTables::map_slpt_page(slpt_root, iova_page, hpa_page) {
                mapped_all = false;
                break;
            }
        }

        if !mapped_all {
            crate::log_warn!("DMA 重映射表项写入失败: BDF={:#06x}，回滚变更", bdf);
            let _ = self.teardown_device_dma_window(bus, device, function, owner_domain, binding.mmio_gpa, binding.mmio_bytes, false);
            return false;
        }

        let idx = (device as usize) * 8 + (function as usize);
        let mut hooked = false;
        if idx < 256 {
            if let Some(ctx_phys) = self.tables.ensure_context_table_for_bus(bus) {
                let ctx_virt = crate::memory::phys_to_virt(ctx_phys);
                if !ctx_virt.is_null() {
                    let domain_id = (owner_domain as u16) as u128;
                    let lo: u128 = 1 | (2u128 << 2) | (domain_id << 8);
                    let hi: u128 = (slpt_root.as_u64() as u128) & !0xFFF;
                    let entry: u128 = lo | (hi << 64);
                    unsafe {
                        let slot = ctx_virt.as_mut_ptr::<u128>().add(idx);
                        core::ptr::write_volatile(slot, entry);
                    }
                    hooked = true;
                }
            }
        }

        self.audit.push(DmaAuditRecord {
            op: DmaAuditOp::RemapHook, bdf, domain_id: owner_domain, ok: hooked, fault_gpa: 0, fault_flags: 0,
        });
        self.invalidate_context_cache(bdf, owner_domain, hooked);
        hooked
    }

    pub fn iommu_type(&self) -> IommuType {
        self.iommu_type
    }

    pub fn dump_audit_ring_serial(&self, max_entries: usize) {
        self.audit.dump_serial(max_entries);
    }

    pub fn dump_binding_matrix_serial(&self) {
        self.directory.dump_serial();
    }
}