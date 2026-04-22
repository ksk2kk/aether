/* src/msb/mod.rs */
pub mod cap;

use crate::memory::ept::{EptFlags, EptManager};
use cap::{CapabilityManager, Permission};
use x86_64::PhysAddr;
use spin::Mutex;

const ASYNC_TRANSFER_VECTOR: u8 = 0xF0;

pub struct MemorySemanticBus {
    cap_mgr: CapabilityManager,
}

impl MemorySemanticBus {
    pub fn new() -> Self {
        let mut msb = MemorySemanticBus {
            cap_mgr: CapabilityManager::new(),
        };
        msb.grant_capability(1, 2, Permission::TRANSFER | Permission::MAP_SHARED);
        msb
    }

    pub fn grant_capability(&mut self, src_enclave_id: u32, target_enclave_id: u32, perms: Permission) {
        self.cap_mgr.grant(src_enclave_id, target_enclave_id, perms);
    }

    pub fn is_authorized(&self, src_id: u32, dst_id: u32, required_perm: Permission) -> bool {
        self.cap_mgr.has_permission(src_id, dst_id, required_perm)
    }

    pub fn transfer_page_ownership(
        &mut self, 
        src_id: u32,
        dst_id: u32,
        src_ept: &mut EptManager, 
        dst_ept: &mut EptManager, 
        src_gpa: PhysAddr, 
        dst_gpa: PhysAddr,
        flags: EptFlags
    ) -> bool {
        if !self.is_authorized(src_id, dst_id, Permission::TRANSFER) {
            crate::log_warn!("MSB 传输拒绝: 权限不足 ({} -> {})", src_id, dst_id);
            return false;
        }

        crate::log_debug!("转移物理页所有权: GPA {:#x} -> GPA {:#x}", src_gpa.as_u64(), dst_gpa.as_u64());

        let hpa = match src_ept.unmap(src_gpa) {
            Some(addr) => addr,
            None => {
                crate::log_error!("MSB 错误: 源 GPA 尚未映射");
                return false;
            }
        };

        dst_ept.map(dst_gpa, hpa, flags);
        crate::coherence::broadcast_vpid_flush(dst_id as u16);

        crate::log_debug!("所有权转移成功，对应物理帧: {:#x}", hpa.as_u64());
        true
    }

    pub fn transfer_page_ownership_async(
        &mut self, 
        src_id: u32,
        dst_id: u32,
        src_ept: &mut EptManager, 
        dst_ept: &mut EptManager, 
        src_gpa: PhysAddr, 
        dst_gpa: PhysAddr,
        flags: EptFlags
    ) -> bool {
        if self.transfer_page_ownership(src_id, dst_id, src_ept, dst_ept, src_gpa, dst_gpa, flags) {
             let apic_guard = crate::arch::x86_64::apic::get_manager();
            if let Some(apic) = apic_guard.as_ref() {
                apic.inject_interrupt_to_guest(ASYNC_TRANSFER_VECTOR, dst_id);
                crate::log_debug!("已向隔离域 {} 注入异步通知向量 {:#x}", dst_id, ASYNC_TRANSFER_VECTOR);
            }
            true
        } else {
            false
        }
    }

    pub fn map_shared_readonly(
        &mut self,
        src_id: u32,
        dst_id: u32,
        src_ept: &EptManager,
        dst_ept: &mut EptManager,
        gpa: PhysAddr,
    ) -> bool {
        if !self.is_authorized(src_id, dst_id, Permission::MAP_SHARED) {
             return false;
        }

        let hpa = match src_ept.translate_gpa(gpa) {
            Some(addr) => addr,
            None => return false,
        };

        let flags = EptFlags::READ | EptFlags::MEMORY_TYPE_WB;
        dst_ept.map(gpa, hpa, flags);
        crate::coherence::broadcast_vpid_flush(dst_id as u16);
        true
    }

    pub fn transfer_pages(
        &mut self, 
        src_id: u32,
        dst_id: u32,
        src_ept: &mut EptManager, 
        dst_ept: &mut EptManager, 
        pages: &[(PhysAddr, PhysAddr, EptFlags)]
    ) -> usize {
        if !self.is_authorized(src_id, dst_id, Permission::TRANSFER) {
            crate::log_warn!("MSB 批量传输拒绝: 权限不足 ({} -> {})", src_id, dst_id);
            return 0;
        }

        crate::log_debug!("执行批量页转移，共 {} 页", pages.len());
        
        let mut successful_transfers = 0;
        
        for &(src_gpa, dst_gpa, flags) in pages {
            if let Some(hpa) = src_ept.unmap(src_gpa) {
                dst_ept.map(dst_gpa, hpa, flags);
                successful_transfers += 1;
            } else {
                crate::log_warn!("批量传输异常: GPA {:#x} 在源 EPT 中无映射", src_gpa.as_u64());
            }
        }
        
        if successful_transfers > 0 {
            crate::coherence::broadcast_vpid_flush(dst_id as u16);
            crate::log_debug!("批量传输结束，转移比例 {}/{}", successful_transfers, pages.len());
        }
        
        successful_transfers
    }
}

static MSB: Mutex<Option<MemorySemanticBus>> = Mutex::new(None);

pub fn init() {
    *MSB.lock() = Some(MemorySemanticBus::new());
    crate::log_info!("内存语义总线 (MSB) 初始化完毕，融合 Capability 权限机制");
}

pub fn get_manager() -> spin::MutexGuard<'static, Option<MemorySemanticBus>> {
    MSB.lock()
}