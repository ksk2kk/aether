// src/arch/x86_64/iommu/mod.rs
pub mod types;
pub mod audit;
pub mod directory;
pub mod tables;
pub mod manager;

pub use types::{RegisterError}; // 移除未使用的导入
pub use audit::{DmaAuditRecord}; // 移除未使用的导入
pub use manager::IommuManager;

use spin::Mutex;

static IOMMU_MANAGER: Mutex<Option<IommuManager>> = Mutex::new(None);

pub fn init() {
    let mut guard = IOMMU_MANAGER.lock();
    *guard = Some(IommuManager::new());
    if let Some(manager) = guard.as_mut() {
        manager.detect();
        manager.initialize_root_context_table();
    }
    crate::log_info!("IOMMU 硬件审计模块完全就绪，启动地址屏障");
}

pub fn get_manager() -> spin::MutexGuard<'static, Option<IommuManager>> {
    IOMMU_MANAGER.lock()
}