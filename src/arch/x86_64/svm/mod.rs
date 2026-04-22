/* src/arch/x86_64/svm/mod.rs */
use crate::arch::x86_64::virtualization::VirtualizationProvider;
use x86_64::PhysAddr;

pub struct SvmManager;

impl SvmManager {
    pub fn new() -> Self {
        Self
    }
}

impl VirtualizationProvider for SvmManager {
    fn check_support(&self) {
        crate::log_warn!("AMD-V (SVM) 支持为框架占位，尚未实现");
    }

    fn enable(&mut self) {
        unimplemented!("AMD-V (SVM) 硬件启用路径尚未实现");
    }

    fn enter_root_mode(&mut self) {
        unimplemented!("AMD-V (SVM) 安全监控模式进入路径尚未实现");
    }

    fn launch_guest(&self) {
        unimplemented!("AMD-V (SVM) VMRUN 路径尚未实现");
    }

    fn get_revision_id(&self) -> u32 {
        0
    }

    fn prepare_guest(
        &self,
        _vmcs_region: PhysAddr,
        _guest_rip: u64,
        _guest_rsp: u64,
        _ept_pointer: u64,
        _vpid: u16,
        _pml_pointer: PhysAddr,
    ) {
        unimplemented!("AMD-V (SVM) VMCB 配置路径尚未实现");
    }
}