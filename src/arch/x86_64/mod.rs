// src/arch/x86_64/mod.rs
pub mod apic;
pub mod iommu;
pub mod vmx;
pub mod svm;
pub mod virtualization;

use self::virtualization::VirtualizationProvider;
use alloc::boxed::Box;
use raw_cpuid::CpuId;

pub fn init() -> Box<dyn VirtualizationProvider> {
    let cpuid = CpuId::new();
    
    // 引入let绑定来延长cpuid.get_vendor_info()返回的临时值的生命周期。
    // 这样，vendor_info_result在as_str()返回的切片被使用期间，都将保持有效。
    let vendor_info_result = cpuid.get_vendor_info()
                                  .expect("CPUID Vendor Info not available");
    let vendor_str = vendor_info_result.as_str();
    
    let provider: Box<dyn VirtualizationProvider> = match vendor_str {
        "GenuineIntel" => {
            crate::log_info!("检测到 Intel 架构，启用 VMX 硬件抽象层");
            Box::new(vmx::VmxManager::new())
        }
        "AuthenticAMD" => {
            crate::log_info!("检测到 AMD 架构，启用 SVM 硬件抽象层");
            Box::new(svm::SvmManager::new())
        }
        _ => panic!("不支持的 CPU 厂商"),
    };

    provider.check_support();
    provider
}