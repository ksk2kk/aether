// src/lib.rs
#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

mod serial;
mod memory;
mod coherence;
mod msb;
mod mmdl;
mod fusion;
mod guest;
#[macro_use]
mod boot_validator;
pub mod enclave;
mod arch;
mod vm;
mod percpu;

use core::panic::PanicInfo;
use core::alloc::Layout;

#[global_allocator]
pub static HEAP_ALLOCATOR: memory::HeapAllocator = memory::HeapAllocator::empty();

#[alloc_error_handler]
fn alloc_error_handler(layout: Layout) -> ! {
    panic!("内存分配失败: 大小为 {:?}", layout.size());
}

#[no_mangle]
pub extern "C" fn kernel_main(multiboot_info_addr: usize) -> ! {
    crate::log_info!("Aether Hyperion 内核启动序列开始...");
    mark_boot_success!(boot_validator::BootPhase::Serial);

    percpu::init();

    let mut virtualization_provider = arch::init();
    mark_boot_success!(boot_validator::BootPhase::CpuDetection);

    memory::init(multiboot_info_addr);
    mark_boot_success!(boot_validator::BootPhase::MemoryManager);

    arch::x86_64::apic::init();
    mark_boot_success!(boot_validator::BootPhase::ApicManager);

    arch::x86_64::iommu::init();
    mark_boot_success!(boot_validator::BootPhase::IommuManager);

    msb::init();
    mark_boot_success!(boot_validator::BootPhase::MemorySemanticBus);

    mmdl::init();
    mark_boot_success!(boot_validator::BootPhase::MmdlLedger);

    fusion::init();
    mark_boot_success!(boot_validator::BootPhase::FusionBridge);

    virtualization_provider.enable();
    virtualization_provider.enter_root_mode();
    mark_boot_success!(boot_validator::BootPhase::VmxRoot);

    if let Some(apic) = arch::x86_64::apic::get_manager().as_ref() {
        apic.boot_aps();
    }

    enclave::init(&mut *virtualization_provider);

    loop {
        x86_64::instructions::hlt();
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    crate::log_error!("内核崩溃: {}", info);
    loop {
        x86_64::instructions::hlt();
    }
}