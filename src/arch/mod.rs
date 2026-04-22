// src/arch/mod.rs
use self::x86_64::virtualization::VirtualizationProvider;
use alloc::boxed::Box;

pub mod x86_64;

pub fn init() -> Box<dyn VirtualizationProvider> {
    x86_64::init()
}