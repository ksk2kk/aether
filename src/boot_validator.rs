// src/boot_validator.rs
use core::cell::RefCell;
use spin::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootPhase {
    Serial,
    CpuDetection,
    MemoryManager,
    ApicManager,
    IommuManager,
    MemorySemanticBus,
    MmdlLedger,
    FusionBridge,
    VmxRoot,
    FirstGuest,
}

pub struct BootValidator {
    current_phase: RefCell<BootPhase>,
    success_count: RefCell<usize>,
    failure_count: RefCell<usize>,
}

impl BootValidator {
    pub const fn new() -> Self {
        BootValidator {
            current_phase: RefCell::new(BootPhase::Serial),
            success_count: RefCell::new(0),
            failure_count: RefCell::new(0),
        }
    }

    pub fn mark_phase_success(&self, phase: BootPhase) {
        *self.current_phase.borrow_mut() = phase;
        let mut count = self.success_count.borrow_mut();
        *count += 1;
        crate::log_debug!("引导阶段完成: {:?} (已完成总数: {})", phase, *count);
    }

    pub fn mark_phase_failure(&self, phase: BootPhase, reason: &str) {
        let mut count = self.failure_count.borrow_mut();
        *count += 1;
        crate::log_error!("引导阶段失败: {:?} 原因: {}", phase, reason);
        panic!("严重引导失败: {}", reason);
    }

    pub fn get_summary(&self) -> (BootPhase, usize, usize) {
        (
            *self.current_phase.borrow(),
            *self.success_count.borrow(),
            *self.failure_count.borrow(),
        )
    }
}

pub static BOOT_VALIDATOR: Mutex<BootValidator> = Mutex::new(BootValidator::new());

#[macro_export]
macro_rules! mark_boot_success {
    ($phase:expr) => {
        $crate::boot_validator::BOOT_VALIDATOR.lock().mark_phase_success($phase);
    };
}

#[macro_export]
macro_rules! mark_boot_failure {
    ($phase:expr, $reason:expr) => {
        $crate::boot_validator::BOOT_VALIDATOR.lock().mark_phase_failure($phase, $reason);
    };
}