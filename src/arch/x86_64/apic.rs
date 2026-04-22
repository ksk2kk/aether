// src/arch/x86_64/apic.rs
use raw_cpuid::CpuId;
use x86_64::PhysAddr;
use x86_64::registers::model_specific::Msr;
use spin::Mutex;
use super::vmx::{instructions, vmcs::VmcsField};

const IA32_APIC_BASE: u32 = 0x1b;
pub const DOORBELL_FLUSH_VECTOR: u8 = 0xfd;
pub const DOORBELL_SCHEDULE_VECTOR: u8 = 0xfc;

const X2APIC_EOI: u32 = 0x80b;
const X2APIC_ICR: u32 = 0x830;
const X2APIC_ID: u32 = 0x802;

const VM_ENTRY_INTR_TYPE_EXT: u32 = 0 << 8;
const RFLAGS_IF: u64 = 1 << 9;

pub fn local_apic_id() -> u32 {
    CpuId::new()
        .get_feature_info()
        .map(|f| u32::from(f.initial_local_apic_id()))
        .unwrap_or(0)
}

fn clear_vm_entry_interruption() {
    unsafe {
        instructions::vmwrite(VmcsField::VmEntryInterruptionInfo as u64, 0);
        instructions::vmwrite(VmcsField::VmEntryInterruptionErrorCode as u64, 0);
    }
}

fn guest_accepts_maskable_external_irq() -> bool {
    let rflags = unsafe { instructions::vmread(VmcsField::GuestRflags as u64) };
    if (rflags & RFLAGS_IF) == 0 {
        return false;
    }
    let intr = unsafe { instructions::vmread(VmcsField::GuestInterruptibilityState as u64) };
    intr & 0b11 == 0
}

fn cpuid_x2apic_supported() -> bool {
    CpuId::new()
        .get_feature_info()
        .map(|f| f.has_x2apic())
        .unwrap_or(false)
}

fn initial_apic_id_from_cpuid() -> u32 {
    local_apic_id()
}

pub struct ApicManager {
    apic_base: u64,
    is_x2apic: bool,
    mmio_phys_base: u64,
    local_apic_id: u32,
}

impl ApicManager {
    pub fn new() -> Self {
        let apic_base = unsafe { Msr::new(IA32_APIC_BASE).read() };
        let is_x2apic = (apic_base & 0x400) != 0;
        let mmio_phys_base = apic_base & 0xFFFF_FFFF_F000;

        let local_apic_id = if is_x2apic {
            (unsafe { Msr::new(X2APIC_ID).read() } & 0xFFFF_FFFF) as u32
        } else {
            initial_apic_id_from_cpuid()
        };

        ApicManager {
            apic_base,
            is_x2apic,
            mmio_phys_base,
            local_apic_id,
        }
    }

    pub fn initialize(&mut self) {
        crate::log_debug!(
            "本地 APIC 校准完毕: ID={} (x2APIC状态: {})",
            self.local_apic_id,
            self.is_x2apic
        );

        if !self.is_x2apic && cpuid_x2apic_supported() {
            unsafe {
                let base = Msr::new(IA32_APIC_BASE).read();
                if (base & (1 << 11)) != 0 {
                    Msr::new(IA32_APIC_BASE).write(base | (1 << 10));
                    self.is_x2apic = true;
                    self.local_apic_id =
                        (Msr::new(X2APIC_ID).read() & 0xFFFF_FFFF) as u32;
                    crate::log_debug!("动态切入 x2APIC 通信机制");
                }
            }
        }

        if self.is_x2apic {
            unsafe {
                let base = Msr::new(IA32_APIC_BASE).read();
                Msr::new(IA32_APIC_BASE).write(base | 0x400);
            }
            crate::log_debug!("确认使用高级可编程中断控制器架构 (x2APIC)");
        } else {
            crate::log_debug!("运行环境降级为 xAPIC 模式 (MMIO寄存器: {:#x})", self.mmio_phys_base);
        }
    }

    pub fn boot_aps(&self) {
        crate::log_info!("执行核间通信启动序列 (INIT-SIPI)");
        if self.is_x2apic {
            unsafe {
                Msr::new(X2APIC_ICR).write(0x000C_4500); 
                Msr::new(X2APIC_ICR).write(0x000C_4608); 
            }
        } else {
            Self::mmio_write_u32(self.mmio_phys_base + 0x300, 0x000C_4500);
            Self::mmio_write_u32(self.mmio_phys_base + 0x300, 0x000C_4608);
        }
    }

    pub fn signal_eoi(&self) {
        if self.is_x2apic {
            unsafe { Msr::new(X2APIC_EOI).write(0); }
        } else {
            Self::mmio_write_u32(self.mmio_phys_base + 0xb0, 0);
        }
    }
    
    pub fn send_ipi_all_excluding_self(&self, _self_id: u32, vector: u8) {
        let delivery_mode = 0b100;
        let level = 1;
        let trigger_mode = 0;
        let shorthand = 0b11;

        let icr_low = (vector as u32)
            | (delivery_mode << 8)
            | (level << 14)
            | (trigger_mode << 15)
            | (shorthand << 18);
        
        let icr: u64 = icr_low as u64;

        if self.is_x2apic {
             unsafe { Msr::new(X2APIC_ICR).write(icr) };
        } else {
            Self::mmio_write_u32(self.mmio_phys_base + 0x300, icr_low);
        }
    }

    pub fn send_ipi(&self, target_lapic_id: u32, vector: u8) {
        if target_lapic_id == self.local_apic_id {
            crate::coherence::fence_and_invalidate_all_epts();
            return;
        }

        if self.is_x2apic {
            let icr: u64 = (vector as u64) | ((target_lapic_id as u64) << 32);
            unsafe { Msr::new(X2APIC_ICR).write(icr); }
            const ICR_DELIVERY_STATUS: u64 = 1 << 12;
            let mut timed_out = true;
            for _ in 0..1_000_000u32 {
                let v = unsafe { Msr::new(X2APIC_ICR).read() };
                if (v & ICR_DELIVERY_STATUS) == 0 {
                    timed_out = false;
                    break;
                }
            }
            if timed_out {
                crate::log_warn!("IPI 发送超时: 向量={}, 目标={}", vector, target_lapic_id);
            }
        } else {
            let dest = (target_lapic_id & 0xFF) << 24;
            Self::mmio_write_u32(self.mmio_phys_base + 0x310, dest);
            let low = (vector as u32) | (1 << 14);
            Self::mmio_write_u32(self.mmio_phys_base + 0x300, low);
            const ICR_LO_DELIVERY_STATUS: u32 = 1 << 12;
            let mut timed_out = true;
            for _ in 0..1_000_000u32 {
                let lo = Self::mmio_read_u32(self.mmio_phys_base + 0x300);
                if (lo & ICR_LO_DELIVERY_STATUS) == 0 {
                    timed_out = false;
                    break;
                }
            }
            if timed_out {
                crate::log_warn!("IPI 发送超时: 向量={}, 目标={}", vector, target_lapic_id);
            }
        }
    }

    pub fn inject_interrupt_to_guest(&self, vector: u8, guest_id: u32) {
        if !guest_accepts_maskable_external_irq() {
            clear_vm_entry_interruption();
            crate::log_debug!("取消外源中断注入: 接收域屏蔽 (向量={}, 域={})", vector, guest_id);
            return;
        }

        let interruption_info: u32 = (1 << 31) | VM_ENTRY_INTR_TYPE_EXT | (vector as u32);

        unsafe {
            instructions::vmwrite(VmcsField::VmEntryInterruptionInfo as u64, interruption_info as u64);
            instructions::vmwrite(VmcsField::VmEntryInterruptionErrorCode as u64, 0);
        }
    }

    pub fn route_external_interrupt_vmexit(&self, exit_interruption_info: u64) {
        let valid = (exit_interruption_info >> 31) & 1 != 0;
        let vector = (exit_interruption_info & 0xFF) as u8;

        if !valid {
            self.signal_eoi();
            return;
        }

        if vector == DOORBELL_FLUSH_VECTOR {
            crate::coherence::fence_and_invalidate_all_epts();
            self.signal_eoi();
            return;
        }

        self.signal_eoi();

        let guest_id = crate::enclave::get_manager()
            .as_ref()
            .and_then(|m| m.current_id())
            .unwrap_or(0);

        self.inject_interrupt_to_guest(vector, guest_id);
    }

    fn mmio_write_u32(phys_off: u64, val: u32) {
        let va = crate::memory::phys_to_virt(PhysAddr::new(phys_off));
        unsafe { core::ptr::write_volatile(va.as_mut_ptr::<u32>(), val); }
    }

    fn mmio_read_u32(phys_off: u64) -> u32 {
        let va = crate::memory::phys_to_virt(PhysAddr::new(phys_off));
        unsafe { core::ptr::read_volatile(va.as_ptr::<u32>()) }
    }
}

static APIC_MANAGER: Mutex<Option<ApicManager>> = Mutex::new(None);

pub fn init() {
    let mut guard = APIC_MANAGER.lock();
    *guard = Some(ApicManager::new());
    if let Some(manager) = guard.as_mut() {
        manager.initialize();
    }
    crate::log_info!("高级可编程中断控制器架构已就位");
}

pub fn get_manager() -> spin::MutexGuard<'static, Option<ApicManager>> {
    APIC_MANAGER.lock()
}