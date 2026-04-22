// src/arch/x86_64/vmx/mod.rs

use crate::arch::x86_64::virtualization::VirtualizationProvider;
use crate::memory::utils;
use core::arch::asm;
use x86_64::registers::control::{Cr0, Cr4};
use x86_64::registers::model_specific::Msr;
use x86_64::PhysAddr;

pub mod controls;
pub mod exit;
pub mod guest;
pub mod host;
pub mod instructions;
pub mod vmcs;

use instructions::vmread;

pub const IA32_VMX_BASIC: u32 = 0x480;
pub const IA32_VMX_PINBASED_CTLS: u32 = 0x481;
pub const IA32_VMX_PROCBASED_CTLS: u32 = 0x482;
pub const IA32_VMX_EXIT_CTLS: u32 = 0x483;
pub const IA32_VMX_ENTRY_CTLS: u32 = 0x484;
pub const IA32_VMX_CR0_FIXED0: u32 = 0x486;
pub const IA32_VMX_CR0_FIXED1: u32 = 0x487;
pub const IA32_VMX_CR4_FIXED0: u32 = 0x488;
pub const IA32_VMX_CR4_FIXED1: u32 = 0x489;
pub const IA32_VMX_PROCBASED_CTLS2: u32 = 0x48B;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GuestRegisters {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

pub struct VmxManager;

impl VmxManager {
    pub fn new() -> Self {
        Self
    }
}

impl VirtualizationProvider for VmxManager {
    fn check_support(&self) {
        let cpuid = raw_cpuid::CpuId::new();
        let feature_info = cpuid.get_feature_info().expect("CPUID 特性探测未响应");
        if !feature_info.has_vmx() {
            panic!("底层执行环境异常：处理器未能提供虚拟化指令集！");
        }
        crate::log_debug!("确认处理器承载虚拟化能力 (VMX支持激活)");
    }

    fn enable(&mut self) {
        unsafe {
            let mut cr0 = Cr0::read_raw();
            cr0 |= Msr::new(IA32_VMX_CR0_FIXED0).read();
            cr0 &= Msr::new(IA32_VMX_CR0_FIXED1).read();
            cr0 |= 0x20;
            Cr0::write_raw(cr0);

            let mut cr4 = Cr4::read_raw();
            cr4 |= 1 << 13;
            cr4 |= Msr::new(IA32_VMX_CR4_FIXED0).read();
            cr4 &= Msr::new(IA32_VMX_CR4_FIXED1).read();
            Cr4::write_raw(cr4);

            let mut feature_control = Msr::new(0x3A);
            let val = feature_control.read();
            if (val & 1) == 0 {
                feature_control.write(val | 0x5);
            } else {
                if (val & 0x4) == 0 {
                    panic!("严重限制：系统 BIOS 在微架构层禁止了虚拟化执行");
                }
            }
        }
    }

    fn enter_root_mode(&mut self) {
        unsafe {
            let tss_frame = crate::memory::allocate_frame().expect("TSS 分配失败");
            let tss_addr = tss_frame.start_address().as_u64();
            let tss_virt = crate::memory::phys_to_virt(tss_frame.start_address());
            utils::zero_bytes(tss_virt, 104);

            let gdt_frame = crate::memory::allocate_frame().expect("GDT 分配失败");
            let gdt_addr = gdt_frame.start_address().as_u64();
            let gdt_ptr = crate::memory::phys_to_virt(gdt_frame.start_address()).as_mut_ptr::<u64>();

            *gdt_ptr.add(0) = 0;
            *gdt_ptr.add(1) = (1 << 43) | (1 << 44) | (1 << 47) | (1 << 53);
            *gdt_ptr.add(2) = (1 << 41) | (1 << 44) | (1 << 47);

            let limit = 103u64;
            let base = tss_addr;
            let tss_low = (limit & 0xFFFF)
                | ((base & 0xFFFFFF) << 16)
                | (0x89 << 40)
                | (((limit >> 16) & 0xF) << 48)
                | (((base >> 24) & 0xFF) << 56);
            let tss_high = base >> 32;

            *gdt_ptr.add(3) = tss_low;
            *gdt_ptr.add(4) = tss_high;

            let mut gdtr_array: [u16; 5] = [0; 5];
            gdtr_array[0] = (5 * 8 - 1) as u16;
            gdtr_array[1] = (gdt_addr & 0xFFFF) as u16;
            gdtr_array[2] = ((gdt_addr >> 16) & 0xFFFF) as u16;
            gdtr_array[3] = ((gdt_addr >> 32) & 0xFFFF) as u16;
            gdtr_array[4] = ((gdt_addr >> 48) & 0xFFFF) as u16;
            asm!("lgdt [{0}]", in(reg) gdtr_array.as_ptr());
            host::set_tr(0x18);
            asm!(
                "mov ax, 0x10", "mov ds, ax", "mov es, ax", "mov ss, ax", "mov fs, ax", "mov gs, ax",
                out("ax") _, options(nomem, nostack, preserves_flags)
            );
        }

        let frame = crate::memory::allocate_frame().expect("VMXON 内存区域分配失败");
        let phys_addr = frame.start_address().as_u64();

        unsafe {
            let revision_id = Msr::new(IA32_VMX_BASIC).read() as u32;
            let virt_addr = crate::memory::phys_to_virt(frame.start_address());
            let ptr = virt_addr.as_mut_ptr::<u32>();
            ptr.write_volatile(revision_id);
        }

        vmxon(phys_addr);
    }

    fn launch_guest(&self) {
        crate::log_info!("矩阵执行载荷组装完毕，激活 VMLAUNCH 序列");
        unsafe {
            let rflags: u64;
            asm!(
                "vmlaunch", "pushfq", "pop {0}",
                out(reg) rflags, options(nostack)
            );
            let error = vmread(vmcs::VmcsField::VmInstructionError as u64);
            crate::log_error!("VMLAUNCH 断言失败! 指令返回错误码: {:#x}, RFLAGS: {:#x}", error, rflags);
            panic!("致命物理隔离中断：未能完成隔离域侵入操作。");
        }
    }
    
    fn get_revision_id(&self) -> u32 {
        unsafe { Msr::new(IA32_VMX_BASIC).read() as u32 }
    }
    
    fn prepare_guest(
        &self,
        vmcs_region: PhysAddr,
        guest_rip: u64,
        guest_rsp: u64,
        ept_pointer: u64,
        vpid: u16,
        pml_pointer: PhysAddr,
    ) {
        unsafe {
            instructions::vmclear(vmcs_region);
            instructions::vmptrld(vmcs_region);
        }
        host::setup_host_state();
        controls::setup_control_fields(ept_pointer, vpid, pml_pointer);
        guest::setup_guest_state(guest_rip, guest_rsp);
    }
}

fn vmxon(vmxon_region_phys: u64) {
    unsafe {
        let rflags: u64;
        asm!(
            "vmxon[{0}]", "pushfq", "pop {1}",
            in(reg) &vmxon_region_phys, out(reg) rflags, options(nostack)
        );
        if (rflags & 0x41) != 0 {
            panic!("指令拒绝：VMXON 引发执行异常");
        }
    }
    crate::log_info!("系统已接管底层 VMX Root 执行平面");
}