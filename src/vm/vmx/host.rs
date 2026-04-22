// src/vm/vmx/host.rs

use x86_64::registers::control::{Cr0, Cr3, Cr4};
use x86_64::registers::model_specific::Msr;
use x86_64::instructions::segmentation::{CS, Segment};
use x86_64::instructions::tables::{sgdt, sidt};
use core::arch::asm;
use crate::arch::x86_64::vmx::{
    exit::vmx_exit_handler,
    instructions::vmwrite,
    vmcs::VmcsField,
    IA32_VMX_CR0_FIXED0, IA32_VMX_CR0_FIXED1, IA32_VMX_CR4_FIXED0, IA32_VMX_CR4_FIXED1,
};

pub(super) fn setup_host_state() {
    unsafe {
        let cr0_fixed0 = Msr::new(IA32_VMX_CR0_FIXED0).read();
        let cr0_fixed1 = Msr::new(IA32_VMX_CR0_FIXED1).read();
        let mut host_cr0 = Cr0::read_raw();
        host_cr0 &= cr0_fixed1;
        host_cr0 |= cr0_fixed0;
        vmwrite(VmcsField::HostCr0 as u64, host_cr0);
        vmwrite(VmcsField::HostCr3 as u64, Cr3::read_raw().0.start_address().as_u64());
        let cr4_fixed0 = Msr::new(IA32_VMX_CR4_FIXED0).read();
        let cr4_fixed1 = Msr::new(IA32_VMX_CR4_FIXED1).read();
        let mut host_cr4 = Cr4::read_raw();
        host_cr4 &= cr4_fixed1;
        host_cr4 |= cr4_fixed0;
        vmwrite(VmcsField::HostCr4 as u64, host_cr4);

        vmwrite(VmcsField::HostCsSelector as u64, (CS::get_reg().0 & 0xF8) as u64);
        
        let tr = tr();
        vmwrite(VmcsField::HostTrSelector as u64, (tr & 0xF8) as u64);
        
        let mut ss: u16;
        let mut ds: u16;
        let mut es: u16;
        let mut fs: u16;
        let mut gs: u16;
        asm!(
            "mov {:x}, ss",
            "mov {:x}, ds",
            "mov {:x}, es",
            "mov {:x}, fs",
            "mov {:x}, gs",
            out(reg) ss,
            out(reg) ds,
            out(reg) es,
            out(reg) fs,
            out(reg) gs,
        );
        vmwrite(VmcsField::HostSsSelector as u64, (ss & 0xF8) as u64);
        vmwrite(VmcsField::HostDsSelector as u64, (ds & 0xF8) as u64);
        vmwrite(VmcsField::HostEsSelector as u64, (es & 0xF8) as u64);
        vmwrite(VmcsField::HostFsSelector as u64, (fs & 0xF8) as u64);
        vmwrite(VmcsField::HostGsSelector as u64, (gs & 0xF8) as u64);

        let sgdt = sgdt();
        let gdt_base = sgdt.base.as_u64();
        vmwrite(VmcsField::HostGdtrBase as u64, gdt_base);

        let sidt = sidt();
        vmwrite(VmcsField::HostIdtrBase as u64, sidt.base.as_u64());
        
        let tr_index = tr >> 3;
        let gdt_ptr = gdt_base as *const u64;
        let tr_desc_low = *gdt_ptr.add(tr_index as usize);
        let tr_desc_high = *gdt_ptr.add((tr_index + 1) as usize);
        
        let tr_base_low = ((tr_desc_low >> 16) & 0xFFFFFF) | (((tr_desc_low >> 56) & 0xFF) << 24);
        let tr_base = tr_base_low | (tr_desc_high << 32);
        
        vmwrite(VmcsField::HostTrBase as u64, tr_base);
        
        vmwrite(VmcsField::HostFsBase as u64, Msr::new(0xC0000100).read());
        vmwrite(VmcsField::HostGsBase as u64, Msr::new(0xC0000101).read());

        vmwrite(VmcsField::HostIa32SysenterCs as u64, Msr::new(0x174).read());
        vmwrite(VmcsField::HostIa32SysenterEsp as u64, Msr::new(0x175).read());
        vmwrite(VmcsField::HostIa32SysenterEip as u64, Msr::new(0x176).read());
        vmwrite(VmcsField::HostIa32Efer as u64, Msr::new(0xC0000080).read());

        let mut rsp: u64;
        asm!("mov {}, rsp", out(reg) rsp);
        vmwrite(VmcsField::HostRsp as u64, rsp);
        vmwrite(VmcsField::HostRip as u64, vmx_exit_handler as *const () as u64);
    }
}

#[inline]
pub fn tr() -> u16 {
    let tr: u16;
    unsafe {
        asm!("str {0:x}", out(reg) tr);
    }
    tr
}

#[inline]
pub fn set_tr(selector: u16) {
    unsafe {
        asm!("ltr {0:x}", in(reg) selector);
    }
}